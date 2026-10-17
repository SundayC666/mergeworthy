"""Unit tests for harness/llm.py. No network: the OpenAI client is replaced by a fake
whose `chat.completions.create` replays a scripted list of responses and errors."""

from types import SimpleNamespace

import httpx
import pytest
from openai import BadRequestError

from harness.llm import (
    GATEWAY_BASE_URL,
    OLLAMA_BASE_URL,
    ModelCallError,
    ModelConfig,
    ModelConfigError,
    call_model,
    load_model_config,
)


# --- fakes -----------------------------------------------------------------------


def bad_request(message: str) -> BadRequestError:
    request = httpx.Request("POST", "http://fake/v1/chat/completions")
    response = httpx.Response(400, request=request)
    return BadRequestError(message, response=response, body=None)


def reply(text, prompt_tokens=10, completion_tokens=5):
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
        usage=SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens),
    )


class FakeCompletions:
    def __init__(self, script):
        self.script = list(script)
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeClient:
    def __init__(self, script):
        self.chat = SimpleNamespace(completions=FakeCompletions(script))

    @property
    def calls(self):
        return self.chat.completions.calls


def config(**overrides) -> ModelConfig:
    base = dict(
        provider="gateway",
        model="fake-model",
        base_url=GATEWAY_BASE_URL,
        api_key="x",
        temperature=1.0,
        max_tokens=100,
    )
    base.update(overrides)
    return ModelConfig(**base)


# --- configuration -----------------------------------------------------------------


def test_gateway_requires_a_key():
    with pytest.raises(ModelConfigError):
        load_model_config("claude-sonnet-5", provider="gateway", env={})


def test_gateway_config_from_env():
    cfg = load_model_config("claude-sonnet-5", env={"DUKE_API_KEY": "sk-test"})
    assert cfg.provider == "gateway"
    assert cfg.base_url == GATEWAY_BASE_URL
    assert cfg.api_key == "sk-test"
    assert cfg.temperature == 1.0  # ARCHITECTURE §7: explicit, logged, not provider default


def test_ollama_needs_no_key():
    cfg = load_model_config("gpt-oss:20b", env={"HARNESS_PROVIDER": "ollama"})
    assert cfg.provider == "ollama"
    assert cfg.base_url == OLLAMA_BASE_URL


def test_unknown_provider_is_rejected():
    with pytest.raises(ModelConfigError):
        load_model_config("x", provider="banana", env={})


# --- calling the model -------------------------------------------------------------


def test_call_returns_text_params_and_usage():
    client = FakeClient([reply("diff --git a b")])
    result = call_model(client, config(), "sys", "usr")
    assert result.text == "diff --git a b"
    assert result.params_used == {"temperature": 1.0, "max_tokens": 100}
    assert result.prompt_tokens == 10 and result.completion_tokens == 5
    assert result.notes == []
    sent = client.calls[0]
    assert sent["model"] == "fake-model"
    assert sent["messages"][0] == {"role": "system", "content": "sys"}


def test_rejected_temperature_is_dropped_and_recorded():
    client = FakeClient([bad_request("Unsupported parameter: 'temperature'"), reply("ok")])
    result = call_model(client, config(), "s", "u")
    assert "temperature" not in client.calls[1]
    assert "temperature" not in result.params_used
    assert result.notes == ["fake-model rejected temperature; retried without it"]


def test_max_tokens_is_renamed_not_dropped():
    msg = "Use 'max_completion_tokens' instead of 'max_tokens'"
    client = FakeClient([bad_request(msg), reply("ok")])
    result = call_model(client, config(), "s", "u")
    assert client.calls[1]["max_completion_tokens"] == 100
    assert "max_tokens" not in client.calls[1]
    assert result.params_used == {"temperature": 1.0, "max_completion_tokens": 100}


def test_unrelated_400_is_raised_unchanged():
    client = FakeClient([bad_request("model not found")])
    with pytest.raises(BadRequestError):
        call_model(client, config(), "s", "u")
    assert len(client.calls) == 1


def test_empty_reply_fails_closed():
    client = FakeClient([reply("   ")])
    with pytest.raises(ModelCallError):
        call_model(client, config(), "s", "u")


def test_gives_up_after_every_param_was_rejected():
    client = FakeClient([bad_request("'temperature'"), bad_request("'max_tokens'"),
                         bad_request("'max_completion_tokens'"), bad_request("'nothing'")])
    with pytest.raises((ModelCallError, BadRequestError)):
        call_model(client, config(), "s", "u")


def test_gateway_calls_bypass_the_litellm_cache():
    client = FakeClient([reply("ok")])
    call_model(client, config(provider="gateway"), "s", "u")
    assert client.calls[0]["extra_body"] == {"cache": {"no-cache": True}}


def test_ollama_calls_send_no_cache_header():
    client = FakeClient([reply("ok")])
    call_model(client, config(provider="ollama", base_url=OLLAMA_BASE_URL, api_key="ollama"), "s", "u")
    assert "extra_body" not in client.calls[0]


def test_finish_reason_is_recorded():
    r = reply("ok")
    r.choices[0].finish_reason = "stop"
    client = FakeClient([r])
    assert call_model(client, config(), "s", "u").finish_reason == "stop"
