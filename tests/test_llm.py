"""Unit tests for harness/llm.py. No network: the OpenAI client is replaced by a fake
whose `chat.completions.create` replays a scripted list of responses and errors."""

from types import SimpleNamespace

import httpx
import pytest
from openai import BadRequestError

import harness.llm as llm_mod
from harness.llm import (
    GATEWAY_BASE_URL,
    OLLAMA_BASE_URL,
    BudgetExhausted,
    ModelCallError,
    ModelConfig,
    ModelConfigError,
    assert_budget,
    call_model,
    gateway_budget,
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
    client = FakeClient(
        [
            bad_request("'temperature'"),
            bad_request("'max_tokens'"),
            bad_request("'max_completion_tokens'"),
            bad_request("'nothing'"),
        ]
    )
    with pytest.raises((ModelCallError, BadRequestError)):
        call_model(client, config(), "s", "u")


def test_gateway_calls_bypass_the_litellm_cache():
    client = FakeClient([reply("ok")])
    call_model(client, config(provider="gateway"), "s", "u")
    assert client.calls[0]["extra_body"] == {"cache": {"no-cache": True}}


def test_ollama_calls_send_no_cache_header():
    client = FakeClient([reply("ok")])
    call_model(
        client, config(provider="ollama", base_url=OLLAMA_BASE_URL, api_key="ollama"), "s", "u"
    )
    assert "extra_body" not in client.calls[0]


def test_finish_reason_is_recorded():
    r = reply("ok")
    r.choices[0].finish_reason = "stop"
    client = FakeClient([r])
    assert call_model(client, config(), "s", "u").finish_reason == "stop"


# --- budget ------------------------------------------------------------------------


def fake_key_info(spend, max_budget):
    class R:
        def raise_for_status(self):
            pass

        def json(self):
            return {"info": {"spend": spend, "max_budget": max_budget}}

    def get(url, headers=None, timeout=None):
        assert url == "https://litellm.oit.duke.edu/key/info"  # root, not /v1
        assert headers["Authorization"].startswith("Bearer ")
        return R()

    return get


def test_gateway_budget_reads_spend_and_cap(monkeypatch):
    monkeypatch.setattr(httpx, "get", fake_key_info(0.154, 1.0))
    b = gateway_budget(config())
    assert (b.spend, b.max_budget) == (0.154, 1.0)
    assert round(b.remaining, 3) == 0.846


def test_assert_budget_stops_before_spending(monkeypatch):
    monkeypatch.setattr(httpx, "get", fake_key_info(0.95, 1.0))
    monkeypatch.setattr(llm_mod, "BUDGET_RESERVE_USD", 0.30)
    with pytest.raises(BudgetExhausted):
        assert_budget(config())


def test_assert_budget_passes_with_room(monkeypatch):
    monkeypatch.setattr(httpx, "get", fake_key_info(0.10, 1.0))
    monkeypatch.setattr(llm_mod, "BUDGET_RESERVE_USD", 0.30)
    assert assert_budget(config()).spend == 0.10


def test_uncapped_key_never_stops(monkeypatch):
    monkeypatch.setattr(httpx, "get", fake_key_info(5.0, None))
    monkeypatch.setattr(llm_mod, "BUDGET_RESERVE_USD", 0.30)
    assert assert_budget(config()).remaining is None


def test_ollama_has_no_budget():
    assert assert_budget(config(provider="ollama")) is None


def test_reserve_must_be_decided():
    assert llm_mod.BUDGET_RESERVE_USD is not None, "fill in BUDGET_RESERVE_USD (TODO in llm.py)"


def test_unreachable_gateway_is_fail_closed(monkeypatch):
    # VPN down / DNS / timeout: the budget is unknown, so no run may start. This must be
    # the same stop path as "budget exhausted", not a traceback.
    def boom(url, headers=None, timeout=None):
        raise httpx.ConnectTimeout("timed out")

    monkeypatch.setattr(httpx, "get", boom)
    monkeypatch.setattr(llm_mod, "BUDGET_RESERVE_USD", 0.30)
    with pytest.raises(BudgetExhausted, match="VPN"):
        assert_budget(config())


# --- transient errors: slow retry on top of the SDK's fast retries ---------------------

from openai import APIConnectionError, InternalServerError, RateLimitError  # noqa: E402


def status_error(cls, status: int):
    request = httpx.Request("POST", "http://fake/v1/chat/completions")
    return cls("boom", response=httpx.Response(status, request=request), body=None)


def test_rate_limit_is_retried_after_a_long_wait(monkeypatch):
    waits = []
    monkeypatch.setattr(llm_mod, "_sleep", waits.append)
    client = FakeClient([status_error(RateLimitError, 429), reply("ok")])
    result = call_model(client, config(), "s", "u")
    assert result.text == "ok" and waits == [30]
    assert result.notes == ["RateLimitError on attempt 1; waiting 30s before retry"]


def test_persistent_rate_limit_gives_up_after_the_backoff_schedule(monkeypatch):
    waits = []
    monkeypatch.setattr(llm_mod, "_sleep", waits.append)
    client = FakeClient([status_error(RateLimitError, 429)] * 3)
    with pytest.raises(RateLimitError):
        call_model(client, config(), "s", "u")
    assert waits == [30, 60] and len(client.calls) == 3


def test_server_and_connection_errors_use_the_same_path(monkeypatch):
    monkeypatch.setattr(llm_mod, "_sleep", lambda s: None)
    request = httpx.Request("POST", "http://fake/v1/chat/completions")
    client = FakeClient(
        [status_error(InternalServerError, 503), APIConnectionError(request=request), reply("ok")]
    )
    result = call_model(client, config(), "s", "u")
    assert result.text == "ok" and len(result.notes) == 2


def test_bad_request_is_never_retried_as_transient(monkeypatch):
    monkeypatch.setattr(llm_mod, "_sleep", lambda s: pytest.fail("must not sleep on a 400"))
    client = FakeClient([bad_request("model not found")])
    with pytest.raises(BadRequestError):
        call_model(client, config(), "s", "u")


def test_client_gets_timeout_and_sdk_retries(monkeypatch):
    cfg = load_model_config("x", provider="ollama", env={})
    client = llm_mod.build_client(cfg)
    assert client.timeout == llm_mod.REQUEST_TIMEOUT_S
    assert client.max_retries == llm_mod.SDK_MAX_RETRIES


def test_gateway_budget_422_stops_the_wave(monkeypatch):
    # LiteLLM's own counter said "Budget has been exceeded!" while /key/info still
    # showed room. That must become BudgetExhausted (stop), not ten error records.
    from openai import UnprocessableEntityError

    monkeypatch.setattr(llm_mod, "_sleep", lambda s: pytest.fail("no backoff for budget"))
    request = httpx.Request("POST", "http://fake/v1/chat/completions")
    exc = UnprocessableEntityError(
        "Budget has been exceeded! Key=abc",
        response=httpx.Response(422, request=request),
        body=None,
    )
    client = FakeClient([exc])
    with pytest.raises(BudgetExhausted, match="refused"):
        call_model(client, config(), "s", "u")


def test_other_422_is_not_treated_as_budget():
    from openai import UnprocessableEntityError

    client = FakeClient([status_error(UnprocessableEntityError, 422)])
    with pytest.raises(UnprocessableEntityError):
        call_model(client, config(), "s", "u")


# --- gateway headers: exact cost and the enforced spend counter ---------------------


class FakeRaw:
    def __init__(self, parsed, headers):
        self._parsed, self.headers = parsed, headers

    def parse(self):
        return self._parsed


class FakeRawClient:
    """A client whose completions expose with_raw_response, like the real SDK."""

    def __init__(self, parsed, headers):
        raw = SimpleNamespace(create=lambda **kw: FakeRaw(parsed, headers))
        self.chat = SimpleNamespace(
            completions=SimpleNamespace(create=lambda **kw: parsed, with_raw_response=raw)
        )


def test_gateway_headers_are_recorded():
    client = FakeRawClient(
        reply("ok"),
        {
            "X-LiteLLM-Response-Cost": "0.0123",
            "x-litellm-key-spend": "0.456",
            "x-ratelimit-remaining-tokens": "19980",
        },
    )
    r = call_model(client, config(provider="gateway"), "s", "u")
    assert (r.cost_usd, r.gateway_spend_usd, r.rate_remaining_tokens) == (0.0123, 0.456, 19980)


def test_missing_headers_are_none_not_errors():
    r = call_model(FakeClient([reply("ok")]), config(), "s", "u")
    assert r.cost_usd is None and r.gateway_spend_usd is None and r.rate_remaining_tokens is None
