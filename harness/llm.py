"""Model layer: one OpenAI-compatible client for every model under test.

Both providers speak the OpenAI chat-completions protocol, so the harness never
branches on "which vendor": it only changes ``base_url`` and the key.

    provider "gateway"  Duke AI Gateway (LiteLLM), https://litellm.oit.duke.edu/v1
                        models: claude-sonnet-5, gpt-5.3-codex, gpt-oss-120b, ...
    provider "ollama"   local Ollama, http://localhost:11434/v1
                        models: gpt-oss:20b, ...

Design borrowed from the author's course project cwe-explainer (ideas only, rewritten):
  * configuration comes from the environment, never from code;
  * send the preferred request parameters, and when the gateway answers 400 naming
    one of them (reasoning models reject ``temperature``; some endpoints want
    ``max_completion_tokens`` instead of ``max_tokens``), drop or rename that one
    parameter and retry, recording what was changed;
  * the model's reply is untrusted input: an empty reply is an error, not a result.

Reproducibility (ARCHITECTURE §7): every call returns the exact parameters that were
finally accepted plus token usage and latency, so a run can be re-created and costed.
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx
from openai import APIConnectionError, BadRequestError, InternalServerError, OpenAI, RateLimitError

GATEWAY_BASE_URL = "https://litellm.oit.duke.edu/v1"
OLLAMA_BASE_URL = "http://localhost:11434/v1"

# ARCHITECTURE §7: 1.0 is the provider default for the gateway models, but Ollama's
# default is 0.8 and defaults change between versions, so the value is written here
# and the parameters actually accepted are logged in ModelCall.params_used.
DEFAULT_TEMPERATURE: float = 1.0
# 4096 was too small: on justhtml (207-line snippet) claude-sonnet-5 hit finish_reason
# "length" with an empty body, i.e. the budget went to reasoning. Output tokens are
# only billed when used, so a high ceiling costs nothing on short replies.
DEFAULT_MAX_TOKENS = 16384

# One HTTP request may not hang a whole evening's wave. justhtml took ~120 s on sonnet,
# so 300 s leaves room; anything slower is recorded as an error and re-run later.
REQUEST_TIMEOUT_S = 300
# The OpenAI SDK already retries 408/409/429/5xx and connection errors with a short
# exponential backoff (0.5 s .. 8 s). A gateway rate limit is usually per minute, so on
# top of that we wait longer, twice, before giving up on the run.
SDK_MAX_RETRIES = 2
RATE_LIMIT_BACKOFF_S: tuple[int, ...] = (30, 60)
_sleep = time.sleep  # replaced in tests

PROVIDERS = ("gateway", "ollama")


class ModelConfigError(RuntimeError):
    """The environment does not describe a usable model endpoint."""


class ModelCallError(RuntimeError):
    """The model endpoint answered, but not with something the harness can use.

    Carries token usage when known: an empty reply still costs money and the
    run record must show that.
    """

    def __init__(self, message: str, usage: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.usage = usage or {}


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    base_url: str
    api_key: str
    temperature: float
    max_tokens: int = DEFAULT_MAX_TOKENS


def load_model_config(
    model: str,
    provider: str | None = None,
    env: Mapping[str, str] | None = None,
) -> ModelConfig:
    """Assemble a ModelConfig from environment variables.

    ``provider`` defaults to ``HARNESS_PROVIDER`` (then "gateway"). The gateway needs
    ``DUKE_API_KEY``; Ollama needs no key. ``env`` is injectable so tests never touch
    the real environment.
    """
    import os

    env = os.environ if env is None else env
    provider = (provider or env.get("HARNESS_PROVIDER", "") or "gateway").strip().lower()
    if provider not in PROVIDERS:
        raise ModelConfigError(
            f"unknown provider {provider!r}; expected one of {', '.join(PROVIDERS)}"
        )

    if provider == "gateway":
        api_key = env.get("DUKE_API_KEY", "").strip()
        if not api_key:
            raise ModelConfigError(
                "DUKE_API_KEY is not set. Put it in .env (never in code or in git)."
            )
        base_url = env.get("DUKE_BASE_URL", "").strip() or GATEWAY_BASE_URL
    else:
        api_key = "ollama"  # Ollama ignores the key but the SDK insists on one
        base_url = env.get("OLLAMA_BASE_URL", "").strip() or OLLAMA_BASE_URL

    return ModelConfig(
        provider=provider,
        model=model,
        base_url=base_url,
        api_key=api_key,
        temperature=DEFAULT_TEMPERATURE,
    )


def build_client(config: ModelConfig) -> OpenAI:
    """One SDK client works for both providers; only base_url and key differ."""
    return OpenAI(
        api_key=config.api_key,
        base_url=config.base_url,
        timeout=REQUEST_TIMEOUT_S,
        max_retries=SDK_MAX_RETRIES,
    )


_TRANSIENT = (RateLimitError, InternalServerError, APIConnectionError)


def _create_with_backoff(client: Any, notes: list[str], **kwargs: Any) -> Any:
    """One completion request, with a slow second line of retries for transient errors.

    The SDK's own fast retries run inside each attempt here. If they are exhausted
    (the exception reaches us), wait RATE_LIMIT_BACKOFF_S and try again; after the last
    wait the exception propagates and the run is recorded as an error, to be re-run.
    """
    for attempt, wait in enumerate((*RATE_LIMIT_BACKOFF_S, None)):
        try:
            return client.chat.completions.create(**kwargs)
        except _TRANSIENT as exc:
            if wait is None:
                raise
            notes.append(
                f"{type(exc).__name__} on attempt {attempt + 1}; waiting {wait}s before retry"
            )
            _sleep(wait)
    raise AssertionError("unreachable")


# --- budget -------------------------------------------------------------------------

# Reserve two worst-case calls (16384 output tokens × claude-sonnet-5 ≈ $0.25 each):
# a long justhtml-sized run must never be cut off halfway through the day's budget.
BUDGET_RESERVE_USD: float = 0.50


@dataclass(frozen=True)
class Budget:
    """What the gateway says about this key, in USD."""

    spend: float
    max_budget: float | None  # None = the key has no cap

    @property
    def remaining(self) -> float | None:
        return None if self.max_budget is None else self.max_budget - self.spend


class BudgetExhausted(RuntimeError):
    """Not enough budget left to start another run. Stop, do not count anything."""


class BudgetUnavailable(BudgetExhausted):
    """The budget could not be checked (gateway unreachable, e.g. VPN down).

    Fail closed: an unknown budget is treated like an exhausted one. Subclassing
    BudgetExhausted means every caller that stops on exhaustion also stops here.
    """


def gateway_budget(config: ModelConfig) -> Budget:
    """Ask LiteLLM's /key/info for this key's spend and cap. Gateway only."""
    if config.provider != "gateway":
        raise ModelConfigError("budget lookup only exists for the gateway")
    root = config.base_url.rsplit("/v1", 1)[0]
    try:
        response = httpx.get(
            f"{root}/key/info",
            headers={"Authorization": f"Bearer {config.api_key}"},
            timeout=15,
        )
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise BudgetUnavailable(
            f"cannot check the gateway budget ({type(exc).__name__}: {exc}); "
            "is the Duke VPN connected? Not starting a run with an unknown budget."
        ) from exc
    info = response.json().get("info", {})
    max_budget = info.get("max_budget")
    return Budget(
        spend=float(info.get("spend") or 0.0),
        max_budget=None if max_budget is None else float(max_budget),
    )


def assert_budget(config: ModelConfig) -> Budget | None:
    """Fail closed before spending: raise BudgetExhausted if too little is left.

    Returns the Budget so the caller can record spend before/after a run. Returns
    None for providers without a budget (Ollama).
    """
    if config.provider != "gateway":
        return None
    if BUDGET_RESERVE_USD is None:
        raise ModelConfigError("BUDGET_RESERVE_USD has not been decided yet (see TODO).")
    budget = gateway_budget(config)
    if budget.remaining is not None and budget.remaining < BUDGET_RESERVE_USD:
        raise BudgetExhausted(
            f"only ${budget.remaining:.3f} of ${budget.max_budget:.2f} left "
            f"(reserve is ${BUDGET_RESERVE_USD:.2f}); not starting another run"
        )
    return budget


@dataclass
class ModelCall:
    """Everything about one completion that a results table needs."""

    text: str
    model: str
    provider: str
    params_used: dict[str, Any]
    notes: list[str] = field(default_factory=list)
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_s: float = 0.0
    finish_reason: str | None = None  # "stop" is normal; "length" means max_tokens ran out


# Parameters some gateways rename instead of rejecting outright.
_PARAM_RENAMES: dict[str, str] = {"max_tokens": "max_completion_tokens"}


def _rejected_param(message: str, params: Mapping[str, Any]) -> str | None:
    """Which of our parameters is this 400 complaining about? None if unclear.

    Quoted mentions win over bare words, so "use 'max_completion_tokens' instead of
    'max_tokens'" resolves to max_tokens (the one we actually sent).
    """
    for name in params:
        if any(f"{q}{name}{q}" in message for q in ("'", '"', "`")):
            return name
    for name in params:
        if re.search(rf"\b{re.escape(name)}\b", message):
            return name
    return None


def call_model(client: Any, config: ModelConfig, system: str, user: str) -> ModelCall:
    """Send one chat completion, adapting the parameters if the endpoint rejects them.

    Retries at most once per parameter, then once with no optional parameters.
    Any 400 that does not name one of our parameters is re-raised unchanged.
    """
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    params: dict[str, Any] = {
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }
    # The Duke gateway (LiteLLM) caches identical requests and replays the same reply
    # in ~50 ms, which would turn "3 runs per case" into one run copied three times.
    # LiteLLM honours a per-request cache-control field; Ollama has no cache.
    extra: dict[str, Any] = (
        {"extra_body": {"cache": {"no-cache": True}}} if config.provider == "gateway" else {}
    )
    notes: list[str] = []
    started = time.monotonic()

    for _ in range(len(params) + 2):
        try:
            response = _create_with_backoff(
                client, notes, model=config.model, messages=messages, **params, **extra
            )
        except BadRequestError as exc:
            offender = _rejected_param(str(exc), params)
            if offender is None:
                raise
            value = params.pop(offender)
            renamed = _PARAM_RENAMES.get(offender)
            if renamed and renamed not in params:
                params[renamed] = value
                notes.append(f"{config.model} rejected {offender}; retried as {renamed}")
            else:
                notes.append(f"{config.model} rejected {offender}; retried without it")
            continue

        latency = time.monotonic() - started
        choice = response.choices[0]
        finish_reason = getattr(choice, "finish_reason", None)
        usage = getattr(response, "usage", None)
        text = choice.message.content or ""
        if not text.strip():
            # 200 with no text (e.g. a reasoning model spent max_tokens thinking) means
            # the model was never really evaluated. Fail closed: this run is an error,
            # not one of the four outcomes.
            raise ModelCallError(
                f"{config.model} returned an empty reply (finish_reason={finish_reason!r})",
                usage={
                    "params_used": dict(params),
                    "prompt_tokens": getattr(usage, "prompt_tokens", None),
                    "completion_tokens": getattr(usage, "completion_tokens", None),
                    "latency_s": round(time.monotonic() - started, 1),
                    "finish_reason": finish_reason,
                },
            )

        return ModelCall(
            text=text,
            model=config.model,
            provider=config.provider,
            params_used=dict(params),
            notes=notes,
            prompt_tokens=getattr(usage, "prompt_tokens", None),
            completion_tokens=getattr(usage, "completion_tokens", None),
            latency_s=latency,
            finish_reason=finish_reason,
        )

    raise ModelCallError(f"{config.model} rejected every parameter combination tried")
