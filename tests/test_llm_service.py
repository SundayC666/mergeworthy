"""The web app's optional Ollama analysis after the LangChain removal.
No Ollama is needed: availability and the completion call are faked."""

from types import SimpleNamespace

import pytest

from app.services.llm_service import LLMService

REPLY = """AFFECTS_USER: YES
CONFIDENCE: HIGH
EXPLANATION: The installed version is in the affected range.
ACTION: Upgrade to 2.1.0.
PRIORITY: HIGH"""


class FakeChat:
    def __init__(self, text):
        self.calls = []

        async def create(**kwargs):
            self.calls.append(kwargs)
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=text))])

        self.completions = SimpleNamespace(create=create)


@pytest.mark.asyncio
async def test_analysis_goes_through_the_openai_compatible_endpoint():
    svc = LLMService(model="llama3.2:3b")
    svc._available = True
    fake = FakeChat(REPLY)
    svc._client = SimpleNamespace(chat=fake)
    result = await svc.analyze_cve_impact("CVE-2024-1", "desc", "HIGH", "Ubuntu 22.04", ["2.0.0"])
    assert result["affects_user"] is True and result["priority"] == "high"
    assert result["recommended_action"] == "Upgrade to 2.1.0."
    sent = fake.calls[0]
    assert sent["model"] == "llama3.2:3b" and sent["temperature"] == 0.1
    assert "CVE-2024-1" in sent["messages"][0]["content"]


@pytest.mark.asyncio
async def test_unavailable_ollama_falls_back_without_calling_it():
    svc = LLMService()
    svc._available = False
    fake = FakeChat(REPLY)
    svc._client = SimpleNamespace(chat=fake)
    result = await svc.analyze_cve_impact("CVE-2024-1", "desc", "LOW", "macOS", None)
    assert result["explanation"].startswith("LLM unavailable") and fake.calls == []


def test_client_targets_ollama_v1_with_no_retries():
    svc = LLMService()
    assert str(svc.client.base_url).rstrip("/").endswith("localhost:11434/v1")
    assert svc.client.max_retries == 0
