import pytest
from unittest.mock import MagicMock
from agent_engine.llm.client import BaseLLMClient, FallbackLLMClient, MockLLMClient


class FailingLLMClient(BaseLLMClient):
    def generate(self, prompt: str, system_prompt: str = None, temperature: float = 0.0) -> str:
        raise RuntimeError("Primary provider rate limit exceeded or connection timeout")


def test_fallback_llm_client_primary_success():
    primary = MockLLMClient()
    fallback = MockLLMClient()
    client = FallbackLLMClient(primary=primary, fallback=fallback)

    res = client.generate("test prompt")
    assert res is not None
    assert len(res) > 0


def test_fallback_llm_client_fallback_activated_on_error():
    primary = FailingLLMClient()
    fallback = MockLLMClient()
    client = FallbackLLMClient(primary=primary, fallback=fallback)

    res = client.generate("test prompt")
    assert res is not None
    assert len(res) > 0


def test_fallback_llm_client_both_fail():
    primary = FailingLLMClient()
    fallback = FailingLLMClient()
    client = FallbackLLMClient(primary=primary, fallback=fallback)

    with pytest.raises(RuntimeError):
        client.generate("test prompt")
