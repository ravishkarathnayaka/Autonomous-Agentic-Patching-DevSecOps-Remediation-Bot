"""Unified LLM client interface supporting Ollama, OpenAI-compatible APIs, and local Mock."""

from abc import ABC, abstractmethod
import logging
import os
from typing import Optional
import httpx

from agent_engine.llm.mock_provider import MockLLMProvider

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.0) -> str:
        """Generate text completion from the language model."""
        pass


class MockLLMClient(BaseLLMClient):
    """Mock LLM client wrapping deterministic test responses."""

    def __init__(self, simulate_retry_failure: bool = False):
        self._provider = MockLLMProvider(simulate_retry_failure=simulate_retry_failure)

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.0) -> str:
        return self._provider.generate(prompt, system_prompt=system_prompt, temperature=temperature)


class OllamaLLMClient(BaseLLMClient):
    """Local LLM client calling Ollama REST API ($0 cost, local models)."""

    def __init__(
        self,
        model: str = "qwen2.5-coder:7b",
        base_url: str = "http://localhost:11434",
        timeout_seconds: float = 120.0
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.0) -> str:
        url = f"{self.base_url}/api/chat"
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data.get("message", {}).get("content", "")
                return str(content).strip()
        except httpx.HTTPError as e:
            logger.error("Ollama request failed: %s", e)
            raise RuntimeError(f"Ollama API request error: {e}") from e


class OpenAILLMClient(BaseLLMClient):
    """OpenAI-compatible LLM client (OpenAI, vLLM, LM Studio, etc.)."""

    def __init__(
        self,
        model: str = "gpt-4o",
        base_url: str = "https://api.openai.com/v1",
        api_key: Optional[str] = None,
        timeout_seconds: float = 90.0
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or os.getenv("OPENAI_API_KEY", "")
        self.timeout_seconds = timeout_seconds

    def generate(self, prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.0) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Content-Type": "application/json"
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature
        }

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                return str(content).strip()
        except httpx.HTTPError as e:
            logger.error("OpenAI request failed: %s", e)
            raise RuntimeError(f"LLM API request error: {e}") from e


def get_llm_client(
    provider: str = "mock",
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    simulate_retry_failure: bool = False
) -> BaseLLMClient:
    """Factory creating appropriate LLM client instance."""
    normalized_provider = (provider or "mock").lower()

    if normalized_provider == "mock":
        return MockLLMClient(simulate_retry_failure=simulate_retry_failure)

    if normalized_provider == "ollama":
        target_model = model or os.getenv("OLLAMA_MODEL") or "qwen2.5-coder:7b"
        target_url = base_url or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434"
        return OllamaLLMClient(model=str(target_model), base_url=str(target_url))

    if normalized_provider in ("openai", "vllm", "compatible"):
        openai_model = model or os.getenv("LLM_MODEL") or "gpt-4o-mini"
        openai_url = base_url or os.getenv("LLM_BASE_URL") or "https://api.openai.com/v1"
        return OpenAILLMClient(model=str(openai_model), base_url=str(openai_url), api_key=api_key)

    raise ValueError(f"Unknown LLM provider: {provider}. Choose 'mock', 'ollama', or 'openai'.")
