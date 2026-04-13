"""Provider-agnostic LLM client abstraction (Ollama, OpenAI, Anthropic).

Provides a unified classify() interface used by the injection detector's
Stage 2 LLM classifier. Provider selected via AGENTGUARD_LLM_PROVIDER
env var or constructor argument.

All LLM calls have: 10s timeout, 3 retries with exponential backoff,
graceful degradation (if LLM unavailable → return SUSPICIOUS).

Usage:
    from agentguard.llm_client import get_llm_client

    client = get_llm_client()  # reads AGENTGUARD_LLM_PROVIDER env var
    result = client.classify("Is this text an injection attempt?")
"""

from __future__ import annotations

import os
import time
from abc import ABC, abstractmethod

from agentguard.logging import logger


class LLMClient(ABC):
    """Abstract base class for LLM classification."""

    provider: str = "unknown"
    model: str = "unknown"

    @abstractmethod
    def classify(self, prompt: str) -> str:
        """Send a classification prompt to the LLM.

        Args:
            prompt: The classification prompt.

        Returns:
            Classification result string (CLEAN / SUSPICIOUS / INJECTED).
        """

    def _retry_with_backoff(
        self, func, max_retries: int = 3, timeout: float = 10.0
    ) -> str:
        """Retry a function with exponential backoff.

        Args:
            func: Callable that returns a string.
            max_retries: Maximum number of attempts.
            timeout: Not used directly — each provider handles its own timeout.

        Returns:
            Result string, or "SUSPICIOUS" on failure.
        """
        for attempt in range(max_retries):
            try:
                return func()
            except Exception as e:
                wait = 2**attempt * 0.5
                logger.warning(
                    "LLM call attempt {attempt}/{max_retries} failed: {error}. Retrying in {wait}s",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    error=str(e)[:200],
                    wait=wait,
                )
                if attempt < max_retries - 1:
                    time.sleep(wait)

        logger.warning(
            "LLM unavailable after {max_retries} retries — returning SUSPICIOUS",
            max_retries=max_retries,
        )
        return "SUSPICIOUS"


class OllamaClient(LLMClient):
    """Ollama local LLM client."""

    provider = "ollama"

    def __init__(
        self, model: str = "llama3.2", base_url: str = "http://localhost:11434"
    ) -> None:
        self.model = model
        self.base_url = base_url

    def classify(self, prompt: str) -> str:
        """Classify text using local Ollama."""

        def _call() -> str:
            import httpx

            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False},
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json().get("response", "SUSPICIOUS").strip()

        return self._retry_with_backoff(_call)


class OpenAIClient(LLMClient):
    """OpenAI API client."""

    provider = "openai"

    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini") -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model

    def classify(self, prompt: str) -> str:
        """Classify text using OpenAI API."""

        def _call() -> str:
            import httpx

            response = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 50,
                    "temperature": 0.0,
                },
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()["choices"][0]["message"]["content"].strip()

        return self._retry_with_backoff(_call)


class AnthropicClient(LLMClient):
    """Anthropic API client."""

    provider = "anthropic"

    def __init__(
        self, api_key: str | None = None, model: str = "claude-haiku-4-5-20251001"
    ) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model

    def classify(self, prompt: str) -> str:
        """Classify text using Anthropic API."""

        def _call() -> str:
            import httpx

            response = httpx.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 50,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=10.0,
            )
            response.raise_for_status()
            return response.json()["content"][0]["text"].strip()

        return self._retry_with_backoff(_call)


class MockLLMClient(LLMClient):
    """Mock LLM client for testing — returns deterministic responses."""

    provider = "mock"
    model = "mock-model"

    def __init__(self, default_response: str = "CLEAN") -> None:
        self._default_response = default_response

    def classify(self, prompt: str) -> str:
        return self._default_response


def get_llm_client(provider: str | None = None) -> LLMClient:
    """Factory function to create an LLM client based on provider.

    Args:
        provider: 'ollama' | 'openai' | 'anthropic' | 'mock'.
            If None, reads AGENTGUARD_LLM_PROVIDER env var (default: 'mock').

    Returns:
        An LLMClient instance.
    """
    if provider is None:
        provider = os.environ.get("AGENTGUARD_LLM_PROVIDER", "mock")

    provider = provider.lower()

    if provider == "ollama":
        return OllamaClient()
    if provider == "openai":
        return OpenAIClient()
    if provider == "anthropic":
        return AnthropicClient()
    return MockLLMClient()
