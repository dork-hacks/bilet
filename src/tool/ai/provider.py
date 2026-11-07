"""LLM providers for the AI layer (MASTERPLAN §5.2), chosen by environment variables.

LLM_PROVIDER: "anthropic" (cloud API), "ollama" (local model, e.g. on the Pi 5) or
"none" / empty (AI off: the built-in texts are shown). LLM_MODEL picks the model and
LLM_API_KEY holds the cloud key. The key is read from the environment only. It is
never logged, never put in an exception message and never sent to the frontend.

Every failure (no key, SDK not installed, network error, timeout, bad reply) raises
ProviderUnavailable, and the caller falls back to the built-in texts.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Protocol

DEFAULT_ANTHROPIC_MODEL = "claude-haiku-5-5"  # fast and cheap (MASTERPLAN §5.2)
DEFAULT_OLLAMA_MODEL = "llama3.2:3b"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
MAX_OUTPUT_TOKENS = 1024  # deliberately short: two sentences per language, as JSON


class ProviderUnavailable(Exception):
    """The provider can't answer right now. Show the built-in text instead."""


class Provider(Protocol):
    name: str  # "anthropic:<model>" etc.; part of the cache key

    def complete(self, system: str, prompt: str, timeout: float) -> str:
        """Return the model's raw text reply, or raise ProviderUnavailable."""
        ...


class AnthropicProvider:
    """Claude through the official Anthropic SDK (imported lazily, so it stays optional)."""

    def __init__(self, api_key: str, model: str = DEFAULT_ANTHROPIC_MODEL):
        self._api_key = api_key
        self.model = model
        self.name = f"anthropic:{model}"

    def __repr__(self) -> str:  # never show the key
        return f"AnthropicProvider(model={self.model!r})"

    def complete(self, system: str, prompt: str, timeout: float) -> str:
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderUnavailable("anthropic SDK not installed") from exc
        try:
            client = anthropic.Anthropic(api_key=self._api_key, timeout=timeout, max_retries=0)
            response = client.messages.create(
                model=self.model,
                max_tokens=MAX_OUTPUT_TOKENS,
                system=system,
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.APIError as exc:  # timeouts, connection and status errors
            raise ProviderUnavailable(type(exc).__name__) from None
        if response.stop_reason == "refusal":
            raise ProviderUnavailable("refusal")
        text = "".join(b.text for b in response.content if b.type == "text")
        if not text.strip():
            raise ProviderUnavailable("empty reply")
        return text


class OllamaProvider:
    """A local model served by Ollama. Only localhost-style URLs are expected here."""

    def __init__(self, model: str = DEFAULT_OLLAMA_MODEL, url: str = DEFAULT_OLLAMA_URL):
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            raise ValueError("LLM_OLLAMA_URL must be an http(s) URL")
        self.model = model
        self.url = url.rstrip("/")
        self.name = f"ollama:{model}"

    def complete(self, system: str, prompt: str, timeout: float) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "stream": False,
                "format": "json",
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
            }
        ).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 (scheme checked in __init__)
            f"{self.url}/api/chat", data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as reply:  # noqa: S310
                data = json.loads(reply.read(256_000))
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise ProviderUnavailable(type(exc).__name__) from None
        text = ((data or {}).get("message") or {}).get("content")
        if not isinstance(text, str) or not text.strip():
            raise ProviderUnavailable("empty reply")
        return text


def provider_from_env(env: Mapping[str, str] | None = None) -> Provider | None:
    """The configured provider, or None when AI is off or not set up."""
    env = os.environ if env is None else env
    kind = (env.get("LLM_PROVIDER") or "none").strip().lower()
    model = (env.get("LLM_MODEL") or "").strip()
    if kind == "anthropic":
        key = (env.get("LLM_API_KEY") or "").strip()
        if not key:
            return None
        return AnthropicProvider(key, model or DEFAULT_ANTHROPIC_MODEL)
    if kind == "ollama":
        url = (env.get("LLM_OLLAMA_URL") or DEFAULT_OLLAMA_URL).strip()
        return OllamaProvider(model or DEFAULT_OLLAMA_MODEL, url)
    return None
