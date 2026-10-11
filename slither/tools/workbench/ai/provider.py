"""LLM provider abstraction. Providers only turn a prompt into text; they never act."""

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass

REQUEST_TIMEOUT_S = 90


class AIProviderError(Exception):
    pass


@dataclass
class ProviderConfig:
    kind: str
    model: str
    api_key: str | None = None
    base_url: str | None = None


class AIProvider(ABC):
    name = "abstract"

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    @property
    def model(self) -> str:
        return self.config.model

    @abstractmethod
    def complete(self, system: str, user: str) -> str:
        """Return the model's text response. Must raise AIProviderError on failure."""

    def _post(self, url: str, headers: dict[str, str], body: dict) -> dict:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"content-type": "application/json", **headers},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_S) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:500]
            raise AIProviderError(f"{self.name} returned HTTP {e.code}: {detail}")
        except (urllib.error.URLError, TimeoutError) as e:
            raise AIProviderError(f"{self.name} unreachable at {url}: {e}")


class AnthropicProvider(AIProvider):
    name = "anthropic"

    def complete(self, system: str, user: str) -> str:
        base = self.config.base_url or "https://api.anthropic.com"
        data = self._post(
            f"{base}/v1/messages",
            {"x-api-key": self.config.api_key or "", "anthropic-version": "2023-06-01"},
            {
                "model": self.model,
                "max_tokens": 2000,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        texts = [block.get("text", "") for block in data.get("content", [])]
        return "".join(texts)


class OpenAIProvider(AIProvider):
    """OpenAI chat-completions API; also used for local OpenAI-compatible servers."""

    name = "openai"
    default_base_url = "https://api.openai.com/v1"

    def complete(self, system: str, user: str) -> str:
        base = self.config.base_url or self.default_base_url
        headers = {"authorization": f"Bearer {self.config.api_key}"} if self.config.api_key else {}
        data = self._post(
            f"{base}/chat/completions",
            headers,
            {
                "model": self.model,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            },
        )
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise AIProviderError(f"{self.name} response missing message content: {e}")


class LocalProvider(OpenAIProvider):
    """Any OpenAI-compatible local server, e.g. Ollama or llama.cpp."""

    name = "local"
    default_base_url = "http://localhost:11434/v1"


PROVIDERS: dict[str, type[AIProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
    "local": LocalProvider,
}

DEFAULT_MODELS = {"anthropic": "claude-sonnet-5", "openai": "gpt-4o", "local": "llama3.1"}
KEY_VARIABLES = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}


def config_from_env() -> ProviderConfig | None:
    kind = os.environ.get("WORKBENCH_AI_PROVIDER", "").lower()
    if not kind:
        kind = next((k for k, var in KEY_VARIABLES.items() if os.environ.get(var)), "")
    if not kind:
        return None
    if kind not in PROVIDERS:
        raise AIProviderError(
            f"Unknown WORKBENCH_AI_PROVIDER '{kind}'. Use one of: {', '.join(PROVIDERS)}"
        )
    return ProviderConfig(
        kind=kind,
        model=os.environ.get("WORKBENCH_AI_MODEL", DEFAULT_MODELS[kind]),
        api_key=os.environ.get(KEY_VARIABLES.get(kind, ""), None),
        base_url=os.environ.get("WORKBENCH_AI_BASE_URL"),
    )


def make_provider(config: ProviderConfig | None) -> AIProvider | None:
    if config is None:
        return None
    if config.kind in KEY_VARIABLES and not config.api_key:
        raise AIProviderError(
            f"Provider '{config.kind}' needs an API key: set {KEY_VARIABLES[config.kind]}"
        )
    return PROVIDERS[config.kind](config)
