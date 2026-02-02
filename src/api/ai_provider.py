"""AI Provider Module - Unified interface for multiple AI providers."""

import json
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class AIProvider(Enum):
    """Supported AI providers."""
    OPENAI = "openai"
    GEMINI = "gemini"
    GROK = "grok"  # xAI
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"  # Local models


@dataclass
class AIResponse:
    """Standardized response from any AI provider."""
    content: str
    model: str
    provider: AIProvider
    usage: Optional[Dict[str, int]] = None
    raw_response: Optional[Any] = None

    def get_json(self) -> Optional[Dict]:
        """Parse content as JSON if possible."""
        try:
            content = self.content.strip()
            # Remove markdown code blocks if present
            if content.startswith("```"):
                content = re.sub(r'^```\w*\n?', '', content)
                content = re.sub(r'\n?```$', '', content)
            return json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return None


class BaseAIProvider(ABC):
    """Abstract base class for AI providers."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key
        self.model = model or self.default_model

    @property
    @abstractmethod
    def provider_type(self) -> AIProvider:
        """Return the provider type."""
        pass

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Return the default model for this provider."""
        pass

    @property
    @abstractmethod
    def env_key_name(self) -> str:
        """Return the environment variable name for the API key."""
        pass

    def is_available(self) -> bool:
        """Check if this provider is available."""
        return self.api_key is not None or os.getenv(self.env_key_name) is not None

    def get_api_key(self) -> Optional[str]:
        """Get the API key from instance or environment."""
        return self.api_key or os.getenv(self.env_key_name)

    @abstractmethod
    async def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> AIResponse:
        """Send a completion request to the provider.

        Args:
            messages: List of message dicts with 'role' and 'content'
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            json_mode: Request JSON response format

        Returns:
            AIResponse with the completion
        """
        pass


class OpenAIProvider(BaseAIProvider):
    """OpenAI API provider."""

    @property
    def provider_type(self) -> AIProvider:
        return AIProvider.OPENAI

    @property
    def default_model(self) -> str:
        return "gpt-4o-mini"

    @property
    def env_key_name(self) -> str:
        return "OPENAI_API_KEY"

    async def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> AIResponse:
        try:
            from openai import AsyncOpenAI
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")

        client = AsyncOpenAI(api_key=self.get_api_key())

        kwargs = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = await client.chat.completions.create(**kwargs)

        return AIResponse(
            content=response.choices[0].message.content,
            model=self.model,
            provider=self.provider_type,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
            } if response.usage else None,
            raw_response=response,
        )


class GeminiProvider(BaseAIProvider):
    """Google Gemini API provider."""

    @property
    def provider_type(self) -> AIProvider:
        return AIProvider.GEMINI

    @property
    def default_model(self) -> str:
        return "gemini-1.5-flash"

    @property
    def env_key_name(self) -> str:
        return "GEMINI_API_KEY"

    async def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> AIResponse:
        try:
            import google.generativeai as genai
        except ImportError:
            raise ImportError("google-generativeai package not installed. Run: pip install google-generativeai")

        genai.configure(api_key=self.get_api_key())

        # Convert messages to Gemini format
        model = genai.GenerativeModel(self.model)

        # Build conversation history
        history = []
        system_prompt = ""

        for msg in messages:
            role = msg["role"]
            content = msg["content"]

            if role == "system":
                system_prompt = content
            elif role == "user":
                if system_prompt:
                    content = f"{system_prompt}\n\n{content}"
                    system_prompt = ""
                history.append({"role": "user", "parts": [content]})
            elif role == "assistant":
                history.append({"role": "model", "parts": [content]})

        # Get the last user message for the prompt
        chat = model.start_chat(history=history[:-1] if len(history) > 1 else [])

        generation_config = genai.types.GenerationConfig(
            max_output_tokens=max_tokens,
            temperature=temperature,
        )

        if json_mode:
            generation_config.response_mime_type = "application/json"

        last_message = history[-1]["parts"][0] if history else ""
        response = await chat.send_message_async(
            last_message,
            generation_config=generation_config,
        )

        return AIResponse(
            content=response.text,
            model=self.model,
            provider=self.provider_type,
            usage=None,  # Gemini doesn't provide token counts the same way
            raw_response=response,
        )


class GrokProvider(BaseAIProvider):
    """xAI Grok API provider (OpenAI-compatible)."""

    @property
    def provider_type(self) -> AIProvider:
        return AIProvider.GROK

    @property
    def default_model(self) -> str:
        return "grok-beta"

    @property
    def env_key_name(self) -> str:
        return "XAI_API_KEY"

    async def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> AIResponse:
        try:
            from openai import AsyncOpenAI
        except ImportError:
            raise ImportError("openai package not installed. Run: pip install openai")

        # xAI uses OpenAI-compatible API
        client = AsyncOpenAI(
            api_key=self.get_api_key(),
            base_url="https://api.x.ai/v1",
        )

        kwargs = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = await client.chat.completions.create(**kwargs)

        return AIResponse(
            content=response.choices[0].message.content,
            model=self.model,
            provider=self.provider_type,
            usage={
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
            } if response.usage else None,
            raw_response=response,
        )


class AnthropicProvider(BaseAIProvider):
    """Anthropic Claude API provider."""

    @property
    def provider_type(self) -> AIProvider:
        return AIProvider.ANTHROPIC

    @property
    def default_model(self) -> str:
        return "claude-3-haiku-20240307"

    @property
    def env_key_name(self) -> str:
        return "ANTHROPIC_API_KEY"

    async def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> AIResponse:
        try:
            from anthropic import AsyncAnthropic
        except ImportError:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")

        client = AsyncAnthropic(api_key=self.get_api_key())

        # Extract system message
        system_prompt = None
        filtered_messages = []

        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                filtered_messages.append(msg)

        # Add JSON instruction if needed
        if json_mode and filtered_messages:
            last_msg = filtered_messages[-1]
            if last_msg["role"] == "user":
                last_msg["content"] += "\n\nRespond with valid JSON only."

        kwargs = {
            "model": self.model,
            "messages": filtered_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        if system_prompt:
            kwargs["system"] = system_prompt

        response = await client.messages.create(**kwargs)

        return AIResponse(
            content=response.content[0].text,
            model=self.model,
            provider=self.provider_type,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            } if response.usage else None,
            raw_response=response,
        )


class OllamaProvider(BaseAIProvider):
    """Ollama local model provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: str = "http://localhost:11434",
    ):
        super().__init__(api_key, model)
        self.base_url = base_url

    @property
    def provider_type(self) -> AIProvider:
        return AIProvider.OLLAMA

    @property
    def default_model(self) -> str:
        return "llama3.2"

    @property
    def env_key_name(self) -> str:
        return "OLLAMA_API_KEY"  # Optional for Ollama

    def is_available(self) -> bool:
        """Ollama doesn't require API key, check if server is running."""
        try:
            import httpx
            response = httpx.get(f"{self.base_url}/api/tags", timeout=2.0)
            return response.status_code == 200
        except Exception:
            return False

    async def complete(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.3,
        json_mode: bool = False,
    ) -> AIResponse:
        try:
            import httpx
        except ImportError:
            raise ImportError("httpx package not installed. Run: pip install httpx")

        async with httpx.AsyncClient() as client:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "num_predict": max_tokens,
                    "temperature": temperature,
                },
            }

            if json_mode:
                payload["format"] = "json"

            response = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=120.0,
            )
            response.raise_for_status()
            data = response.json()

            return AIResponse(
                content=data["message"]["content"],
                model=self.model,
                provider=self.provider_type,
                usage={
                    "prompt_tokens": data.get("prompt_eval_count", 0),
                    "completion_tokens": data.get("eval_count", 0),
                } if "eval_count" in data else None,
                raw_response=data,
            )


# Provider registry
PROVIDERS: Dict[AIProvider, type] = {
    AIProvider.OPENAI: OpenAIProvider,
    AIProvider.GEMINI: GeminiProvider,
    AIProvider.GROK: GrokProvider,
    AIProvider.ANTHROPIC: AnthropicProvider,
    AIProvider.OLLAMA: OllamaProvider,
}


def get_provider(
    provider: Union[str, AIProvider],
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    **kwargs,
) -> BaseAIProvider:
    """Get an AI provider instance.

    Args:
        provider: Provider name or enum
        api_key: API key (optional, will use env var if not provided)
        model: Model name (optional, will use default if not provided)
        **kwargs: Additional provider-specific arguments

    Returns:
        Configured provider instance
    """
    if isinstance(provider, str):
        provider = AIProvider(provider.lower())

    provider_class = PROVIDERS.get(provider)
    if not provider_class:
        raise ValueError(f"Unknown provider: {provider}")

    return provider_class(api_key=api_key, model=model, **kwargs)


def get_available_provider(
    preferred: Optional[Union[str, AIProvider]] = None,
) -> Optional[BaseAIProvider]:
    """Get the first available provider.

    Args:
        preferred: Preferred provider to try first

    Returns:
        Available provider instance or None
    """
    # Try preferred provider first
    if preferred:
        try:
            provider = get_provider(preferred)
            if provider.is_available():
                return provider
        except (ValueError, ImportError):
            pass

    # Try providers in order of preference
    priority_order = [
        AIProvider.OPENAI,
        AIProvider.GEMINI,
        AIProvider.GROK,
        AIProvider.ANTHROPIC,
        AIProvider.OLLAMA,
    ]

    for provider_type in priority_order:
        try:
            provider = get_provider(provider_type)
            if provider.is_available():
                return provider
        except ImportError:
            continue

    return None


def list_available_providers() -> List[Dict[str, Any]]:
    """List all providers and their availability status.

    Returns:
        List of provider info dicts
    """
    result = []

    for provider_type, provider_class in PROVIDERS.items():
        try:
            instance = provider_class()
            available = instance.is_available()
            env_key = instance.env_key_name
            default_model = instance.default_model
        except Exception as e:
            available = False
            env_key = "unknown"
            default_model = "unknown"

        result.append({
            "provider": provider_type.value,
            "available": available,
            "env_key": env_key,
            "default_model": default_model,
        })

    return result
