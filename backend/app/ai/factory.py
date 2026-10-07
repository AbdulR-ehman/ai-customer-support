"""AI provider factory.

``mock`` is the only supported provider. Any other value is rejected at startup
by :class:`app.config.Settings`, and this factory refuses as well, as a second
line of defence against accidentally wiring up a paid provider.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import lru_cache

from app.ai.base import AIProvider
from app.ai.mock import MockAIProvider
from app.config import Settings, get_settings
from app.errors import ConfigurationError

PROVIDERS: dict[str, Callable[[], AIProvider]] = {
    "mock": MockAIProvider,
}


def build_provider(settings: Settings | None = None) -> AIProvider:
    """Instantiate the configured provider (mock only)."""
    active = settings or get_settings()
    factory = PROVIDERS.get(active.ai_provider)
    if factory is None:
        raise ConfigurationError(
            f"AI_PROVIDER {active.ai_provider!r} is not available. This project is zero-cost "
            "and offline, so only 'mock' is supported."
        )
    return factory()


@lru_cache(maxsize=1)
def get_provider() -> AIProvider:
    """Process-wide provider instance."""
    return build_provider()


def reset_provider_cache() -> None:
    """Clear the provider cache (used by tests)."""
    get_provider.cache_clear()
