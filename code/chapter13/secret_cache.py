"""Rotation-aware secret caching example for Chapter 13.

The example deliberately uses an in-process demonstration provider. Replace it
with an authenticated, non-production secret-store client before integrating
the cache with an MCP server.
"""

from __future__ import annotations

import logging
import math
import re
import secrets
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol


LOGGER = logging.getLogger(__name__)
SECRET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9/_-]{0,254}\Z")


class SecretUnavailable(RuntimeError):
    """Raised when a current secret cannot be retrieved safely."""


@dataclass(frozen=True)
class ProviderSecret:
    """A secret value and the provider version that identifies it."""

    value: str = field(repr=False)
    version: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value:
            raise ValueError("secret value must be a non-empty string")
        if not isinstance(self.version, str) or not self.version:
            raise ValueError("secret version must be a non-empty string")


class SecretProvider(Protocol):
    """The minimal interface required from a secret-store adapter."""

    def get_secret(self, name: str) -> ProviderSecret: ...


class PlaintextSecretProvider(Protocol):
    """The string-only provider interface used in the chapter's first listing."""

    def get_secret(self, secret_name: str) -> str: ...


@dataclass(frozen=True)
class CachedSecret:
    secret: ProviderSecret
    expires_at: float


class SecretCache:
    """A bounded, fail-closed cache for one MCP server process."""

    def __init__(
        self,
        provider: SecretProvider,
        ttl_seconds: float = 60.0,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 128,
    ) -> None:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(ttl_seconds)
            or not 0 < ttl_seconds <= 300
        ):
            raise ValueError("ttl_seconds must be between 0 and 300")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")

        self._provider = provider
        self._ttl = float(ttl_seconds)
        self._clock = clock
        self._max_entries = max_entries
        self._cache: OrderedDict[str, CachedSecret] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _validate_name(name: str) -> str:
        if (
            not isinstance(name, str)
            or not SECRET_NAME.fullmatch(name)
            or ".." in name
            or "//" in name
            or name.endswith("/")
        ):
            raise ValueError("invalid secret identifier")
        return name

    def read(self, name: str) -> ProviderSecret:
        """Return a current secret or fail without serving expired data."""

        key = self._validate_name(name)

        # Holding the lock across a refresh prevents duplicate provider reads
        # in this teaching example. A high-throughput service can use per-key
        # locks and jitter so unrelated secrets do not block one another.
        with self._lock:
            now = self._clock()
            for expired_key in tuple(self._cache):
                if self._cache[expired_key].expires_at <= now:
                    del self._cache[expired_key]
            cached = self._cache.get(key)
            if cached is not None and cached.expires_at > now:
                self._cache.move_to_end(key)
                return cached.secret

            try:
                fresh = self._provider.get_secret(key)
            except Exception as exc:
                LOGGER.warning(
                    "Secret retrieval failed",
                    extra={
                        "secret_name": key,
                        "error_type": type(exc).__name__,
                    },
                )
                # Provider exception text may contain sensitive payloads.
                raise SecretUnavailable("current secret unavailable") from None

            if (
                not isinstance(fresh, ProviderSecret)
                or not isinstance(fresh.value, str)
                or not fresh.value
                or not isinstance(fresh.version, str)
                or not fresh.version
            ):
                raise SecretUnavailable("provider returned an invalid secret")

            if len(self._cache) >= self._max_entries:
                self._cache.popitem(last=False)
            self._cache[key] = CachedSecret(
                secret=fresh,
                expires_at=self._clock() + self._ttl,
            )
            return fresh

    def invalidate(self, name: str) -> None:
        """Drop the application's reference to one cached secret."""

        key = self._validate_name(name)
        with self._lock:
            self._cache.pop(key, None)

    def refresh(self, name: str) -> ProviderSecret:
        """Invalidate and retrieve a current provider version."""

        self.invalidate(name)
        return self.read(name)

    def clear_memory(self, name: str | None = None) -> None:
        """Drop cached references, without promising physical zeroization."""
        if name is not None:
            self.invalidate(name)
            return
        with self._lock:
            self._cache.clear()


class _PlaintextProviderAdapter:
    def __init__(self, provider: PlaintextSecretProvider) -> None:
        self.provider = provider

    def get_secret(self, name: str) -> ProviderSecret:
        value = self.provider.get_secret(name)
        # The source interface does not report versions or backend lease data.
        return ProviderSecret(value, "unreported-by-string-provider")


class ThreadSafeSecretCache:
    """Chapter-compatible string interface over the bounded cache.

    This interface cannot enforce provider lease expiry or prove rotation:
    production adapters should use SecretCache with ProviderSecret metadata.
    """

    def __init__(
        self,
        provider: PlaintextSecretProvider,
        ttl_seconds: float = 300,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_entries: int = 128,
    ) -> None:
        self.provider = provider
        self._implementation = SecretCache(
            _PlaintextProviderAdapter(provider), ttl_seconds,
            clock=clock, max_entries=max_entries,
        )
        self.ttl = float(ttl_seconds)

    def read(self, secret_name: str) -> str:
        return self._implementation.read(secret_name).value

    def clear_memory(self, secret_name: str | None = None) -> None:
        self._implementation.clear_memory(secret_name)


class MockVaultProvider:
    """Fixed-per-instance synthetic value; no vault or rotation is implemented."""

    def __init__(self) -> None:
        self._value = secrets.token_urlsafe(24)

    def get_secret(self, secret_name: str) -> str:
        return self._value


class DemoProvider:
    """Issue ephemeral demonstration values; never use this in production."""

    def __init__(self) -> None:
        self._version = 0

    def get_secret(self, name: str) -> ProviderSecret:
        self._version += 1
        return ProviderSecret(
            value=secrets.token_urlsafe(24),
            version=f"demo-{self._version}",
        )


def execute_database_query(
    query: str,
    cache: SecretCache,
    query_runner: Callable[[str, str], int],
) -> dict[str, object]:
    """Run a supplied, parameterizing query adapter with a current secret."""

    try:
        database_secret = cache.read("postgres/agent-role")
        rows = query_runner(query, database_secret.value)
    except SecretUnavailable:
        return {
            "status": "failed",
            "error": "credential_unavailable",
            "retryable": False,
        }

    return {
        "status": "success",
        "rows": rows,
        "credential_version": database_secret.version,
    }


if __name__ == "__main__":
    demo_cache = SecretCache(DemoProvider(), ttl_seconds=30)
    first = demo_cache.read("support/create-ticket")
    second = demo_cache.read("support/create-ticket")
    assert first.version == second.version

    demo_cache.invalidate("support/create-ticket")
    rotated = demo_cache.read("support/create-ticket")
    assert rotated.version != first.version
    print("Secret cache demonstration completed without printing secret values.")
