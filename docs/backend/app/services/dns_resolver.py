"""
Live DNS resolver layer for PhishIntel online authentication.

All SPF / DKIM / DMARC lookups go through the small `DnsResolver` interface so the
verification logic can be unit-tested with an in-memory fake (no network) while
production uses dnspython against real DNS.

Error contract (important for RFC 7208 / RFC 6376 semantics):
  * NXDOMAIN / "no such record"  -> returns an empty list   (definitive "not found")
  * timeout / SERVFAIL / refused -> raises DnsTempError     (temporary, result is unknown)
"""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Sequence, Tuple


class DnsTempError(Exception):
    """Temporary DNS failure (timeout, SERVFAIL, network down). Outcome is unknown."""


class DnsResolver:
    """Interface used by the live SPF / DKIM / DMARC verifiers."""

    def txt(self, name: str) -> List[str]:
        raise NotImplementedError

    def a(self, name: str) -> List[str]:
        raise NotImplementedError

    def aaaa(self, name: str) -> List[str]:
        raise NotImplementedError

    def mx(self, name: str) -> List[str]:
        """Return MX exchange host names (lowest preference first)."""
        raise NotImplementedError

    def ptr(self, ip: str) -> List[str]:
        raise NotImplementedError


class DnsPythonResolver(DnsResolver):
    """Production resolver backed by dnspython with timeouts and a small TTL cache."""

    FALLBACK_NAMESERVERS = ["1.1.1.1", "8.8.8.8"]

    def __init__(
        self,
        timeout: float = 3.0,
        nameservers: Optional[Sequence[str]] = None,
        cache_ttl: int = 300,
        negative_cache_ttl: int = 60,
    ):
        import dns.resolver  # imported lazily so the app still starts without dnspython

        try:
            resolver = dns.resolver.Resolver(configure=True)
        except dns.resolver.NoResolverConfiguration:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = list(self.FALLBACK_NAMESERVERS)
        if nameservers:
            resolver.nameservers = list(nameservers)
        resolver.timeout = timeout
        resolver.lifetime = timeout * 2
        self._resolver = resolver
        self._cache_ttl = cache_ttl
        self._neg_ttl = negative_cache_ttl
        self._cache: Dict[Tuple[str, str], Tuple[float, List[str]]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    def _query(self, name: str, rtype: str) -> List[str]:
        import dns.exception
        import dns.name
        import dns.resolver

        key = (name.lower().rstrip("."), rtype)
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[0] > now:
                return list(hit[1])

        try:
            answer = self._resolver.resolve(key[0], rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            self._store(key, [], self._neg_ttl)
            return []
        except (dns.name.NameTooLong, dns.name.LabelTooLong, dns.name.EmptyLabel):
            return []
        except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as exc:
            raise DnsTempError(f"{rtype} lookup for {key[0]} failed: {exc.__class__.__name__}") from exc
        except dns.exception.DNSException as exc:
            raise DnsTempError(f"{rtype} lookup for {key[0]} failed: {exc.__class__.__name__}") from exc
        except OSError as exc:  # network unreachable etc.
            raise DnsTempError(f"{rtype} lookup for {key[0]} failed: {exc}") from exc

        values = self._to_text(answer, rtype)
        ttl = min(int(getattr(answer.rrset, "ttl", self._cache_ttl)), self._cache_ttl)
        self._store(key, values, ttl)
        return list(values)

    @staticmethod
    def _to_text(answer, rtype: str) -> List[str]:
        out: List[str] = []
        if rtype == "TXT":
            for r in answer:
                # Multiple <character-string>s in one record are concatenated with no
                # separator (RFC 7208 s4.5, RFC 6376 s3.6.2.2).
                out.append(b"".join(r.strings).decode("utf-8", errors="replace"))
        elif rtype == "MX":
            for r in sorted(answer, key=lambda x: x.preference):
                out.append(str(r.exchange).rstrip("."))
        elif rtype == "PTR":
            for r in answer:
                out.append(str(r.target).rstrip("."))
        else:  # A / AAAA
            for r in answer:
                out.append(r.to_text())
        return out

    def _store(self, key, values: List[str], ttl: int) -> None:
        with self._lock:
            self._cache[key] = (time.monotonic() + max(ttl, 1), list(values))

    # ------------------------------------------------------------------ #
    def txt(self, name: str) -> List[str]:
        return self._query(name, "TXT")

    def a(self, name: str) -> List[str]:
        return self._query(name, "A")

    def aaaa(self, name: str) -> List[str]:
        return self._query(name, "AAAA")

    def mx(self, name: str) -> List[str]:
        return self._query(name, "MX")

    def ptr(self, ip: str) -> List[str]:
        import dns.reversename

        return self._query(str(dns.reversename.from_address(ip)), "PTR")


def build_default_resolver(settings) -> DnsResolver:
    """Create the production resolver from application settings."""
    nameservers = getattr(settings, "DNS_NAMESERVERS", None) or None
    return DnsPythonResolver(
        timeout=float(getattr(settings, "DNS_TIMEOUT_SECONDS", 3.0)),
        nameservers=nameservers,
        cache_ttl=int(getattr(settings, "DNS_CACHE_TTL_SECONDS", 300)),
    )
