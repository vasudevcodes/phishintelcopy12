"""
Live DKIM public-key retrieval for PhishIntel.

`DNSKeyStore` plugs into `verify_dkim_signatures()` in place of `LocalKeyStore` and fetches the
signer's key from the selector._domainkey.<domain> TXT record at verification time.

Fallback rule (deliberate): pinned keys are used ONLY when DNS is temporarily unavailable.
If DNS answers definitively (key missing or revoked) we do NOT fall back, because a stale
pinned key would hide a rotated or revoked key.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from app.services.dkim_crypto_verifier import (
    DKIMCryptoResult,
    DKIMCryptoStatus,
    LocalKeyStore,
    _parse_tags,
)
from app.services.dns_resolver import DnsResolver, DnsTempError


class DNSKeyStore(LocalKeyStore):
    def __init__(self, resolver: DnsResolver, fallback: Optional[LocalKeyStore] = None):
        super().__init__()
        self.resolver = resolver
        self.fallback = fallback
        self.last_source: Optional[str] = None
        # "selector._domainkey.domain" -> {"outcome": found|not_found|revoked|dns_error|fallback_used, ...}
        self.lookups: Dict[str, dict] = {}

    # Called by the verifier when get() returns None
    def missing_note(self, selector: str, domain: str) -> str:
        name = f"{selector}._domainkey.{domain}".lower()
        info = self.lookups.get(name, {})
        outcome = info.get("outcome")
        if outcome == "revoked":
            return f"DKIM key {name} is revoked (empty p= tag in DNS); signature cannot be valid."
        if outcome == "not_found":
            return f"No DKIM key published in DNS at {name} (NXDOMAIN / no TXT record); signature cannot be verified."
        return f"DKIM key lookup for {name} did not return a usable key; signature not checked."

    def get(self, selector: str, domain: str):
        name = f"{selector}._domainkey.{domain}".lower()
        self.last_source = None
        try:
            txts = self.resolver.txt(name)
        except DnsTempError as exc:
            self.lookups[name] = {"outcome": "dns_error", "detail": str(exc)}
            if self.fallback is not None:
                key = self.fallback.get(selector, domain)
                if key is not None:
                    self.lookups[name]["outcome"] = "fallback_used"
                    self.last_source = "local_keystore_dns_fallback"
                    return key
            raise

        candidates: List[str] = []
        for rec in txts:
            tags = _parse_tags(rec)
            if "v" in tags and tags["v"].strip().upper() != "DKIM1":
                continue
            if "p" in tags:
                candidates.append(rec)
        if not candidates:
            self.lookups[name] = {"outcome": "not_found"}
            return None

        record = candidates[0]
        tags = _parse_tags(record)
        flags = {f.strip().lower() for f in tags.get("t", "").split(":") if f.strip()}
        if not re.sub(r"\s+", "", tags.get("p", "")):
            self.lookups[name] = {"outcome": "revoked", "record": record}
            return None

        key = LocalKeyStore(records={name: record}).get(selector, domain)  # parses RSA / Ed25519 key
        self.lookups[name] = {
            "outcome": "found",
            "record": record,
            "testing_mode": "y" in flags,
            "key_type": tags.get("k", "rsa").lower(),
        }
        self.last_source = "dns"
        return key


def summarize_dkim(results: List[DKIMCryptoResult], keystore: DNSKeyStore) -> dict:
    """
    Collapse per-signature crypto results into one RFC 8601-style DKIM verdict
    (pass | fail | permerror | temperror | neutral | none).
    """
    if not results or all(r.status == DKIMCryptoStatus.NO_SIGNATURE for r in results):
        return {"result": "none", "explanation": "Message carries no DKIM-Signature header."}

    verified = [r for r in results if r.status == DKIMCryptoStatus.VERIFIED]
    invalid = [r for r in results if r.status in (DKIMCryptoStatus.BODY_MODIFIED, DKIMCryptoStatus.SIGNATURE_INVALID)]
    outcomes = {v.get("outcome") for v in keystore.lookups.values()}

    if verified:
        best = next((r for r in verified if r.aligned_with_from), verified[0])
        return {
            "result": "pass",
            "domain": best.domain,
            "selector": best.selector,
            "explanation": (
                f"DKIM signature from {best.domain} (selector {best.selector}) verified cryptographically "
                f"against the live public key in DNS."
            ),
        }
    if invalid:
        bad = invalid[0]
        why = "message body was modified after signing" if bad.status == DKIMCryptoStatus.BODY_MODIFIED \
            else "signature does not verify with the live DNS key"
        return {"result": "fail", "domain": bad.domain, "selector": bad.selector,
                "explanation": f"DKIM verification failed for {bad.domain}: {why}."}
    if "dns_error" in outcomes:
        return {"result": "temperror",
                "explanation": "DKIM key could not be retrieved because DNS was temporarily unavailable."}
    if outcomes & {"not_found", "revoked"}:
        first = results[0]
        return {"result": "permerror", "domain": first.domain, "selector": first.selector,
                "explanation": "DKIM key is missing or revoked in DNS, so the signature cannot be verified."}
    first = results[0]
    return {"result": "neutral" if first.status == DKIMCryptoStatus.UNSUPPORTED else "permerror",
            "domain": first.domain, "selector": first.selector,
            "explanation": "DKIM signature is malformed or uses an unsupported algorithm."}
