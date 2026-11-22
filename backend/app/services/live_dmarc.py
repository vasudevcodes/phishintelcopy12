"""
Live DMARC evaluation (RFC 7489) for PhishIntel.

Fetches the _dmarc TXT policy record from DNS (falling back to the organizational domain),
then evaluates identifier alignment using the *live* SPF and DKIM results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.services.dns_resolver import DnsResolver, DnsTempError

# Used only when the `publicsuffix2` package is not installed.
_TWO_PART_SUFFIXES = (
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "org.in", "net.in", "gov.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in",
    "co.nz", "org.nz", "co.za", "org.za", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.ar", "com.sg", "com.hk", "com.tw", "com.my", "com.tr", "com.ua", "com.pk", "com.ng",
)


def organizational_domain(domain: str) -> str:
    """Registered / organizational domain (eTLD+1). Uses the Public Suffix List when available."""
    d = (domain or "").lower().strip().rstrip(".")
    if not d:
        return ""
    try:
        from publicsuffix2 import get_sld

        sld = get_sld(d, strict=False)
        if sld:
            return sld
    except Exception:
        pass
    parts = d.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _TWO_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


@dataclass
class DMARCLiveResult:
    result: str                         # pass | fail | none | temperror | permerror
    from_domain: str
    policy_domain: Optional[str] = None
    record: Optional[str] = None
    policy: Optional[str] = None        # p= (as published)
    subdomain_policy: Optional[str] = None
    applied_policy: Optional[str] = None  # policy that applies to this From domain
    pct: int = 100
    adkim: str = "r"
    aspf: str = "r"
    spf_aligned: bool = False
    dkim_aligned: bool = False
    disposition: str = "none"           # action the domain owner asked receivers to take on failure
    explanation: str = ""
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def _parse_dmarc(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def _fetch_policy(resolver: DnsResolver, name: str) -> Optional[str]:
    """Return the single valid DMARC record at _dmarc.<name>, or None."""
    txts = resolver.txt(f"_dmarc.{name}")
    valid = [t.strip() for t in txts if re.match(r"(?i)^v\s*=\s*DMARC1\s*(;|$)", t.strip())]
    if len(valid) == 1:
        return valid[0]
    return None  # none, or multiple (ignored per RFC 7489 s6.6.3)


def _aligned(a: str, b: str, mode: str) -> bool:
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    if not a or not b:
        return False
    if mode == "s":
        return a == b
    return organizational_domain(a) == organizational_domain(b)


def evaluate_dmarc(
    resolver: DnsResolver,
    from_domain: str,
    spf_result: Optional[str],
    spf_domain: Optional[str],
    spf_identity_is_mailfrom: bool,
    dkim_verified_domains: List[str],
) -> DMARCLiveResult:
    """
    spf_result / spf_domain: live SPF verdict and the domain it authenticated.
    spf_identity_is_mailfrom: False when SPF fell back to the HELO identity (no DMARC alignment credit).
    dkim_verified_domains: d= values of signatures that verified cryptographically.
    """
    from_domain = (from_domain or "").lower().rstrip(".")
    res = DMARCLiveResult(result="none", from_domain=from_domain)
    if not from_domain:
        res.explanation = "No From-header domain could be extracted; DMARC cannot be evaluated."
        return res

    org = organizational_domain(from_domain)
    try:
        record = _fetch_policy(resolver, from_domain)
        policy_domain = from_domain
        if record is None and org != from_domain:
            record = _fetch_policy(resolver, org)
            policy_domain = org
    except DnsTempError as exc:
        res.result = "temperror"
        res.explanation = f"DMARC policy lookup failed temporarily: {exc}"
        return res

    if record is None:
        res.explanation = f"No DMARC record published for {from_domain} (checked _dmarc.{from_domain}" + \
            (f" and _dmarc.{org})." if org != from_domain else ").")
        return res

    tags = _parse_dmarc(record)
    res.record = record
    res.policy_domain = policy_domain
    p = tags.get("p", "").lower()
    if p not in ("none", "quarantine", "reject"):
        res.notes.append(f"Invalid or missing p= tag ('{tags.get('p', '')}'); treated as p=none.")
        p = "none"
    sp = tags.get("sp", "").lower() or None
    if sp and sp not in ("none", "quarantine", "reject"):
        res.notes.append(f"Invalid sp= tag '{sp}' ignored.")
        sp = None
    res.policy, res.subdomain_policy = p, sp
    is_subdomain = policy_domain != from_domain
    res.applied_policy = (sp or p) if is_subdomain else p
    res.adkim = tags.get("adkim", "r").lower()[:1] if tags.get("adkim", "r").lower()[:1] in ("r", "s") else "r"
    res.aspf = tags.get("aspf", "r").lower()[:1] if tags.get("aspf", "r").lower()[:1] in ("r", "s") else "r"
    try:
        res.pct = max(0, min(100, int(tags.get("pct", "100"))))
    except ValueError:
        res.pct = 100

    # --- identifier alignment --------------------------------------------- #
    res.spf_aligned = bool(
        spf_result == "pass" and spf_identity_is_mailfrom and spf_domain
        and _aligned(spf_domain, from_domain, res.aspf)
    )
    res.dkim_aligned = any(_aligned(d, from_domain, res.adkim) for d in dkim_verified_domains if d)

    if res.spf_aligned or res.dkim_aligned:
        res.result = "pass"
        via = " and ".join(x for x, ok in (("SPF", res.spf_aligned), ("DKIM", res.dkim_aligned)) if ok)
        res.explanation = f"DMARC pass for {from_domain}: {via} passed with identifier alignment (policy p={p})."
        return res

    # not aligned/passing
    if spf_result == "temperror":
        res.result = "temperror"
        res.explanation = "SPF could not be evaluated (temporary DNS error) and no aligned DKIM passed; DMARC outcome unknown."
        return res

    res.result = "fail"
    res.disposition = res.applied_policy or "none"
    reasons = []
    reasons.append("SPF " + (f"result '{spf_result}'" if spf_result != "pass" else "passed but not aligned with From domain"))
    reasons.append("no DKIM signature verified with an aligned d= domain")
    res.explanation = (
        f"DMARC fail for {from_domain}: {'; '.join(reasons)}. "
        f"Domain owner's policy: p={res.applied_policy}" + (f" (pct={res.pct})" if res.pct != 100 else "") + "."
    )
    return res
