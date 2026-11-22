"""
Live (online) SPF / DKIM / DMARC verification orchestrator for PhishIntel.

Unlike the header-interpretation engine in email_authentication.py (which only *reads* results that
some mail server claims to have computed), this module re-computes all three checks itself,
against live DNS, at analysis time:

  SPF   - real RFC 7208 check_host() for the connecting IP taken from the Received chain
  DKIM  - real RFC 6376 verification using the signer's public key fetched from DNS
  DMARC - real RFC 7489 policy lookup + identifier alignment using the live SPF/DKIM results

The module is pure Python (no pydantic/FastAPI) and returns a plain dict, so it is easy to test with
an injected fake resolver.
"""

from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any, Dict, List, Optional

from app.services.dkim_crypto_verifier import LocalKeyStore, verify_dkim_signatures
from app.services.dns_resolver import DnsResolver, DnsTempError, build_default_resolver
from app.services.live_dkim import DNSKeyStore, summarize_dkim
from app.services.live_dmarc import evaluate_dmarc
from app.services.live_spf import check_spf

MAX_SPF_HOPS = 3

_shared_resolver: Optional[DnsResolver] = None
_shared_lock = threading.Lock()


def get_shared_resolver(settings_obj) -> DnsResolver:
    """One resolver (and DNS cache) shared by all requests."""
    global _shared_resolver
    with _shared_lock:
        if _shared_resolver is None:
            _shared_resolver = build_default_resolver(settings_obj)
        return _shared_resolver


def reset_shared_resolver() -> None:  # used by tests
    global _shared_resolver
    with _shared_lock:
        _shared_resolver = None


# --------------------------------------------------------------------------- #
def _domain_of(addr_header: Optional[str]) -> str:
    if not addr_header:
        return ""
    addr = parseaddr(addr_header)[1]
    return addr.rpartition("@")[2].lower().strip(".") if "@" in addr else ""


def _helo_of(received: str) -> str:
    m = re.search(r"(?i)\bfrom\s+([^\s(;]+)", received or "")
    return m.group(1).strip("[]") if m else ""


def _message_age_days(date_header: Optional[str], now: datetime) -> Optional[float]:
    if not date_header:
        return None
    try:
        dt = parsedate_to_datetime(date_header)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return round((now - dt).total_seconds() / 86400, 1)
    except Exception:
        return None


def _select_client_ips(ip_candidates) -> List[Dict[str, Any]]:
    """Public candidate IPs, newest Received hop first, de-duplicated, capped."""
    seen, picked = set(), []
    ordered = sorted(
        [c for c in (ip_candidates or []) if getattr(c, "classification", "") == "Public"],
        key=lambda c: getattr(c, "hop_index", 0),
    )
    for c in ordered:
        ip = getattr(c, "ip", None)
        if ip and ip not in seen:
            seen.add(ip)
            picked.append({"ip": ip, "hop_index": getattr(c, "hop_index", 0)})
        if len(picked) >= MAX_SPF_HOPS:
            break
    return picked


# --------------------------------------------------------------------------- #
def run_live_authentication(
    raw_message: bytes,
    header_info: Any,
    ip_candidates: Optional[list] = None,
    resolver: Optional[DnsResolver] = None,
    pinned_keystore: Optional[LocalKeyStore] = None,
    settings_obj: Any = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    started = time.monotonic()
    now = now or datetime.now(timezone.utc)
    out: Dict[str, Any] = {
        "mode": "LIVE_DNS",
        "available": True,
        "performed_at": now.isoformat(),
        "message_age_days": _message_age_days(getattr(header_info, "date", None), now),
        "dns_errors": [],
        "caveats": [],
    }

    if resolver is None:
        try:
            resolver = get_shared_resolver(settings_obj)
        except Exception as exc:  # dnspython missing, bad config
            out.update(available=False, error=f"Live DNS resolver unavailable: {exc}")
            return out

    from_domain = _domain_of(getattr(header_info, "from_header", None))
    out["from_domain"] = from_domain

    # ------------------------------------------------------------------ SPF
    spf: Dict[str, Any] = {"evaluated": False, "result": "none"}
    spf_is_mailfrom = False
    try:
        hops = _select_client_ips(ip_candidates)
        received = list(getattr(header_info, "received_headers", []) or [])
        rp_raw = getattr(header_info, "return_path", None)
        rp_addr = parseaddr(rp_raw)[1] if rp_raw else ""
        if rp_raw is None or not str(rp_raw).strip():
            mail_from, identity = "", "helo"   # no Return-Path: cannot know MAIL FROM
        elif not rp_addr:                      # "<>" null reverse-path (bounce)
            mail_from, identity = "", "helo"
        else:
            mail_from, identity = rp_addr, "mail_from"

        if not hops:
            spf["explanation"] = "No public client IP found in the Received headers, so SPF cannot be evaluated."
        else:
            evaluated = []
            for h in hops:
                helo = _helo_of(received[h["hop_index"]]) if h["hop_index"] < len(received) else ""
                evaluated.append((h, check_spf(h["ip"], mail_from, helo, resolver), helo))
            (h0, r0, helo0) = evaluated[0]
            spf = {
                "evaluated": True,
                **r0.to_dict(),
                "client_ip_source": f"Received[{h0['hop_index']}]",
                "helo": helo0,
                "identity": identity,
                "other_hops": [
                    {"client_ip": r.client_ip, "hop_index": h["hop_index"], "result": r.result,
                     "explanation": r.explanation}
                    for (h, r, _) in evaluated[1:]
                ],
            }
            spf_is_mailfrom = identity == "mail_from"
            if r0.result == "temperror":
                out["dns_errors"].append(f"SPF: {r0.explanation}")
    except DnsTempError as exc:
        spf = {"evaluated": True, "result": "temperror", "explanation": str(exc)}
        out["dns_errors"].append(f"SPF: {exc}")
    except Exception as exc:
        spf = {"evaluated": False, "result": "none", "explanation": f"SPF evaluation error: {exc}"}
        out["dns_errors"].append(f"SPF: {exc}")
    out["spf"] = spf

    # ----------------------------------------------------------------- DKIM
    dkim: Dict[str, Any] = {"result": "none", "signatures": []}
    verified_domains: List[str] = []
    try:
        store = DNSKeyStore(resolver, fallback=pinned_keystore)
        results = verify_dkim_signatures(raw_message, store)
        dkim = summarize_dkim(results, store)
        sigs = []
        for r in results:
            d = r.to_dict()
            lk = store.lookups.get(f"{r.selector}._domainkey.{r.domain}".lower()) if r.selector and r.domain else None
            if lk:
                lk = dict(lk)
                if lk.get("record"):
                    lk["record"] = lk["record"][:400]
            d["key_lookup"] = lk
            sigs.append(d)
            if r.status.value == "VERIFIED" and r.domain:
                verified_domains.append(r.domain)
        dkim["signatures"] = sigs
        if dkim["result"] == "temperror":
            out["dns_errors"].append("DKIM: key lookup failed temporarily")
        if any((s.get("key_lookup") or {}).get("testing_mode") for s in sigs):
            out["caveats"].append("A DKIM key is published in testing mode (t=y); receivers should not treat failures as definitive.")
    except Exception as exc:
        dkim = {"result": "temperror", "explanation": f"DKIM verification error: {exc}", "signatures": []}
        out["dns_errors"].append(f"DKIM: {exc}")
    out["dkim"] = dkim

    # ---------------------------------------------------------------- DMARC
    try:
        dm = evaluate_dmarc(
            resolver, from_domain,
            spf.get("result") if spf.get("evaluated") else None,
            spf.get("domain"), spf_is_mailfrom, verified_domains,
        )
        dmarc = dm.to_dict()
        if dm.result == "temperror":
            out["dns_errors"].append(f"DMARC: {dm.explanation}")
    except DnsTempError as exc:
        dmarc = {"result": "temperror", "from_domain": from_domain, "explanation": str(exc)}
        out["dns_errors"].append(f"DMARC: {exc}")
    except Exception as exc:
        dmarc = {"result": "temperror", "from_domain": from_domain, "explanation": f"DMARC evaluation error: {exc}"}
        out["dns_errors"].append(f"DMARC: {exc}")
    out["dmarc"] = dmarc

    # -------------------------------------------------------------- summary
    out["summary"] = {"spf": spf.get("result"), "dkim": dkim.get("result"), "dmarc": dmarc.get("result")}
    if all(out["summary"][k] == "temperror" for k in ("spf", "dkim", "dmarc")):
        out["available"] = False
        out["error"] = "DNS appears to be unreachable from the server; no live result could be computed."

    out["caveats"].append(
        "Live results are computed from DNS records as they are NOW, not as they were when the message was sent."
    )
    age = out["message_age_days"]
    if age is not None and age > 2:
        out["caveats"].append(
            f"This message is about {age} days old; DKIM keys may have been rotated and SPF/DMARC records edited since, "
            "so a live FAIL on an old message is weaker evidence than on a freshly received one."
        )
    if spf.get("evaluated"):
        out["caveats"].append(
            "The SPF client IP comes from the Received header in the uploaded file; it is only trustworthy if that header "
            "was added by your own receiving mail server."
        )
    if spf.get("result") in ("fail", "softfail") and dkim.get("result") == "pass":
        out["caveats"].append(
            "SPF failed while DKIM passed: this is typical of legitimately forwarded mail (SPF breaks on forwarding, DKIM survives)."
        )

    out["duration_ms"] = int((time.monotonic() - started) * 1000)
    return out
