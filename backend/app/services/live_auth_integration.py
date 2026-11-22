"""
Bridges live DNS verification results into the existing EmailAuthenticationAnalysis model so that
scoring, evidence fusion and the UI all consume *verified* SPF / DKIM / DMARC outcomes instead of
unverified header claims.

Rules:
  * Live result definitive (pass/fail/softfail/neutral/none/permerror) -> replaces the status.
  * Live result temperror (DNS problem)                                  -> header-reported status is kept.
  * Header-reported status that disagrees with the live result is kept in `findings`
    and called out in `warnings` (a discrepancy is itself forensic evidence).
  * `is_boundary_trusted` / `provenance_status` are NOT touched: we verify the sender's authentication
    ourselves, but we still cannot prove the uploaded Received headers were written by a trusted MTA.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.schemas.email_authentication import AuthResultStatus, OverallAuthStatus

_STATUS = {
    "pass": AuthResultStatus.PASS,
    "fail": AuthResultStatus.FAIL,
    "softfail": AuthResultStatus.SOFTFAIL,
    "neutral": AuthResultStatus.NEUTRAL,
    "none": AuthResultStatus.NONE,
    "temperror": AuthResultStatus.TEMPERROR,
    "permerror": AuthResultStatus.PERMERROR,
}

OLD_MESSAGE_DAYS = 30

LIVE_DISCLAIMER = (
    "SPF, DKIM and DMARC were re-computed by PhishIntel against live DNS at analysis time (RFC 7208, RFC 6376, RFC 7489); "
    "they are not merely copied from headers. Live results reflect DNS as it is now, not as it was when the message was sent, "
    "and the SPF client IP is read from the uploaded Received headers, which are only trustworthy if written by your own "
    "receiving server. A PASS proves control of the authenticated domain, not that the message is benign."
)


def _val(x) -> str:
    return x.value if hasattr(x, "value") else str(x)


def apply_live_results(auth_analysis: Any, live: Dict[str, Any]) -> None:
    """Mutate `auth_analysis` in place with live verification results."""
    auth_analysis.live_verification = live

    if not live.get("available", True):
        auth_analysis.warnings.append(
            "Live DNS verification could not be performed (" + str(live.get("error", "DNS unreachable"))
            + "); statuses below come from header claims and pinned keys only."
        )
        return

    applied = 0
    discrepancies: List[str] = []

    # ------------------------------------------------------------------ SPF
    spf = live.get("spf") or {}
    if spf.get("evaluated") and spf.get("result") in _STATUS and spf["result"] != "temperror":
        reported = _val(auth_analysis.spf.status)
        live_status = _STATUS[spf["result"]]
        if reported not in ("NOT_PRESENT", _val(live_status)):
            discrepancies.append(f"SPF: headers claim {reported} but live DNS check gives {_val(live_status)}")
        auth_analysis.spf.status = live_status
        auth_analysis.spf.explanation = "Live DNS SPF check: " + (spf.get("explanation") or "")
        if spf.get("domain"):
            auth_analysis.spf.domain = spf["domain"]
        if spf.get("client_ip"):
            auth_analysis.spf.client_ip = spf["client_ip"]
        auth_analysis.spf.trust_limitation = (
            f"Computed by PhishIntel from live DNS. Client IP {spf.get('client_ip')} was read from "
            f"{spf.get('client_ip_source', 'the Received headers')} of the uploaded file."
        )
        applied += 1

    # ----------------------------------------------------------------- DKIM
    dkim = live.get("dkim") or {}
    if dkim.get("result") in _STATUS and dkim["result"] != "temperror":
        reported = _val(auth_analysis.dkim.status)
        live_status = _STATUS[dkim["result"]]
        age = live.get("message_age_days")
        if dkim["result"] == "permerror" and age is not None and age > OLD_MESSAGE_DAYS:
            # The signing key is gone from DNS, but the message is old: key rotation/removal is the most
            # likely reason, so do not score this as an authentication failure.
            live_status = AuthResultStatus.UNKNOWN
            dkim = {**dkim, "explanation": (dkim.get("explanation") or "") +
                    f" Message is {age} days old, so key rotation/removal is likely; not treated as a failure."}
        if reported not in ("NOT_PRESENT", "UNKNOWN", _val(live_status)):
            discrepancies.append(f"DKIM: headers claim {reported} but live verification gives {_val(live_status)}")
        auth_analysis.dkim.status = live_status
        auth_analysis.dkim.explanation = "Live DKIM verification: " + (dkim.get("explanation") or "")
        if dkim.get("domain"):
            auth_analysis.dkim.domain = dkim["domain"]
        if dkim.get("selector"):
            auth_analysis.dkim.selector = dkim["selector"]
        auth_analysis.dkim.trust_limitation = (
            "Signature cryptographically verified by PhishIntel using the public key currently published in DNS."
            if dkim["result"] == "pass"
            else "Computed by PhishIntel from the DKIM-Signature header and the key currently published in DNS."
        )
        applied += 1
    if dkim.get("signatures"):
        auth_analysis.dkim_crypto = dkim["signatures"]

    # ---------------------------------------------------------------- DMARC
    dmarc = live.get("dmarc") or {}
    if dmarc.get("result") in _STATUS and dmarc["result"] != "temperror":
        reported = _val(auth_analysis.dmarc.status)
        live_status = _STATUS[dmarc["result"]]
        if reported not in ("NOT_PRESENT", _val(live_status)):
            discrepancies.append(f"DMARC: headers claim {reported} but live evaluation gives {_val(live_status)}")
        auth_analysis.dmarc.status = live_status
        auth_analysis.dmarc.explanation = "Live DMARC evaluation: " + (dmarc.get("explanation") or "")
        if dmarc.get("applied_policy"):
            auth_analysis.dmarc.policy = dmarc.get("policy") or dmarc["applied_policy"]
            auth_analysis.dmarc.subdomain_policy = dmarc.get("subdomain_policy")
        if dmarc["result"] == "fail":
            auth_analysis.dmarc.disposition = dmarc.get("disposition")
        if dmarc.get("from_domain"):
            auth_analysis.dmarc.header_from = dmarc["from_domain"]
        auth_analysis.dmarc.alignment_verified = bool(dmarc.get("spf_aligned") or dmarc.get("dkim_aligned"))
        auth_analysis.dmarc.trust_limitation = (
            "Computed by PhishIntel from the domain's live DMARC policy and the live SPF/DKIM results above."
        )
        applied += 1

    if not applied:
        auth_analysis.warnings.append(
            "Live DNS verification ran but produced no definitive result (temporary DNS errors); "
            "statuses come from header claims."
        )
        return

    auth_analysis.verification_mode = "LIVE_DNS"
    auth_analysis.disclaimer = LIVE_DISCLAIMER
    if "Live DNS (SPF/DKIM/DMARC)" not in auth_analysis.headers_inspected:
        auth_analysis.headers_inspected.append("Live DNS (SPF/DKIM/DMARC)")
    for d in discrepancies:
        auth_analysis.warnings.append("Header/live discrepancy - " + d + ". The live result is used for scoring.")
    for e in live.get("dns_errors", []):
        auth_analysis.warnings.append("Live DNS issue: " + e)
    for c in live.get("caveats", [])[:3]:
        auth_analysis.warnings.append(c)

    # Recompute overall status so live evidence is never discarded as NO_EVIDENCE.
    statuses = [_val(auth_analysis.spf.status), _val(auth_analysis.dkim.status), _val(auth_analysis.dmarc.status)]
    if auth_analysis.has_conflicts or "CONFLICTING_EVIDENCE" in statuses:
        auth_analysis.status = OverallAuthStatus.CONFLICTING_EVIDENCE
    elif all(s == "NOT_PRESENT" for s in statuses):
        auth_analysis.status = OverallAuthStatus.NO_EVIDENCE
    elif "NOT_PRESENT" in statuses:
        auth_analysis.status = OverallAuthStatus.PARTIAL_EVIDENCE
    else:
        auth_analysis.status = OverallAuthStatus.EVALUATED
