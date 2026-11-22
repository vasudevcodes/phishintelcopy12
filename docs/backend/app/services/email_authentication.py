"""
Standalone Email Authentication Evidence Engine for PhishIntel (Phase 5A).
Interprets reported SPF, DKIM, and DMARC evidence from email headers
(Authentication-Results RFC 8601/RFC 7601 and Received-SPF RFC 7208).

Offline, deterministic, explainable.
NEVER performs DNS queries, SMTP connections, public key fetching,
or cryptographic DKIM verification.
"""

from collections import Counter
import re
from typing import Dict, List, Optional, Sequence, Set, Tuple

from app.core.config import settings
from app.schemas.email import EmailHeaderInfo
from app.schemas.email_authentication import (
    AuthResultStatus,
    AuthservTrustResult,
    AuthservTrustStatus,
    DKIMEvidence,
    DMARCEvidence,
    EmailAuthenticationAnalysis,
    HeaderFinding,
    OverallAuthStatus,
    ProvenanceStatus,
    SPFEvidence,
)

# Standard result tokens mapped to normalized AuthResultStatus
RESULT_TOKEN_MAP: Dict[str, AuthResultStatus] = {
    "pass": AuthResultStatus.PASS,
    "passed": AuthResultStatus.PASS,
    "success": AuthResultStatus.PASS,
    "fail": AuthResultStatus.FAIL,
    "failed": AuthResultStatus.FAIL,
    "hardfail": AuthResultStatus.FAIL,
    "softfail": AuthResultStatus.SOFTFAIL,
    "soft-fail": AuthResultStatus.SOFTFAIL,
    "neutral": AuthResultStatus.NEUTRAL,
    "none": AuthResultStatus.NONE,
    "temperror": AuthResultStatus.TEMPERROR,
    "tempfail": AuthResultStatus.TEMPERROR,
    "permerror": AuthResultStatus.PERMERROR,
    "perm-error": AuthResultStatus.PERMERROR,
    "error": AuthResultStatus.PERMERROR,
}

# Explicitly configured trusted authserv-id domains (RFC 8601 Section 2.2)
DEFAULT_TRUSTED_AUTHSERV_DOMAINS: Tuple[str, ...] = tuple(
    getattr(
        settings,
        "TRUSTED_AUTHSERV_DOMAINS",
        [
            "google.com",
            "mx.google.com",
            "protection.outlook.com",
            "outlook.com",
            "microsoft.com",
            "office365.com",
            "proofpoint.com",
            "pphosted.com",
            "mimecast.com",
            "cisco.com",
            "ironport.com",
            "barracuda.com",
            "sendgrid.net",
            "mailgun.org",
            "amazonses.com",
        ],
    )
)


def validate_authserv_id_trust(
    authserv_id: Optional[str],
    trusted_domains: Optional[Sequence[str]] = None,
) -> AuthservTrustResult:
    """
    Validates an Authentication-Results authserv-id against configured trust policy (RFC 8601).
    Treats missing or unrecognized authserv-id values as untrusted.

    Stage A.3 Boolean Safety Guarantee:
    Returns an `AuthservTrustResult` (NamedTuple).
    The first element `is_trusted` is ALWAYS False for offline .eml uploads, even when
    the domain matches configured policy, because text matching in an uploaded file
    does NOT prove cryptographic or infrastructure-level provenance.

    Callers checking domain matching must use `result.domain_matches_policy` or
    `result.status == AuthservTrustStatus.REPORTED`.
    Callers checking trust must use `result.is_trusted` (which will be False).

    Preserves 3-tuple unpacking compatibility:
        is_trusted, status, explanation = validate_authserv_id_trust(...)
    where `is_trusted` is guaranteed to be False for reported assertions.
    """
    if not authserv_id or not authserv_id.strip():
        return AuthservTrustResult(
            is_trusted=False,
            status=AuthservTrustStatus.MISSING,
            explanation="Missing authserv-id identifier in Authentication-Results.",
        )

    cleaned_id = authserv_id.strip().lower()

    # Reject invalid or suspicious tokens (spaces, slashes, semicolons, quotes, @, etc.)
    if any(ch in cleaned_id for ch in (" ", "/", "\\", "@", ";", '"', "'", ":", "?", "#")):
        return AuthservTrustResult(
            is_trusted=False,
            status=AuthservTrustStatus.SUSPICIOUS,
            explanation=f"Malformed or suspicious authserv-id identifier: '{authserv_id}'.",
        )

    policy_domains = trusted_domains if trusted_domains is not None else DEFAULT_TRUSTED_AUTHSERV_DOMAINS

    for domain in policy_domains:
        d = domain.strip().lower()
        if cleaned_id == d or cleaned_id.endswith("." + d):
            # Stage A.3: Domain matches a known mail gateway name, BUT is_trusted is False
            # because provenance is NOT independently established for offline .eml uploads.
            # Callers can check .domain_matches_policy if they need to verify policy match.
            return AuthservTrustResult(
                is_trusted=False,
                status=AuthservTrustStatus.REPORTED,
                explanation=(
                    f"authserv-id '{cleaned_id}' matches known gateway policy '{domain}', "
                    "but provenance is NOT independently established for offline .eml uploads. "
                    "This string can be forged by any sender."
                ),
            )

    return AuthservTrustResult(
        is_trusted=False,
        status=AuthservTrustStatus.UNTRUSTED,
        explanation=f"Unrecognized authserv-id '{cleaned_id}' does not match any configured trusted boundary MTA domain.",
    )


def split_header_clauses(header_val: str) -> List[str]:
    """
    Splits an Authentication-Results header by semicolon, respecting
    parenthesized comments (CFWS) and quotes.
    """
    clauses: List[str] = []
    current: List[str] = []
    depth = 0
    in_quote = False
    quote_char = None

    for char in header_val:
        if in_quote:
            current.append(char)
            if char == quote_char:
                in_quote = False
        elif char in ('"', "'"):
            in_quote = True
            quote_char = char
            current.append(char)
        elif char == '(':
            depth += 1
            current.append(char)
        elif char == ')':
            if depth > 0:
                depth -= 1
            current.append(char)
        elif char == ';' and depth == 0:
            clause = "".join(current).strip()
            if clause:
                clauses.append(clause)
            current = []
        else:
            current.append(char)

    last = "".join(current).strip()
    if last:
        clauses.append(last)

    return clauses


def extract_comments_and_clean(clause: str) -> Tuple[str, List[str]]:
    """
    Extracts all parenthesized comments from a clause string and returns
    the cleaned clause plus the list of comment strings.
    """
    comments = re.findall(r"\(([^)]*)\)", clause)
    cleaned = re.sub(r"\([^)]*\)", " ", clause)
    cleaned = " ".join(cleaned.split())
    return cleaned, comments


def parse_key_value_pairs(cleaned_text: str) -> Dict[str, str]:
    """
    Extracts key=value tokens from cleaned text.
    Handles quotes: key="quoted value" or key=unquoted_value.
    """
    pairs: Dict[str, str] = {}
    pattern = re.compile(r'([a-zA-Z0-9_.\-]+)\s*=\s*(?:"([^"]*)"|([^\s;]+))')
    for match in pattern.finditer(cleaned_text):
        key = match.group(1).lower()
        val = match.group(2) if match.group(2) is not None else match.group(3)
        pairs[key] = val.strip()
    return pairs


def parse_auth_results_header(
    header_val: str,
    header_index: int,
    trusted_domains: Optional[Sequence[str]] = None,
) -> Tuple[Optional[str], List[HeaderFinding], List[str]]:
    """
    Parses a single Authentication-Results header according to RFC 8601.
    Validates the authserv-id against configured trust policy.
    Returns: (authserv_id, findings, warnings)
    """
    findings: List[HeaderFinding] = []
    warnings: List[str] = []

    clauses = split_header_clauses(header_val)
    if not clauses:
        warnings.append(f"Empty or whitespace-only Authentication-Results header at index {header_index}.")
        return None, findings, warnings

    first_clause = clauses[0].strip()
    authserv_id: Optional[str] = None
    remaining_clauses: List[str] = []

    # Check if first clause is the authserv-id or already a method clause
    # RFC 8601: Authentication-Results: <authserv-id> [version]; method=result ...
    if "=" not in first_clause:
        tokens = first_clause.split()
        if tokens:
            authserv_id = tokens[0]
        remaining_clauses = clauses[1:]
    else:
        # Some MTAs omit authserv-id or put methods directly before semicolon
        # Check if authserv-id precedes the '='
        match = re.match(r"^([a-zA-Z0-9_.\-]+(?:\.[a-zA-Z0-9_.\-]+)*)\s*;\s*", first_clause)
        if match:
            authserv_id = match.group(1)
            remaining_clauses = clauses[1:]
        else:
            remaining_clauses = clauses

    aid_res = validate_authserv_id_trust(authserv_id, trusted_domains)
    aid_trust_status = aid_res.status

    method_keywords = {"spf", "dkim", "dmarc"}

    for clause in remaining_clauses:
        clause_str = clause.strip()
        if not clause_str:
            continue

        cleaned_text, comments = extract_comments_and_clean(clause_str)
        reason_text = " ".join(comments).strip() if comments else None
        props = parse_key_value_pairs(cleaned_text)

        # Detect any method in this clause
        found_methods_in_clause = 0
        for method in method_keywords:
            if method in props:
                found_methods_in_clause += 1
                raw_res = props[method].lower()
                norm_res = RESULT_TOKEN_MAP.get(raw_res, AuthResultStatus.UNKNOWN)

                # Collect related properties (excluding the method itself)
                clause_props = {k: v for k, v in props.items() if k != method}

                # Also inspect comments for embedded properties (e.g. p=reject, dis=none)
                if comments:
                    for comment in comments:
                        comment_props = parse_key_value_pairs(comment)
                        for ck, cv in comment_props.items():
                            if ck not in clause_props and ck != method:
                                clause_props[ck] = cv

                findings.append(
                    HeaderFinding(
                        method=method,
                        result=norm_res,
                        raw_result=raw_res,
                        source_header="Authentication-Results",
                        header_index=header_index,
                        authserv_id=authserv_id,
                        authserv_trust=aid_trust_status,
                        properties=clause_props,
                        reason=reason_text,
                        raw_snippet=clause_str[:250],
                        is_boundary_mta=(header_index == 0),
                    )
                )

        if found_methods_in_clause == 0 and ("=" in clause_str):
            # Unrelated method (e.g., compauth, arc, iprev) or non-standard token
            pass
        elif found_methods_in_clause == 0 and not ("=" in clause_str):
            warnings.append(
                f"Authentication-Results[{header_index}] clause '{clause_str[:50]}' contains no recognized key=value methods."
            )

    return authserv_id, findings, warnings


def parse_received_spf_header(
    header_val: str, header_index: int
) -> Tuple[Optional[HeaderFinding], List[str]]:
    """
    Parses a single Received-SPF header according to RFC 7208.
    Format: Received-SPF: <result> (comments) [key=value; ...]
    """
    warnings: List[str] = []
    clean_val = header_val.strip()
    if not clean_val:
        return None, warnings

    cleaned_text, comments = extract_comments_and_clean(clean_val)
    tokens = cleaned_text.split()
    if not tokens:
        warnings.append(f"Received-SPF header at index {header_index} is empty.")
        return None, warnings

    raw_token = tokens[0].lower().rstrip(";:.,")
    norm_res = RESULT_TOKEN_MAP.get(raw_token, AuthResultStatus.UNKNOWN)

    reason_text = " ".join(comments).strip() if comments else None
    props = parse_key_value_pairs(cleaned_text)

    # If first token was parsed as key=val, remove it from props
    if raw_token in props:
        props.pop(raw_token, None)

    finding = HeaderFinding(
        method="spf",
        result=norm_res,
        raw_result=raw_token,
        source_header="Received-SPF",
        header_index=header_index,
        authserv_id=None,
        authserv_trust=AuthservTrustStatus.MISSING,
        properties=props,
        reason=reason_text,
        raw_snippet=clean_val[:250],
        is_boundary_mta=(header_index == 0),
    )
    return finding, warnings


def consolidate_method_findings(
    method: str, findings: List[HeaderFinding]
) -> Tuple[AuthResultStatus, str, Optional[str]]:
    """
    Consolidates multiple findings for a specific method into a single status,
    detecting agreement or conflicting evidence across headers.
    Returns: (consolidated_status, explanation, trust_limitation)
    """
    if not findings:
        return (
            AuthResultStatus.NOT_PRESENT,
            f"No {method.upper()} authentication evidence found in headers.",
            None,
        )

    # Collect distinct results
    distinct_results = {f.result for f in findings}

    # If all unknown
    if distinct_results == {AuthResultStatus.UNKNOWN}:
        return (
            AuthResultStatus.UNKNOWN,
            f"Unrecognized or malformed {method.upper()} result token(s) reported in headers.",
            "Evidence could not be interpreted reliably.",
        )

    # Filter out UNKNOWN for contradiction analysis if valid results exist
    valid_results = {r for r in distinct_results if r != AuthResultStatus.UNKNOWN}

    if len(valid_results) > 1:
        # Conflicting evidence! (e.g. one header says PASS, another says FAIL or SOFTFAIL)
        results_str = ", ".join(f"{f.result.value} ({f.source_header}[{f.header_index}])" for f in findings)
        return (
            AuthResultStatus.CONFLICTING_EVIDENCE,
            f"Conflicting {method.upper()} results reported across headers: {results_str}.",
            "Header conflict detected. Trust boundary or intermediate relays may have modified results.",
        )

    # Single consistent result
    final_status = list(valid_results)[0]
    sources = ", ".join(f"{f.source_header}[{f.header_index}]" for f in findings)
    authserv = findings[0].authserv_id or "unspecified MTA"
    explanation = f"{method.upper()} reported {final_status.value} by {authserv} via {sources}."

    trust_limitation = (
        f"Result reflects downstream claim from {authserv}. "
        "Offline analysis cannot verify if upstream mail relays stripped untrusted headers."
    )

    return final_status, explanation, trust_limitation


def analyze_email_authentication(
    header_info: EmailHeaderInfo,
    raw_dkim_signatures: Optional[List[str]] = None,
    trusted_authserv_domains: Optional[Sequence[str]] = None,
) -> EmailAuthenticationAnalysis:
    """
    Main entry point for Email Authentication Evidence Engine.
    Interprets reported SPF, DKIM, and DMARC evidence from extracted headers.
    Validates authserv-id against configured trust policy.
    """
    headers_inspected: List[str] = []
    authserv_ids: Set[str] = set()
    warnings: List[str] = []

    spf_findings: List[HeaderFinding] = []
    dkim_findings: List[HeaderFinding] = []
    dmarc_findings: List[HeaderFinding] = []

    # 1. Inspect Authentication-Results headers
    auth_results_headers = header_info.authentication_results
    if auth_results_headers:
        headers_inspected.append("Authentication-Results")
        for idx, ar_header in enumerate(auth_results_headers):
            try:
                aid, findings, ar_warns = parse_auth_results_header(
                    ar_header, idx, trusted_domains=trusted_authserv_domains
                )
                if aid:
                    authserv_ids.add(aid)
                warnings.extend(ar_warns)
                for f in findings:
                    if f.method == "spf":
                        spf_findings.append(f)
                    elif f.method == "dkim":
                        dkim_findings.append(f)
                    elif f.method == "dmarc":
                        dmarc_findings.append(f)
            except Exception as exc:
                warnings.append(f"Failed parsing Authentication-Results[{idx}]: {str(exc)}")

    # 2. Inspect Received-SPF headers
    received_spf_headers = header_info.received_spf
    if received_spf_headers:
        headers_inspected.append("Received-SPF")
        for idx, rspf_header in enumerate(received_spf_headers):
            try:
                finding, rspf_warns = parse_received_spf_header(rspf_header, idx)
                warnings.extend(rspf_warns)
                if finding:
                    spf_findings.append(finding)
            except Exception as exc:
                warnings.append(f"Failed parsing Received-SPF[{idx}]: {str(exc)}")

    # 3. Inspect raw DKIM-Signature presence
    dkim_signatures = raw_dkim_signatures or getattr(header_info, "dkim_signatures", [])
    has_dkim_sig = bool(dkim_signatures)
    dkim_sig_count = len(dkim_signatures)
    if has_dkim_sig:
        headers_inspected.append("DKIM-Signature")

    # Consolidate SPF
    spf_status, spf_exp, spf_trust = consolidate_method_findings("spf", spf_findings)
    spf_domain = None
    spf_ip = None
    for f in spf_findings:
        if "smtp.mailfrom" in f.properties:
            spf_domain = f.properties["smtp.mailfrom"]
        elif "envelope-from" in f.properties:
            spf_domain = f.properties["envelope-from"]
        if "client-ip" in f.properties:
            spf_ip = f.properties["client-ip"]

    spf_evidence = SPFEvidence(
        status=spf_status,
        findings=spf_findings,
        domain=spf_domain,
        client_ip=spf_ip,
        explanation=spf_exp,
        trust_limitation=spf_trust,
    )

    # Consolidate DKIM
    dkim_status, dkim_exp, dkim_trust = consolidate_method_findings("dkim", dkim_findings)
    dkim_domain = None
    dkim_selector = None
    for f in dkim_findings:
        if "header.d" in f.properties:
            dkim_domain = f.properties["header.d"]
        elif "header.i" in f.properties:
            dkim_domain = f.properties["header.i"]
        if "header.s" in f.properties:
            dkim_selector = f.properties["header.s"]

    # Special handling for DKIM-Signature presence when no Authentication-Results found
    if dkim_status == AuthResultStatus.NOT_PRESENT and has_dkim_sig:
        dkim_status = AuthResultStatus.UNKNOWN
        dkim_exp = (
            f"Message contains {dkim_sig_count} DKIM-Signature header(s), but no receiving MTA recorded a "
            "verification result in Authentication-Results. Offline analysis does not perform cryptographic signature verification."
        )
        dkim_trust = (
            "A DKIM signature header alone does NOT prove authenticity without cryptographic verification against "
            "the signer's public key."
        )

    dkim_evidence = DKIMEvidence(
        status=dkim_status,
        findings=dkim_findings,
        has_dkim_signature_header=has_dkim_sig,
        dkim_signature_count=dkim_sig_count,
        domain=dkim_domain,
        selector=dkim_selector,
        explanation=dkim_exp,
        trust_limitation=dkim_trust,
    )

    # Consolidate DMARC
    dmarc_status, dmarc_exp, dmarc_trust = consolidate_method_findings("dmarc", dmarc_findings)
    dmarc_policy = None
    dmarc_sp = None
    dmarc_dis = None
    dmarc_from = None
    dmarc_alignment = False

    for f in dmarc_findings:
        if "p" in f.properties:
            dmarc_policy = f.properties["p"]
        elif "policy" in f.properties:
            dmarc_policy = f.properties["policy"]

        if "sp" in f.properties:
            dmarc_sp = f.properties["sp"]

        if "dis" in f.properties:
            dmarc_dis = f.properties["dis"]
        elif "action" in f.properties:
            dmarc_dis = f.properties["action"]

        if "header.from" in f.properties:
            dmarc_from = f.properties["header.from"]

        # Check explicit alignment evidence
        reason_low = (f.reason or "").lower()
        snippet_low = (f.raw_snippet or "").lower()
        if "alignment=pass" in snippet_low or "aligned" in reason_low or "alignment=yes" in snippet_low:
            dmarc_alignment = True

    dmarc_evidence = DMARCEvidence(
        status=dmarc_status,
        findings=dmarc_findings,
        policy=dmarc_policy,
        subdomain_policy=dmarc_sp,
        disposition=dmarc_dis,
        header_from=dmarc_from,
        alignment_verified=dmarc_alignment,
        explanation=dmarc_exp,
        trust_limitation=dmarc_trust,
    )

    # Overall analysis status
    has_conflicts = (
        spf_status == AuthResultStatus.CONFLICTING_EVIDENCE
        or dkim_status == AuthResultStatus.CONFLICTING_EVIDENCE
        or dmarc_status == AuthResultStatus.CONFLICTING_EVIDENCE
    )

    all_statuses = [spf_status, dkim_status, dmarc_status]

    if has_conflicts:
        overall_status = OverallAuthStatus.CONFLICTING_EVIDENCE
    elif all(s == AuthResultStatus.NOT_PRESENT for s in all_statuses):
        overall_status = OverallAuthStatus.NO_EVIDENCE
    elif any(s in [AuthResultStatus.PASS, AuthResultStatus.FAIL, AuthResultStatus.SOFTFAIL] for s in all_statuses):
        if any(s == AuthResultStatus.NOT_PRESENT for s in all_statuses):
            overall_status = OverallAuthStatus.PARTIAL_EVIDENCE
        else:
            overall_status = OverallAuthStatus.EVALUATED
    else:
        overall_status = OverallAuthStatus.PARTIAL_EVIDENCE

    # Determine boundary MTA authserv-id (from outermost Authentication-Results[0])
    boundary_authserv_id: Optional[str] = None
    boundary_authserv_trust: AuthservTrustStatus = AuthservTrustStatus.MISSING
    is_boundary_trusted: bool = False

    if auth_results_headers:
        first_aid, _, _ = parse_auth_results_header(
            auth_results_headers[0], 0, trusted_domains=trusted_authserv_domains
        )
        boundary_authserv_id = first_aid
        aid_validation = validate_authserv_id_trust(
            first_aid, trusted_domains=trusted_authserv_domains
        )
        aid_status = aid_validation.status
        boundary_authserv_trust = aid_status

        if len(auth_results_headers) > 1:
            warnings.append(
                f"Multiple Authentication-Results headers ({len(auth_results_headers)}) present in message. Only outermost boundary header (index 0) is evaluated against trust policy."
            )

        if aid_status == AuthservTrustStatus.MISSING:
            warnings.append(
                f"Outermost Authentication-Results header (index 0) has no authserv-id. Reported authentication results cannot be attributed to any gateway."
            )
        elif aid_status == AuthservTrustStatus.SUSPICIOUS:
            warnings.append(
                f"Outermost Authentication-Results header (index 0) has a malformed or suspicious authserv-id '{boundary_authserv_id}'. Header may be crafted."
            )
        elif aid_status == AuthservTrustStatus.UNTRUSTED:
            warnings.append(
                f"Outermost Authentication-Results header (index 0) specifies unrecognized authserv-id '{boundary_authserv_id}'. Reported authentication results cannot be trusted as boundary assertions."
            )
        elif aid_status == AuthservTrustStatus.REPORTED:
            # Stage A.2: domain matched a known gateway name, but this is an offline .eml upload.
            # The authserv-id string cannot be verified as genuinely originating from that gateway.
            warnings.append(
                f"Outermost Authentication-Results header (index 0) specifies authserv-id '{boundary_authserv_id}', which matches a known mail gateway name. "
                "However, this is an offline .eml upload — the authserv-id string can be trivially forged. "
                "Authentication assertions are REPORTED (unverified), not independently established."
            )
    else:
        boundary_authserv_trust = AuthservTrustStatus.MISSING

    # Stage A.2: Determine provenance_status for the analysis result.
    # For offline .eml upload workflows:
    #   - is_boundary_trusted MUST remain False — authserv-id domain matching is NOT provenance proof.
    #   - provenance_status reflects the best classification of what we have.
    all_findings = spf_findings + dkim_findings + dmarc_findings
    pass_findings = [f for f in all_findings if f.result == AuthResultStatus.PASS]

    if not auth_results_headers and not header_info.received_spf:
        provenance_status = ProvenanceStatus.MISSING_AUTHENTICATION
    elif boundary_authserv_trust in (AuthservTrustStatus.SUSPICIOUS,):
        provenance_status = ProvenanceStatus.UNTRUSTED_AUTHENTICATION
    elif boundary_authserv_trust == AuthservTrustStatus.MISSING and not all_findings:
        provenance_status = ProvenanceStatus.MISSING_AUTHENTICATION
    else:
        # All remaining cases for offline .eml uploads are REPORTED — including when authserv-id
        # matches a known gateway (REPORTED status). Provenance cannot be established offline.
        provenance_status = ProvenanceStatus.REPORTED_AUTHENTICATION

    # is_boundary_trusted is always False for offline .eml uploads regardless of authserv-id.
    # Stage A.2: Do NOT set is_boundary_trusted=True based on authserv-id domain matching alone.
    is_boundary_trusted = False

    if pass_findings and not is_boundary_trusted:
        boundary_has_pass = any(f.header_index == 0 for f in pass_findings)
        if not boundary_has_pass:
            warnings.append(
                "Authentication PASS was recorded only in upstream/lower headers (index > 0), not by the outermost recipient boundary MTA. Downstream filters cannot verify if this header was injected by the sender."
            )
        # Note: even if boundary_has_pass, is_boundary_trusted stays False — authserv-id match
        # is not provenance proof for offline uploads. See Stage A.2 rationale.

    return EmailAuthenticationAnalysis(
        status=overall_status,
        spf=spf_evidence,
        dkim=dkim_evidence,
        dmarc=dmarc_evidence,
        headers_inspected=headers_inspected,
        authserv_ids=sorted(list(authserv_ids)),
        boundary_authserv_id=boundary_authserv_id,
        boundary_authserv_trust=boundary_authserv_trust,
        is_boundary_trusted=is_boundary_trusted,
        has_conflicts=has_conflicts,
        warnings=warnings,
        provenance_status=provenance_status,
    )
