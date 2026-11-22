"""
PhishIntel — Evidence-Based Phishing Risk Scoring Engine.
Calculates a transparent, explainable 0–100 heuristic risk score across 5 modalities:
1. Sender Identity and Authentication: max 25 points
2. URL and Link Intelligence: max 25 points
3. Content and Language Analysis: max 20 points
4. ML Model Analysis (DistilBERT with Corroboration Dampening): max 20 points
5. Header, IP and Infrastructure Intelligence: max 10 points

Design Guarantees:
- Heuristic risk-index points (0-100), NOT calibrated real-world phishing probabilities.
- Offline SPF/DKIM/DMARC PASS results remain explicitly identified as reported assertions.
- Resolves the offline provenance deadlock without falsely granting boundary trust.
- Neutralizes ordinary enterprise tracking (OIDC login_hint on aligned domains, UTMs, tracking pixels, CDN paths).
- DistilBERT corroboration dampening: an isolated high ML score on clean technical evidence is dampened to max 5 pts,
  while corroborated phishing evidence operates at full linear weight.
- Critical Threat Floor: confirmed malicious executable attachments, deceptive displayed links, or userinfo authority
  deception escalate the score to >= 75 (HIGH_RISK_INDICATORS_PRESENT).
"""

from datetime import datetime, timezone
import re
from typing import Dict, List, Optional, Set, Tuple

from app.schemas.email import (
    AttachmentInfo,
    EmailBodyInfo,
    EmailHeaderInfo,
)
from app.schemas.email_authentication import (
    EmailAuthenticationAnalysis,
)
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    AuthEvidenceSummary,
    CategoryScoreDetail,
    CategoryScoresBreakdown,
    EvidenceCompletenessStatus,
    EvidenceFusionResult,
    IPEvidenceSummary,
    ModelEvidenceInterpretation,
    ModelInferenceEvidence,
    ModelInferenceStatus,
    URLEvidenceSummary,
)
from app.schemas.ip_intelligence import IPIntelligenceResult
from app.schemas.url_intelligence import URLBatchAnalysisResult
from app.services.homoglyph_detector import (
    detect_mixed_script_homoglyphs,
    has_mixed_script_homoglyphs,
    normalize_homoglyphs,
)


# Executable / dangerous attachment extensions
DANGEROUS_EXTENSIONS: Set[str] = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".iso", ".hta", ".cmd",
    ".wsf", ".ps1", ".jar", ".cpl", ".msc", ".com", ".pif",
}

# Double extension pattern (e.g. invoice.pdf.exe)
DOUBLE_EXT_REGEX = re.compile(
    r"\.[a-zA-Z0-9]{2,4}\.(exe|scr|vbs|js|bat|iso|hta|cmd|wsf|ps1|cpl)$",
    re.IGNORECASE,
)

# High-profile targeted brands for display name spoofing
TARGETED_DISPLAY_BRANDS: Dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "openai": "openai.com",
    "metamask": "metamask.io",
    "okx": "okx.com",
    "bradesco": "bradesco.com.br",
    "livelo": "livelo.com.br",
    "itau": "itau.com.br",
    "santander": "santander.com.br",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "ledger": "ledger.com",
    "trezor": "trezor.io",
    "trustwallet": "trustwallet.com",
    "phantom": "phantom.app",
}

# Public webmail domains for suspicious Reply-To mismatch
PUBLIC_WEBMAIL_DOMAINS: Set[str] = {
    "gmail.com", "yahoo.com", "ymail.com", "outlook.com", "hotmail.com",
    "live.com", "protonmail.com", "proton.me", "aol.com", "yandex.ru",
    "yandex.com", "mail.ru", "zoho.com", "icloud.com",
}

# Disposable / throwaway mailbox domains frequently abused in phishing
DISPOSABLE_WEBMAIL_DOMAINS: Set[str] = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "10minutemail.com",
    "yopmail.com", "trashmail.com", "throwawaymail.com", "sharklasers.com",
    "dispostable.com", "getairmail.com",
}


# Common two-part public suffixes for accurate base domain extraction
COMMON_TWO_PART_SUFFIXES = (
    ".com.br", ".co.uk", ".com.au", ".org.uk", ".gov.uk", ".co.jp", ".co.nz",
    ".com.cn", ".net.cn", ".org.cn", ".com.mx", ".co.za", ".com.sg", ".com.tr",
    ".com.ar", ".edu.br", ".gov.br",
)


def _extract_domain_from_email_str(email_str: Optional[str]) -> Optional[str]:
    """Safely extracts domain/host part from an RFC 5322 address string."""
    if not email_str:
        return None
    match = re.search(r"[\w.+-]+@([a-zA-Z0-9.-]+)", email_str)
    return match.group(1).lower().rstrip(".") if match else None


def _get_registered_domain(domain: Optional[str]) -> str:
    """Extracts base registered domain (e.g. sub.example.com -> example.com, sub.bank.com.br -> bank.com.br)."""
    if not domain:
        return ""
    d = domain.lower().rstrip(".")
    parts = d.split(".")
    if any(d.endswith(sfx) for sfx in COMMON_TWO_PART_SUFFIXES):
        return ".".join(parts[-3:]) if len(parts) >= 3 else d
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


# ==============================================================================
# Category 1: Sender Identity & Authentication (Max 25 points)
# ==============================================================================
def score_sender_identity_and_auth(
    header_info: Optional[EmailHeaderInfo],
    auth_analysis: Optional[EmailAuthenticationAnalysis],
) -> Tuple[int, List[str], List[str], List[str]]:
    """
    Evaluates sender identity, display name spoofing, reply-to alignment,
    and reported authentication results.

    Returns: (score, positive_evidence, negative_evidence, rules_triggered)
    """
    points = 0
    pos_ev: List[str] = []
    neg_ev: List[str] = []
    rules: List[str] = []

    from_raw = header_info.from_header if header_info else None
    from_domain = _extract_domain_from_email_str(from_raw)
    from_reg = _get_registered_domain(from_domain)

    # 1. Display Name Spoofing Check with Homoglyph Detection
    is_brand_spoofed = False
    claimed_brand_name: Optional[str] = None
    if from_raw and from_domain:
        display_part = from_raw.split("<")[0].strip().strip('"').strip("'") if "<" in from_raw else ""
        if has_mixed_script_homoglyphs(display_part):
            points += 18
            rules.append("RULE_HOMOGLYPH_DISPLAY_NAME")
            homo_matches = detect_mixed_script_homoglyphs(display_part)
            sub_detail = homo_matches[0]["substituted_chars"] if homo_matches else "Cyrillic/Greek lookalikes"
            neg_ev.append(
                f"Display name '{display_part}' uses mixed-script homoglyph obfuscation ({sub_detail}) to mimic legitimate brand."
            )

        norm_display = normalize_homoglyphs(display_part).lower()
        for brand_key, official_dom in TARGETED_DISPLAY_BRANDS.items():
            if brand_key in norm_display:
                if from_reg != _get_registered_domain(official_dom):
                    if "RULE_DISPLAY_NAME_SPOOFING" not in rules:
                        points += 18
                        rules.append("RULE_DISPLAY_NAME_SPOOFING")
                        neg_ev.append(
                            f"Display name claims '{display_part}' (mimicking {brand_key.title()}), "
                            f"but actual From address domain is '{from_domain}'."
                        )
                    is_brand_spoofed = True
                    claimed_brand_name = brand_key.title()
                    break

    # 2. Suspicious Reply-To Mismatch
    reply_to = header_info.reply_to if header_info else None
    reply_domain = _extract_domain_from_email_str(reply_to)
    if reply_domain and from_domain:
        reply_reg = _get_registered_domain(reply_domain)
        if reply_reg != from_reg:
            if reply_domain in DISPOSABLE_WEBMAIL_DOMAINS:
                points += 16
                rules.append("RULE_SUSPICIOUS_REPLYTO_DISPOSABLE_MAIL")
                neg_ev.append(
                    f"Suspicious Reply-To redirection: From address domain is '@{from_domain}', "
                    f"but replies redirect to a disposable/throwaway mailbox ('@{reply_domain}')."
                )
            elif reply_domain in PUBLIC_WEBMAIL_DOMAINS:
                points += 14
                rules.append("RULE_SUSPICIOUS_REPLYTO_MISMATCH_WEBMAIL")
                neg_ev.append(
                    f"Suspicious Reply-To redirection: From address is '@{from_domain}', "
                    f"but replies redirect to a free public webmail address ('@{reply_domain}')."
                )
            else:
                points += 8
                rules.append("RULE_REPLYTO_DOMAIN_MISMATCH")
                neg_ev.append(
                    f"Reply-To domain mismatch: Replies redirect to '@{reply_domain}' "
                    f"instead of the sender domain '@{from_domain}'."
                )

    # 2b. Return-Path Mismatch / Envelope Spoofing
    return_path = header_info.return_path if header_info else None
    return_dom = _extract_domain_from_email_str(return_path)
    if return_dom and from_domain:
        return_reg = _get_registered_domain(return_dom)
        if "." not in return_dom or return_dom.startswith(("ubuntu-", "ip-", "vps-", "server-", "mail-")):
            points += 6
            rules.append("RULE_UNQUALIFIED_RETURN_PATH")
            neg_ev.append(
                f"Return-Path specifies an unqualified server/VPS hostname ('{return_dom}') rather than a valid domain."
            )
        elif return_reg != from_reg:
            spf_passed_on_return = (
                auth_analysis
                and auth_analysis.spf
                and auth_analysis.spf.status
                and str(getattr(auth_analysis.spf.status, "value", auth_analysis.spf.status)).upper() == "PASS"
                and auth_analysis.spf.domain
                and _get_registered_domain(auth_analysis.spf.domain) == return_reg
            )
            if not spf_passed_on_return:
                points += 6
                rules.append("RULE_RETURN_PATH_MISMATCH")
                neg_ev.append(
                    f"Return-Path envelope domain ('{return_dom}') does not align with sender From domain ('{from_domain}')."
                )

    # 3. Authentication Evaluation
    if auth_analysis:
        live_mode = getattr(auth_analysis, "verification_mode", "OFFLINE_REPORTED") == "LIVE_DNS"
        spf_status = auth_analysis.spf.status.value if hasattr(auth_analysis.spf.status, "value") else str(auth_analysis.spf.status)
        dkim_status = auth_analysis.dkim.status.value if hasattr(auth_analysis.dkim.status, "value") else str(auth_analysis.dkim.status)
        dmarc_status = auth_analysis.dmarc.status.value if hasattr(auth_analysis.dmarc.status, "value") else str(auth_analysis.dmarc.status)

        has_spf_fail = (spf_status in ("FAIL", "PERMERROR"))
        has_dkim_fail = (dkim_status in ("FAIL", "PERMERROR"))
        has_dmarc_fail = (dmarc_status in ("FAIL", "REJECT", "QUARANTINE"))
        has_fail = has_spf_fail or has_dkim_fail or has_dmarc_fail

        # Check for explicit failures
        if has_fail:
            if dmarc_status in ("FAIL", "REJECT", "QUARANTINE"):
                points += 15
                rules.append("RULE_AUTH_EXPLICIT_FAILURE_DMARC_ENFORCED")
                neg_ev.append(
                    f"explicit domain authentication failure ({'live DNS verification failure' if live_mode else 'reported authentication failure observed'}): SPF={spf_status}, "
                    f"DKIM={dkim_status}, with correlated downstream DMARC={dmarc_status}."
                )
            else:
                points += 10
                rules.append("RULE_AUTH_EXPLICIT_FAILURE")
                neg_ev.append(f"Reported authentication failure recorded in headers: SPF={spf_status}, DKIM={dkim_status}.")

        # Check for conflicting intermediate headers
        if auth_analysis.has_conflicts:
            points += 8
            rules.append("RULE_AUTH_CONTRADICTORY_HEADERS")
            neg_ev.append("Contradictory authentication assertions recorded across intermediate receiving headers.")

        # Check for consistent reported pass
        has_spf_pass = (spf_status == "PASS")
        has_dkim_pass = (dkim_status == "PASS")
        has_dmarc_pass = (dmarc_status == "PASS")

        if (has_spf_pass or has_dkim_pass or has_dmarc_pass) and not has_fail:
            passed_mechs = []
            if has_spf_pass:
                passed_mechs.append("SPF")
            if has_dkim_pass:
                passed_mechs.append("DKIM")
            if has_dmarc_pass:
                passed_mechs.append("DMARC")
            mechs_str = ", ".join(passed_mechs)

            if is_brand_spoofed:
                neg_ev.append(
                    f"Receiver-reported authentication ({mechs_str}) passed only for underlying infrastructure domain ('{from_domain}'), "
                    f"failing to authenticate the claimed brand identity ('{claimed_brand_name}'). "
                    f"Authentication of an unrelated domain provides no proof of sender legitimacy."
                )
            else:
                # Check alignment with sender domain
                dkim_dom = auth_analysis.dkim.domain
                if live_mode:
                    aligned_txt = (
                        " with domain alignment to the From header"
                        if (dkim_dom and from_domain and _get_registered_domain(dkim_dom) == from_reg)
                        else ""
                    )
                    pos_ev.append(
                        f"Authentication independently verified by PhishIntel via live DNS ({mechs_str}){aligned_txt} "
                        f"for From domain ('{from_domain}'). Passing authentication proves control of that domain, not benign intent."
                    )
                elif dkim_dom and from_domain and _get_registered_domain(dkim_dom) == from_reg:
                    pos_ev.append(
                        f"Receiver-reported domain authentication passed ({mechs_str}) with verified domain alignment to From header ('{from_domain}'). Note: cannot be independently verified in offline context."
                    )
                else:
                    pos_ev.append(
                        f"Receiver-reported domain authentication passed ({mechs_str}) as recorded by receiving MTA headers (unverified offline provenance; cannot be independently verified)."
                    )

    capped_score = min(25, points)
    return capped_score, pos_ev, neg_ev, rules


# ==============================================================================
# Category 2: URL & Link Intelligence (Max 25 points)
# ==============================================================================
def score_url_and_link_intelligence(
    url_analysis: Optional[URLBatchAnalysisResult],
    header_info: Optional[EmailHeaderInfo] = None,
) -> Tuple[int, List[str], List[str], List[str]]:
    """
    Evaluates URL structural patterns, anchor text deception, lookalike domains,
    and IP literals.
    """
    points = 0
    pos_ev: List[str] = []
    neg_ev: List[str] = []
    rules: List[str] = []

    if not url_analysis or url_analysis.total_urls == 0:
        pos_ev.append("No external hyperlinks detected in email body.")
        return 0, pos_ev, neg_ev, rules

    total_urls = url_analysis.total_urls
    unique_urls = url_analysis.unique_urls

    # Collect rule occurrences without double counting
    observed_rule_ids: Set[str] = set()
    for u in url_analysis.url_results:
        for obs in u.observations:
            observed_rule_ids.add(obs.rule_id)

    # Scored Risk Rules
    if "RULE_USERINFO_AUTH" in observed_rule_ids or "RULE_USERINFO_AUTH_TRICK" in observed_rule_ids:
        points += 25
        rules.append("RULE_USERINFO_AUTH")
        neg_ev.append("User-info authority deception (@ in authority) detected in embedded URL.")

    if "RULE_DECEPTIVE_DISPLAYED_LINK" in observed_rule_ids:
        points += 20
        rules.append("RULE_DECEPTIVE_DISPLAYED_LINK")
        neg_ev.append("Deceptive displayed hyperlink: Anchor text visually displays a different destination than the href URL.")

    if "RULE_LOOKALIKE_IMPERSONATION_DOMAIN" in observed_rule_ids:
        points += 20
        rules.append("RULE_LOOKALIKE_IMPERSONATION_DOMAIN")
        neg_ev.append("Lookalike / Brand impersonation domain detected in destination URL.")

    if (
        "RULE_PUBLIC_IP_HOST" in observed_rule_ids
        or "RULE_IP_LITERAL_HOST" in observed_rule_ids
        or "RULE_NESTED_REDIRECT_IP_LITERAL" in observed_rule_ids
    ):
        points += 15
        rules.append("RULE_PUBLIC_IP_HOST")
        neg_ev.append("Raw public IP-literal used as destination host instead of a registered domain.")

    if "RULE_UNUSUAL_SCHEME" in observed_rule_ids:
        points += 15
        rules.append("RULE_UNUSUAL_SCHEME")
        neg_ev.append("Dangerous or unusual protocol scheme (e.g. data:, javascript:, file:) detected.")

    if "RULE_EMAIL_IN_QUERY" in observed_rule_ids:
        # Check if email in query is on an aligned sender domain or standard IdP (e.g. login_hint)
        is_harvesting_query = False
        from_reg = ""
        if header_info and header_info.from_header:
            m = re.search(r"[\w.+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", header_info.from_header)
            if m:
                from_reg = _get_registered_domain(m.group(1))

        for u in url_analysis.url_results:
            has_email_rule = any(obs.rule_id == "RULE_EMAIL_IN_QUERY" for obs in u.observations)
            if has_email_rule:
                host_reg = _get_registered_domain(u.normalized_hostname)
                is_aligned = (
                    (from_reg and host_reg == from_reg)
                    or (from_reg == "openai.com" and host_reg in ("openai.com", "chatgpt.com"))
                    or (from_reg in ("google.com", "gmail.com") and host_reg in ("google.com", "youtube.com", "googleusercontent.com"))
                    or (from_reg == "microsoft.com" and host_reg in ("microsoft.com", "live.com", "office.com"))
                )
                if not is_aligned:
                    is_harvesting_query = True
                    break

        if is_harvesting_query:
            points += 8
            rules.append("RULE_EMAIL_IN_QUERY")
            neg_ev.append("Query string contains embedded recipient email address on an unaligned external domain.")
        else:
            pos_ev.append("Standard OIDC identity hint (login_hint) detected on authentic sender/IdP domain.")

    if "RULE_PUNYCODE_HOST" in observed_rule_ids or "RULE_UNICODE_HOST" in observed_rule_ids:
        points += 10
        rules.append("RULE_PUNYCODE_HOMOGLYPH")
        neg_ev.append("Punycode (xn--) or internationalized Unicode homoglyph characters detected in hostname.")

    if "RULE_UNICODE_PATH_OR_QUERY" in observed_rule_ids:
        points += 15
        rules.append("RULE_UNICODE_PATH_OR_QUERY")
        neg_ev.append("Non-ASCII or homoglyph characters detected in URL path or query parameter.")

    if "RULE_SUSPICIOUS_SECURITY_KEYWORD_DOMAIN" in observed_rule_ids:
        points += 15
        rules.append("RULE_SUSPICIOUS_SECURITY_KEYWORD_DOMAIN")
        neg_ev.append("Destination domain incorporates high-risk security/2FA authentication keywords on an unaligned third-party domain.")

    if "RULE_HOMOGLYPH_ANCHOR_TEXT" in observed_rule_ids:
        points += 10
        rules.append("RULE_HOMOGLYPH_ANCHOR_TEXT")
        neg_ev.append("Hyperlink anchor text contains mixed-script homoglyphs disguising destination intent.")

    # Brand-to-URL Destination Alignment Check
    if header_info and header_info.from_header:
        from_disp = normalize_homoglyphs(header_info.from_header.split("<")[0]).lower()
        for b_name, b_dom in TARGETED_DISPLAY_BRANDS.items():
            if b_name in from_disp:
                b_reg = _get_registered_domain(b_dom)
                external_hosts = [
                    u.normalized_hostname for u in url_analysis.url_results
                    if u.normalized_hostname and not any(
                        u.normalized_hostname.lower().endswith("." + cdn) or u.normalized_hostname.lower() == cdn
                        for cdn in ("gstatic.com", "googleapis.com", "googleusercontent.com")
                    )
                ]
                if external_hosts:
                    has_brand_dest = any(_get_registered_domain(h) == b_reg for h in external_hosts)
                    if not has_brand_dest and "RULE_LOOKALIKE_IMPERSONATION_DOMAIN" not in rules and "RULE_URL_BRAND_MISMATCH" not in rules:
                        points += 15
                        rules.append("RULE_URL_BRAND_MISMATCH")
                        neg_ev.append(
                            f"Email claims to represent {b_name.title()}, but destination link(s) navigate to unrelated third-party domain(s) ('{external_hosts[0]}')."
                        )
                break

    if "RULE_DOUBLE_PERCENT_ENCODING" in observed_rule_ids:
        points += 8
        rules.append("RULE_DOUBLE_PERCENT_ENCODING")
        neg_ev.append("Double percent-encoding sequences detected in URL path.")

    if "RULE_EXCESSIVE_PATH_LENGTH" in observed_rule_ids:
        points += 5
        rules.append("RULE_EXCESSIVE_PATH_LENGTH")
        neg_ev.append("Excessively long non-CDN path structure (>200 characters) detected.")

    if "RULE_NON_DEFAULT_PORT" in observed_rule_ids:
        points += 6
        rules.append("RULE_NON_DEFAULT_PORT")
        neg_ev.append("Explicit non-standard web port specified in URL.")

    # Positive evidence if clean
    if points == 0:
        if "RULE_OIDC_LOGIN_HINT_PARAMETER" in observed_rule_ids:
            pos_ev.append("Standard OIDC identity hint (login_hint) detected on authentic sender/IdP domain.")
        pos_ev.append(f"All {total_urls} extracted link(s) across {unique_urls} unique destination(s) conform to benign structural patterns.")

    capped_score = min(25, points)
    return capped_score, pos_ev, neg_ev, rules


# ==============================================================================
# Category 3: Content & Language Analysis (Max 20 points)
# ==============================================================================
def score_content_and_language(
    body_info: Optional[EmailBodyInfo],
    attachments: Optional[List[AttachmentInfo]],
    header_info: Optional[EmailHeaderInfo] = None,
) -> Tuple[int, List[str], List[str], List[str], bool]:
    """
    Evaluates rule-based content indicators: dangerous attachments, coercive urgency,
    financial/credential demands, and hidden text obfuscation.

    Returns: (score, positive_evidence, negative_evidence, rules_triggered, has_critical_attachment)
    """
    points = 0
    pos_ev: List[str] = []
    neg_ev: List[str] = []
    rules: List[str] = []
    has_critical_attachment = False

    # 1. Attachment Metadata Inspection
    if attachments:
        for att in attachments:
            fname = att.filename.lower()

            # Double extension check (e.g. invoice.pdf.exe)
            if DOUBLE_EXT_REGEX.search(fname):
                points += 20
                rules.append("RULE_DOUBLE_EXTENSION_ATTACHMENT")
                neg_ev.append(f"High-risk disguised double extension detected in attachment '{att.filename}'.")
                has_critical_attachment = True

            # Direct executable / script extension check
            elif any(fname.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                points += 20
                rules.append("RULE_MALICIOUS_ATTACHMENT_EXTENSION")
                neg_ev.append(f"Dangerous executable/script attachment detected: '{att.filename}' ({att.content_type}).")
                has_critical_attachment = True

        if not has_critical_attachment and attachments:
            pos_ev.append(f"{len(attachments)} attachment(s) inspected; all filenames exhibit standard document/data extensions.")

    # 2. Body Text Linguistic & Structural Inspection
    full_text = ""
    if header_info and header_info.subject:
        full_text += header_info.subject + " "
    if body_info:
        if body_info.plain_text:
            full_text += body_info.plain_text + " "
        if body_info.html_extracted_text:
            full_text += body_info.html_extracted_text + " "

    if full_text:
        # Check for mixed-script homoglyphs in content
        if has_mixed_script_homoglyphs(full_text):
            homo_tokens = detect_mixed_script_homoglyphs(full_text)
            points += 10
            rules.append("RULE_HOMOGLYPH_TEXT_OBFUSCATION")
            neg_ev.append(
                f"Mixed-script homoglyphs detected in message content ({len(homo_tokens)} token(s) substituted), indicating intentional filter evasion."
            )

        # Normalize homoglyphs for reliable linguistic analysis
        norm_text = normalize_homoglyphs(full_text).lower()

        # Severe Urgency / Account Suspension Threats
        urgent_phrases = [
            "account will be suspended", "account has been suspended", "account is locked",
            "immediate action required to prevent", "within 24 hours to avoid",
            "within 48 hours to avoid", "failure to verify will result in termination",
            "legal action will be taken",
        ]
        if any(p in norm_text for p in urgent_phrases):
            points += 8
            rules.append("RULE_URGENT_ACCOUNT_THREAT")
            neg_ev.append("Coercive urgency language detected (threat of imminent account suspension or termination).")

        # Direct Credential Solicitation
        cred_phrases = [
            "enter your current password", "confirm your password", "verify your login credentials",
            "submit your secret key", "enter your seed phrase", "provide your credit card pin",
        ]
        if any(p in norm_text for p in cred_phrases):
            points += 10
            rules.append("RULE_CREDENTIAL_SOLICITATION")
            neg_ev.append("Direct solicitation of sensitive account credentials or passwords in message body.")

        # Cryptocurrency / Gift Card Demands
        financial_phrases = [
            "send bitcoin", "btc wallet", "crypto transfer", "buy gift card",
            "western union wire", "wire transfer immediately", "send eth to",
        ]
        if any(p in norm_text for p in financial_phrases):
            points += 10
            rules.append("RULE_FINANCIAL_CRYPTO_DEMAND")
            neg_ev.append("Solicitation of non-standard financial transfer (cryptocurrency wallet or gift cards).")

        # Rewards / Points Expiry Urgency
        rewards_phrases = [
            "pontos livelo", "expiram hoje", "expirando hoje", "pontos expirando",
            "resgate agora", "resgatar agora", "antes que expirem", "evite a perda",
            "points expiring", "miles expiring", "rewards expiring", "expire today",
            "expiring today", "claim before they expire", "redeem immediately",
        ]
        if any(p in norm_text for p in rewards_phrases):
            points += 10
            rules.append("RULE_REWARDS_EXPIRATION_URGENCY")
            neg_ev.append("Coercive rewards/points expiration urgency lure detected.")

        # Mandatory Security / 2FA Activation & Wallet Protection Lures
        security_wallet_phrases = [
            "enable 2fa", "2-factor authentication", "two-factor authentication",
            "mandatory for all", "protect your wallet", "stepping up your security",
            "wallet protection", "enable two factor", "activate 2fa", "mandatory security",
            "unauthorized access to your wallet",
        ]
        if any(p in norm_text for p in security_wallet_phrases):
            points += 10
            rules.append("RULE_MANDATORY_SECURITY_WALLET_LURE")
            neg_ev.append("Mandatory 2FA security activation or wallet protection lure detected.")

    if points == 0:
        pos_ev.append("No coercive urgency threats, direct credential solicitations, or dangerous attachments detected.")

    capped_score = min(20, points)
    return capped_score, pos_ev, neg_ev, rules, has_critical_attachment


# ==============================================================================
# Category 4: ML Model Analysis & Corroboration Dampening (Max 20 points)
# ==============================================================================
def score_ml_model_analysis(
    model_inference: Optional[ModelInferenceEvidence],
    other_evidence_score: int,
) -> Tuple[int, List[str], List[str], List[str], bool, Optional[float]]:
    """
    Evaluates DistilBERT uncalibrated text inference with corroboration-based dampening:
    - If other technical evidence is clean (score <= 5): dampens model weight to max 5 pts,
      neutralizing false-positive shortcut learning on legitimate corporate phrases.
    - If other technical evidence is corroborated (score >= 15): allows full linear weight up to 20 pts.
    - Low model score does not suppress corroborated technical phishing evidence.

    Returns: (score, positive_evidence, negative_evidence, rules_triggered, is_dampened, raw_score)
    """
    if (
        not model_inference
        or model_inference.uncalibrated_score is None
        or model_inference.status in (ModelInferenceStatus.UNAVAILABLE, ModelInferenceStatus.ERROR)
    ):
        return 0, [], [], [], False, None

    raw_score = model_inference.uncalibrated_score
    rules: List[str] = []
    pos_ev: List[str] = []
    neg_ev: List[str] = []
    is_dampened = False

    # Corroboration Dampening Formula
    if other_evidence_score <= 5:
        # Technical evidence is clean -> dampen shortcut learning
        dampened_multiplier = 0.25
        score = min(5, round(raw_score * 20 * dampened_multiplier))
        is_dampened = (raw_score >= 0.50)
        rules.append("RULE_MODEL_DAMPENED_UNITS")
        if raw_score >= 0.70:
            neg_ev.append(
                f"DistilBERT NLP text similarity heuristic: {raw_score:.3f} (Dampened to {score} pts due to clean, aligned technical evidence)."
            )
        else:
            pos_ev.append(f"DistilBERT NLP text heuristic score is low or dampened ({raw_score:.3f}).")
    elif other_evidence_score < 15:
        # Moderate corroboration
        dampened_multiplier = 0.50
        score = min(10, round(raw_score * 20 * dampened_multiplier))
        is_dampened = (raw_score >= 0.50)
        rules.append("RULE_MODEL_PARTIAL_CORROBORATION")
        if raw_score >= 0.50:
            neg_ev.append(
                f"DistilBERT NLP text similarity heuristic: {raw_score:.3f} (Weighted to {score} pts with partial technical corroboration)."
            )
    else:
        # Corroborated by external indicators -> full linear weight
        score = min(20, round(raw_score * 20))
        rules.append("RULE_MODEL_FULL_CORROBORATION")
        if raw_score >= 0.50:
            neg_ev.append(
                f"DistilBERT NLP text similarity heuristic: {raw_score:.3f} (Full weight: {score} pts corroborated by technical evidence)."
            )

    return score, pos_ev, neg_ev, rules, is_dampened, raw_score


# ==============================================================================
# Category 5: Header, IP & Infrastructure Intelligence (Max 10 points)
# ==============================================================================
def score_header_ip_and_infrastructure(
    ip_analysis: Optional[IPIntelligenceResult],
    header_info: Optional[EmailHeaderInfo],
) -> Tuple[int, List[str], List[str], List[str]]:
    """
    Evaluates routing anomalies, forged internal transit hops, and contextual provider matching.
    """
    points = 0
    pos_ev: List[str] = []
    neg_ev: List[str] = []
    rules: List[str] = []

    if ip_analysis and ip_analysis.total_candidates > 0:
        # Check for provider infrastructure match
        if ip_analysis.provider_infrastructure_match:
            pos_ev.append(
                f"Transit boundary matches documented provider delivery infrastructure ({ip_analysis.provider_infrastructure_match})."
            )

        # Check for routing warnings
        if ip_analysis.warnings:
            for w in ip_analysis.warnings:
                if "Transit path consists entirely of private or non-routable" in w:
                    points += 4
                    rules.append("RULE_NON_ROUTABLE_TRANSIT")
                    neg_ev.append("Transit chain consists entirely of private or non-routable IP addresses.")

    capped_score = min(10, points)
    return capped_score, pos_ev, neg_ev, rules


# ==============================================================================
# Evidence Completeness Determination
# ==============================================================================
def determine_evidence_completeness(
    header_info: Optional[EmailHeaderInfo],
    body_info: Optional[EmailBodyInfo],
    auth_analysis: Optional[EmailAuthenticationAnalysis],
    ip_analysis: Optional[IPIntelligenceResult],
    url_analysis: Optional[URLBatchAnalysisResult] = None,
    model_inference: Optional[ModelInferenceEvidence] = None,
) -> Tuple[EvidenceCompletenessStatus, str]:
    """
    Distinguishes:
    - FULL_COVERAGE: Headers, body text, reported authentication, and transit chain present.
    - PARTIAL_COVERAGE: Body and core headers present, but auth or hops absent.
    - MINIMAL_OR_INSUFFICIENT: Empty/unparseable body or missing essential headers.
    """
    has_from = bool(header_info and header_info.from_header)
    has_subject = bool(header_info and header_info.subject)
    has_body_text = bool(body_info and (body_info.plain_text or body_info.html_extracted_text))
    has_auth_headers = bool(auth_analysis and auth_analysis.headers_inspected)
    has_transit_hops = bool(ip_analysis and ip_analysis.total_candidates > 0)
    has_urls = bool(url_analysis and url_analysis.total_urls > 0)
    has_model = bool(model_inference and model_inference.status == ModelInferenceStatus.EVALUATED)

    # Empty or unparseable: No headers, no body, no URLs, no auth, no model
    if (
        not has_body_text
        and not has_from
        and not has_subject
        and not has_urls
        and not has_auth_headers
        and not has_transit_hops
        and not has_model
    ):
        return (
            EvidenceCompletenessStatus.MINIMAL_OR_INSUFFICIENT,
            "Minimal or unparseable email content; insufficient data for a reliable forensic assessment."
        )

    if has_from and has_body_text and has_auth_headers and has_transit_hops:
        return (
            EvidenceCompletenessStatus.FULL_COVERAGE,
            "Comprehensive evidence available across headers, message body, reported authentication, and transit routing."
        )

    missing_elements = []
    if not has_auth_headers:
        missing_elements.append("reported authentication headers")
    if not has_transit_hops:
        missing_elements.append("extractable transit hops")
    if not has_body_text:
        missing_elements.append("body text")

    missing_str = " and ".join(missing_elements) if missing_elements else "transit evidence"
    return (
        EvidenceCompletenessStatus.PARTIAL_COVERAGE,
        f"Partial forensic evidence available ({missing_str} absent from file)."
    )


# ==============================================================================
# Primary Scoring Engine Entrypoint
# ==============================================================================
def calculate_phishing_risk_score(
    header_info: Optional[EmailHeaderInfo],
    body_info: Optional[EmailBodyInfo],
    attachments: Optional[List[AttachmentInfo]],
    url_analysis: Optional[URLBatchAnalysisResult],
    auth_analysis: Optional[EmailAuthenticationAnalysis],
    ip_analysis: Optional[IPIntelligenceResult],
    model_inference: Optional[ModelInferenceEvidence],
) -> Tuple[int, AssessmentCategory, CategoryScoresBreakdown, EvidenceCompletenessStatus, str, List[str], List[str]]:
    """
    Executes transparent 5-category scoring, applies corroboration dampening and critical threat floors,
    and returns (overall_score, category, breakdown, completeness_status, completeness_detail, positive_ev, negative_ev).
    """
    # 1. Score Categories 1, 2, 3, 5
    s1, pos1, neg1, rules1 = score_sender_identity_and_auth(header_info, auth_analysis)
    s2, pos2, neg2, rules2 = score_url_and_link_intelligence(url_analysis, header_info=header_info)
    s3, pos3, neg3, rules3, has_critical_att = score_content_and_language(body_info, attachments, header_info=header_info)
    s5, pos5, neg5, rules5 = score_header_ip_and_infrastructure(ip_analysis, header_info)

    # 2. Score Category 4 with Corroboration Dampening
    other_evidence_score = s1 + s2 + s3 + s5
    s4, pos4, neg4, rules4, is_dampened, raw_model_score = score_ml_model_analysis(
        model_inference, other_evidence_score=other_evidence_score
    )

    # 3. Base Numerical Sum
    raw_sum = s1 + s2 + s3 + s4 + s5

    # 4. Critical Threat Floor Check
    # Severe attacks (executable attachments, deceptive displayed link, userinfo authority deception,
    # public IP host with unaligned/model corroboration, credential-query on unaligned domain,
    # homoglyph spoofing, disposable reply-to, security lure domains)
    # must be classified as HIGH_RISK_INDICATORS_PRESENT (score >= 75)
    is_critical_threat = False
    critical_reasons: List[str] = []

    if has_critical_att:
        is_critical_threat = True
        critical_reasons.append("Dangerous executable or double-extension attachment detected")

    if "RULE_HOMOGLYPH_DISPLAY_NAME" in rules1:
        is_critical_threat = True
        critical_reasons.append("Homoglyph brand impersonation detected in sender display name")

    if "RULE_SUSPICIOUS_REPLYTO_DISPOSABLE_MAIL" in rules1:
        is_critical_threat = True
        critical_reasons.append("Sender directs replies to disposable/throwaway email inbox")

    if "RULE_DECEPTIVE_DISPLAYED_LINK" in rules2:
        is_critical_threat = True
        critical_reasons.append("Deceptive displayed hyperlink (anchor spoofing) detected")

    if "RULE_USERINFO_AUTH" in rules2:
        is_critical_threat = True
        critical_reasons.append("User-info authority deception (@ trick) detected")

    if "RULE_LOOKALIKE_IMPERSONATION_DOMAIN" in rules2:
        is_critical_threat = True
        critical_reasons.append("Lookalike brand domain detected in destination URL")

    if "RULE_UNICODE_PATH_OR_QUERY" in rules2:
        is_critical_threat = True
        critical_reasons.append("Non-ASCII/homoglyph characters detected in URL path or query")

    if "RULE_SUSPICIOUS_SECURITY_KEYWORD_DOMAIN" in rules2:
        is_critical_threat = True
        critical_reasons.append("Suspicious security/2FA authentication domain detected in URL")

    if "RULE_DISPLAY_NAME_SPOOFING" in rules1 and (raw_model_score and raw_model_score >= 0.70):
        is_critical_threat = True
        critical_reasons.append("Display name brand spoofing corroborated by elevated ML phishing text score")

    if "RULE_HOMOGLYPH_TEXT_OBFUSCATION" in rules3 and (raw_model_score and raw_model_score >= 0.70):
        is_critical_threat = True
        critical_reasons.append("Content homoglyph obfuscation corroborated by elevated phishing text score")

    if "RULE_URL_BRAND_MISMATCH" in rules2 and (s1 > 0 or (raw_model_score and raw_model_score >= 0.70)):
        is_critical_threat = True
        critical_reasons.append("Brand claimed in headers navigates to unaligned external destination domain")

    has_ip_literal = ("RULE_PUBLIC_IP_HOST" in rules2 or "RULE_NESTED_REDIRECT_IP_LITERAL" in rules2)
    if has_ip_literal and (s1 > 0 or (raw_model_score and raw_model_score >= 0.70)):
        is_critical_threat = True
        critical_reasons.append("Public IP literal link corroborated by unaligned sender or model score")

    has_auth_fail = "RULE_AUTH_EXPLICIT_FAILURE" in rules1 or "RULE_AUTH_EXPLICIT_FAILURE_DMARC_ENFORCED" in rules1
    if "RULE_EMAIL_IN_QUERY" in rules2 and (s1 > 0 or has_auth_fail or (raw_model_score and raw_model_score >= 0.70)):
        is_critical_threat = True
        critical_reasons.append("Credential-harvesting parameter on unaligned or failing domain")

    has_severe_url_anomaly = any(
        r in rules2
        for r in [
            "RULE_NON_DEFAULT_PORT",
            "RULE_EMAIL_IN_QUERY",
            "RULE_PUBLIC_IP_HOST",
            "RULE_IP_LITERAL_HOST",
            "RULE_NESTED_REDIRECT_IP_LITERAL",
            "RULE_USERINFO_AUTH",
            "RULE_DECEPTIVE_DISPLAYED_LINK",
            "RULE_LOOKALIKE_IMPERSONATION_DOMAIN",
            "RULE_PUNYCODE_HOMOGLYPH",
            "RULE_UNICODE_PATH_OR_QUERY",
            "RULE_SUSPICIOUS_SECURITY_KEYWORD_DOMAIN",
            "RULE_HOMOGLYPH_ANCHOR_TEXT",
            "RULE_URL_BRAND_MISMATCH",
        ]
    )
    if raw_model_score and raw_model_score >= 0.85 and has_severe_url_anomaly:
        is_critical_threat = True
        critical_reasons.append("Elevated model score corroborated by severe URL threat indicator")

    if has_auth_fail and raw_model_score and raw_model_score >= 0.70:
        is_critical_threat = True
        critical_reasons.append("Explicit authentication failure corroborated by high phishing text similarity")

    final_score = raw_sum
    if is_critical_threat and final_score < 75:
        final_score = 75

    # Floor for auth failures / conflicts (must not evaluate to LOW_RISK_INDICATORS)
    has_auth_conflict = "RULE_AUTH_CONTRADICTORY_HEADERS" in rules1
    if (has_auth_fail or has_auth_conflict) and final_score < 30:
        final_score = 30

    # Model inference error floor
    if model_inference and model_inference.status == ModelInferenceStatus.ERROR and final_score < 30:
        final_score = 30

    final_score = min(100, max(0, final_score))

    # 5. Determine Completeness
    completeness_status, completeness_detail = determine_evidence_completeness(
        header_info, body_info, auth_analysis, ip_analysis, url_analysis=url_analysis, model_inference=model_inference
    )

    # 6. Map to Risk Category Band
    if final_score >= 70:
        category = AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT
    elif final_score >= 30:
        category = AssessmentCategory.REVIEW_RECOMMENDED
    elif completeness_status == EvidenceCompletenessStatus.MINIMAL_OR_INSUFFICIENT:
        category = AssessmentCategory.INSUFFICIENT_EVIDENCE
    else:
        category = AssessmentCategory.LOW_RISK_INDICATORS

    # 7. Assemble Structured Category Breakdown
    raw_score_str = f"{raw_model_score:.3f}" if raw_model_score is not None else "N/A"
    breakdown = CategoryScoresBreakdown(
        sender_auth=CategoryScoreDetail(
            category_name="Sender Identity & Authentication",
            score=s1,
            max_score=25,
            weight_percentage=25,
            explanation=f"{s1}/25 points assigned based on sender-domain alignment, Reply-To consistency, and reported authentication.",
            rules_triggered=rules1,
            is_dampened=False,
        ),
        url_intelligence=CategoryScoreDetail(
            category_name="URL & Link Intelligence",
            score=s2,
            max_score=25,
            weight_percentage=25,
            explanation=f"{s2}/25 points assigned based on structural URL features, anchor text alignment, and domain reputations.",
            rules_triggered=rules2,
            is_dampened=False,
        ),
        content_language=CategoryScoreDetail(
            category_name="Content & Language Analysis",
            score=s3,
            max_score=20,
            weight_percentage=20,
            explanation=f"{s3}/20 points assigned based on attachment metadata, urgency threats, and credential solicitations.",
            rules_triggered=rules3,
            is_dampened=False,
        ),
        ml_model=CategoryScoreDetail(
            category_name="DistilBERT NLP Model Analysis",
            score=s4,
            max_score=20,
            weight_percentage=20,
            explanation=(
                f"{s4}/20 points assigned (Raw text heuristic score: {raw_score_str}"
                f"{'; corroboration dampening applied due to clean technical proof' if is_dampened else ''})."
            ),
            rules_triggered=rules4,
            is_dampened=is_dampened,
        ),
        header_ip=CategoryScoreDetail(
            category_name="Header, IP & Infrastructure Intelligence",
            score=s5,
            max_score=10,
            weight_percentage=10,
            explanation=f"{s5}/10 points assigned based on transit routing hops, MTA syntax, and infrastructure provenance.",
            rules_triggered=rules5,
            is_dampened=False,
        ),
    )

    all_pos = pos1 + pos2 + pos3 + pos4 + pos5
    all_neg = neg1 + neg2 + neg3 + neg4 + neg5

    return final_score, category, breakdown, completeness_status, completeness_detail, all_pos, all_neg