"""
PhishIntel — Phase 4A URL Intelligence Engine
Deterministic, explainable, and zero-network URL analysis module.

Extracts comprehensive structural and lexical features from URLs, identifies
evasion techniques and structural anomalies, and provides rule-based observations
with transparent severity tiers (INFO, LOW, MEDIUM, HIGH).

Safety Guarantees:
- ZERO network requests (No HTTP requests, No DNS lookups, No external APIs)
- 100% deterministic and local
- Uses Python standard library (urllib.parse, ipaddress, re, unicodedata)
"""

from datetime import datetime, timezone
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from app.schemas.email import EmailAnalysisResponse, ExtractedURL
from app.services.homoglyph_detector import detect_mixed_script_homoglyphs, has_mixed_script_homoglyphs
from app.schemas.url_intelligence import (
    HeuristicRiskCategory,
    HostClassification,
    HostType,
    ObservationSeverity,
    ParseStatus,
    URLAnalysisResult,
    URLBatchAnalysisResult,
    URLFeatures,
    URLObservation,
)

# Regex patterns for lexical analysis
PERCENT_ENCODING_REGEX = re.compile(r"%[0-9a-fA-F]{2}")
DOUBLE_ENCODING_REGEX = re.compile(r"%25[0-9a-fA-F]{2}", re.IGNORECASE)
EMAIL_PATTERN_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
REDIRECT_PARAM_NAMES = {"redirect", "url", "next", "goto", "return", "dest", "target", "link", "r"}

# Standard default ports for common schemes
DEFAULT_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ftps": 990,
}


# Documentation ranges (RFC 5737 for IPv4 TEST-NET-1/2/3, RFC 3849 for IPv6)
DOCUMENTATION_NETWORKS = (
    ipaddress.IPv4Network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv6Network("2001:db8::/32"),   # IPv6 Documentation
)

# RFC 1918 (IPv4 Private) & RFC 4193 (IPv6 Unique Local / ULA)
RFC_1918_NETWORKS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
RFC_4193_NETWORKS = (
    ipaddress.IPv6Network("fc00::/7"),
)

# Stage A.2: Additional special-purpose ranges that must NOT fall through to PUBLIC.
# These addresses are non-global but may not be caught by is_private / is_reserved alone
# depending on Python version. Explicit enumeration prevents the PUBLIC fallback bug.
SPECIAL_PURPOSE_NETWORKS = (
    ipaddress.IPv4Network("100.64.0.0/10"),   # RFC 6598 Shared Address Space
    ipaddress.IPv4Network("192.0.0.0/24"),    # IANA Special-Purpose (RFC 6890)
    ipaddress.IPv4Network("198.18.0.0/15"),   # Benchmarking (RFC 2544)
    ipaddress.IPv4Network("240.0.0.0/4"),     # Reserved (RFC 1112)
    ipaddress.IPv4Network("0.0.0.0/8"),       # Unspecified / "This" network (RFC 1122)
)

# Standard Identity Provider (IdP) domains where login hints / federated email params are expected
WELL_KNOWN_IDP_DOMAINS: Set[str] = {
    "accounts.google.com",
    "login.microsoftonline.com",
    "login.live.com",
    "appleid.apple.com",
    "github.com",
    "auth0.com",
    "okta.com",
}

# Major cloud CDN and asset domains where content-addressable storage paths commonly exceed 200 chars
KNOWN_ASSET_CDN_DOMAINS: Set[str] = {
    "adobeaemcloud.com",
    "sendgrid.net",
    "cloudfront.net",
    "googleusercontent.com",
    "akamaihd.net",
    "azureedge.net",
    "licdn.com",
    "oaistatic.com",
    "gstatic.com",
    "fbcdn.net",
    "twimg.com",
}

# High-profile targeted brands for lookalike / typosquatting detection
TARGETED_BRAND_KEYWORDS: Dict[str, str] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "docusign": "docusign.com",
    "dropbox": "dropbox.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
    "coinbase": "coinbase.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "okx": "okx.com",
    "bradesco": "bradesco.com.br",
    "livelo": "livelo.com.br",
    "ledger": "ledger.com",
    "trezor": "trezor.io",
    "trustwallet": "trustwallet.com",
    "phantom": "phantom.app",
    "openai": "openai.com",
}

# Suspicious TLDs frequently abused in disposable phishing campaigns
SUSPICIOUS_PHISHING_TLDS: Set[str] = {
    ".shop", ".top", ".xyz", ".club", ".click", ".buzz", ".site", ".work",
    ".live", ".icu", ".monster", ".cfd", ".tk", ".ml", ".ga", ".cf", ".gq",
}

# Security and authentication keywords targeted in credential/wallet harvesting lures
SECURITY_AUTH_KEYWORDS: Set[str] = {
    "twofactor", "2fa", "enabletwofactor", "security-verify", "verify-wallet",
    "wallet-auth", "account-protection", "metamask-auth", "crypto-security",
    "auth-verify", "security-activation",
}


def is_valid_ipv4_or_ipv6(host_str: str) -> Tuple[bool, Optional[int], HostClassification]:
    """
    Checks if a hostname string is an IPv4 or IPv6 address literal.
    Accurately distinguishes RFC 1918/4193 private space from RFC 5737/3849 documentation space.
    Stage A.3: Correct classification order — special-purpose networks (RFC 6598 Shared,
    RFC 2544 Benchmarking, RFC 1112 Reserved, RFC 1122 Unspecified) are explicitly classified
    as RESERVED before the generic `is_private` check, preventing Python 3.13's `is_private=True`
    from misclassifying them as PRIVATE.
    Returns: (is_ip, ip_version, classification)
    """
    cleaned = host_str.strip("[]")
    try:
        ip_obj = ipaddress.ip_address(cleaned)
        version = ip_obj.version

        if ip_obj.is_loopback:
            classification = HostClassification.LOOPBACK
        elif ip_obj.is_link_local:
            classification = HostClassification.LINK_LOCAL
        elif any(ip_obj in net for net in DOCUMENTATION_NETWORKS):
            # Documentation ranges (TEST-NET-1/2/3, 2001:db8::/32) — RFC 5737 / RFC 3849
            classification = HostClassification.DOCUMENTATION
        elif ip_obj.is_multicast:
            # Multicast addresses (224.0.0.0/4, ff00::/8)
            classification = HostClassification.RESERVED
        elif (
            ip_obj.is_unspecified
            or ip_obj.is_reserved
            or (ip_obj.version == 4 and any(ip_obj in net for net in SPECIAL_PURPOSE_NETWORKS))
        ):
            # Stage A.3: Special-purpose networks (RFC 6598 Shared, RFC 2544 Benchmarking,
            # RFC 1112 Reserved, RFC 1122 / RFC 6890 Unspecified) evaluated BEFORE is_private.
            # Python 3.13 reports is_private=True for benchmarking and reserved ranges;
            # this check guarantees they are correctly classified as RESERVED rather than PRIVATE.
            classification = HostClassification.RESERVED
        elif (
            (ip_obj.version == 4 and any(ip_obj in net for net in RFC_1918_NETWORKS))
            or (ip_obj.version == 6 and any(ip_obj in net for net in RFC_4193_NETWORKS))
            or ip_obj.is_private
        ):
            # Genuine private networks: RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
            # and RFC 4193 IPv6 ULA (fc00::/7).
            classification = HostClassification.PRIVATE
        elif ip_obj.is_global:
            classification = HostClassification.PUBLIC
        else:
            # Stage A.3: Safe catch-all — non-global addresses must never fall through to PUBLIC.
            classification = HostClassification.RESERVED

        return True, version, classification
    except ValueError:
        return False, None, HostClassification.UNKNOWN


def extract_host_components(host_str: str) -> Tuple[int, int, int]:
    """
    Computes dot count, hyphen count, and estimated subdomain count in hostname.
    """
    dots = host_str.count(".")
    hyphens = host_str.count("-")
    
    # Estimate subdomains (dot-separated labels excluding TLD and SLD)
    parts = host_str.split(".")
    # If standard domain with at least 3 labels (e.g. sub.example.com -> 1 subdomain)
    subdomains = max(0, len(parts) - 2) if len(parts) >= 2 else 0

    return dots, hyphens, subdomains


def check_punycode_and_unicode(host_str: str) -> Tuple[bool, bool]:
    """
    Detects Punycode (xn--) labels and non-ASCII Unicode characters in host.
    """
    is_punycode = False
    has_unicode = False

    labels = host_str.split(".")
    for label in labels:
        if label.lower().startswith("xn--"):
            is_punycode = True
            break

    # Check for non-ASCII characters
    try:
        host_str.encode("ascii")
    except UnicodeEncodeError:
        has_unicode = True

    return is_punycode, has_unicode


def calculate_heuristic_score(observations: List[URLObservation]) -> Tuple[int, HeuristicRiskCategory]:
    """
    Computes an explainable, weighted heuristic risk score (0-100) and risk category.
    The category directly matches or exceeds the highest individual observation severity.
    This is an indicator score based on heuristic severity, NOT a calibrated probability.
    """
    if not observations:
        return 0, HeuristicRiskCategory.INFO

    severities = [obs.severity for obs in observations]

    if ObservationSeverity.HIGH in severities:
        category = HeuristicRiskCategory.HIGH
        base_score = 65
    elif ObservationSeverity.MEDIUM in severities:
        category = HeuristicRiskCategory.MEDIUM
        base_score = 35
    elif ObservationSeverity.LOW in severities:
        category = HeuristicRiskCategory.LOW
        base_score = 15
    else:
        category = HeuristicRiskCategory.INFO
        base_score = 0

    # Accumulate minor additional points for multiple findings
    additional = 0
    for sev in severities:
        if sev == ObservationSeverity.HIGH:
            additional += 10
        elif sev == ObservationSeverity.MEDIUM:
            additional += 5
        elif sev == ObservationSeverity.LOW:
            additional += 2

    score = min(100, base_score + additional)
    return score, category


def analyze_url(
    url: str,
    url_index: int = 0,
    source: Optional[str] = None,
    anchor_text: Optional[str] = None,
    sender_domain: Optional[str] = None,
) -> URLAnalysisResult:
    """
    Performs comprehensive, deterministic, local analysis on a single URL string.
    Zero network access: does not resolve DNS, follow redirects, or query external APIs.
    """
    trimmed_url = url.strip()
    observations: List[URLObservation] = []

    # 1. Basic empty or whitespace check
    if not trimmed_url:
        features = URLFeatures(url_length=0)
        observations.append(
            URLObservation(
                rule_id="RULE_EMPTY_URL",
                rule_name="Empty URL String",
                severity=ObservationSeverity.HIGH,
                description="The provided URL string is empty or contains only whitespace.",
            )
        )
        return URLAnalysisResult(
            url_index=url_index,
            original_url=url,
            source=source,
            normalized_url=None,
            parse_status=ParseStatus.MALFORMED,
            normalized_hostname=None,
            features=features,
            observations=observations,
            heuristic_risk_category=HeuristicRiskCategory.HIGH,
            heuristic_risk_score=50,
            risk_summary="URL string is empty or unparseable.",
        )

    # 2. Parse using urllib.parse.urlsplit
    try:
        parsed = urlsplit(trimmed_url)
    except Exception as exc:
        features = URLFeatures(url_length=len(trimmed_url))
        observations.append(
            URLObservation(
                rule_id="RULE_PARSE_EXCEPTION",
                rule_name="Unparseable URL Format",
                severity=ObservationSeverity.HIGH,
                description=f"Standard URL parser failed to parse the URL string: {str(exc)}",
            )
        )
        return URLAnalysisResult(
            url_index=url_index,
            original_url=url,
            source=source,
            normalized_url=None,
            parse_status=ParseStatus.MALFORMED,
            normalized_hostname=None,
            features=features,
            observations=observations,
            heuristic_risk_category=HeuristicRiskCategory.HIGH,
            heuristic_risk_score=70,
            risk_summary="Malformed URL could not be parsed by standard RFC 3986 parser.",
        )

    raw_scheme = parsed.scheme.lower() if parsed.scheme else None
    netloc = parsed.netloc
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    # 3. Scheme Validation
    is_http = raw_scheme == "http"
    is_https = raw_scheme == "https"
    is_unusual_scheme = False
    parse_status = ParseStatus.PARSED

    if not raw_scheme:
        parse_status = ParseStatus.MISSING_SCHEME
        observations.append(
            URLObservation(
                rule_id="RULE_MISSING_SCHEME",
                rule_name="Missing Protocol Scheme",
                severity=ObservationSeverity.LOW,
                description="The URL lacks an explicit protocol scheme (e.g., http:// or https://).",
            )
        )
    elif is_https:
        observations.append(
            URLObservation(
                rule_id="RULE_HTTPS_STANDARD",
                rule_name="Standard HTTPS Protocol",
                severity=ObservationSeverity.INFO,
                description="The URL uses encrypted HTTPS protocol.",
            )
        )
    elif is_http:
        observations.append(
            URLObservation(
                rule_id="RULE_HTTP_UNENCRYPTED",
                rule_name="Unencrypted HTTP Protocol",
                severity=ObservationSeverity.LOW,
                description="The URL uses unencrypted HTTP protocol; communications are transmitted in cleartext.",
            )
        )
    else:
        is_unusual_scheme = True
        parse_status = ParseStatus.UNSUPPORTED_SCHEME
        severity = ObservationSeverity.HIGH if raw_scheme in {"javascript", "data", "vbscript"} else ObservationSeverity.MEDIUM
        observations.append(
            URLObservation(
                rule_id="RULE_UNUSUAL_SCHEME",
                rule_name="Unusual Protocol Scheme",
                severity=severity,
                description=f"The URL utilizes an uncommon or script-capable protocol scheme: '{raw_scheme}'.",
            )
        )

    # 4. Authority, User-Info, Host and Port Extraction
    has_userinfo = False
    raw_host = None
    explicit_port = None
    is_non_default_port = False

    if netloc:
        # Check for userinfo (@ in authority)
        if "@" in netloc:
            has_userinfo = True
            observations.append(
                URLObservation(
                    rule_id="RULE_USERINFO_AUTH",
                    rule_name="User-Info Authority Deception",
                    severity=ObservationSeverity.HIGH,
                    description="The URL contains user-info (@) in the authority component. In web browsers, text preceding '@' is disregarded and navigation proceeds to the destination after '@', a technique frequently used to mask malicious domains.",
                )
            )
            # Safe extraction of host without userinfo
            auth_target = netloc.split("@")[-1]
        else:
            auth_target = netloc

        # Parse host and port safely
        try:
            # Handle bracketed IPv6 with port: [2001:db8::1]:8080
            if auth_target.startswith("["):
                closing_bracket = auth_target.find("]")
                if closing_bracket != -1:
                    raw_host = auth_target[: closing_bracket + 1]
                    remainder = auth_target[closing_bracket + 1 :]
                    if remainder.startswith(":") and remainder[1:].isdigit():
                        explicit_port = int(remainder[1:])
                else:
                    raw_host = auth_target
            elif ":" in auth_target:
                host_part, port_part = auth_target.rsplit(":", 1)
                if port_part.isdigit():
                    raw_host = host_part
                    explicit_port = int(port_part)
                else:
                    raw_host = auth_target
            else:
                raw_host = auth_target
        except Exception:
            raw_host = auth_target

    # Validate extracted host
    if not raw_host and parse_status == ParseStatus.PARSED:
        parse_status = ParseStatus.MALFORMED
        observations.append(
            URLObservation(
                rule_id="RULE_MISSING_HOSTNAME",
                rule_name="Missing Hostname in Authority",
                severity=ObservationSeverity.HIGH,
                description="The URL has a standard scheme but lacks a parseable destination hostname.",
            )
        )

    # 5. Host Normalization & IP-Literal Checks
    normalized_host = None
    has_trailing_dot = False
    host_type = HostType.DOMAIN
    is_ip_literal = False
    ip_version = None
    host_classification = HostClassification.UNKNOWN

    if raw_host:
        temp_host = raw_host.lower().strip()
        # Check trailing dot (e.g. example.com.)
        if temp_host.endswith(".") and not temp_host.endswith(".."):
            has_trailing_dot = True
            temp_host = temp_host[:-1]
            observations.append(
                URLObservation(
                    rule_id="RULE_TRAILING_DOT",
                    rule_name="Trailing Root Dot in Hostname",
                    severity=ObservationSeverity.INFO,
                    description="The hostname specifies an explicit DNS root trailing dot (FQDN representation).",
                )
            )

        normalized_host = temp_host

        # Localhost check
        if normalized_host == "localhost":
            host_type = HostType.LOCALHOST
            host_classification = HostClassification.LOOPBACK
            observations.append(
                URLObservation(
                    rule_id="RULE_LOCALHOST_HOST",
                    rule_name="Localhost Hostname",
                    severity=ObservationSeverity.MEDIUM,
                    description="The URL specifies 'localhost', pointing to the local host interface rather than an internet domain.",
                )
            )
        else:
            # IP literal check
            is_ip, ip_ver, ip_class = is_valid_ipv4_or_ipv6(normalized_host)
            if is_ip:
                is_ip_literal = True
                ip_version = ip_ver
                host_classification = ip_class
                host_type = HostType.IPV4 if ip_ver == 4 else HostType.IPV6

                if ip_class == HostClassification.PUBLIC:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_PUBLIC_IP_HOST",
                            rule_name="Public IP-Literal Hostname",
                            severity=ObservationSeverity.MEDIUM,
                            description=f"The URL hostname is a raw public IPv{ip_ver} literal rather than a registered domain name. Phishing campaigns often deploy raw IPs to evade domain reputation tracking.",
                        )
                    )
                elif ip_class == HostClassification.PRIVATE:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_PRIVATE_IP_HOST",
                            rule_name="Private IP-Literal Hostname",
                            severity=ObservationSeverity.LOW,
                            description=f"The URL specifies a private/internal IPv{ip_ver} address ({normalized_host}). Private IP addresses belong to local network infrastructure and do not automatically indicate malicious destinations.",
                        )
                    )
                elif ip_class == HostClassification.LOOPBACK:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_LOOPBACK_IP_HOST",
                            rule_name="Loopback IP-Literal Hostname",
                            severity=ObservationSeverity.LOW,
                            description=f"The URL targets a loopback IP address (IPv{ip_ver}, {normalized_host}) referring to the local host interface.",
                        )
                    )
                elif ip_class == HostClassification.LINK_LOCAL:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_LINK_LOCAL_IP_HOST",
                            rule_name="Link-Local IP-Literal Hostname",
                            severity=ObservationSeverity.LOW,
                            description=f"The URL specifies a link-local IPv{ip_ver} address ({normalized_host}) valid only for local network segment communication.",
                        )
                    )
                elif ip_class == HostClassification.DOCUMENTATION:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_DOCUMENTATION_IP_HOST",
                            rule_name="Documentation IP-Literal Hostname (RFC 5737 / RFC 3849)",
                            severity=ObservationSeverity.INFO,
                            description=f"The URL specifies a documentation IP address (IPv{ip_ver}, {normalized_host}) reserved by RFC 5737 (TEST-NET) or RFC 3849. Documentation IPs do not represent real malicious destinations.",
                        )
                    )
                elif ip_class == HostClassification.RESERVED:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_RESERVED_IP_HOST",
                            rule_name="Reserved / Special-Purpose IP Hostname",
                            severity=ObservationSeverity.LOW,
                            description=f"The URL specifies a reserved or special-purpose IPv{ip_ver} address ({normalized_host}).",
                        )
                    )

    # 6. Port Analysis
    if explicit_port is not None and raw_scheme is not None:
        standard_port = DEFAULT_PORTS.get(raw_scheme)
        if standard_port and explicit_port != standard_port:
            is_non_default_port = True
            observations.append(
                URLObservation(
                    rule_id="RULE_NON_DEFAULT_PORT",
                    rule_name="Explicit Non-Default Port",
                    severity=ObservationSeverity.MEDIUM,
                    description=f"The URL specifies explicit non-standard port {explicit_port} (standard for '{raw_scheme}' is {standard_port}). Unconventional ports are frequently used to host disposable attack infrastructure.",
                )
            )

    # 7. Subdomains, Dots, Hyphens, Punycode, Unicode
    dots_in_host, hyphens_in_host, subdomain_count = 0, 0, 0
    is_punycode, has_unicode = False, False

    if normalized_host and host_type == HostType.DOMAIN:
        dots_in_host, hyphens_in_host, subdomain_count = extract_host_components(normalized_host)
        is_punycode, has_unicode = check_punycode_and_unicode(normalized_host)

        if is_punycode:
            observations.append(
                URLObservation(
                    rule_id="RULE_PUNYCODE_HOST",
                    rule_name="Punycode / IDN Hostname",
                    severity=ObservationSeverity.MEDIUM,
                    description="The hostname contains Punycode ('xn--') encoded labels. Punycode allows internationalized domain names but is often abused in homograph spoofing attacks to imitate reputable brands.",
                )
            )
        elif has_unicode:
            observations.append(
                URLObservation(
                    rule_id="RULE_UNICODE_HOST",
                    rule_name="Non-ASCII Unicode in Hostname",
                    severity=ObservationSeverity.MEDIUM,
                    description="The hostname contains non-ASCII Unicode characters, which can indicate internationalized domain ambiguity or homoglyph visual spoofing.",
                )
            )

        if subdomain_count >= 3:
            observations.append(
                URLObservation(
                    rule_id="RULE_DEEP_SUBDOMAINS",
                    rule_name="Deep Subdomain Hierarchy",
                    severity=ObservationSeverity.LOW if subdomain_count == 3 else ObservationSeverity.MEDIUM,
                    description=f"The hostname contains an unusually deep subdomain structure ({subdomain_count} subdomains), often used in sub-delegation services or bulletproof hosting to emulate legitimate brands.",
                )
            )

        if hyphens_in_host >= 2:
            observations.append(
                URLObservation(
                    rule_id="RULE_HYPHENATED_HOST",
                    rule_name="Multiple Hyphens in Hostname",
                    severity=ObservationSeverity.LOW,
                    description=f"The hostname contains {hyphens_in_host} hyphens, a pattern common in typosquatted and lookalike registration domains.",
                )
            )

        if len(normalized_host) > 40:
            observations.append(
                URLObservation(
                    rule_id="RULE_LONG_HOSTNAME",
                    rule_name="Unusually Long Hostname",
                    severity=ObservationSeverity.LOW,
                    description=f"The hostname is unusually long ({len(normalized_host)} characters).",
                )
            )

        # Lookalike / Impersonation Brand Domain Check
        norm_host_lower = normalized_host.lower()
        reg_host_parts = norm_host_lower.split(".")
        reg_host = ".".join(reg_host_parts[-2:]) if len(reg_host_parts) >= 2 else norm_host_lower

        # Leetspeak translation for brand homoglyph/typosquat matching (e.g. paypa1 -> paypal)
        leetspeak_host = (
            norm_host_lower
            .replace("1", "l")
            .replace("0", "o")
            .replace("5", "s")
            .replace("vv", "w")
            .replace("@", "a")
        )

        for brand_key, official_dom in TARGETED_BRAND_KEYWORDS.items():
            if brand_key in norm_host_lower or brand_key in leetspeak_host:
                official_reg = ".".join(official_dom.split(".")[-2:])
                if reg_host != official_reg and not norm_host_lower.endswith("." + official_dom):
                    observations.append(
                        URLObservation(
                            rule_id="RULE_LOOKALIKE_IMPERSONATION_DOMAIN",
                            rule_name="Lookalike / Brand Impersonation Domain",
                            severity=ObservationSeverity.HIGH,
                            description=f"Destination domain '{normalized_host}' contains targeted brand keyword '{brand_key}' but does not belong to the official brand domain ('{official_dom}').",
                        )
                    )
                    break

        # Suspicious Security / 2FA Impersonation Keyword in Domain
        has_sec_keyword = any(kw in norm_host_lower for kw in SECURITY_AUTH_KEYWORDS)
        has_phish_tld = any(norm_host_lower.endswith(tld) for tld in SUSPICIOUS_PHISHING_TLDS)
        if has_sec_keyword and (has_phish_tld or norm_host_lower not in WELL_KNOWN_IDP_DOMAINS):
            observations.append(
                URLObservation(
                    rule_id="RULE_SUSPICIOUS_SECURITY_KEYWORD_DOMAIN",
                    rule_name="Suspicious Security Impersonation Domain",
                    severity=ObservationSeverity.HIGH,
                    description=f"Destination domain '{normalized_host}' contains high-risk security/2FA authentication keywords on an unaligned third-party domain, characteristic of credential harvesting infrastructure.",
                )
            )

        # Deceptive Displayed Link Check (Anchor text vs Href destination)
        if anchor_text:
            anchor_clean = anchor_text.strip()
            if has_mixed_script_homoglyphs(anchor_clean):
                homo_details = detect_mixed_script_homoglyphs(anchor_clean)
                first_sub = homo_details[0]["substituted_chars"] if homo_details else "Cyrillic/Greek lookalikes"
                observations.append(
                    URLObservation(
                        rule_id="RULE_HOMOGLYPH_ANCHOR_TEXT",
                        rule_name="Homoglyph Obfuscation in Anchor Text",
                        severity=ObservationSeverity.HIGH,
                        description=f"Hyperlink anchor text '{anchor_clean}' contains mixed-script homoglyphs ({first_sub}) designed to disguise link intent.",
                    )
                )
            anchor_match = re.search(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", anchor_clean)
            if anchor_match:
                anchor_host = anchor_match.group(1).lower().rstrip(".")
                anchor_reg = ".".join(anchor_host.split(".")[-2:]) if len(anchor_host.split(".")) >= 2 else anchor_host
                if anchor_reg != reg_host and not norm_host_lower.endswith("." + anchor_host) and not anchor_host.endswith("." + norm_host_lower):
                    observations.append(
                        URLObservation(
                            rule_id="RULE_DECEPTIVE_DISPLAYED_LINK",
                            rule_name="Deceptive Displayed Hyperlink",
                            severity=ObservationSeverity.HIGH,
                            description=f"Anchor text visually displays destination '{anchor_host}', but the underlying link navigates to an entirely different host ('{normalized_host}'). This visual discrepancy is a primary indicator of link spoofing.",
                        )
                    )

    # 8. Lengths, Percent-Encoding, Path & Query
    url_len = len(trimmed_url)
    dots_in_url = trimmed_url.count(".")
    hyphens_in_url = trimmed_url.count("-")
    percent_encodings = len(PERCENT_ENCODING_REGEX.findall(trimmed_url))
    has_double_encoding = bool(DOUBLE_ENCODING_REGEX.search(trimmed_url))

    # Check for non-ASCII Unicode or homoglyph characters in path or query
    path_str = path or ""
    query_str = query or ""
    if any(ord(c) > 127 for c in (path_str + query_str)):
        path_homoglyphs = detect_mixed_script_homoglyphs(path_str + query_str)
        if path_homoglyphs:
            first_sub = path_homoglyphs[0]["substituted_chars"]
            desc = f"The URL path or query contains mixed-script homoglyph substitutions ({first_sub}) mimicking legitimate identifiers."
        else:
            desc = "The URL path or query contains non-ASCII Unicode characters often used to evade URL filters."
        observations.append(
            URLObservation(
                rule_id="RULE_UNICODE_PATH_OR_QUERY",
                rule_name="Non-ASCII / Homoglyph in URL Path or Query",
                severity=ObservationSeverity.HIGH,
                description=desc,
            )
        )

    if has_double_encoding:
        double_in_path = bool(DOUBLE_ENCODING_REGEX.search(path or ""))
        double_in_query = bool(DOUBLE_ENCODING_REGEX.search(query or ""))
        if double_in_path:
            observations.append(
                URLObservation(
                    rule_id="RULE_DOUBLE_PERCENT_ENCODING",
                    rule_name="Double Percent-Encoding in URL Path",
                    severity=ObservationSeverity.MEDIUM,
                    description="The URL path contains double percent-encoding sequences (e.g., %252e), which can be used to bypass web application filters and path traversal protections.",
                )
            )
        elif double_in_query:
            observations.append(
                URLObservation(
                    rule_id="RULE_REDIRECT_QUERY_ENCODING",
                    rule_name="Nested Redirect Parameter Encoding",
                    severity=ObservationSeverity.LOW,
                    description="The URL query string contains nested encoding for an embedded redirect parameter, typical of marketing delivery routers and ESP click tracking.",
                )
            )
        else:
            observations.append(
                URLObservation(
                    rule_id="RULE_DOUBLE_PERCENT_ENCODING",
                    rule_name="Double Percent-Encoding Detected",
                    severity=ObservationSeverity.MEDIUM,
                    description="The URL contains double percent-encoding sequences.",
                )
            )
    elif percent_encodings >= 3:
        observations.append(
            URLObservation(
                rule_id="RULE_HEAVY_PERCENT_ENCODING",
                rule_name="Heavy Percent-Encoding",
                severity=ObservationSeverity.LOW,
                description=f"The URL contains {percent_encodings} percent-encoded characters, frequently employed to obfuscate target URLs or payload parameters.",
            )
        )

    path_len = len(path) if path else 0
    query_len = len(query) if query else 0
    has_query = bool(query)
    non_query_len = url_len - query_len - (1 if has_query else 0)

    # Check for recognized enterprise asset or CDN domain
    is_cdn_host = any(
        (normalized_host or "").lower().endswith("." + cdn) or (normalized_host or "").lower() == cdn
        for cdn in KNOWN_ASSET_CDN_DOMAINS
    )

    # Path length evaluation
    if path_len > 200:
        if is_cdn_host:
            observations.append(
                URLObservation(
                    rule_id="RULE_LONG_PATH",
                    rule_name="Long CDN Asset Path",
                    severity=ObservationSeverity.INFO,
                    description=f"The URL path is long ({path_len} characters) on a recognized enterprise asset or CDN domain.",
                )
            )
        else:
            observations.append(
                URLObservation(
                    rule_id="RULE_EXCESSIVE_PATH_LENGTH",
                    rule_name="Excessive URL Path Length",
                    severity=ObservationSeverity.MEDIUM,
                    description=f"The URL path is exceptionally long ({path_len} characters), a pattern often used in multi-stage phishing payload routing or deep directory obfuscation.",
                )
            )
    elif path_len > 100:
        observations.append(
            URLObservation(
                rule_id="RULE_LONG_PATH",
                rule_name="Long URL Path",
                severity=ObservationSeverity.LOW,
                description=f"The URL path component is relatively long ({path_len} characters).",
            )
        )

    # Non-query structural length evaluation
    if non_query_len > 250:
        observations.append(
            URLObservation(
                rule_id="RULE_EXCESSIVE_URL_LENGTH",
                rule_name="Excessive Non-Query URL Length",
                severity=ObservationSeverity.LOW,
                description=f"The non-query structural portion of the URL is exceptionally long ({non_query_len} characters), indicating deep path obfuscation or multi-label spoofing.",
            )
        )
    elif non_query_len > 150:
        observations.append(
            URLObservation(
                rule_id="RULE_LONG_URL",
                rule_name="Long URL Structure",
                severity=ObservationSeverity.LOW,
                description=f"The non-query structural portion of the URL is relatively long ({non_query_len} characters).",
            )
        )

    # Query string length evaluation (long query strings alone must NOT be MEDIUM or HIGH)
    if query_len > 350:
        observations.append(
            URLObservation(
                rule_id="RULE_LONG_QUERY_STRING",
                rule_name="Extended Query String",
                severity=ObservationSeverity.LOW,
                description=f"The URL query string contains extensive tracking or state parameters ({query_len} characters).",
            )
        )
    elif query_len > 150:
        observations.append(
            URLObservation(
                rule_id="RULE_LONG_QUERY_STRING",
                rule_name="Long Query String",
                severity=ObservationSeverity.INFO,
                description=f"The URL query string contains extended tracking or session parameters ({query_len} characters).",
            )
        )

    # Path features
    has_non_root_path = bool(path and path != "/")
    if has_non_root_path:
        observations.append(
            URLObservation(
                rule_id="RULE_NON_ROOT_PATH",
                rule_name="Non-Root Path Present",
                severity=ObservationSeverity.INFO,
                description="The URL specifies a path beyond the root directory.",
            )
        )

    # Query features
    query_param_count = 0
    if has_query:
        try:
            parsed_query = parse_qs(query, keep_blank_values=True)
            query_param_count = len(parsed_query)

            # Check for embedded redirect destination URLs or open redirect parameters
            has_nested_redirect = False
            for key, values in parsed_query.items():
                for val in values:
                    unquoted_val = unquote(val).strip()
                    # Check if parameter value contains an explicit nested URL
                    nested_match = re.search(r"https?://[^\s/?#]+", unquoted_val, re.IGNORECASE)
                    if not nested_match and unquoted_val.startswith("//"):
                        nested_match = re.search(r"//[^\s/?#]+", unquoted_val)

                    if nested_match:
                        nested_target = nested_match.group(0)
                        has_nested_redirect = True

                        target_without_scheme = nested_target.split("://")[-1].lstrip("/")
                        target_authority = target_without_scheme.split("/")[0].split("?")[0].split("#")[0]
                        has_target_userinfo = "@" in target_authority
                        clean_target_host = target_authority.split("@")[-1].split(":")[0].strip("[]").lower()

                        outer_host = (normalized_host or "").lower()
                        is_same_domain = bool(
                            outer_host and (
                                clean_target_host == outer_host
                                or clean_target_host.endswith("." + outer_host)
                                or outer_host.endswith("." + clean_target_host)
                            )
                        )

                        is_nested_ip, nested_ip_ver, nested_class = is_valid_ipv4_or_ipv6(clean_target_host)

                        if has_target_userinfo:
                            observations.append(
                                URLObservation(
                                    rule_id="RULE_NESTED_REDIRECT_CREDENTIAL_TRICK",
                                    rule_name="Suspicious Nested Redirect with Userinfo (@)",
                                    severity=ObservationSeverity.HIGH,
                                    description=f"Query parameter '{key}' contains a nested redirect target with userinfo syntax (@ in authority: '{target_authority}'). This structural indicator is commonly used to deceive recipients about the true destination.",
                                )
                            )
                        elif is_nested_ip:
                            if nested_class == HostClassification.DOCUMENTATION:
                                observations.append(
                                    URLObservation(
                                        rule_id="RULE_NESTED_REDIRECT_DOCUMENTATION",
                                        rule_name="Nested Redirect to Documentation IP (RFC 5737 / RFC 3849)",
                                        severity=ObservationSeverity.INFO,
                                        description=f"Query parameter '{key}' contains an embedded redirect target pointing to documentation IP ({clean_target_host}). Documentation IPs do not represent real malicious destinations.",
                                    )
                                )
                            elif nested_class in (HostClassification.PRIVATE, HostClassification.LOOPBACK, HostClassification.LINK_LOCAL):
                                observations.append(
                                    URLObservation(
                                        rule_id="RULE_NESTED_REDIRECT_INTERNAL_IP",
                                        rule_name="Nested Redirect to Internal/Private IP",
                                        severity=ObservationSeverity.LOW,
                                        description=f"Query parameter '{key}' contains an embedded redirect target pointing to an internal/private IP ({clean_target_host}).",
                                    )
                                )
                            elif nested_class == HostClassification.PUBLIC:
                                observations.append(
                                    URLObservation(
                                        rule_id="RULE_NESTED_REDIRECT_IP_LITERAL",
                                        rule_name="Suspicious Nested Redirect to Public IP Literal",
                                        severity=ObservationSeverity.HIGH,
                                        description=f"Query parameter '{key}' contains an embedded redirect target pointing to a raw public IP literal ({clean_target_host}). Redirecting through a domain to an external IP literal is a strong evasion indicator.",
                                    )
                                )
                            else:
                                observations.append(
                                    URLObservation(
                                        rule_id="RULE_NESTED_REDIRECT_URL",
                                        rule_name="Nested Redirect URL to Reserved IP",
                                        severity=ObservationSeverity.LOW,
                                        description=f"Query parameter '{key}' contains an embedded redirect target pointing to a reserved IP literal ({clean_target_host}).",
                                    )
                                )
                        elif is_same_domain:
                            observations.append(
                                URLObservation(
                                    rule_id="RULE_NESTED_REDIRECT_INTERNAL",
                                    rule_name="Internal Same-Domain Redirect Target",
                                    severity=ObservationSeverity.INFO,
                                    description=f"Query parameter '{key}' contains an internal or same-domain redirect target ('{clean_target_host}'). Same-domain redirects are standard application navigation patterns.",
                                )
                            )
                        else:
                            observations.append(
                                URLObservation(
                                    rule_id="RULE_NESTED_REDIRECT_URL",
                                    rule_name="External Redirect Target URL",
                                    severity=ObservationSeverity.LOW,
                                    description=f"Query parameter '{key}' contains an external redirect destination ('{clean_target_host}'). External redirection is widely used in legitimate tracking, newsletters, and federated SSO; it is recorded as a structural indicator but is not inherently malicious.",
                                )
                            )
                        break
                if has_nested_redirect:
                    break

            # Check if parameter name indicates redirect
            for key in parsed_query.keys():
                if key.lower() in REDIRECT_PARAM_NAMES:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_OPEN_REDIRECT_PARAM",
                            rule_name="Potential Redirect Parameter",
                            severity=ObservationSeverity.LOW,
                            description=f"The query string contains a parameter ('{key}') commonly associated with URL redirection mechanisms.",
                        )
                    )
                    break

            # Check for embedded email address in query string
            unquoted_query = unquote(query)
            if EMAIL_PATTERN_REGEX.search(unquoted_query):
                norm_host_lower = (normalized_host or "").lower()
                reg_norm = ".".join(norm_host_lower.split(".")[-2:]) if len(norm_host_lower.split(".")) >= 2 else norm_host_lower
                sender_norm = ".".join((sender_domain or "").lower().split(".")[-2:]) if len((sender_domain or "").split(".")) >= 2 else (sender_domain or "").lower()

                is_sender_aligned = bool(
                    sender_norm and (
                        reg_norm == sender_norm
                        or (sender_norm == "openai.com" and reg_norm in ("openai.com", "chatgpt.com"))
                        or (sender_norm == "linkedin.com" and reg_norm in ("linkedin.com", "licdn.com"))
                        or (sender_norm == "google.com" and reg_norm in ("google.com", "youtube.com", "gmail.com"))
                    )
                )
                is_known_idp = any(norm_host_lower == idp or norm_host_lower.endswith("." + idp) for idp in WELL_KNOWN_IDP_DOMAINS)

                has_login_hint_param = any(
                    k.lower() in ("login_hint", "email", "u", "user", "username", "account")
                    for k in parsed_query.keys()
                )

                if (is_sender_aligned or is_known_idp) and has_login_hint_param:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_OIDC_LOGIN_HINT_PARAMETER",
                            rule_name="Standard OIDC / Identity Hint in Query",
                            severity=ObservationSeverity.INFO,
                            description=f"The query string specifies an identity hint parameter on a recognized or sender-aligned authentication domain ('{normalized_host}'). Standard federated authentication protocol behavior.",
                        )
                    )
                else:
                    observations.append(
                        URLObservation(
                            rule_id="RULE_EMAIL_IN_QUERY",
                            rule_name="Email Address Present in Query Parameters",
                            severity=ObservationSeverity.MEDIUM,
                            description="The query string contains an embedded email address on an unaligned or external destination host. Credential harvesting campaigns commonly pre-populate target recipient addresses via query parameters.",
                        )
                    )
        except Exception:
            pass

        observations.append(
            URLObservation(
                rule_id="RULE_QUERY_PARAMETERS",
                rule_name="Query Parameters Present",
                severity=ObservationSeverity.INFO,
                description=f"The URL contains {query_param_count} query parameter(s).",
            )
        )

    # Fragment feature
    has_fragment = bool(fragment)
    if has_fragment:
        observations.append(
            URLObservation(
                rule_id="RULE_FRAGMENT_PRESENT",
                rule_name="Fragment Identifier Present",
                severity=ObservationSeverity.INFO,
                description="The URL contains a client-side fragment identifier (#).",
            )
        )

    # Assemble features model
    features = URLFeatures(
        scheme=raw_scheme,
        is_https=is_https,
        is_http=is_http,
        is_unusual_scheme=is_unusual_scheme,
        raw_host=raw_host,
        normalized_host=normalized_host,
        host_type=host_type,
        is_ip_literal=is_ip_literal,
        ip_version=ip_version,
        host_classification=host_classification,
        has_trailing_dot=has_trailing_dot,
        url_length=url_len,
        host_length=len(normalized_host) if normalized_host else 0,
        subdomain_count=subdomain_count,
        dots_in_host=dots_in_host,
        hyphens_in_host=hyphens_in_host,
        dots_in_url=dots_in_url,
        hyphens_in_url=hyphens_in_url,
        has_userinfo=has_userinfo,
        port=explicit_port,
        is_non_default_port=is_non_default_port,
        percent_encoding_count=percent_encodings,
        is_punycode=is_punycode,
        has_unicode=has_unicode,
        has_path=has_non_root_path,
        path_length=path_len,
        has_query=has_query,
        query_length=query_len,
        query_param_count=query_param_count,
        has_fragment=has_fragment,
    )

    # Construct safe normalized URL (excluding userinfo credentials, normalizing scheme and host)
    normalized_url = None
    if parse_status == ParseStatus.PARSED and raw_scheme and normalized_host:
        port_str = f":{explicit_port}" if (explicit_port and is_non_default_port) else ""
        norm_path = path if path else "/"
        norm_query = f"?{query}" if query else ""
        norm_frag = f"#{fragment}" if fragment else ""
        normalized_url = f"{raw_scheme}://{normalized_host}{port_str}{norm_path}{norm_query}{norm_frag}"

    # Calculate explainable heuristic score
    risk_score, risk_category = calculate_heuristic_score(observations)

    # Generate transparent risk summary
    if risk_category == HeuristicRiskCategory.HIGH:
        risk_summary = "High heuristic risk: Contains severe structural indicators (e.g. authority userinfo deception, internal private IP, or dangerous scheme)."
    elif risk_category == HeuristicRiskCategory.MEDIUM:
        risk_summary = "Medium heuristic risk: Contains notable evasion or structural indicators (e.g. raw IP literal, non-standard port, Punycode/IDN, or pre-filled email in query)."
    elif risk_category == HeuristicRiskCategory.LOW:
        risk_summary = "Low heuristic risk: Displays minor structural variations (e.g. unencrypted HTTP, long URL length, redirect parameters, or multiple subdomains)."
    else:
        risk_summary = "Informational / Standard: Conforms to expected web URL structures with no elevated heuristic risk indicators."

    return URLAnalysisResult(
        url_index=url_index,
        original_url=url,
        source=source,
        normalized_url=normalized_url,
        parse_status=parse_status,
        normalized_hostname=normalized_host,
        features=features,
        observations=observations,
        heuristic_risk_category=risk_category,
        heuristic_risk_score=risk_score,
        risk_summary=risk_summary,
    )


def analyze_urls(urls: List[str]) -> URLBatchAnalysisResult:
    """
    Analyzes an ordered list of URL strings, deduplicates them by normalized form,
    and aggregates overall risk tier and count statistics.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    if not urls:
        return URLBatchAnalysisResult(
            total_urls=0,
            unique_urls=0,
            risk_breakdown={"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0},
            highest_risk_category=HeuristicRiskCategory.INFO,
            url_results=[],
            analyzed_at=timestamp,
        )

    results: List[URLAnalysisResult] = []
    seen_normalized: Set[str] = set()
    risk_counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}
    severity_rank = {
        HeuristicRiskCategory.INFO: 0,
        HeuristicRiskCategory.LOW: 1,
        HeuristicRiskCategory.MEDIUM: 2,
        HeuristicRiskCategory.HIGH: 3,
    }
    highest_rank = 0
    highest_category = HeuristicRiskCategory.INFO

    for idx, raw_url in enumerate(urls):
        res = analyze_url(raw_url, url_index=idx)
        results.append(res)

        cat_str = res.heuristic_risk_category.value
        risk_counts[cat_str] = risk_counts.get(cat_str, 0) + 1

        rank = severity_rank.get(res.heuristic_risk_category, 0)
        if rank > highest_rank:
            highest_rank = rank
            highest_category = res.heuristic_risk_category

        norm_key = res.normalized_url or res.original_url
        seen_normalized.add(norm_key)

    return URLBatchAnalysisResult(
        total_urls=len(urls),
        unique_urls=len(seen_normalized),
        risk_breakdown=risk_counts,
        highest_risk_category=highest_category,
        url_results=results,
        analyzed_at=timestamp,
    )


def analyze_email_extracted_urls(
    email_urls: List[ExtractedURL],
    sender_domain: Optional[str] = None,
) -> URLBatchAnalysisResult:
    """
    Analyzes ExtractedURL models from the Phase 1 email parser,
    preserving each URL's origin source ('plain_text', 'html_href', or 'both')
    and visual anchor text for link spoofing detection.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    if not email_urls:
        return URLBatchAnalysisResult(
            total_urls=0,
            unique_urls=0,
            risk_breakdown={"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0},
            highest_risk_category=HeuristicRiskCategory.INFO,
            url_results=[],
            analyzed_at=timestamp,
        )

    results: List[URLAnalysisResult] = []
    seen_normalized: Set[str] = set()
    risk_counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}
    severity_rank = {
        HeuristicRiskCategory.INFO: 0,
        HeuristicRiskCategory.LOW: 1,
        HeuristicRiskCategory.MEDIUM: 2,
        HeuristicRiskCategory.HIGH: 3,
    }
    highest_rank = 0
    highest_category = HeuristicRiskCategory.INFO

    for idx, ext in enumerate(email_urls):
        res = analyze_url(
            ext.url,
            url_index=idx,
            source=ext.source,
            anchor_text=getattr(ext, "anchor_text", None),
            sender_domain=sender_domain,
        )
        results.append(res)

        cat_str = res.heuristic_risk_category.value
        risk_counts[cat_str] = risk_counts.get(cat_str, 0) + 1

        rank = severity_rank.get(res.heuristic_risk_category, 0)
        if rank > highest_rank:
            highest_rank = rank
            highest_category = res.heuristic_risk_category

        norm_key = res.normalized_url or res.original_url
        seen_normalized.add(norm_key)

    return URLBatchAnalysisResult(
        total_urls=len(email_urls),
        unique_urls=len(seen_normalized),
        risk_breakdown=risk_counts,
        highest_risk_category=highest_category,
        url_results=results,
        analyzed_at=timestamp,
    )
