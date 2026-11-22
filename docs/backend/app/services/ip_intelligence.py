"""
Standalone IP Intelligence and Forensic Classification Engine for PhishIntel (Phase 6A).
Analyzes candidate IP addresses extracted from RFC 5322 Received headers.

Offline, deterministic, explainable.
NEVER performs DNS queries or outbound HTTP requests.
Supports optional offline local GeoLite2 .mmdb databases without network calls.
"""

from enum import Enum
import ipaddress
import os
from pathlib import Path
import re
from typing import Any, Dict, List, NamedTuple, Optional, Tuple, Union

from app.schemas.email import IPCandidate
from app.schemas.ip_intelligence import (
    CandidateIPIntelligence,
    GeolocationStatus,
    IPClassification,
    IPGeolocationData,
    IPIntelligenceResult,
)

# Documentation ranges (RFC 5737 for IPv4 TEST-NET, RFC 3849 for IPv6)
DOCUMENTATION_NETWORKS = [
    ipaddress.IPv4Network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv6Network("2001:db8::/32"),   # IPv6 Documentation
]

# RFC 1918 (IPv4 Private) & RFC 4193 (IPv6 Unique Local / ULA)
RFC_1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

RFC_4193_NETWORKS = [
    ipaddress.IPv6Network("fc00::/7"),
]

# Benchmarking (RFC 2544, RFC 5180)
BENCHMARKING_NETWORKS = [
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv6Network("2001:2::/48"),
]

# Carrier-Grade NAT (RFC 6598 Shared Address Space)
CGNAT_NETWORKS = [
    ipaddress.IPv4Network("100.64.0.0/10"),
]

# IETF Protocol Assignments (RFC 6890, RFC 5736)
IETF_PROTOCOL_NETWORKS = [
    ipaddress.IPv4Network("192.0.0.0/24"),
]

# --- Provider Catalogue Definitions & Offline Metadata ---

class ProviderCategory(str, Enum):
    CONFIRMED_MAIL_RANGE = "Confirmed Email-Delivery Network Range"
    GENERAL_PROVIDER_RANGE = "General Provider-Owned Network Range"
    EMPIRICAL_HOSTNAME_PATTERN = "Empirical Hostname Pattern"
    UNVERIFIED_UNKNOWN = "Unverified / Unknown Entry"


class ProviderConfidence(str, Enum):
    HIGH_CONFIRMED = "High (Confirmed Mail Range)"
    LOW_GENERAL = "Low (Broad Provider Range)"
    UNVERIFIED_PATTERN = "Unverified (Hostname Pattern Only)"
    UNKNOWN = "UNKNOWN"


class ProviderNetworkEntry(NamedTuple):
    network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
    provider_name: str
    service_category: ProviderCategory
    confidence: ProviderConfidence
    source_url: str
    retrieval_date: str
    source_version: str
    short_label: str


class ProviderHostnameEntry(NamedTuple):
    pattern: re.Pattern
    provider_name: str
    service_category: ProviderCategory
    confidence: ProviderConfidence
    source_url: str
    retrieval_date: str
    source_version: str
    short_label: str


class ProviderMatchResult(NamedTuple):
    is_provider: bool
    provider_name: Optional[str] = None
    service_category: Optional[str] = None
    confidence: Optional[str] = None
    source_url: Optional[str] = None
    short_label: Optional[str] = None


# Curated static catalog of known shared email provider delivery infrastructure and broad ranges.
#
# METADATA & PROVENANCE POLICY:
# - Sources:
#     * Google Confirmed Mail: Google SPF TXT records (_spf.google.com -> _netblocks*.google.com)
#       Source URL: https://support.google.com/a/answer/60764
#     * Google Broad Cloud: Google Cloud IP range list (goog.json)
#       Source URL: https://www.gstatic.com/ipranges/goog.json (Unconfirmed mail-only provenance)
#     * SendGrid: Twilio SendGrid public IP documentation & SPF include records (sendgrid.net)
#       Source URL: https://docs.sendgrid.com/ui/account-and-settings/ip-addresses
#     * Microsoft 365 Confirmed: Microsoft Worldwide IP Endpoints published JSON feed (ID 1, Exchange)
#       Source URL: https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges
#     * Microsoft Broad Azure: Azure Cloud IP ranges (service tags)
#       Source URL: https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview
#     * Amazon SES: AWS IP Address Ranges (ip-ranges.json, service: AMAZON_SES)
#       Source URL: https://ip-ranges.amazonaws.com/ip-ranges.json
#     * Mailgun: Sinch Mailgun public sending IP documentation & SPF netblocks
#       Source URL: https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/
# - Retrieval Date: November 2026 snapshot.
# - Version: Static Snapshot v1.0 (offline).
# - Maintenance Policy: Static curated list. Operating in an offline, air-gapped forensic
#   environment; live network synchronization, dynamic SPF queries, or automated feeds are
#   strictly disabled by architectural design.
# - Authoritative Provenance: Dynamic runtime provenance is UNKNOWN. These static ranges are
#   NOT comprehensive, do NOT encompass all mail providers or CIDR allocations, and do NOT
#   guarantee complete coverage. Matching a provider CIDR or hostname pattern indicates
#   likely shared provider infrastructure, NOT proof that an IP performed or authorized delivery.
PROVIDER_GATEWAY_NETWORKS: List[ProviderNetworkEntry] = [
    # -------------------------------------------------------------------------
    # 1. Google Mail / Google Workspace: Current SPF-Confirmed Sending Subnets
    # Source: https://support.google.com/a/answer/60764
    # Published DNS TXT: _spf.google.com -> _netblocks.google.com (IPv4) & _netblocks2.google.com (IPv6)
    # Service Scope: Google Workspace & Gmail outbound delivery infrastructure
    # Snapshot Date: 2026-11-05
    # -------------------------------------------------------------------------
    ProviderNetworkEntry(
        ipaddress.IPv4Network("209.85.128.0/17"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("74.125.0.0/16"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2001:4860:4000::/36"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks2.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2404:6800:4000::/36"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks2.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2607:f8b0:4000::/36"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks2.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2800:3f0:4000::/36"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks2.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2a00:1450:4000::/36"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks2.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2c0f:fb50:4000::/36"),
        "Google Mail / Workspace",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://support.google.com/a/answer/60764",
        "2026-11-05",
        "SPF _netblocks2.google.com Snapshot v1.0",
        "Likely Google infrastructure",
    ),

    # -------------------------------------------------------------------------
    # 2. Microsoft 365 / Exchange Online: Documented Mail Delivery & Protection Ranges
    # Source: https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges
    # Published Endpoint: Microsoft 365 Worldwide IP Endpoints JSON feed (ID 9 & 10, Exchange)
    # Service Scope: Exchange Online, Exchange Online Protection (EOP), Inbound/Hybrid Mail Flow (TCP 25)
    # Snapshot Date: 2026-11-05
    # Important Note: An Exchange Online network match indicates likely shared Microsoft
    # mail-protection infrastructure, NOT proof of genuine sender authorization or actual email delivery.
    # -------------------------------------------------------------------------
    ProviderNetworkEntry(
        ipaddress.IPv4Network("40.92.0.0/15"),
        "Microsoft 365 / Exchange Online",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges",
        "2026-11-05",
        "M365 Endpoints ID 10 (Exchange Online Protection / Mail flow)",
        "Likely Microsoft 365 / Exchange infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("40.107.0.0/16"),
        "Microsoft 365 / Exchange Online",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges",
        "2026-11-05",
        "M365 Endpoints ID 10 (Exchange Online Protection Outbound)",
        "Likely Microsoft 365 / Exchange infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("52.100.0.0/14"),
        "Microsoft 365 / Exchange Online",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges",
        "2026-11-05",
        "M365 Endpoints ID 9 & 10 (Exchange Online Protection / Mail flow TCP 25)",
        "Likely Microsoft 365 / Exchange Online protection infrastructure (mail-protection connectivity; not proof of actual sender authorization)",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("104.47.0.0/17"),
        "Microsoft 365 / Exchange Online",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges",
        "2026-11-05",
        "M365 Endpoints ID 10 (Exchange Online Protection Outbound)",
        "Likely Microsoft 365 / Exchange infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2a01:111:f400::/48"),
        "Microsoft 365 / Exchange Online",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges",
        "2026-11-05",
        "M365 Endpoints ID 10 (Exchange Online IPv6 Protection / Mail flow)",
        "Likely Microsoft 365 / Exchange infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2a01:111:f403::/48"),
        "Microsoft 365 / Exchange Online",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges",
        "2026-11-05",
        "M365 Endpoints ID 10 (Exchange Online IPv6 Protection / Mail flow)",
        "Likely Microsoft 365 / Exchange infrastructure",
    ),

    # -------------------------------------------------------------------------
    # 3. SendGrid / Twilio: Documented & Published SPF Sending Netblocks
    # Source: https://docs.sendgrid.com/ui/account-and-settings/ip-addresses
    # Published SPF: include:sendgrid.net
    # Service Scope: Outbound email sending relays
    # Range Precision: Documented SPF block is 167.89.0.0/17 (NOT broadened to /16)
    # Snapshot Date: 2026-11-05
    # -------------------------------------------------------------------------
    ProviderNetworkEntry(
        ipaddress.IPv4Network("167.89.0.0/17"),
        "SendGrid",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://docs.sendgrid.com/ui/account-and-settings/ip-addresses",
        "2026-11-05",
        "SendGrid SPF sendgrid.net Snapshot v1.0",
        "Likely SendGrid infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("168.245.0.0/17"),
        "SendGrid",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://docs.sendgrid.com/ui/account-and-settings/ip-addresses",
        "2026-11-05",
        "SendGrid SPF sendgrid.net Snapshot v1.0",
        "Likely SendGrid infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("149.72.0.0/16"),
        "SendGrid",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://docs.sendgrid.com/ui/account-and-settings/ip-addresses",
        "2026-11-05",
        "SendGrid SPF sendgrid.net Snapshot v1.0",
        "Likely SendGrid infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("198.21.0.0/21"),
        "SendGrid",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://docs.sendgrid.com/ui/account-and-settings/ip-addresses",
        "2026-11-05",
        "SendGrid SPF sendgrid.net Snapshot v1.0",
        "Likely SendGrid infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("198.37.144.0/20"),
        "SendGrid",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://docs.sendgrid.com/ui/account-and-settings/ip-addresses",
        "2026-11-05",
        "SendGrid SPF sendgrid.net Snapshot v1.0",
        "Likely SendGrid infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("159.183.0.0/16"),
        "SendGrid",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://docs.sendgrid.com/ui/account-and-settings/ip-addresses",
        "2026-11-05",
        "SendGrid SPF sendgrid.net Snapshot v1.0",
        "Likely SendGrid infrastructure",
    ),

    # -------------------------------------------------------------------------
    # 4. Amazon SES: Confirmed Email-Delivery Ranges
    # Source: https://ip-ranges.amazonaws.com/ip-ranges.json
    # Service Scope: Outbound email delivery relays (AMAZON_SES)
    # Snapshot Date: 2026-11-05
    # -------------------------------------------------------------------------
    ProviderNetworkEntry(
        ipaddress.IPv4Network("54.240.0.0/18"),
        "Amazon SES",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "2026-11-05",
        "AWS ip-ranges.json (AMAZON_SES)",
        "Likely Amazon SES infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("69.169.224.0/20"),
        "Amazon SES",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "2026-11-05",
        "AWS ip-ranges.json (AMAZON_SES)",
        "Likely Amazon SES infrastructure",
    ),

    # -------------------------------------------------------------------------
    # 5. Mailgun: Confirmed Sending IP Netblocks
    # Source: https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/
    # Service Scope: Outbound email sending relays
    # Snapshot Date: 2026-11-05
    # -------------------------------------------------------------------------
    ProviderNetworkEntry(
        ipaddress.IPv4Network("159.112.240.0/20"),
        "Mailgun",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/",
        "2026-11-05",
        "Mailgun Docs Snapshot v1.0",
        "Likely Mailgun infrastructure",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("198.61.254.0/24"),
        "Mailgun",
        ProviderCategory.CONFIRMED_MAIL_RANGE,
        ProviderConfidence.HIGH_CONFIRMED,
        "https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/",
        "2026-11-05",
        "Mailgun Docs Snapshot v1.0",
        "Likely Mailgun infrastructure",
    ),

    # -------------------------------------------------------------------------
    # 6. Google: Historical SPF Netblocks & General Provider-Owned Cloud Ranges
    # Note: These are separated from current SPF-confirmed entries. Historical
    # prefixes (retired from _netblocks3) and broad cloud ranges (goog.json)
    # have unconfirmed mail-only provenance and are downgraded to Low confidence.
    # -------------------------------------------------------------------------
    ProviderNetworkEntry(
        ipaddress.IPv4Network("64.233.160.0/19"),
        "Google Mail / Workspace",
        ProviderCategory.GENERAL_PROVIDER_RANGE,
        ProviderConfidence.LOW_GENERAL,
        "https://www.gstatic.com/ipranges/goog.json",
        "2026-11-05",
        "Historical SPF / goog.json Snapshot v1.0",
        "Likely general Google infrastructure (unconfirmed mail provenance)",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("66.249.80.0/20"),
        "Google Mail / Workspace",
        ProviderCategory.GENERAL_PROVIDER_RANGE,
        ProviderConfidence.LOW_GENERAL,
        "https://www.gstatic.com/ipranges/goog.json",
        "2026-11-05",
        "Historical SPF / goog.json Snapshot v1.0",
        "Likely general Google infrastructure (unconfirmed mail provenance)",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("108.177.0.0/17"),
        "Google Mail / Workspace",
        ProviderCategory.GENERAL_PROVIDER_RANGE,
        ProviderConfidence.LOW_GENERAL,
        "https://www.gstatic.com/ipranges/goog.json",
        "2026-11-05",
        "Historical SPF / goog.json Snapshot v1.0",
        "Likely general Google infrastructure (unconfirmed mail provenance)",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("142.250.0.0/15"),
        "Google Mail / Workspace",
        ProviderCategory.GENERAL_PROVIDER_RANGE,
        ProviderConfidence.LOW_GENERAL,
        "https://www.gstatic.com/ipranges/goog.json",
        "2026-11-05",
        "goog.json Snapshot v1.0",
        "Likely general Google infrastructure (unconfirmed mail provenance)",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("172.217.0.0/16"),
        "Google Mail / Workspace",
        ProviderCategory.GENERAL_PROVIDER_RANGE,
        ProviderConfidence.LOW_GENERAL,
        "https://www.gstatic.com/ipranges/goog.json",
        "2026-11-05",
        "goog.json Snapshot v1.0",
        "Likely general Google infrastructure (unconfirmed mail provenance)",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv4Network("172.253.0.0/16"),
        "Google Mail / Workspace",
        ProviderCategory.GENERAL_PROVIDER_RANGE,
        ProviderConfidence.LOW_GENERAL,
        "https://www.gstatic.com/ipranges/goog.json",
        "2026-11-05",
        "goog.json Snapshot v1.0",
        "Likely general Google infrastructure (unconfirmed mail provenance)",
    ),
    ProviderNetworkEntry(
        ipaddress.IPv6Network("2607:f8b0::/32"),
        "Google Mail / Workspace",
        ProviderCategory.GENERAL_PROVIDER_RANGE,
        ProviderConfidence.LOW_GENERAL,
        "https://www.gstatic.com/ipranges/goog.json",
        "2026-11-05",
        "ARIN Allocation / goog.json Snapshot v1.0",
        "Likely general Google infrastructure (unconfirmed mail provenance)",
    ),
]

PROVIDER_HOSTNAME_PATTERNS: List[ProviderHostnameEntry] = [
    ProviderHostnameEntry(re.compile(r"\b(?:mail-[a-z0-9\-]+\.google\.com|mx\.google\.com)\b", re.I), "Google Mail / Workspace", ProviderCategory.EMPIRICAL_HOSTNAME_PATTERN, ProviderConfidence.UNVERIFIED_PATTERN, "UNKNOWN (Empirical header trace pattern; unverified by authoritative API)", "2026-11-05", "Pattern Snapshot v1.0", "Unverified Google hostname pattern"),
    ProviderHostnameEntry(re.compile(r"\b(?:[a-z0-9\-]+\.outbound-mail\.sendgrid\.net|sendgrid\.net)\b", re.I), "SendGrid", ProviderCategory.EMPIRICAL_HOSTNAME_PATTERN, ProviderConfidence.UNVERIFIED_PATTERN, "UNKNOWN (Empirical header trace pattern; unverified by authoritative API)", "2026-11-05", "Pattern Snapshot v1.0", "Unverified SendGrid hostname pattern"),
    ProviderHostnameEntry(re.compile(r"\b[a-z0-9\-]+\.outbound\.protection\.outlook\.com\b", re.I), "Microsoft 365 / Exchange Online", ProviderCategory.EMPIRICAL_HOSTNAME_PATTERN, ProviderConfidence.UNVERIFIED_PATTERN, "UNKNOWN (Empirical header trace pattern; unverified by authoritative API)", "2026-11-05", "Pattern Snapshot v1.0", "Unverified Microsoft Exchange hostname pattern"),
    ProviderHostnameEntry(re.compile(r"\b[a-z0-9\-]+\.amazonses\.com\b", re.I), "Amazon SES", ProviderCategory.EMPIRICAL_HOSTNAME_PATTERN, ProviderConfidence.UNVERIFIED_PATTERN, "UNKNOWN (Empirical header trace pattern; unverified by authoritative API)", "2026-11-05", "Pattern Snapshot v1.0", "Unverified Amazon SES hostname pattern"),
    ProviderHostnameEntry(re.compile(r"\b[a-z0-9\-]+\.mailgun\.(?:org|net)\b", re.I), "Mailgun", ProviderCategory.EMPIRICAL_HOSTNAME_PATTERN, ProviderConfidence.UNVERIFIED_PATTERN, "UNKNOWN (Empirical header trace pattern; unverified by authoritative API)", "2026-11-05", "Pattern Snapshot v1.0", "Unverified Mailgun hostname pattern"),
]


def identify_provider_gateway(
    ip_obj: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
    source_header: Optional[str] = None,
    hop_index: Optional[int] = None,
) -> ProviderMatchResult:
    """
    Deterministically evaluates an IP literal and/or header snippet against curated shared
    provider infrastructure ranges and empirical hostname patterns.

    CRITICAL SECURITY & PROVENANCE RULES:
    1. Matching a provider CIDR indicates likely shared multi-tenant provider infrastructure,
       NOT proof that the IP specifically originated or authorized a given message.
    2. A hostname appearing in an attacker-controlled upstream Received header (hop_index > 0)
       MUST NOT establish trusted provider identity. If the IP is not in a confirmed provider
       CIDR, an upstream hostname pattern is treated as an UNVERIFIED / UNTRUSTED indicator.
    3. Classification is strictly offline and deterministic.
    """
    # 1. Authoritative network matching against provider CIDR allocations
    if ip_obj:
        for entry in PROVIDER_GATEWAY_NETWORKS:
            try:
                if ip_obj in entry.network:
                    return ProviderMatchResult(
                        is_provider=True,
                        provider_name=entry.provider_name,
                        service_category=entry.service_category.value,
                        confidence=entry.confidence.value,
                        source_url=entry.source_url,
                        short_label=entry.short_label,
                    )
            except TypeError:
                continue

    # 2. Check source header for hostname patterns
    if source_header:
        for entry in PROVIDER_HOSTNAME_PATTERNS:
            if entry.pattern.search(source_header):
                # An upstream header (hop_index > 0) is potentially attacker-crafted!
                if hop_index is not None and hop_index > 0:
                    return ProviderMatchResult(
                        is_provider=False,
                        provider_name=entry.provider_name,
                        service_category="Unverified Upstream Hostname Indicator (Untrusted)",
                        confidence="UNKNOWN",
                        source_url=entry.source_url,
                        short_label=f"Unverified {entry.provider_name} hostname indicator (untrusted upstream header)",
                    )
                else:
                    # Boundary hop (hop_index == 0)
                    return ProviderMatchResult(
                        is_provider=True,
                        provider_name=entry.provider_name,
                        service_category=entry.service_category.value,
                        confidence=entry.confidence.value,
                        source_url=entry.source_url,
                        short_label=entry.short_label,
                    )

    return ProviderMatchResult(
        is_provider=False,
        provider_name=None,
        service_category=None,
        confidence=None,
        source_url=None,
        short_label=None,
    )



def classify_ip_string(ip_str: str) -> Tuple[IPClassification, Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]]:
    """
    Parses and classifies an IP string into granular forensic categories using
    Python's standard library ipaddress module.
    Returns: (IPClassification, parsed_ip_object_or_None)
    """
    clean_str = ip_str.strip()
    if not clean_str:
        return IPClassification.UNAVAILABLE, None

    try:
        ip_obj = ipaddress.ip_address(clean_str)
    except ValueError:
        return IPClassification.INVALID, None

    # 1. Unspecified (0.0.0.0, ::)
    if ip_obj.is_unspecified:
        return IPClassification.UNSPECIFIED, ip_obj

    # 2. Loopback (127.0.0.0/8, ::1)
    if ip_obj.is_loopback:
        return IPClassification.LOOPBACK, ip_obj

    # 3. Link-Local (169.254.0.0/16, fe80::/10)
    if ip_obj.is_link_local:
        return IPClassification.LINK_LOCAL, ip_obj

    # 4. Multicast (224.0.0.0/4, ff00::/8)
    if ip_obj.is_multicast:
        return IPClassification.MULTICAST, ip_obj

    # 5. Documentation (TEST-NET-1/2/3, 2001:db8::/32)
    if any(ip_obj in net for net in DOCUMENTATION_NETWORKS):
        return IPClassification.DOCUMENTATION, ip_obj

    # 6. Private (RFC 1918 for IPv4, RFC 4193 ULA for IPv6)
    if ip_obj.version == 4:
        if any(ip_obj in net for net in RFC_1918_NETWORKS):
            return IPClassification.PRIVATE, ip_obj
    else:
        if any(ip_obj in net for net in RFC_4193_NETWORKS):
            return IPClassification.PRIVATE, ip_obj

    # 7. Special-Purpose (CGNAT, Benchmarking, IETF Protocol assignments)
    if any(ip_obj in net for net in CGNAT_NETWORKS):
        return IPClassification.SPECIAL_PURPOSE, ip_obj
    if any(ip_obj in net for net in BENCHMARKING_NETWORKS):
        return IPClassification.SPECIAL_PURPOSE, ip_obj
    if any(ip_obj in net for net in IETF_PROTOCOL_NETWORKS):
        return IPClassification.SPECIAL_PURPOSE, ip_obj

    # 8. Reserved (RFC 1112 240.0.0.0/4, broadcast 255.255.255.255)
    if ip_obj.is_reserved:
        return IPClassification.RESERVED, ip_obj

    # 9. Public (Globally routable unicast)
    if getattr(ip_obj, "is_global", False):
        return IPClassification.PUBLIC, ip_obj

    return IPClassification.SPECIAL_PURPOSE, ip_obj


class LocalGeoIPReader:
    """
    Encapsulates optional local offline MaxMind GeoLite2 reader.
    Only queries local .mmdb files if explicitly present on disk.
    NEVER makes network or DNS calls.
    """
    def __init__(self, city_db_path: Optional[str] = None, asn_db_path: Optional[str] = None):
        self.city_db_path = city_db_path or os.environ.get("GEOLITE2_CITY_PATH")
        self.asn_db_path = asn_db_path or os.environ.get("GEOLITE2_ASN_PATH")
        self._city_reader = None
        self._asn_reader = None
        self._checked = False

    def is_available(self) -> bool:
        if not self._checked:
            self._init_readers()
        return self._city_reader is not None or self._asn_reader is not None

    def _init_readers(self):
        self._checked = True
        try:
            import maxminddb
            if self.city_db_path and Path(self.city_db_path).is_file():
                self._city_reader = maxminddb.open_database(self.city_db_path)
            if self.asn_db_path and Path(self.asn_db_path).is_file():
                self._asn_reader = maxminddb.open_database(self.asn_db_path)
        except Exception:
            self._city_reader = None
            self._asn_reader = None

    def lookup(self, ip_str: str) -> Tuple[GeolocationStatus, Optional[IPGeolocationData]]:
        if not self.is_available():
            return GeolocationStatus.DATABASE_UNAVAILABLE, None

        geo_data = IPGeolocationData()
        found = False

        if self._city_reader:
            try:
                rec = self._city_reader.get(ip_str)
                if rec and isinstance(rec, dict):
                    found = True
                    country = rec.get("country", {})
                    geo_data.country_name = country.get("names", {}).get("en")
                    geo_data.country_code = country.get("iso_code")
                    city = rec.get("city", {})
                    geo_data.city_name = city.get("names", {}).get("en")
                    loc = rec.get("location", {})
                    geo_data.latitude = loc.get("latitude")
                    geo_data.longitude = loc.get("longitude")
            except Exception:
                pass

        if self._asn_reader:
            try:
                rec = self._asn_reader.get(ip_str)
                if rec and isinstance(rec, dict):
                    found = True
                    geo_data.asn = rec.get("autonomous_system_number")
                    geo_data.as_org = rec.get("autonomous_system_organization")
            except Exception:
                pass

        if found:
            return GeolocationStatus.LOOKUP_SUCCESS, geo_data
        return GeolocationStatus.NOT_FOUND, None


# Global reader instance
_GLOBAL_GEOIP_READER = LocalGeoIPReader()


def analyze_candidate_ip(
    ip_str: str,
    hop_index: Optional[int] = None,
    source_header: Optional[str] = None,
    total_hops: int = 1,
    geoip_reader: Optional[LocalGeoIPReader] = None,
) -> CandidateIPIntelligence:
    """
    Analyzes and classifies a single candidate IP address.
    """
    reader = geoip_reader or _GLOBAL_GEOIP_READER
    classification, ip_obj = classify_ip_string(ip_str)
    version = ip_obj.version if ip_obj else None
    is_routable = (classification == IPClassification.PUBLIC)

    # 1. Determine forensic role hint & provider gateway identity
    pmatch = identify_provider_gateway(ip_obj, source_header, hop_index)
    is_gw = pmatch.is_provider
    gw_name = pmatch.provider_name
    provider_indicator = pmatch.short_label
    provider_match_category = pmatch.service_category
    provider_confidence = pmatch.confidence
    provider_source_url = pmatch.source_url

    if is_gw:
        if hop_index is None:
            role_hint = f"Likely Shared Provider Infrastructure ({gw_name})"
        elif hop_index == 0:
            role_hint = f"Likely Shared Provider Infrastructure ({gw_name}) (Recipient Ingress / Perimeter Gateway)"
        elif hop_index == total_hops - 1:
            role_hint = f"Likely Shared Provider Infrastructure ({gw_name}) (Apparent Outbound Relay)"
        else:
            role_hint = f"Likely Shared Provider Infrastructure ({gw_name}) (Intermediate Transit Relay Hop {hop_index})"
    elif pmatch.service_category == "Unverified Upstream Hostname Indicator (Untrusted)":
        role_hint = f"Unverified Provider Hostname Indicator ({gw_name}) (Untrusted Upstream Hop {hop_index})"
    else:
        if hop_index is None:
            role_hint = "Unassociated IP Candidate"
        elif hop_index == 0:
            role_hint = "Recipient Ingress / Perimeter Gateway (Newest Hop)"
        elif hop_index == total_hops - 1:
            role_hint = "Apparent Earliest Relay / Origin Candidate (Oldest Hop)"
        else:
            role_hint = f"Intermediate Transit Relay (Hop {hop_index})"

    # 2. Geolocation handling
    if not is_routable:
        geo_status = GeolocationStatus.NOT_ROUTABLE
        geo_data = None
        geo_explanation = "Non-routable IP; offline geolocation is not applicable."
    else:
        geo_status, geo_data = reader.lookup(ip_str)
        if geo_status == GeolocationStatus.DATABASE_UNAVAILABLE:
            geo_explanation = "Globally routable public IP. Local offline GeoLite2 database is not installed or configured."
        elif geo_status == GeolocationStatus.LOOKUP_SUCCESS and geo_data is not None:
            geo_explanation = f"Offline geolocation derived: {geo_data.country_name or 'Unknown Country'}, {geo_data.city_name or 'Unknown City'}."
        else:
            geo_explanation = "Public IP not found in local offline database."

    # 3. Build concise forensic explanation
    explanation = (
        f"{classification.value} IPv{version if version else '?'} address ({role_hint}). {geo_explanation}"
    )

    return CandidateIPIntelligence(
        ip=ip_str,
        version=version,
        classification=classification,
        hop_index=hop_index,
        source_header=source_header,
        is_routable=is_routable,
        geolocation_status=geo_status,
        geolocation=geo_data,
        role_hint=role_hint,
        explanation=explanation,
        provider_indicator=provider_indicator,
        provider_match_category=provider_match_category,
        provider_confidence=provider_confidence,
        provider_source_url=provider_source_url,
    )


def analyze_ip_candidates(
    ip_candidates: List[IPCandidate],
    geoip_reader: Optional[LocalGeoIPReader] = None,
    total_received_headers: Optional[int] = None,
    raw_received_headers: Optional[List[str]] = None,
) -> IPIntelligenceResult:
    """
    Analyzes a collection of extracted IPCandidate objects from email Received headers.
    Determines origin hop, distinguishes public vs internal IPs vs provider gateways,
    and provides conservative provenance caveats without assuming the earliest available
    public IP is the sender's originating IP.
    """
    reader = geoip_reader or _GLOBAL_GEOIP_READER
    db_available = reader.is_available()
    total_candidates = len(ip_candidates)
    warnings: List[str] = []

    if not ip_candidates:
        return IPIntelligenceResult(
            total_candidates=0,
            candidates=[],
            origin_candidate=None,
            origin_assessment="Originating IP is UNAVAILABLE. No IP candidates found in email Received headers.",
            origin_attribution_status="UNAVAILABLE",
            sender_identity_status="Not established",
            provider_infrastructure_match=None,
            candidate_ip_classification="Unavailable",
            is_candidate_routable=None,
            public_count=0,
            private_count=0,
            other_count=0,
            database_available=db_available,
            warnings=["No Received headers containing IP addresses were detected."],
        )

    # Determine total recorded Received hops in the transit path
    max_hop_index = max((c.hop_index for c in ip_candidates if c.hop_index is not None), default=0)
    if total_received_headers is not None and total_received_headers > 0:
        total_hops = max(total_received_headers, max_hop_index + 1)
    else:
        total_hops = max_hop_index + 1

    analyzed_candidates: List[CandidateIPIntelligence] = []
    public_count = 0
    private_count = 0
    other_count = 0

    for cand in ip_candidates:
        cand_intel = analyze_candidate_ip(
            ip_str=cand.ip,
            hop_index=cand.hop_index,
            source_header=cand.source_header,
            total_hops=total_hops,
            geoip_reader=reader,
        )
        analyzed_candidates.append(cand_intel)

        if cand_intel.classification == IPClassification.PUBLIC:
            public_count += 1
        elif cand_intel.classification == IPClassification.PRIVATE:
            private_count += 1
        else:
            other_count += 1

    # Sort candidates by hop_index descending (oldest/earliest hop first)
    candidates_by_hop = sorted(
        analyzed_candidates,
        key=lambda c: (c.hop_index if c.hop_index is not None else -1),
        reverse=True,
    )
    highest_hop_index = candidates_by_hop[0].hop_index if candidates_by_hop else None

    # Identify candidate(s) at the highest observed hop index
    earliest_hop_candidates = [
        c for c in candidates_by_hop if c.hop_index == highest_hop_index
    ]
    # At the earliest hop with multiple candidates, prefer public IP if available
    chosen_candidate = next(
        (c for c in earliest_hop_candidates if c.classification == IPClassification.PUBLIC),
        earliest_hop_candidates[0] if earliest_hop_candidates else None,
    )

    origin_candidate: Optional[CandidateIPIntelligence] = None
    origin_assessment: str = ""

    # Check whether the earliest observed candidate represents a provider delivery gateway
    chosen_ip_obj = None
    if chosen_candidate:
        try:
            chosen_ip_obj = ipaddress.ip_address(chosen_candidate.ip)
        except ValueError:
            pass
    chosen_pmatch = identify_provider_gateway(
        chosen_ip_obj,
        chosen_candidate.source_header if chosen_candidate else None,
        chosen_candidate.hop_index if chosen_candidate else None,
    )
    is_provider = chosen_pmatch.is_provider
    provider_name = chosen_pmatch.provider_name
    is_untrusted_upstream_pattern = (
        chosen_pmatch.service_category == "Unverified Upstream Hostname Indicator (Untrusted)"
    )

    origin_attribution_status = "UNAVAILABLE"
    sender_identity_status = "Not established"
    provider_infrastructure_match: Optional[str] = None
    candidate_ip_classification = "Unavailable"
    is_candidate_routable: Optional[bool] = None

    if chosen_candidate:
        candidate_ip_classification = chosen_candidate.classification.value
        is_candidate_routable = chosen_candidate.is_routable
        provider_infrastructure_match = chosen_candidate.provider_indicator or chosen_pmatch.short_label

    earliest_recorded_hop_idx = total_hops - 1

    # Evaluation Scenario 1: Missing earlier transit hop IP evidence
    # An earlier transit hop exists upstream, but contains no extractable IP literal.
    # Never fall back to boundary/intermediate relay!
    if (
        highest_hop_index is not None
        and highest_hop_index < earliest_recorded_hop_idx
        and chosen_candidate is not None
    ):
        origin_candidate = None
        origin_attribution_status = "UNAVAILABLE"
        sender_identity_status = "Not established"
        if highest_hop_index == 0:
            if is_provider:
                provider_infrastructure_match = chosen_candidate.provider_indicator or f"Likely {provider_name} infrastructure"
                origin_assessment = (
                    f"Originating IP is UNAVAILABLE. Earlier transit hop(s) (Hop 1 to Hop {earliest_recorded_hop_idx} of {total_hops}) "
                    f"contain no extractable IP address. Boundary relay at Hop 0 ({chosen_candidate.ip}) matches likely shared "
                    f"provider infrastructure ({provider_name}); shared multi-tenant infrastructure matches cannot prove "
                    "or establish individual sender-origin attribution."
                )
                warnings.append(
                    f"Originating IP is unavailable: earlier Received transit hop (Hop {earliest_recorded_hop_idx}) lacks IP evidence. "
                    f"Boundary hop {chosen_candidate.ip} matches likely shared provider infrastructure ({provider_name})."
                )
            else:
                origin_assessment = (
                    f"Originating IP is UNAVAILABLE. Earlier transit hop(s) (Hop 1 to Hop {earliest_recorded_hop_idx} of {total_hops}) "
                    f"contain no extractable IP address. Boundary candidate at Hop 0 ({chosen_candidate.ip}) cannot be "
                    "reliably attributed as the sender origin."
                )
                warnings.append(
                    f"Originating IP is unavailable: earliest recorded transit hop (Hop {earliest_recorded_hop_idx} of {total_hops}) "
                    "contains no usable IP literal."
                )
        else:
            origin_assessment = (
                f"Originating IP is UNAVAILABLE. Earlier transit hop(s) (Hop {highest_hop_index + 1} to Hop {earliest_recorded_hop_idx} of {total_hops}) "
                f"contain no extractable IP address. Intermediate candidate at Hop {highest_hop_index} ({chosen_candidate.ip}) "
                "cannot be reliably attributed as the sender origin."
            )
            warnings.append(
                f"Originating IP is unavailable: earliest recorded transit hop (Hop {earliest_recorded_hop_idx} of {total_hops}) "
                "contains no usable IP literal."
            )

    # Evaluation Scenario 2: Candidate at earliest hop matches likely shared Provider Infrastructure
    elif is_provider and chosen_candidate is not None:
        origin_candidate = None
        origin_attribution_status = "UNAVAILABLE"
        sender_identity_status = "Not established"
        provider_infrastructure_match = chosen_candidate.provider_indicator or chosen_pmatch.short_label
        if total_hops == 1:
            origin_assessment = (
                f"Originating IP is UNAVAILABLE. The sole recorded transit hop matches likely shared "
                f"provider infrastructure ({provider_name}) ({chosen_candidate.ip}). Shared multi-tenant infrastructure "
                "cannot prove individual sender-origin attribution."
            )
            warnings.append(
                f"Originating IP is unavailable: sole transit hop matches likely shared provider infrastructure ({provider_name})."
            )
        else:
            origin_assessment = (
                f"Originating IP is UNAVAILABLE. The earliest recorded transit hop (Hop {chosen_candidate.hop_index}) matches likely shared "
                f"provider infrastructure ({provider_name}) ({chosen_candidate.ip}). The original client submission IP "
                "was not recorded by the provider."
            )
            warnings.append(
                f"Originating IP is unavailable: earliest recorded hop matches likely shared provider infrastructure ({provider_name})."
            )

    # Evaluation Scenario 3: Untrusted Upstream Provider Hostname Pattern (Spoofing defense)
    elif is_untrusted_upstream_pattern and chosen_candidate is not None:
        origin_candidate = None
        origin_attribution_status = "UNAVAILABLE"
        sender_identity_status = "Not established (Untrusted upstream hostname)"
        provider_infrastructure_match = chosen_pmatch.short_label
        origin_assessment = (
            f"Originating IP is UNAVAILABLE. Upstream header (Hop {chosen_candidate.hop_index}) matches provider "
            f"hostname pattern ({provider_name}) without confirmed provider IP range; upstream hostnames cannot "
            "establish trusted provider identity or sender origin."
        )
        warnings.append(
            f"Originating IP is unavailable: earliest recorded hop matches likely shared provider infrastructure pattern ({provider_name}), "
            "but upstream header cannot establish trusted provider identity."
        )

    # Evaluation Scenario 4: Candidate at earliest recorded hop is a valid non-provider candidate
    elif chosen_candidate is not None:
        if chosen_candidate.classification == IPClassification.PUBLIC:
            origin_candidate = chosen_candidate
            origin_attribution_status = "AVAILABLE_UNVERIFIED"
            if chosen_candidate.hop_index == 0:
                sender_identity_status = "Unverified candidate (Perimeter boundary)"
            else:
                sender_identity_status = "Unverified candidate (Pre-boundary / No cryptographic proof)"
            provider_infrastructure_match = chosen_candidate.provider_indicator
            origin_assessment = (
                f"Candidate {chosen_candidate.ip} at earliest recorded hop (Hop {chosen_candidate.hop_index}) "
                "is an EXTRACTED_PUBLIC IP candidate representing the apparent network egress with unverified provenance."
            )
        elif chosen_candidate.classification == IPClassification.PRIVATE:
            origin_candidate = chosen_candidate
            origin_attribution_status = "UNAVAILABLE"
            sender_identity_status = "Not established (Non-routable internal address)"
            provider_infrastructure_match = chosen_candidate.provider_indicator
            earliest_public_candidate = next(
                (c for c in candidates_by_hop if c.classification == IPClassification.PUBLIC),
                None,
            )
            if earliest_public_candidate:
                origin_assessment = (
                    f"Originating Internet host is UNAVAILABLE from internal private hops. "
                    f"Earliest recorded hop (Hop {chosen_candidate.hop_index}) is an INTERNAL_PRIVATE address ({chosen_candidate.ip}). "
                    f"Earliest public Internet ingress relay in the transit chain is {earliest_public_candidate.ip} (Hop {earliest_public_candidate.hop_index})."
                )
            else:
                origin_assessment = (
                    f"Originating Internet host is UNAVAILABLE. "
                    f"Earliest recorded hop (Hop {chosen_candidate.hop_index}) is an INTERNAL_PRIVATE address ({chosen_candidate.ip}). "
                    "No public IP addresses were observed in the Received header trace."
                )
            warnings.append(
                f"Originating Internet host is unavailable: earliest recorded hop {chosen_candidate.ip} is a non-routable Private address; Internet sender-origin attribution is unsupported."
            )
        elif chosen_candidate.classification == IPClassification.LOOPBACK:
            origin_candidate = chosen_candidate
            origin_attribution_status = "UNAVAILABLE"
            sender_identity_status = "Not established (Non-routable loopback address)"
            provider_infrastructure_match = chosen_candidate.provider_indicator
            origin_assessment = (
                f"Originating Internet host is UNAVAILABLE. "
                f"Earliest recorded hop (Hop {chosen_candidate.hop_index}) is a local Loopback address ({chosen_candidate.ip}). "
                "Loopback addresses are host-internal non-routable addresses; direct local sender submission cannot be inferred from loopback addresses alone."
            )
            warnings.append(
                f"Originating Internet host is unavailable: earliest recorded hop {chosen_candidate.ip} is a non-routable Loopback address; sender-origin attribution is unsupported."
            )
        elif chosen_candidate.classification == IPClassification.LINK_LOCAL:
            origin_candidate = chosen_candidate
            origin_attribution_status = "UNAVAILABLE"
            sender_identity_status = "Not established (Non-routable link-local address)"
            provider_infrastructure_match = chosen_candidate.provider_indicator
            origin_assessment = (
                f"Originating Internet host is UNAVAILABLE. "
                f"Earliest recorded hop (Hop {chosen_candidate.hop_index}) is a Link-Local address ({chosen_candidate.ip}). "
                "Link-local addresses are non-routable link-scoped addresses and do not support sender-origin attribution."
            )
            warnings.append(
                f"Originating Internet host is unavailable: earliest recorded hop {chosen_candidate.ip} is a non-routable Link-Local address; sender-origin attribution is unsupported."
            )
        else:
            origin_candidate = chosen_candidate
            origin_attribution_status = "UNAVAILABLE"
            sender_identity_status = f"Not established ({chosen_candidate.classification.value})"
            provider_infrastructure_match = chosen_candidate.provider_indicator
            origin_assessment = (
                f"Earliest recorded hop (Hop {chosen_candidate.hop_index}) is classified as {chosen_candidate.classification.value} ({chosen_candidate.ip})."
            )

        # For any candidate extracted prior to receiving boundary (hop_index > 0), append unverified provenance warning
        if origin_candidate and origin_candidate.hop_index is not None and origin_candidate.hop_index > 0:
            origin_assessment += " Note: Pre-boundary Received headers may be forged or manipulated by untrusted upstream relays."
            warnings.append(
                f"Candidate {origin_candidate.ip} was extracted from an upstream Received header (Hop {origin_candidate.hop_index}) "
                "prior to receiving boundary; provenance cannot be independently verified."
            )
    else:
        origin_candidate = None
        origin_attribution_status = "UNAVAILABLE"
        sender_identity_status = "Not established"
        candidate_ip_classification = "Unavailable"
        is_candidate_routable = None
        provider_infrastructure_match = None
        origin_assessment = "Originating IP is UNAVAILABLE. Unable to determine originating IP."

    if total_hops > 1 and public_count == 0:
        warnings.append("Transit path consists entirely of private or non-routable IP addresses.")

    return IPIntelligenceResult(
        total_candidates=total_candidates,
        candidates=analyzed_candidates,
        origin_candidate=origin_candidate,
        origin_assessment=origin_assessment,
        origin_attribution_status=origin_attribution_status,
        sender_identity_status=sender_identity_status,
        provider_infrastructure_match=provider_infrastructure_match,
        candidate_ip_classification=candidate_ip_classification,
        is_candidate_routable=is_candidate_routable,
        public_count=public_count,
        private_count=private_count,
        other_count=other_count,
        database_available=db_available,
        warnings=warnings,
    )
