"""
IP Candidate Extractor and Classifier for Received Headers.
RFC 5322 Received header analysis.
"""

import ipaddress
import re
from typing import List, Set, Tuple
from app.schemas.email import IPCandidate

# IPv4 regex matching valid octet ranges 0-255
IPV4_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
)

# IPv6 candidates inside brackets or delimited by whitespace/punctuation
IPV6_BRACKET_REGEX = re.compile(r"\[([a-fA-F0-9:]+)\]")
IPV6_STANDALONE_REGEX = re.compile(
    r"(?:::)?(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}(?:::)?|"
    r"\b(?:[a-f0-9]{1,4}:)+[a-f0-9]{1,4}\b",
    re.IGNORECASE,
)


# RFC 1918 IPv4 Private networks
RFC_1918_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

# RFC 4193 Unique Local IPv6 Addresses (ULA Private)
RFC_4193_NETWORKS = [
    ipaddress.IPv6Network("fc00::/7"),
]

# Documentation ranges (RFC 5737 for IPv4 TEST-NET, RFC 3849 for IPv6)
DOCUMENTATION_NETWORKS = [
    ipaddress.IPv4Network("192.0.2.0/24"),    # TEST-NET-1
    ipaddress.IPv4Network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.IPv4Network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.IPv6Network("2001:db8::/32"),   # IPv6 Documentation
]

# Benchmarking / Inter-network communications (RFC 2544, RFC 5180)
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


def classify_ip_address(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """
    Classifies an IP address into distinct forensic categories:
    - 'Loopback': 127.0.0.0/8, ::1
    - 'Link-Local': 169.254.0.0/16, fe80::/10
    - 'Multicast': 224.0.0.0/4, ff00::/8
    - 'Documentation': TEST-NET-1, TEST-NET-2, TEST-NET-3, 2001:db8::/32
    - 'Private': Strictly RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and RFC 4193 (fc00::/7)
    - 'Special-Purpose': CGNAT (100.64.0.0/10), Benchmarking (198.18.0.0/15), IETF Protocol Assignments
    - 'Reserved': 240.0.0.0/4 (future use), 0.0.0.0/8, 255.255.255.255/32
    - 'Public': Globally routable unicast IP addresses

    Crucially: Does NOT classify every address where ipaddress.is_private is True as Private.
    TEST-NET documentation addresses and other special ranges are strictly distinguished.
    """
    # 1. Loopback
    if ip_obj.is_loopback:
        return "Loopback"

    # 2. Link-Local
    if ip_obj.is_link_local:
        return "Link-Local"

    # 3. Multicast
    if ip_obj.is_multicast:
        return "Multicast"

    # 4. Documentation (TEST-NET-1, TEST-NET-2, TEST-NET-3, 2001:db8::/32)
    if any(ip_obj in net for net in DOCUMENTATION_NETWORKS):
        return "Documentation"

    # 5. RFC 1918 (IPv4) and RFC 4193 Unique Local Address (IPv6)
    if ip_obj.version == 4:
        if any(ip_obj in net for net in RFC_1918_NETWORKS):
            return "Private"
    else:
        if any(ip_obj in net for net in RFC_4193_NETWORKS):
            return "Private"

    # 6. Special-Purpose (CGNAT, Benchmarking, IETF Protocol Assignments)
    if any(ip_obj in net for net in CGNAT_NETWORKS):
        return "Special-Purpose"
    if any(ip_obj in net for net in BENCHMARKING_NETWORKS):
        return "Special-Purpose"
    if any(ip_obj in net for net in IETF_PROTOCOL_NETWORKS):
        return "Special-Purpose"

    # 7. Reserved (RFC 1112 240.0.0.0/4, broadcast, unspecified 0.0.0.0)
    if ip_obj.is_reserved or ip_obj.is_unspecified:
        return "Reserved"

    # 8. Public (Globally routable unicast)
    if getattr(ip_obj, "is_global", False):
        return "Public"

    return "Special-Purpose"


def extract_ip_candidates_from_received_headers(
    received_headers: List[str],
) -> List[IPCandidate]:
    """
    Extracts candidate IP addresses from a list of Received headers.
    Preserves original order of appearance as extracted from the email
    (where hop_index 0 is typically the newest/most recent hop, and the
    last index is typically the oldest hop closest to origin).
    Preserves exact source header snippet for provenance.
    Does NOT assume any candidate is the true originating sender IP.
    """
    candidates: List[IPCandidate] = []
    seen_in_hop: Set[Tuple[str, int]] = set()

    for hop_idx, header in enumerate(received_headers):
        clean_header = " ".join(header.split())
        found_tokens: List[str] = []

        # 1. Look for IPv4 addresses
        for match in IPV4_REGEX.finditer(clean_header):
            found_tokens.append(match.group(0))

        # 2. Look for bracketed IPv6 addresses: [2001:db8::1]
        for match in IPV6_BRACKET_REGEX.finditer(clean_header):
            found_tokens.append(match.group(1))

        # 3. Look for standalone IPv6 candidates
        for match in IPV6_STANDALONE_REGEX.finditer(clean_header):
            token = match.group(0)
            if ":" in token:
                found_tokens.append(token)

        # Validate and classify candidates
        for token in found_tokens:
            token = token.strip()
            # Avoid duplicate report of the same IP within the identical hop
            if (token, hop_idx) in seen_in_hop:
                continue

            try:
                ip_obj = ipaddress.ip_address(token)
            except ValueError:
                continue

            normalized_ip = str(ip_obj)
            if (normalized_ip, hop_idx) in seen_in_hop:
                continue

            seen_in_hop.add((normalized_ip, hop_idx))
            classification = classify_ip_address(ip_obj)

            # Preserve header snippet (first 140 chars if very long)
            snippet = clean_header if len(clean_header) <= 160 else clean_header[:157] + "..."

            candidates.append(
                IPCandidate(
                    ip=normalized_ip,
                    version=ip_obj.version,
                    classification=classification,
                    hop_index=hop_idx,
                    source_header=snippet,
                )
            )

    return candidates
