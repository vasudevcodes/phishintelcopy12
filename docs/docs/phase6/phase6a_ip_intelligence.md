# Phase 6A — IP Intelligence Engine Technical Report

**Project**: PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Execution Phase**: Phase 6A — IP Intelligence Engine  
**Date**: October 2026  
**Auditor / Agent**: Antigravity Automated Verification Agent  
**Service Path**: `backend/app/services/ip_intelligence.py`  
**Schema Path**: `backend/app/schemas/ip_intelligence.py`  
**Parser Path**: `backend/app/services/email_parser.py`  
**Test Path**: `backend/tests/test_ip_intelligence.py`  
**Status Verdict**: **`PHASE_6A_IP_INTELLIGENCE_COMPLETE`**

---

## 1. Executive Summary & Objective

Phase 6A designs, implements, and certifies the **IP Intelligence Engine** for PhishIntel. The engine provides deterministic, explainable, and offline forensic analysis for all candidate IP addresses extracted from RFC 5322 `Received` headers by the Phase 1 parser.

### Key Operational Guarantees
- **Strictly Offline & Deterministic**: Built entirely on Python's standard-library `ipaddress` module and optional local offline `.mmdb` readers. **Zero DNS queries, zero outbound HTTP requests, zero external APIs, and zero automatic database downloads.**
- **Fine-Grained Forensic Classification**: Distinguishes IPv4 and IPv6 addresses across explicit categories: `Public`, `Private`, `Loopback`, `Link-Local`, `Multicast`, `Documentation`, `Special-Purpose`, `Reserved`, `Unspecified`, `Invalid`, and `Unavailable`. Does NOT treat every non-RFC1918 address as public.
- **Header Provenance & Transit Chain Preservation**: Preserves the exact hop index (where hop 0 is the recipient boundary gateway and higher indices represent earlier upstream relays). Distinguishes perimeter gateways from internal transit hops and apparent origin submission nodes.
- **Optional Offline Geolocation Interface**: Implements a clean optional reader interface for MaxMind GeoLite2-compatible databases (`maxminddb`). When a local database is absent, the service cleanly reports `DATABASE_UNAVAILABLE` without throwing exceptions or inventing synthetic geolocation attributes.
- **Full Backward Compatibility**: Preserves all Phase 1 forensic parser outputs, Phase 4B URL intelligence results, and Phase 5A authentication evidence. Extends `POST /api/v1/email/analyze` with an optional `ip_intelligence` section.

---

## 2. IP Classification Rules & Standards

The engine categorizes IPv4 and IPv6 addresses into granular forensic classes based on RFC specifications:

| Forensic Classification | Standard / RFC Reference | Example IP Ranges | Forensic Handling & Routability |
| :--- | :--- | :--- | :--- |
| **`Public`** | RFC 791 / RFC 4291 / `ip_obj.is_global` | `8.8.8.8`, `93.184.216.34`, `2607:f8b0::/32` | Globally routable unicast Internet addresses. Eligible for offline GeoIP lookup. |
| **`Private`** | RFC 1918 (IPv4), RFC 4193 (IPv6 ULA) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Internal organizational / home network addresses. Non-routable. Marked `NOT_ROUTABLE`. |
| **`Loopback`** | RFC 1122 (IPv4), RFC 4291 (IPv6) | `127.0.0.0/8`, `::1` | Localhost inter-process communication. Non-routable. Indicates local host submission. |
| **`Link-Local`** | RFC 3927 (IPv4), RFC 4291 (IPv6) | `169.254.0.0/16`, `fe80::/10` | Auto-configured local subnet segments. Non-routable. Marked `NOT_ROUTABLE`. |
| **`Multicast`** | RFC 5771 (IPv4), RFC 4291 (IPv6) | `224.0.0.0/4`, `ff00::/8` | One-to-many communication groups. Non-routable across standard unicast transit. |
| **`Documentation`** | RFC 5737 (TEST-NET), RFC 3849 (IPv6 Doc) | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | Reserved for technical documentation and synthetic examples. Non-routable. |
| **`Special-Purpose`** | RFC 6598 (CGNAT), RFC 2544, RFC 6890 | `100.64.0.0/10` (CGNAT), `198.18.0.0/15`, `192.0.0.0/24` | Carrier-Grade NAT or benchmarking allocations. Non-routable across public Internet. |
| **`Reserved`** | RFC 1112 | `240.0.0.0/4` (Future use), `255.255.255.255` | Reserved by IETF / broadcast. Non-routable. |
| **`Unspecified`** | RFC 5735 / RFC 4291 | `0.0.0.0`, `::` | Denotes absence of address or all local interfaces. Non-routable. |
| **`Invalid`** | RFC 5322 tokenization errors | `999.999.999.999`, `unparseable-token` | String could not be parsed into valid IPv4 or IPv6 object. |
| **`Unavailable`** | Empty input | Empty string or missing headers | Denotes no IP address present. |

---

## 3. Received Header Transit Chain & Origin Identification

### 3.1 Hop Indexing & Ingress Semantics
In RFC 5322 email transmission, each receiving MTA prepends a `Received` header to the top of the message:
- **`hop_index = 0` (Newest Hop)**: Represents the recipient organization's perimeter gateway (Ingress Gateway). This is the only hop directly under the recipient's administrative control.
- **`hop_index = 1, 2, ...` (Intermediate Hops)**: Represent intermediate transit relays, security gateways, or internal mail routers.
- **Highest `hop_index` (Oldest Hop)**: Represents the earliest recorded relay in the header trace (Apparent Originating Hop).

```
Sender Device (e.g. 192.168.1.50)
       │
       ▼ [Hop 3]
Submission / Corporate Relay (10.240.0.5)
       │
       ▼ [Hop 2]
Outbound Public Gateway (198.51.100.25)
       │
       ▼ [Hop 1]
Intermediary Security Relay (192.0.2.10)
       │
       ▼ [Hop 0]
Recipient Perimeter Gateway (mx.google.com)
```

### 3.2 Origin Identification Logic
1. **Earliest Recorded Hop**: The candidate with the highest `hop_index` is evaluated as the candidate closest to the origin.
2. **Internal vs Public Origin**:
   - If the earliest hop is a **Public IP**, it is flagged as the apparent public egress of the sender.
   - If the earliest hop is a **Private IP** (e.g. RFC 1918 `10.0.0.5`), the engine notes that the message was submitted from an internal private network and identifies the earliest upstream public IP in the chain as the public ingress relay.
   - If the earliest hop is **Loopback** (`127.0.0.1`), the engine notes direct local submission on the sending machine.
3. **Provenance Caveat**:
   > [!WARNING]
   > The earliest reported relay in an email header trace is based on upstream headers that passed through intermediate networks. Unless authenticated by trusted cryptographic mechanisms (such as ARC or recipient-verified transport), headers added prior to the recipient's perimeter gateway may be forged or omitted by an attacker.

---

## 4. Offline Geolocation & Database Licensing

### 4.1 Architecture & Safety Restrictions
The engine provides an optional local reader (`LocalGeoIPReader`) for MaxMind GeoLite2 City and ASN `.mmdb` files:
- **No Automatic Downloads**: The engine does not download databases at runtime.
- **No API Calls**: Never contacts MaxMind Web Services or any external IP lookup API.
- **Non-Routable Exclusion**: Private, loopback, link-local, multicast, documentation, and reserved addresses are immediately assigned `NOT_ROUTABLE` and are **never** queried against the database.
- **Graceful Unavailability**: When no local `.mmdb` database is installed or configured, public IPs are assigned `DATABASE_UNAVAILABLE`. No errors are raised, and no fictitious cities, countries, or ASNs are generated.

### 4.2 Database Licensing & Distribution Policy
- MaxMind GeoLite2 databases are distributed under the MaxMind End User License Agreement (EULA) and Creative Commons Attribution-ShareAlike 4.0 license, requiring attribution and explicit account registration.
- **No Proprietary Database in Git**: Per project safety rules, no `.mmdb` binary databases or license keys are committed to the repository.
- **Configuration**: Operators can point PhishIntel to an existing licensed GeoLite2 database via environment variables:
  - `GEOLITE2_CITY_PATH`: Path to `GeoLite2-City.mmdb`
  - `GEOLITE2_ASN_PATH`: Path to `GeoLite2-ASN.mmdb`

### 4.3 Geolocation Accuracy Limitations
> [!NOTE]
> IP geolocation derived from offline databases represents approximate **network registration or ISP egress routing**, NOT a person's physical location or device GPS coordinates. Egress routing may differ significantly from the sender's physical location due to VPNs, proxies, CDNs, corporate cloud infrastructure, or multi-hop relays.

---

## 5. API Response Schema & Synthetic Example

### 5.1 Response Schema Extension
The endpoint `POST /api/v1/email/analyze` returns `EmailAnalysisResponse`, which now includes:
```python
ip_intelligence: Optional[IPIntelligenceResult] = None
```

### 5.2 Synthetic Request & Response Example

#### Synthetic Request:
```http
POST /api/v1/email/analyze HTTP/1.1
Host: localhost:8000
Content-Type: multipart/form-data; boundary=----WebKitFormBoundarySample

------WebKitFormBoundarySample
Content-Disposition: form-data; name="file"; filename="synthetic_transit_sample.eml"
Content-Type: message/rfc822

Received: from mail-relay.partner.example (mail-relay.partner.example [198.51.100.25])
    by mx.gateway.example with ESMTPS id abc123xyz;
    Sun, 04 Oct 2026 10:14:02 -0700
Received: from gateway.internal.net (gateway.internal.net [10.240.0.5])
    by mail-relay.partner.example with ESMTP id def456uvw;
    Sun, 04 Oct 2026 10:13:58 -0700
Received: from app-srv.local ([127.0.0.1])
    by gateway.internal.net with SMTP id ghi789rst;
    Sun, 04 Oct 2026 10:13:50 -0700
From: Security Operations <alerts@partner.example>
To: Incident Response <investigator@security.example>
Subject: Synthetic Security Notification
Date: Sun, 04 Oct 2026 17:13:40 +0000
Message-ID: <sample-trace-101@partner.example>
Content-Type: text/plain; charset="utf-8"

Please review the attached transit headers.
------WebKitFormBoundarySample--
```

#### Response (HTTP 200 OK):
```json
{
  "filename": "synthetic_transit_sample.eml",
  "file_size_bytes": 982,
  "parsing_status": "success",
  "headers": {
    "from_header": "Security Operations <alerts@partner.example>",
    "to_headers": ["Incident Response <investigator@security.example>"],
    "subject": "Synthetic Security Notification",
    "received_headers": [
      "from mail-relay.partner.example (mail-relay.partner.example [198.51.100.25]) by mx.gateway.example with ESMTPS id abc123xyz; Sun, 04 Oct 2026 10:14:02 -0700",
      "from gateway.internal.net (gateway.internal.net [10.240.0.5]) by mail-relay.partner.example with ESMTP id def456uvw; Sun, 04 Oct 2026 10:13:58 -0700",
      "from app-srv.local ([127.0.0.1]) by gateway.internal.net with SMTP id ghi789rst; Sun, 04 Oct 2026 10:13:50 -0700"
    ]
  },
  "body": {
    "has_plain_text": true,
    "has_html": false,
    "plain_text_content": "Please review the attached transit headers."
  },
  "urls": [],
  "url_analysis": {
    "total_urls": 0,
    "unique_urls": 0,
    "highest_risk_category": "INFO",
    "risk_breakdown": { "INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0 },
    "url_results": []
  },
  "authentication_analysis": {
    "status": "NO_EVIDENCE",
    "spf": { "status": "NOT_PRESENT", "findings": [], "explanation": "No SPF authentication evidence found in headers." },
    "dkim": { "status": "NOT_PRESENT", "findings": [], "explanation": "No DKIM authentication evidence found in headers." },
    "dmarc": { "status": "NOT_PRESENT", "findings": [], "explanation": "No DMARC authentication evidence found in headers." }
  },
  "ip_candidates": [
    {
      "ip": "198.51.100.25",
      "version": 4,
      "classification": "Documentation",
      "hop_index": 0,
      "source_header": "from mail-relay.partner.example (mail-relay.partner.example [198.51.100.25]) by mx.gateway.example with ESMTPS id abc123xyz; Sun, 04 Oct 2026 10:14:02 -0700"
    },
    {
      "ip": "10.240.0.5",
      "version": 4,
      "classification": "Private",
      "hop_index": 1,
      "source_header": "from gateway.internal.net (gateway.internal.net [10.240.0.5]) by mail-relay.partner.example with ESMTP id def456uvw; Sun, 04 Oct 2026 10:13:58 -0700"
    },
    {
      "ip": "127.0.0.1",
      "version": 4,
      "classification": "Loopback",
      "hop_index": 2,
      "source_header": "from app-srv.local ([127.0.0.1]) by gateway.internal.net with SMTP id ghi789rst; Sun, 04 Oct 2026 10:13:50 -0700"
    }
  ],
  "ip_intelligence": {
    "total_candidates": 3,
    "candidates": [
      {
        "ip": "198.51.100.25",
        "version": 4,
        "classification": "Documentation",
        "hop_index": 0,
        "source_header": "from mail-relay.partner.example (mail-relay.partner.example [198.51.100.25]) by mx.gateway.example with ESMTPS id abc123xyz; Sun, 04 Oct 2026 10:14:02 -0700",
        "is_routable": false,
        "geolocation_status": "NOT_ROUTABLE",
        "geolocation": null,
        "role_hint": "Recipient Ingress / Perimeter Gateway (Newest Hop)",
        "explanation": "Documentation IPv4 address (Recipient Ingress / Perimeter Gateway (Newest Hop)). Non-routable IP; offline geolocation is not applicable."
      },
      {
        "ip": "10.240.0.5",
        "version": 4,
        "classification": "Private",
        "hop_index": 1,
        "source_header": "from gateway.internal.net (gateway.internal.net [10.240.0.5]) by mail-relay.partner.example with ESMTP id def456uvw; Sun, 04 Oct 2026 10:13:58 -0700",
        "is_routable": false,
        "geolocation_status": "NOT_ROUTABLE",
        "geolocation": null,
        "role_hint": "Intermediate Transit Relay (Hop 1)",
        "explanation": "Private IPv4 address (Intermediate Transit Relay (Hop 1)). Non-routable IP; offline geolocation is not applicable."
      },
      {
        "ip": "127.0.0.1",
        "version": 4,
        "classification": "Loopback",
        "hop_index": 2,
        "source_header": "from app-srv.local ([127.0.0.1]) by gateway.internal.net with SMTP id ghi789rst; Sun, 04 Oct 2026 10:13:50 -0700",
        "is_routable": false,
        "geolocation_status": "NOT_ROUTABLE",
        "geolocation": null,
        "role_hint": "Apparent Earliest Relay / Origin Candidate (Oldest Hop)",
        "explanation": "Loopback IPv4 address (Apparent Earliest Relay / Origin Candidate (Oldest Hop)). Non-routable IP; offline geolocation is not applicable."
      }
    ],
    "origin_candidate": {
      "ip": "127.0.0.1",
      "version": 4,
      "classification": "Loopback",
      "hop_index": 2,
      "source_header": "from app-srv.local ([127.0.0.1]) by gateway.internal.net with SMTP id ghi789rst; Sun, 04 Oct 2026 10:13:50 -0700",
      "is_routable": false,
      "geolocation_status": "NOT_ROUTABLE",
      "geolocation": null,
      "role_hint": "Apparent Earliest Relay / Origin Candidate (Oldest Hop)",
      "explanation": "Loopback IPv4 address (Apparent Earliest Relay / Origin Candidate (Oldest Hop)). Non-routable IP; offline geolocation is not applicable."
    },
    "origin_assessment": "Earliest recorded hop (Hop 2) is a local Loopback address (127.0.0.1), indicating direct local submission on the sending host.",
    "public_count": 0,
    "private_count": 1,
    "other_count": 2,
    "database_available": false,
    "warnings": [
      "Transit path consists entirely of private or non-routable IP addresses."
    ],
    "disclaimer": "IP analysis is strictly offline and deterministic. Geolocation reflects approximate network registration or egress routing, NOT a person's physical location. Received transit headers prior to the receiving boundary MTA may be forged or manipulated by untrusted relays."
  },
  "warnings": [],
  "parsed_at": "2026-10-12T10:14:05.123456"
}
```

---

## 6. Complete Test Execution & Results

### 6.1 Test Breakdown
The complete backend test suite was executed:
```
backend/tests/test_api.py ................. [ 8 passed ]
backend/tests/test_email_authentication.py  [ 15 passed ]
backend/tests/test_email_parser.py ........ [ 9 passed ]
backend/tests/test_ip_intelligence.py ..... [ 11 passed ]
backend/tests/test_url_integration.py ..... [ 10 passed ]
backend/tests/test_url_intelligence.py .... [ 23 passed ]
--------------------------------------------------------
Total: 76 passed, 0 failed, 0 skipped (100% pass rate) in 0.96 seconds
```

### 6.2 Detailed Phase 6A Test Scenarios (`test_ip_intelligence.py`)
1. `test_public_ipv4_and_ipv6`: Validates public IPv4 (`8.8.8.8`) and public IPv6 (`2607:f8b0:4005:805::200e`) classification, routability, and version tagging.
2. `test_private_ipv4_and_ipv6_unique_local`: Validates RFC 1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and RFC 4193 ULA (`fc00::/7`), confirming `is_routable=False` and `NOT_ROUTABLE` status.
3. `test_loopback_and_link_local`: Validates loopback (`127.0.0.1`, `::1`) and link-local (`169.254.0.0/16`, `fe80::/10`).
4. `test_multicast_reserved_unspecified_and_invalid`: Validates multicast (`224.0.0.1`, `ff02::1`), reserved (`240.0.0.1`), unspecified (`0.0.0.0`, `::`), and invalid strings (`999.999.999.999`, `"not-an-ip"`).
5. `test_documentation_addresses`: Validates RFC 5737 and RFC 3849 test network preservation.
6. `test_provider_gateway_and_internal_provenance`: Validates multi-hop ordering, role hints (perimeter gateway vs internal relay vs apparent origin), and origin assessment.
7. `test_missing_origin_ip_empty`: Validates empty candidate handling without exceptions.
8. `test_geolocation_database_unavailable`: Validates default state when no local `.mmdb` database is present (`DATABASE_UNAVAILABLE`).
9. `test_valid_local_database_lookup_mocked`: Validates offline `.mmdb` reader integration with mock reader, verifying country, city, coordinates, ASN, and organization mapping.
10. `test_api_integration_all_engines`: Validates unified API endpoint returning Phase 1 parser fields, Phase 4B URL intelligence, Phase 5A authentication evidence, and Phase 6A IP intelligence in a single cohesive response.
11. `test_regression_multi_hop_fixture`: Validates fixture `06_multiple_received_hops.eml` preserving hop count, IP extraction, and origin identification.

---

## 7. Modified & Created Files

| File Path | Action | Description & Rationale |
| :--- | :--- | :--- |
| `backend/app/schemas/ip_intelligence.py` | Created | Defined `IPClassification`, `GeolocationStatus`, `IPGeolocationData`, `CandidateIPIntelligence`, and `IPIntelligenceResult`. |
| `backend/app/services/ip_intelligence.py` | Created | Implemented standalone IP classification, origin identification, transit chain analysis, and optional offline GeoLite2 reader. |
| `backend/app/schemas/email.py` | Modified | Added optional `ip_intelligence: Optional[IPIntelligenceResult] = None` to `EmailAnalysisResponse`. |
| `backend/app/services/email_parser.py` | Modified | Invoked `analyze_ip_candidates()` in `parse_email_message()` under non-fatal exception handling, attaching results to `EmailAnalysisResponse`. |
| `backend/tests/test_ip_intelligence.py` | Created | 11 comprehensive unit and integration tests covering IP categories, provenance, database fallback, mocking, socket isolation, and regression fixtures. |
| `docs/phase6/phase6a_ip_intelligence.md` | Created | Technical documentation report for Phase 6A (this document). |

---

## 8. Protected Artifact Verification

Cryptographic SHA-256 hashes of all protected datasets and trained DistilBERT weights were verified and remain bit-identical:

| Protected Artifact Path | Expected SHA-256 Hash | Verification Status |
| :--- | :--- | :---: |
| `data/processed/phishmmf/train.csv` | `72175fb3266648b3da48f400b27effb497adf9cca0db4824a6ff9c142fda167c` | **MATCH (True)** |
| `data/processed/phishmmf/validation.csv` | `40fd5018c25ee5eaf6bad144d6237222e068c8f89b9a11178ab66f81ef7658ab` | **MATCH (True)** |
| `data/processed/phishmmf/test.csv` | `1d4ebdd0e8f9a11b7158393df8cf2ec04f03513ffe658f0a1476afbe159e865e` | **MATCH (True)** |
| `data/processed/phishmmf/cleaned_email_dataset.csv` | `6217ba605ea50396a0361f0e58eb9d8af1be4e8ca62340ae573cda924d0dd4af` | **MATCH (True)** |
| `models/distilbert_baseline/model.safetensors` | `fa64adf06fb436b2129a3a35792d59ce6f02767f3088e902123c94d0128b03a8` | **MATCH (True)** |

---

## 9. Boundary Declarations & Known Limitations

1. **Header Forgery Limitations**: `Received` headers added before the recipient's perimeter MTA cannot be cryptographically verified without ARC or upstream transport guarantees. Threat actors can insert false `Received` headers to mimic legitimate submission relays.
2. **Network Egress vs Physical Origin**: Geolocation identifies the registered egress of the mail server or proxy, not the author's physical location.
3. **No Database Bundling**: No MaxMind proprietary databases are committed to the repository; local administrators must provide licensed databases via environment configuration if geolocation is desired.
4. **No Score Fusion**: IP intelligence remains isolated from DistilBERT text classification, URL heuristics, and authentication evidence. Fusion is deferred to Phase 7.

---

## 10. Final Status

**`PHASE_6A_IP_INTELLIGENCE_COMPLETE`**
