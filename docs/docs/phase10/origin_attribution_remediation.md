# Phase 10B — Origin Attribution Remediation Design and Implementation
## Final Provider Catalogue and UI Accuracy Correction
## Final Provider Catalogue Precision and UI Accuracy Correction

**Project:** PhishIntel: Transformer-Based Phishing Detection with Cryptographic Authentication and IP Intelligence  
**Author:** Antigravity Team  
**Date:** November 5, 2026  
**Status:** COMPLETE & VERIFIED (Final Catalogue & UI Accuracy Review)  
**Status:** COMPLETE & VERIFIED (Precision Review)  

---

## 1. Executive Summary

During the Phase 10 offline IP extraction validation on real-world email samples from the Nazario contemporary archive (`phishing-2024`), an origin-attribution defect was uncovered:

- In **8 of 14 genuine emails** (Messages 3–8 and 9–10), PhishIntel's IP intelligence engine selected Google Workspace outbound mail transfer agents (`209.85.x.x`) or SendGrid shared delivery relays (`167.89.77.213`) as the apparent sender origin host.
- These MTAs were the receiving boundary gateway (Hop 0) or outbound delivery relays, **not** the sender's client machine or true origin network egress.
- This misattribution occurred because upstream `Received` transit hops contained internal server hostnames or routing identifiers without extractable IP literals, and the parser silently fell back to the boundary hop.

**Phase 10B Remediation & Final Review Results:**
**Phase 10B Remediation & Precision Results:**
1. **Specific Provider Correction:** **Zero of the eight previously identified Google/SendGrid cases remain attributed to those providers as sender origin.** All eight are now conservatively classified as `origin_candidate = None` with explicit `UNAVAILABLE` provenance assessments explaining that earlier transit hops lack IP evidence and boundary relays match likely shared provider infrastructure. (Note: This finding is specific to the inspected sample and does not claim zero misattributions across all possible email topologies or datasets.)
2. **Provider Catalogue Categorization & Provenance:** Every static CIDR and regex pattern in `PROVIDER_GATEWAY_NETWORKS` and `PROVIDER_HOSTNAME_PATTERNS` has been audited against authoritative documentation and explicitly categorized into:
   - Confirmed Email-Delivery Network Ranges (High Confidence)
   - General Provider-Owned Network Ranges (Downgraded to Low Confidence; unconfirmed mail provenance)
   - Empirical Hostname Patterns (Unverified by authoritative API; Confidence UNKNOWN)
   - Unverified / Unknown Entries (Dynamic runtime sync is strictly disabled offline)
3. **Untrusted Hostname Defense:** A hostname appearing in an attacker-controlled upstream `Received` header ($h > 0$) does **not** establish trusted provider identity. The parser marks such occurrences as unverified upstream indicators (`confidence = "UNKNOWN"`) and retains conservative `UNAVAILABLE` sender-origin behavior (`origin_candidate = None`).
4. **UI/API Accuracy Correction:** In `IPCandidatesCard.tsx`, `reportGenerator.ts`, and the API response schema, origin attribution availability, candidate IP classification, provider-infrastructure match, and sender-origin confidence are strictly decoupled. For a public Google gateway candidate with unavailable sender origin, the UI displays:
2. **Microsoft 365 Reclassification:** `52.100.0.0/14` is reclassified as a documented Exchange Online mail-protection range (`Confirmed Email-Delivery Network Range`, `High (Confirmed Mail Range)`), matching the official Microsoft 365 Endpoint feed (ID 10, Exchange Online Protection / Hybrid Mail Flow on TCP Port 25). General Microsoft Azure cloud ranges outside Endpoint ID 10 are strictly excluded from confirmed mail infrastructure. Matching an Exchange Online network indicates likely shared multi-tenant infrastructure, not proof of actual email delivery.
3. **Google Workspace SPF Verification:** Google prefixes have been audited against current published DNS records for `_spf.google.com` and its sub-netblocks (`_netblocks.google.com` and `_netblocks2.google.com`).
   - Current SPF-confirmed netblocks: `209.85.128.0/17`, `74.125.0.0/16`, and IPv6 `/36` netblocks (`2001:4860:4000::/36`, `2404:6800:4000::/36`, `2607:f8b0:4000::/36`, `2800:3f0:4000::/36`, `2a00:1450:4000::/36`, `2c0f:fb50:4000::/36`).
   - Historical or general network entries: Historical retired SPF netblocks (`64.233.160.0/19`, `66.249.80.0/20`, `108.177.0.0/17`), broad Google Cloud ranges (`142.250.0.0/15`, `172.217.0.0/16`, `172.253.0.0/16`), and broad ARIN allocation `2607:f8b0::/32` are separated and downgraded to `General Provider-Owned Network Range` with `Low (Broad Provider Range)` confidence. No ungrounded claim that historical prefixes are currently published in SPF is made.
4. **SendGrid Precision Correction:** The SendGrid CIDR has been corrected to the precise documented SPF range **`167.89.0.0/17`** (published in `sendgrid.net`), preventing over-broadening to `/16` (which would erroneously encompass unassociated `167.89.128.0/17`). The genuine Nazario candidate `167.89.77.213` falls safely within `167.89.0.0/17`.
5. **Untrusted Hostname Defense:** A hostname appearing in an attacker-controlled upstream `Received` header ($h > 0$) does **not** establish trusted provider identity. The parser marks such occurrences as unverified upstream indicators (`confidence = "UNKNOWN"`) and retains conservative `UNAVAILABLE` sender-origin behavior (`origin_candidate = None`).
6. **UI/API Accuracy Correction:** In `IPCandidatesCard.tsx`, `reportGenerator.ts`, and the API response schema, origin attribution availability, candidate IP classification, provider-infrastructure match, and sender-origin confidence are strictly decoupled. For a public Google gateway candidate with unavailable sender origin, the UI displays:
   - Origin Attribution: `UNAVAILABLE`
   - Candidate IP: `Public`
   - Provider Indicator: `Likely Google infrastructure`
   - Sender Identity: `Not established`
   - Candidate Routability: `Public` (eliminating the bug where `Public Routable: No` was rendered when `origin_candidate` was null).
5. **Conservative Treatment of Non-Routable Addresses:** For private, loopback, and link-local addresses, PhishIntel preserves the extracted evidence while reporting the originating Internet host as `UNAVAILABLE` (`is_candidate_routable = False`, `sender_identity_status = "Not established"`). Direct local sender submission is **not** inferred merely from address type.
6. **Preserved Public Candidates with Caveats:** In the remaining 6 genuine emails in the contemporary Nazario sample, the engine identified **six earliest-recorded public IP candidates with unverified provenance**, explicitly augmented with forensic warnings regarding unverified upstream headers and pre-boundary transit.
7. **Regression Suite Expansion:**
   - Backend test suite: Expanded to **266 automated tests** (all passing).
7. **Conservative Treatment of Non-Routable Addresses:** For private, loopback, and link-local addresses, PhishIntel preserves the extracted evidence while reporting the originating Internet host as `UNAVAILABLE` (`is_candidate_routable = False`, `sender_identity_status = "Not established"`). Direct local sender submission is **not** inferred merely from address type.
8. **Preserved Public Candidates with Caveats:** In the remaining 6 genuine emails in the contemporary Nazario sample, the engine identified **six earliest-recorded public IP candidates with unverified provenance**, explicitly augmented with forensic warnings regarding unverified upstream headers and pre-boundary transit.
9. **Regression Suite Expansion:**
   - Backend test suite: Expanded to **269 automated tests** (all passing).
   - Frontend test suite: Expanded to **78 automated tests** (all passing).
8. **Zero Hash Drift:** All four protected dataset and model weight SHA-256 hashes remain strictly bit-identical.
10. **Zero Hash Drift:** All four protected dataset and model weight SHA-256 hashes remain strictly bit-identical.

---

## 2. Forensic Analysis of the Origin-Attribution Defect

### 2.1 The Observed Failure in Contemporary Nazario Samples

In Phase 10 offline parser validation, 14 sequential genuine emails from the Nazario contemporary archive (`phishing-2024`) were processed. Inspection of their RFC 5322 `Received` headers revealed the following chain topologies:

| Message Index | Total Received Headers | Extracted IP Candidates | Legacy Origin Attribution | Infrastructure Match | Remediation Status |
| :--- | :---: | :--- | :--- | :--- | :--- |
| **Msg 01** | 2 | `162.214.230.221` (Hop 0), `77.105.147.0` (Hop 1) | `77.105.147.0` (Hop 1) | Public Host (Serbia) | Earliest-recorded public IP candidate with unverified provenance |
| **Msg 02** | 2 | `202.226.36.25` (Hop 0), `45.149.156.90` (Hop 1) | `45.149.156.90` (Hop 1) | Public Host (Russia) | Earliest-recorded public IP candidate with unverified provenance |
| **Msg 03** | 2 | `209.85.161.69` (Hop 0) | `209.85.161.69` (Hop 0) | Google Mail / Workspace | **Remediated: UNAVAILABLE (None)** |
| **Msg 04** | 2 | `209.85.160.197` (Hop 0) | `209.85.160.197` (Hop 0) | Google Mail / Workspace | **Remediated: UNAVAILABLE (None)** |
| **Msg 05** | 2 | `209.85.167.199` (Hop 0) | `209.85.167.199` (Hop 0) | Google Mail / Workspace | **Remediated: UNAVAILABLE (None)** |
| **Msg 06** | 2 | `209.85.160.200` (Hop 0) | `209.85.160.200` (Hop 0) | Google Mail / Workspace | **Remediated: UNAVAILABLE (None)** |
| **Msg 07** | 2 | `209.85.167.197` (Hop 0) | `209.85.167.197` (Hop 0) | Google Mail / Workspace | **Remediated: UNAVAILABLE (None)** |
| **Msg 08** | 2 | `209.85.160.71` (Hop 0) | `209.85.160.71` (Hop 0) | Google Mail / Workspace | **Remediated: UNAVAILABLE (None)** |
| **Msg 09** | 3 | `167.89.77.213` (Hop 0) | `167.89.77.213` (Hop 0) | SendGrid / Twilio Relay | **Remediated: UNAVAILABLE (None)** |
| **Msg 10** | 3 | `167.89.77.213` (Hop 0) | `167.89.77.213` (Hop 0) | SendGrid / Twilio Relay | **Remediated: UNAVAILABLE (None)** |
| **Msg 11** | 1 | `103.171.18.98` (Hop 0) | `103.171.18.98` (Hop 0) | Public Host (India) | Earliest-recorded public IP candidate with unverified provenance |
| **Msg 12** | 2 | `101.0.91.100` (Hop 0), `103.153.78.171` (Hop 1) | `103.153.78.171` (Hop 1) | Public Host (India) | Earliest-recorded public IP candidate with unverified provenance |
| **Msg 13** | 6 | 8 IPs across Hops 0–5 | `147.189.174.51` (Hop 5) | Public Host (Hetzner) | Earliest-recorded public IP candidate with unverified provenance |
| **Msg 14** | 2 | `103.2.197.12` (Hop 0), `103.153.78.171` (Hop 1) | `103.153.78.171` (Hop 1) | Public Host (India) | Earliest-recorded public IP candidate with unverified provenance |

### 2.2 Root Cause Analysis

Two fundamental architectural flaws in the legacy `ip_intelligence.py` contributed to this defect:

1. **Header Count Blindness:**
   In the legacy implementation, `analyze_ip_candidates(ip_candidates)` only received extracted IP candidate objects. It computed total hops as:
   ```python
   max_hop_index = max((c.hop_index for c in ip_candidates), default=0)
   total_hops = max_hop_index + 1
   ```
   When upstream hops (e.g., Hop 1 in Google messages, or Hops 1–2 in SendGrid messages) contained internal routing identifiers without IP literals, `ip_candidates` only contained candidates from Hop 0 (`hop_index = 0`).
   Consequently, `max_hop_index` evaluated to `0`, and `total_hops` was falsely calculated as `1`. The parser assumed Hop 0 was both the newest and the oldest recorded hop in the transit chain.

2. **Silent Boundary Gateway Fallback:**
   The parser assumed that the candidate with the highest available `hop_index` was the sender's origin. When Hop 0 was the only candidate with an IP literal, the parser silently selected Hop 0 (the recipient's inbound boundary MTA) and emitted:
   `"Candidate 209.85.x.x at earliest recorded hop (Hop 0) is a globally routable Public IP representing the apparent network egress of the sender."`
   This attributed shared enterprise delivery infrastructure as the attacker's personal workstation.

---

## 3. Provider Infrastructure Catalogue & Provenance Audit
## 3. Provider Infrastructure Catalogue & Provenance Precision

### 3.1 Authoritative Catalogue Definitions & Categorization

To prevent ungrounded attribution, PhishIntel maintains a curated offline catalog of provider infrastructure entries. Each entry is explicitly audited against authoritative documentation, assigned an exact service category, and rated for confidence.

> [!WARNING]
> **Catalogue Limitations & Maintenance Policy:**
> 1. **Non-Comprehensive:** This catalogue is **not** comprehensive and does not encompass all email service providers, autonomous systems, or cloud IP allocations.
> 2. **Offline & Air-Gapped:** PhishIntel operates strictly offline. Dynamic SPF TXT DNS resolution, WHOIS queries, and live cloud JSON feed syncs are disabled by design.
> 3. **Authoritative Provenance Limits:** Dynamic runtime sync is **UNKNOWN**.
> 4. **General Cloud Ranges Downgraded:** General cloud ranges (e.g., broad Google Cloud or Microsoft Azure netblocks) without exclusive mail-delivery provenance are downgraded to low-confidence general provider indicators. They are **never** classified as confirmed email-delivery ranges without specific evidence.
> 4. **General Cloud Ranges Downgraded:** General cloud ranges (e.g., broad Google Cloud netblocks) without exclusive mail-delivery provenance are downgraded to low-confidence general provider indicators. They are **never** classified as confirmed email-delivery ranges without specific evidence.

| Provider / Service | Network CIDR or Hostname Pattern | Entry Type | Service Category | Confidence Rating | Authoritative Source URL & Version | Retrieval Date | Provenance & Coverage Notes |
| Provider / Service | Network CIDR or Hostname Pattern | Entry Type | Service Category | Confidence Rating | Authoritative Source URL & Version | Retrieval Date | Provenance & Service Scope Notes |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Google Mail / Workspace** | `209.85.128.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks.google.com`) | 2026-11-05 | Confirmed SPF sending subnet. Static offline snapshot. |
| **Google Mail / Workspace** | `74.125.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks.google.com`) | 2026-11-05 | Confirmed SPF sending subnet. Static offline snapshot. |
| **Google Mail / Workspace** | `64.233.160.0/19` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks.google.com`) | 2026-11-05 | Confirmed SPF sending subnet. Static offline snapshot. |
| **Google Mail / Workspace** | `66.249.80.0/20` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks.google.com`) | 2026-11-05 | Confirmed SPF sending subnet. Static offline snapshot. |
| **Google Mail / Workspace** | `108.177.0.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks.google.com`) | 2026-11-05 | Confirmed SPF sending subnet. Static offline snapshot. |
| **Google Mail / Workspace** | `2607:f8b0::/32` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks6.google.com`) | 2026-11-05 | Confirmed SPF IPv6 sending subnet. Static offline snapshot. |
| **Google (General Netblock)** | `142.250.0.0/15` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` (Snapshot v1.0) | 2026-11-05 | Broad Google Cloud range; unconfirmed mail-only provenance (downgraded). |
| **Google (General Netblock)** | `172.217.0.0/16` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` (Snapshot v1.0) | 2026-11-05 | Broad Google Cloud range; unconfirmed mail-only provenance (downgraded). |
| **Google (General Netblock)** | `172.253.0.0/16` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` (Snapshot v1.0) | 2026-11-05 | Broad Google Cloud range; unconfirmed mail-only provenance (downgraded). |
| **SendGrid / Twilio** | `167.89.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **Google Mail / Workspace** | `209.85.128.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks.google.com`) | 2026-11-05 | Current active SPF netblock for outbound Google mail delivery (32,768 IPs). |
| **Google Mail / Workspace** | `74.125.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks.google.com`) | 2026-11-05 | Current active SPF netblock for outbound Google mail delivery (65,536 IPs). |
| **Google Mail / Workspace** | `2001:4860:4000::/36` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks2.google.com`) | 2026-11-05 | Current active SPF IPv6 netblock for outbound Google mail delivery. |
| **Google Mail / Workspace** | `2404:6800:4000::/36` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks2.google.com`) | 2026-11-05 | Current active SPF IPv6 netblock for outbound Google mail delivery. |
| **Google Mail / Workspace** | `2607:f8b0:4000::/36` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks2.google.com`) | 2026-11-05 | Current active SPF IPv6 netblock for outbound Google mail delivery. |
| **Google Mail / Workspace** | `2800:3f0:4000::/36` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks2.google.com`) | 2026-11-05 | Current active SPF IPv6 netblock for outbound Google mail delivery. |
| **Google Mail / Workspace** | `2a00:1450:4000::/36` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks2.google.com`) | 2026-11-05 | Current active SPF IPv6 netblock for outbound Google mail delivery. |
| **Google Mail / Workspace** | `2c0f:fb50:4000::/36` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://support.google.com/a/answer/60764` (SPF `_netblocks2.google.com`) | 2026-11-05 | Current active SPF IPv6 netblock for outbound Google mail delivery. |
| **Microsoft 365 / Exchange** | `40.92.0.0/15` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 10 (Exchange Online Protection / Mail flow). |
| **Microsoft 365 / Exchange** | `40.107.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 10 (Exchange Online Protection / Mail flow). |
| **Microsoft 365 / Exchange** | `52.100.0.0/14` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 10 (Exchange Online Protection / Hybrid TCP 25). |
| **Microsoft 365 / Exchange** | `104.47.0.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 10 (Exchange Online Protection Outbound). |
| **Microsoft 365 / Exchange** | `2a01:111:f400::/48` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 10 (Exchange Online IPv6 Protection / Mail flow). |
| **Microsoft 365 / Exchange** | `2a01:111:f403::/48` | IPv6 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 10 (Exchange Online IPv6 Protection / Mail flow). |
| **SendGrid / Twilio** | `167.89.0.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Precise documented SendGrid SPF sending subnet (corrected from overly broad `/16`). |
| **SendGrid / Twilio** | `168.245.0.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **SendGrid / Twilio** | `149.72.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **SendGrid / Twilio** | `198.21.0.0/21` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **SendGrid / Twilio** | `198.37.144.0/20` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **SendGrid / Twilio** | `149.72.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **SendGrid / Twilio** | `168.245.0.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **Microsoft 365 / Exchange** | `40.92.0.0/15` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 1 (Exchange Online). |
| **Microsoft 365 / Exchange** | `40.107.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed M365 Endpoint ID 1 (Exchange Online). |
| **Microsoft 365 / Exchange** | `104.47.0.0/17` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges` | 2026-11-05 | Confirmed Exchange Online Protection (EOP) outbound. |
| **Microsoft (General Netblock)** | `52.100.0.0/14` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview` | 2026-11-05 | Broad Azure datacenter range; unconfirmed mail provenance (downgraded). |
| **SendGrid / Twilio** | `159.183.0.0/16` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://docs.sendgrid.com/ui/account-and-settings/ip-addresses` | 2026-11-05 | Confirmed Twilio SendGrid outbound mail CIDR. |
| **Amazon SES** | `54.240.0.0/18` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://ip-ranges.amazonaws.com/ip-ranges.json` (`AMAZON_SES`) | 2026-11-05 | Confirmed AWS SES outbound sending IP range. |
| **Amazon SES** | `69.169.224.0/20` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://ip-ranges.amazonaws.com/ip-ranges.json` (`AMAZON_SES`) | 2026-11-05 | Confirmed AWS SES outbound sending IP range. |
| **Mailgun** | `159.112.240.0/20` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/` | 2026-11-05 | Confirmed Mailgun sending IP allocation. |
| **Mailgun** | `198.61.254.0/24` | IPv4 CIDR | Confirmed Email-Delivery Network Range | High (Confirmed Mail Range) | `https://documentation.mailgun.com/docs/mailgun/user-manual/sending-messages/` | 2026-11-05 | Confirmed Mailgun sending IP allocation. |
| **Google Hostname Pattern** | `\b(?:mail-[a-z0-9\-]+\.google\.com\|mx\.google\.com)\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops. |
| **SendGrid Hostname Pattern** | `\b(?:[a-z0-9\-]+\.outbound-mail\.sendgrid\.net\|sendgrid\.net)\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops. |
| **Microsoft Hostname Pattern** | `\b[a-z0-9\-]+\.outbound\.protection\.outlook\.com\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops. |
| **Amazon SES Hostname Pattern** | `\b[a-z0-9\-]+\.amazonses\.com\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops. |
| **Mailgun Hostname Pattern** | `\b[a-z0-9\-]+\.mailgun\.(?:org\|net)\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops. |
| **Google (Historical SPF)** | `64.233.160.0/19` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` | 2026-11-05 | Historical Google SPF netblock; unconfirmed mail provenance in active SPF. |
| **Google (Historical SPF)** | `66.249.80.0/20` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` | 2026-11-05 | Historical Google SPF netblock; unconfirmed mail provenance in active SPF. |
| **Google (Historical SPF)** | `108.177.0.0/17` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` | 2026-11-05 | Historical Google SPF netblock; unconfirmed mail provenance in active SPF. |
| **Google (General Cloud)** | `142.250.0.0/15` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` | 2026-11-05 | Broad Google Cloud range; unconfirmed mail-only provenance. |
| **Google (General Cloud)** | `172.217.0.0/16` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` | 2026-11-05 | Broad Google Cloud range; unconfirmed mail-only provenance. |
| **Google (General Cloud)** | `172.253.0.0/16` | IPv4 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` | 2026-11-05 | Broad Google Cloud range; unconfirmed mail-only provenance. |
| **Google (General Allocation)**| `2607:f8b0::/32` | IPv6 CIDR | General Provider-Owned Network Range | Low (Broad Provider Range) | `https://www.gstatic.com/ipranges/goog.json` | 2026-11-05 | Broad Google ARIN IPv6 allocation; unconfirmed in active SPF without `/36`. |
| **Google Hostname Pattern** | `\b(?:mail-[a-z0-9\-]+\.google\.com\|mx\.google\.com)\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops ($h > 0$). |
| **SendGrid Hostname Pattern** | `\b(?:[a-z0-9\-]+\.outbound-mail\.sendgrid\.net\|sendgrid\.net)\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops ($h > 0$). |
| **Microsoft Hostname Pattern** | `\b[a-z0-9\-]+\.outbound\.protection\.outlook\.com\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops ($h > 0$). |
| **Amazon SES Hostname Pattern** | `\b[a-z0-9\-]+\.amazonses\.com\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops ($h > 0$). |
| **Mailgun Hostname Pattern** | `\b[a-z0-9\-]+\.mailgun\.(?:org\|net)\b` | Regex | Empirical Hostname Pattern | UNKNOWN | UNKNOWN (Empirical header trace pattern; unverified by authoritative API) | 2026-11-05 | Empirical naming convention. Untrusted in upstream hops ($h > 0$). |

---

## 4. Untrusted Hostname Defense & Origin Attribution Decision Engine

### 4.1 Untrusted Upstream Hostname Handling ($h > 0$)

In RFC 5322 transit, any `Received` header prior to the receiving boundary MTA ($h > 0$) is potentially fabricated by an attacker. 

**Defensive Rule:** A hostname appearing in an attacker-controlled upstream `Received` header ($h > 0$) must **NOT** establish trusted provider identity. 
- If an upstream header contains a hostname matching `mail-*.google.com` but the IP literal is **not** in a confirmed Google CIDR, the engine flags it as:
  `service_category = "Unverified Upstream Hostname Indicator (Untrusted)"`, `confidence = "UNKNOWN"`.
- It sets `is_provider = False` to prevent claiming verified provider ownership.
- It retains conservative `UNAVAILABLE` sender-origin behavior (`origin_candidate = None`, `origin_attribution_status = "UNAVAILABLE"`, `sender_identity_status = "Not established (Untrusted upstream hostname)"`).
- An explicit forensic warning is attached noting that upstream provider hostnames cannot establish identity.

### 4.2 Comprehensive Attribution Decision Engine

`email_parser.py` passes `total_received_headers=len(received_headers)` to `analyze_ip_candidates()`. Total recorded hops are computed as:
$$H_{\text{total}} = \max(H_{\text{received\_headers}}, h_{\max} + 1)$$

```
                          ┌───────────────────────────┐
                          │   analyze_ip_candidates   │
                          └─────────────┬─────────────┘
                                        │
                         Are there any IP candidates?
                                 /         \
                             No /           \ Yes
                                v             v
                    ┌──────────────────┐    Find candidate at highest hop:
                    │ origin = None    │    h_max = highest_candidate.hop_index
                    │ UNAVAILABLE      │    H_total = total recorded hops
                    └──────────────────┘    Evaluate provider gateway match
                                                           │
        ┌──────────────────────────────────────────────────┼──────────────────────────────────────────────────┐
        │                                                  │                                                  │
        v                                                  v                                                  v
[Scenario 1: Missing Earlier Hop IP]       [Scenario 2: Provider Infrastructure Match]        [Scenario 3: Non-Provider Earliest Hop]
  Condition: h_max < H_total - 1             Condition: is_provider == True                     Condition: is_provider == False
  Action:                                    OR untrusted_upstream_pattern == True              Action:
  - origin_candidate = None                  Action:                                            - If PUBLIC:
  - origin_attribution_status =              - origin_candidate = None                            origin_candidate = cand
    "UNAVAILABLE"                            - origin_attribution_status = "UNAVAILABLE"         origin_attribution_status = "AVAILABLE_UNVERIFIED"
  - candidate_ip_classification =            - sender_identity_status =                           sender_identity_status = "Unverified candidate"
    boundary_candidate.classification          "Not established"                                  candidate_ip_classification = "Public"
  - is_candidate_routable =                  - candidate_ip_classification preserved              is_candidate_routable = True
    boundary_candidate.is_routable           - is_candidate_routable preserved                 - If PRIVATE / LOOPBACK / LINK-LOCAL:
  - sender_identity_status =                 - provider_infrastructure_match =                    origin_candidate = cand (evidence preserved)
    "Not established"                          pmatch.short_label                                 origin_attribution_status = "UNAVAILABLE"
  - DO NOT fall back to Hop 0!                                                                    sender_identity_status = "Not established"
                                                                                                  candidate_ip_classification preserved
                                                                                                  is_candidate_routable = False
                                                                                                  Do NOT infer direct local submission!
```

### 4.3 Treatment of Private, Loopback, and Link-Local Addresses

When the candidate at the earliest recorded hop ($h_{\max} == H_{\text{total}} - 1$) is a non-routable address:
- **Evidence Preservation:** The candidate object is preserved in `candidates` and assigned to `origin_candidate` so the forensic record remains complete.
- **Attribution Status:** `origin_attribution_status` is explicitly set to **`UNAVAILABLE`** and `is_candidate_routable` is `False`.
- **Sender Identity:** `sender_identity_status` is set to `"Not established (Non-routable internal address)"` (or `loopback` / `link-local`).
- **No Ungrounded Inferences:** The engine strictly avoids inferring "direct local sender submission" merely from a loopback address (`127.0.0.1` or `::1`). In real-world mail systems, loopback hops frequently result from local content filters, milters, anti-virus daemons, or internal MTA proxies.

---

## 5. UI and API Accuracy Correction

In `IPCandidatesCard.tsx`, `reportGenerator.ts`, and the API response schema:
Origin attribution availability, candidate IP classification, provider-infrastructure match, and sender-origin confidence are strictly decoupled.

### 5.1 Public Gateway Candidate with Unavailable Origin
For a public Google gateway candidate at Hop 0 where earlier transit hops lack IP literals:
- **Origin Attribution:** `UNAVAILABLE`
- **Candidate IP:** `Public (Public Routable)`
- **Provider Indicator:** `Likely Google infrastructure`
- **Sender Identity:** `Not established`
- **Candidate Routability:** `Public`
- **Bug Fixed:** The interface no longer renders `Public Routable: No` when `origin_candidate` is null. It evaluates `is_candidate_routable` independently of origin availability.

### 5.2 Non-Routable Addresses (Private, Loopback, Link-Local)
For private or internal addresses at the earliest hop:
- **Origin Attribution:** `UNAVAILABLE`
- **Candidate IP:** `Private` / `Loopback` / `Link-Local`
- **Candidate Routability:** `Non-routable`
- **Sender Identity:** `Not established (Non-routable internal address)`
- **Evidence Retained:** The candidate remains visible in the hops table and summary without false external claims.

### 5.3 Earliest-Recorded Public Candidate with Unverified Provenance
For an upstream public IP candidate without cryptographic authentication:
- **Origin Attribution:** `AVAILABLE_UNVERIFIED`
- **Candidate IP:** `Public`
- **Sender Identity:** `Unverified candidate (Pre-boundary / No cryptographic proof)`
- **Role Badge in Report/UI:** `Earliest Public Candidate (Unverified)`
- **Prohibition:** The candidate is **never** presented as verified sender proof or confirmed sender origin.

---

## 6. Regression Test Suite Verification

### 6.1 Backend Pytest Suite (266 Passed)
### 6.1 Backend Pytest Suite (269 Passed)

The backend test suite in `backend/tests/test_ip_intelligence.py` includes dedicated regression tests for all Phase 10B requirements:

1. `test_phase10b_public_routable_provider_candidate_unavailable_origin`:
   Verifies that a public Google gateway candidate at Hop 0 with missing upstream IPs returns `origin_attribution_status == "UNAVAILABLE"`, `candidate_ip_classification == "Public"`, `is_candidate_routable is True`, `provider_infrastructure_match == "Likely Google infrastructure"`, and `sender_identity_status == "Not established"`.
2. `test_phase10b_spoofed_provider_hostname_in_untrusted_upstream_header`:
   Verifies that a spoofed provider hostname in an untrusted upstream header ($h = 1$) does not establish provider identity (`confidence == "UNKNOWN"`), retains `origin_candidate is None`, and reports `sender_identity_status == "Not established (Untrusted upstream hostname)"`.
3. `test_phase10b_broad_provider_owned_cidr_without_confirmed_mail_provenance`:
   Verifies that broad cloud ranges (Google `142.250.180.1` and Azure `52.100.50.1`) are categorized as `General Provider-Owned Network Range` with downgraded confidence `Low (Broad Provider Range)`.
4. `test_phase10b_non_routable_evidence_retained_with_unavailable_sender_attribution`:
   Verifies that broad cloud ranges (Google `142.250.180.1`), historical retired SPF ranges (`64.233.160.1`), and broad ARIN IPv6 ranges (`2607:f8b0:1000::1`) are categorized as `General Provider-Owned Network Range` with downgraded confidence `Low (Broad Provider Range)`.
4. `test_phase10b_m365_exchange_online_mail_protection_reclassification`:
   Verifies that `52.100.0.0/14` is classified as `Confirmed Email-Delivery Network Range` with `High (Confirmed Mail Range)` confidence from M365 Endpoint ID 10.
5. `test_phase10b_sendgrid_cidr_precision_17_not_16`:
   Verifies that `167.89.77.213` (inside `167.89.0.0/17`) matches SendGrid confirmed mail range, while `167.89.200.1` (outside `/17`) is not classified as SendGrid confirmed mail range.
6. `test_phase10b_google_workspace_current_spf_netblocks_verification`:
   Verifies that current SPF netblocks (`209.85.128.0/17`, `74.125.0.0/16`, `2607:f8b0:4000::/36`) match as `Confirmed Email-Delivery Network Range` with High confidence.
7. `test_phase10b_non_routable_evidence_retained_with_unavailable_sender_attribution`:
   Verifies that private (`10.20.30.40`), loopback (`127.0.0.1`), and link-local (`169.254.10.20`) evidence is retained with `origin_attribution_status == "UNAVAILABLE"` and `is_candidate_routable is False`.
5. Existing 25 unit and integration tests covering multi-hop chains, geolocation fallbacks, and boundary assertions.

```
============================= test session starts =============================
platform win32 -- Python 3.13.15, pytest-9.1.1, pluggy-1.6.0
rootdir: C:\Users\Lenovo\Desktop\PhishIntel\backend
configfile: pytest.ini
plugins: anyio-4.15.1
collected 266 items
collected 269 items

backend\tests\test_api.py ........                                       [  3%]
backend\tests\test_api.py ........                                       [  2%]
backend\tests\test_email_authentication.py ...............               [  8%]
backend\tests\test_email_parser.py .........                             [ 12%]
backend\tests\test_email_parser.py .........                             [ 11%]
backend\tests\test_evidence_fusion.py .............                      [ 16%]
backend\tests\test_ip_intelligence.py .............................      [ 27%]
backend\tests\test_model_integration.py ...........                      [ 31%]
backend\tests\test_phase9_e2e_validation.py ............                 [ 36%]
backend\tests\test_stage_a1_corrections.py .............                 [ 41%]
backend\tests\test_ip_intelligence.py ................................   [ 28%]
backend\tests\test_model_integration.py ...........                      [ 32%]
backend\tests\test_phase9_e2e_validation.py ............                 [ 37%]
backend\tests\test_stage_a1_corrections.py .............                 [ 42%]
backend\tests\test_stage_a2_corrections.py ............................. [ 52%]
.........................                                                [ 61%]
.........................                                                [ 62%]
backend\tests\test_stage_a3_corrections.py ............................. [ 72%]
.........................                                                [ 81%]
.........................                                                [ 82%]
backend\tests\test_stage_a_b_corrections.py ...............              [ 87%]
backend\tests\test_url_integration.py ..........                         [ 91%]
backend\tests\test_url_intelligence.py .......................           [100%]
======================= 266 passed, 1 warning in 10.39s =======================
======================= 269 passed, 1 warning in 13.30s =======================
```

### 6.2 Frontend Test Suite (78 Passed)

The frontend test suite in `frontend/src/tests/` verifies the UI and report generation:

1. `test 12: Phase 10B: UI/report rendering for unavailable origin with a public candidate`:
   Asserts that the downloadable report HTML contains `Origin Attribution: UNAVAILABLE`, `Candidate IP: Public`, `Provider Indicator: Likely Google infrastructure`, `Sender Identity: Not established`, and `Candidate Routability: Public` without rendering `Non-routable`.
2. `test 13: Phase 10B: UI/report rendering for an unverified public origin candidate`:
   Asserts that the report contains `Origin Attribution: AVAILABLE_UNVERIFIED`, `Sender Identity: Unverified candidate (Pre-boundary / No cryptographic proof)`, and table badge `Earliest Public Candidate (Unverified)`.

```
▶ Phase 8B — Frontend-to-Backend Integration Audit Tests (8 tests) ... pass
▶ Real Frontend-to-Backend Contract Verification (8 Real Fixtures) ... pass
▶ Phase 8C — Downloadable Forensic Report Tests (13 tests)
  ✔ 12. Phase 10B: UI/report rendering for unavailable origin with a public candidate
  ✔ 13. Phase 10B: UI/report rendering for an unverified public origin candidate
ℹ tests 78
ℹ suites 11
ℹ pass 78
ℹ fail 0
```

---

## 7. Protected File Hash Verification

All four protected files were independently verified via SHA-256 using PowerShell `Get-FileHash`. All hashes remain strictly unchanged:

| File Path | Protected Expected SHA-256 Hash | Actual Measured SHA-256 Hash | Verification Status |
| :--- | :--- | :--- | :---: |
| `data/processed/phishmmf/train.csv` | `72175FB3266648B3DA48F400B27EFFB497ADF9CCA0DB4824A6FF9C142FDA167C` | `72175FB3266648B3DA48F400B27EFFB497ADF9CCA0DB4824A6FF9C142FDA167C` | **MATCH / UNMODIFIED** |
| `data/processed/phishmmf/validation.csv` | `40FD5018C25EE5EAF6BAD144D6237222E068C8F89B9A11178AB66F81EF7658AB` | `40FD5018C25EE5EAF6BAD144D6237222E068C8F89B9A11178AB66F81EF7658AB` | **MATCH / UNMODIFIED** |
| `data/processed/phishmmf/test.csv` | `1D4EBDD0E8F9A11B7158393DF8CF2EC04F03513FFE658F0A1476AFBE159E865E` | `1D4EBDD0E8F9A11B7158393DF8CF2EC04F03513FFE658F0A1476AFBE159E865E` | **MATCH / UNMODIFIED** |
| `models/distilbert_baseline/model.safetensors` | `FA64ADF06FB436B2129A3A35792D59CE6F02767F3088E902123C94D0128B03A8` | `FA64ADF06FB436B2129A3A35792D59CE6F02767F3088E902123C94D0128B03A8` | **MATCH / UNMODIFIED** |

---

## 8. Summary of Remaining UNKNOWN Catalogue Entries

In compliance with strict scientific integrity, the following catalogue entries and operational aspects remain explicitly classified as **UNKNOWN**:

1. **Dynamic Runtime Provenance:** UNKNOWN. Dynamic live SPF DNS queries, WHOIS, and automated feed syncs are intentionally not executed in PhishIntel's offline forensic environment.
1. **Dynamic Runtime Sync:** UNKNOWN. Dynamic live SPF DNS queries, WHOIS, and automated feed syncs are intentionally not executed in PhishIntel's offline forensic environment.
2. **Empirical Hostname Patterns:** UNKNOWN authoritative provider guarantee. Hostname regex patterns (`mail-*.google.com`, `sendgrid.net`, etc.) reflect observed real-world naming conventions and cannot be verified via authoritative APIs offline.
3. **Upstream Hostname Headers ($h > 0$):** UNKNOWN trust status. Any hostname in an upstream Received header is treated as an unverified, untrusted indicator and can never establish trusted provider identity.
4. **Catalogue Coverage:** NON-COMPREHENSIVE. Static ranges cover curated subsets of major providers; coverage of arbitrary or emerging mail providers is UNKNOWN.

---

## 9. Conclusion

Phase 10B final provider catalogue review and UI accuracy correction are complete. The system strictly separates provider infrastructure detection from origin attribution, defends against upstream hostname spoofing, accurately reflects public routability for gateway candidates without false non-routable labels, preserves non-routable evidence without ungrounded local-submission claims, and enforces rigorous provenance caveats across all APIs and user interfaces.
Phase 10B provider catalogue precision corrections are complete. Microsoft 365 `52.100.0.0/14` is correctly categorized under Exchange Online mail protection; Google prefixes are rigorously separated into active SPF netblocks and historical/general cloud ranges with verified `/36` IPv6 netblocks; and SendGrid ranges are strictly scoped to the documented `/17` subnet without broadening. The entire forensic engine remains fully offline, all tests pass, and all protected hashes remain bit-identical.
