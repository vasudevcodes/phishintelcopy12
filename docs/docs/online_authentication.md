# Online (live DNS) SPF / DKIM / DMARC verification

## What changed

Before, PhishIntel only *read* the SPF/DKIM/DMARC results that some mail server had already written into the
headers (`Authentication-Results`, `Received-SPF`), plus a DKIM check against keys pinned in
`dkim_keys.json`. Those header strings can be forged, and nothing was looked up on the internet.

Now PhishIntel **re-computes all three checks itself against live DNS** when an email is analysed:

| Check | What is done online |
|-------|---------------------|
| **SPF** (RFC 7208) | Takes the connecting public IP from the `Received` chain and the `Return-Path` domain, fetches the domain's SPF TXT record and evaluates it (`include`, `redirect`, `a`, `mx`, `ptr`, `exists`, `ip4`, `ip6`, macros, 10-lookup and 2-void-lookup limits). |
| **DKIM** (RFC 6376) | Fetches the signer's public key from `selector._domainkey.domain` (TXT), recomputes the body hash and verifies the RSA/Ed25519 signature. |
| **DMARC** (RFC 7489) | Fetches `_dmarc.<From domain>` (falling back to the organizational domain), then checks SPF/DKIM identifier alignment (strict/relaxed) using the live results above. |

The live results replace the header-claimed statuses in the analysis, so the risk score, evidence fusion and the
UI all use verified outcomes. If a header says `spf=pass` but live DNS says `FAIL`, the live result is used and a
"Header/live discrepancy" warning is added (that mismatch is itself strong forensic evidence).

## Files

New (`backend/app/services/`): `dns_resolver.py`, `live_spf.py`, `live_dkim.py`, `live_dmarc.py`,
`live_auth_verifier.py` (orchestrator), `live_auth_integration.py` (feeds results into the existing models).

Modified: `core/config.py`, `main.py`, `api/v1/endpoints/email.py`, `schemas/email_authentication.py`,
`schemas/evidence_fusion.py`, `services/email_parser.py`, `services/dkim_crypto_verifier.py`,
`services/scoring_engine.py`, `services/evidence_fusion.py`, `requirements.txt`,
frontend `AuthenticationCard.tsx` and `types/forensics.ts`.

New tests: `tests/conftest.py`, `tests/test_live_authentication.py`, `tests/test_live_integration.py`.

## Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `PHISHINTEL_ONLINE_AUTH` | `1` | `0` turns live verification off (fully offline behaviour, as before). |
| `PHISHINTEL_DNS_TIMEOUT` | `3` | Seconds per DNS query. |
| `PHISHINTEL_DNS_SERVERS` | *(system resolver)* | Comma-separated resolver IPs, e.g. `1.1.1.1,8.8.8.8`. |
| `PHISHINTEL_DNS_CACHE_TTL` | `300` | Max seconds a DNS answer is cached. |

## Checking that it works

1. `pip install -r backend/requirements.txt` (adds `dnspython`, `publicsuffix2`).
2. Start the backend and open `http://localhost:8000/health/dns` — expect `"dns_reachable": true`.
3. Upload a real `.eml` in the UI. The Authentication card shows a **Live DNS Verification** panel with the
   actual DNS records used, the client IP evaluated, and caveats.

## Behaviour you should know about

* **DNS is queried "now", not at send time.** For old emails, rotated DKIM keys or edited SPF/DMARC records can
  produce a live FAIL that was a PASS at delivery. The result carries the message age and an explicit caveat; a
  *missing* DKIM key on a message older than 30 days is reported as `UNKNOWN`, not as a failure.
* **The SPF client IP comes from the uploaded file's `Received` headers.** It is only trustworthy when the newest
  public hop was written by *your* receiving server. Up to three public hops are evaluated; extra hops are listed.
* **Pinned DKIM keys are only a fallback** when DNS is temporarily unreachable. If DNS answers "no such key" or
  returns a different key, the pinned key is *not* used (it would hide a rotation or revocation).
* **If DNS is unreachable**, the app does not crash: it adds a warning and falls back to header claims / pinned keys.
* **Forwarded mail** often fails SPF but passes DKIM; the report says so when it sees that pattern.
* `is_boundary_trusted` and `provenance_status` are deliberately unchanged: PhishIntel now verifies the *sender's*
  authentication itself, but still cannot prove that the uploaded `Received` headers were written by a trusted server.
* A live PASS shows the sender controls the authenticated domain — not that the mail is benign.
