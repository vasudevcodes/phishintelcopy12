"""
Cryptographic DKIM verification for PhishIntel (RFC 6376).

Works offline (pinned keys) AND online: the verifier asks a key store for the signer's
public key. `LocalKeyStore` serves pinned keys from disk; `DNSKeyStore`
(app/services/live_dkim.py) fetches the live selector._domainkey TXT record from DNS.
Two real cryptographic checks are performed:

  1. Body-hash check  (bh= tag): recomputes SHA-256/SHA-1 over the canonicalized
     body and compares with the signed value. Needs no public key, so it works
     fully offline on any .eml and proves the body was not altered after signing.

  2. Signature check  (b= tag): verifies the RSA / Ed25519 signature over the
     canonicalized signed headers. Needs the signer's public key, which is read
     from a LOCAL key store (pinned copy of the selector._domainkey DNS TXT
     record) -- never fetched at runtime.

Only dependency: `cryptography` (already a transitive dependency of most stacks).
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa


class DKIMCryptoStatus(str, Enum):
    VERIFIED = "VERIFIED"                    # body hash OK + signature valid with pinned key
    BODY_HASH_ONLY = "BODY_HASH_ONLY"        # body hash OK, no pinned key -> signature unchecked
    BODY_MODIFIED = "BODY_MODIFIED"          # body hash mismatch (tampered / altered after signing)
    SIGNATURE_INVALID = "SIGNATURE_INVALID"  # key present but signature does not verify
    MALFORMED = "MALFORMED"                  # unparsable / missing mandatory tags
    UNSUPPORTED = "UNSUPPORTED"              # unknown algorithm / canonicalization
    NO_SIGNATURE = "NO_SIGNATURE"


@dataclass
class DKIMCryptoResult:
    status: DKIMCryptoStatus
    domain: Optional[str] = None
    selector: Optional[str] = None
    algorithm: Optional[str] = None
    canonicalization: Optional[str] = None
    body_hash_valid: Optional[bool] = None
    signature_valid: Optional[bool] = None
    key_source: Optional[str] = None          # "dns", "local_keystore", "local_keystore_dns_fallback" or None
    key_bits: Optional[int] = None
    aligned_with_from: Optional[bool] = None
    covers_from_header: Optional[bool] = None
    weak_algorithm: bool = False
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["status"] = self.status.value
        return d


# --------------------------------------------------------------------------- #
# Raw message handling
# --------------------------------------------------------------------------- #
def _split_raw(message: bytes) -> Tuple[List[bytes], bytes]:
    """Return (raw header fields incl. folding, body) with CRLF line endings."""
    msg = re.sub(rb"\r?\n", b"\r\n", message)
    idx = msg.find(b"\r\n\r\n")
    if idx == -1:
        head, body = msg, b""
    else:
        head, body = msg[:idx], msg[idx + 4:]
    fields: List[bytes] = []
    for line in head.split(b"\r\n"):
        if line[:1] in (b" ", b"\t") and fields:
            fields[-1] += b"\r\n" + line
        else:
            fields.append(line)
    return fields, body


def _field_name(raw: bytes) -> bytes:
    return raw.split(b":", 1)[0].strip().lower()


# --------------------------------------------------------------------------- #
# Canonicalization (RFC 6376 section 3.4)
# --------------------------------------------------------------------------- #
def _canon_header(raw: bytes, mode: str) -> bytes:
    if mode == "simple":
        return raw + b"\r\n"
    name, _, value = raw.partition(b":")
    value = re.sub(rb"\r\n(?=[ \t])", b"", value)       # unfold
    value = re.sub(rb"[ \t]+", b" ", value).strip(b" \t")
    return name.strip().lower() + b":" + value + b"\r\n"


def _canon_body(body: bytes, mode: str) -> bytes:
    if mode == "simple":
        body = re.sub(rb"(\r\n)+\Z", b"", body)
        return body + b"\r\n"
    lines = body.split(b"\r\n")
    lines = [re.sub(rb"[ \t]+", b" ", ln).rstrip(b" ") for ln in lines]
    out = b"\r\n".join(lines)
    out = re.sub(rb"(\r\n)+\Z", b"", out)
    return out + b"\r\n" if out else b""


# --------------------------------------------------------------------------- #
# Tag parsing / key store
# --------------------------------------------------------------------------- #
def _parse_tags(value: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = re.sub(r"\s+", "", v) if k.strip().lower() in ("b", "bh", "h") else v.strip()
    return tags


class LocalKeyStore:
    """
    Pinned DKIM public keys, stored as a JSON map:
        { "selector._domainkey.example.com": "v=DKIM1; k=rsa; p=MIIBIjANB..." }
    i.e. the exact DNS TXT record, collected once while online (nslookup/dig)
    and shipped with the application. Nothing is fetched at runtime.
    """

    def __init__(self, path: Optional[Path] = None, records: Optional[Dict[str, str]] = None):
        self.records: Dict[str, str] = {k.lower(): v for k, v in (records or {}).items()}
        if path and Path(path).is_file():
            try:
                loaded = json.loads(Path(path).read_text(encoding="utf-8"))
                self.records.update({k.lower(): v for k, v in loaded.items() if not k.startswith("_")})
            except (OSError, ValueError):
                pass

    def get(self, selector: str, domain: str):
        rec = self.records.get(f"{selector}._domainkey.{domain}".lower())
        if not rec:
            return None
        tags = _parse_tags(rec)
        p = re.sub(r"\s+", "", tags.get("p", ""))
        if not p:  # empty p= means key revoked
            return None
        kind = tags.get("k", "rsa").lower()
        raw = base64.b64decode(p + "=" * (-len(p) % 4))
        if kind == "ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(raw)
        return serialization.load_der_public_key(raw)


def required_key_ids(message: bytes) -> List[str]:
    """Helper: list the DNS names to pin for this message (run once while online)."""
    ids = []
    for f in _split_raw(message)[0]:
        if _field_name(f) == b"dkim-signature":
            t = _parse_tags(f.split(b":", 1)[1].decode("latin-1"))
            if t.get("s") and t.get("d"):
                ids.append(f"{t['s']}._domainkey.{t['d']}")
    return ids


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #
def _from_domain(fields: List[bytes]) -> Optional[str]:
    for f in fields:
        if _field_name(f) == b"from":
            m = re.search(rb"@([A-Za-z0-9.-]+)", f)
            return m.group(1).decode().lower() if m else None
    return None


def _aligned(d: str, from_dom: Optional[str]) -> Optional[bool]:
    if not from_dom:
        return None
    d = d.lower()
    return from_dom == d or from_dom.endswith("." + d) or d.endswith("." + from_dom)


def verify_dkim_signatures(message: bytes, keystore: Optional[LocalKeyStore] = None) -> List[DKIMCryptoResult]:
    """Verify every DKIM-Signature header in a raw RFC 5322 message."""
    keystore = keystore or LocalKeyStore()
    fields, body = _split_raw(message)
    sigs = [(i, f) for i, f in enumerate(fields) if _field_name(f) == b"dkim-signature"]
    if not sigs:
        return [DKIMCryptoResult(status=DKIMCryptoStatus.NO_SIGNATURE)]
    from_dom = _from_domain(fields)
    return [_verify_one(fields, body, i, f, from_dom, keystore) for i, f in sigs]


def _verify_one(fields, body, sig_idx, sig_raw, from_dom, keystore) -> DKIMCryptoResult:
    value = sig_raw.split(b":", 1)[1].decode("latin-1")
    t = _parse_tags(value)
    res = DKIMCryptoResult(status=DKIMCryptoStatus.MALFORMED, domain=t.get("d"),
                           selector=t.get("s"), algorithm=t.get("a"))
    for req in ("v", "a", "b", "bh", "d", "h", "s"):
        if req not in t:
            res.notes.append(f"Missing mandatory tag '{req}='.")
            return res

    algo = t["a"].lower()
    if algo not in ("rsa-sha256", "rsa-sha1", "ed25519-sha256"):
        res.status = DKIMCryptoStatus.UNSUPPORTED
        res.notes.append(f"Unsupported algorithm '{algo}'.")
        return res
    res.weak_algorithm = algo == "rsa-sha1"
    if res.weak_algorithm:
        res.notes.append("rsa-sha1 is deprecated (RFC 8301) and treated as weak.")
    hash_name = "sha1" if algo.endswith("sha1") else "sha256"

    c = t.get("c", "simple/simple").lower()
    hc, _, bc = c.partition("/")
    bc = bc or "simple"
    if hc not in ("simple", "relaxed") or bc not in ("simple", "relaxed"):
        res.status = DKIMCryptoStatus.UNSUPPORTED
        res.notes.append(f"Unsupported canonicalization '{c}'.")
        return res
    res.canonicalization = f"{hc}/{bc}"

    signed_names = [h.strip().lower() for h in t["h"].split(":")]
    res.covers_from_header = "from" in signed_names
    res.aligned_with_from = _aligned(t["d"], from_dom)
    if not res.covers_from_header:
        res.notes.append("Signature does not cover the From header (weak: From can be changed freely).")
    if res.aligned_with_from is False:
        res.notes.append(f"Signing domain '{t['d']}' is not aligned with From domain '{from_dom}'.")

    # ---- 1. body hash (needs no key) ------------------------------------- #
    canon_body = _canon_body(body, bc)
    if "l" in t and t["l"].isdigit():
        canon_body = canon_body[: int(t["l"])]
        res.notes.append("Signature uses l= body-length limit (content may be appended unsigned).")
    computed_bh = base64.b64encode(hashlib.new(hash_name, canon_body).digest()).decode()
    res.body_hash_valid = computed_bh == t["bh"]
    if not res.body_hash_valid:
        res.status = DKIMCryptoStatus.BODY_MODIFIED
        res.notes.append("Recomputed body hash differs from bh= tag: body altered after signing.")
        return res

    # ---- 2. signature over headers (needs pinned public key) ------------- #
    try:
        pub = keystore.get(t["s"], t["d"])
    except Exception as exc:  # malformed key record
        pub = None
        res.notes.append(f"Key record unavailable or unreadable: {exc}")
    if pub is None:
        res.status = DKIMCryptoStatus.BODY_HASH_ONLY
        missing_note = getattr(keystore, "missing_note", None)
        res.notes.append(
            missing_note(t["s"], t["d"]) if callable(missing_note)
            else f"No pinned public key for {t['s']}._domainkey.{t['d']}; signature not checked."
        )
        return res
    res.key_source = getattr(keystore, "last_source", None) or "local_keystore"
    if isinstance(pub, rsa.RSAPublicKey):
        res.key_bits = pub.key_size
        if pub.key_size < 1024:
            res.notes.append("RSA key shorter than 1024 bits is not acceptable.")

    # collect signed headers bottom-up, one instance per name occurrence
    pool = [(i, f) for i, f in enumerate(fields) if i != sig_idx]
    chosen: List[bytes] = []
    for name in signed_names:
        for k in range(len(pool) - 1, -1, -1):
            if _field_name(pool[k][1]) == name.encode():
                chosen.append(pool[k][1])
                del pool[k]
                break
    data = b"".join(_canon_header(h, hc) for h in chosen)
    stripped = re.sub(rb"(\bb=)[^;]*", rb"\1", sig_raw, count=1)  # empty b= value
    # keep original b= position; remove only its value
    data += _canon_header(stripped, hc).rstrip(b"\r\n")

    sig_bytes = base64.b64decode(t["b"] + "=" * (-len(t["b"]) % 4))
    try:
        if isinstance(pub, ed25519.Ed25519PublicKey):
            pub.verify(sig_bytes, hashlib.sha256(data).digest())
        else:
            algo_hash = hashes.SHA1() if hash_name == "sha1" else hashes.SHA256()
            pub.verify(sig_bytes, data, padding.PKCS1v15(), algo_hash)
        res.signature_valid = True
        res.status = DKIMCryptoStatus.VERIFIED
    except (InvalidSignature, ValueError):
        res.signature_valid = False
        res.status = DKIMCryptoStatus.SIGNATURE_INVALID
        res.notes.append("Signature does not verify with the retrieved public key (headers altered, wrong key, or forged).")
    return res
