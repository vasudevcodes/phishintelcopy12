"""Tests for offline cryptographic DKIM verification (RFC 6376)."""
import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.services.dkim_crypto_verifier import (
    DKIMCryptoStatus,
    LocalKeyStore,
    _canon_body,
    _canon_header,
    _split_raw,
    required_key_ids,
    verify_dkim_signatures,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _signed_message():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    store = LocalKeyStore(records={
        "sel1._domainkey.example.com": "v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()
    })
    hdrs = (b"From: Alice <alice@example.com>\r\nTo: bob@test.org\r\n"
            b"Subject: Hello   world\r\nDate: Sun, 15 Nov 2026 10:00:00 +0000\r\n")
    body = b"Hi Bob,\r\nPlease review.  \r\n\r\nThanks\r\n"
    bh = base64.b64encode(hashlib.sha256(_canon_body(body, "relaxed")).digest()).decode()
    tmpl = ("DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel1; "
            f"h=from:to:subject:date; bh={bh}; b=")
    fields, _ = _split_raw(hdrs + b"\r\n")
    data = b"".join(_canon_header(f, "relaxed") for f in fields)
    data += _canon_header(tmpl.encode(), "relaxed").rstrip(b"\r\n")
    sig = base64.b64encode(key.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()
    return (tmpl + sig).encode() + b"\r\n" + hdrs + b"\r\n" + body, store


def _status(msg, store=None):
    return verify_dkim_signatures(msg, store)[0].status


def test_valid_signature_with_pinned_key():
    msg, store = _signed_message()
    assert _status(msg, store) == DKIMCryptoStatus.VERIFIED


def test_valid_body_without_pinned_key_is_body_hash_only():
    msg, _ = _signed_message()
    assert _status(msg, LocalKeyStore()) == DKIMCryptoStatus.BODY_HASH_ONLY


def test_tampered_body_detected():
    msg, store = _signed_message()
    assert _status(msg.replace(b"Please review", b"Click link"), store) == DKIMCryptoStatus.BODY_MODIFIED


def test_tampered_header_detected():
    msg, store = _signed_message()
    assert _status(msg.replace(b"Hello   world", b"Urgent invoice"), store) == DKIMCryptoStatus.SIGNATURE_INVALID


def test_lf_line_endings_still_verify():
    msg, store = _signed_message()
    assert _status(msg.replace(b"\r\n", b"\n"), store) == DKIMCryptoStatus.VERIFIED


def test_no_signature():
    msg, _ = _signed_message()
    unsigned = msg.split(b"\r\n", 1)[1]
    assert _status(unsigned) == DKIMCryptoStatus.NO_SIGNATURE


def test_real_linkedin_fixture_body_hash_matches_offline():
    data = (FIXTURES_DIR / "linkedin_complete_profile.eml").read_bytes()
    assert required_key_ids(data) == ["lnkd._domainkey.em.linkedin.com"]
    res = verify_dkim_signatures(data)[0]
    assert res.body_hash_valid is True
    assert res.status == DKIMCryptoStatus.BODY_HASH_ONLY


def test_real_phishing_fixture_flagged():
    data = (FIXTURES_DIR / "sample-10.eml").read_bytes()
    res = verify_dkim_signatures(data)[0]
    assert res.status == DKIMCryptoStatus.BODY_MODIFIED
    assert res.aligned_with_from is False


def test_parser_attaches_dkim_crypto_to_response():
    from app.services.email_parser import parse_email_message
    data = (FIXTURES_DIR / "linkedin_complete_profile.eml").read_bytes()
    res = parse_email_message(data, "linkedin_complete_profile.eml")
    assert res.authentication_analysis is not None
    assert res.authentication_analysis.dkim_crypto
    assert res.authentication_analysis.dkim_crypto[0]["body_hash_valid"] is True
