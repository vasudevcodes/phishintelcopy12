"""
RFC 5322 Forensic Email Parser for PhishIntel (Phase 1).
Extracts email headers, bodies, deduplicated URLs, attachment metadata with SHA-256,
and candidate IPs from Received transit hops.
"""

from datetime import datetime, timezone
import email
from email import policy
from email.message import EmailMessage
import hashlib
import html
import os
import re
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from app.schemas.email import (
    AttachmentInfo,
    EmailAnalysisResponse,
    EmailBodyInfo,
    EmailHeaderInfo,
    ExtractedURL,
)
from app.schemas.evidence_fusion import (
    ModelInferenceEvidence,
    ModelInferenceStatus,
)
from app.core.config import settings
from app.services.dkim_crypto_verifier import LocalKeyStore, verify_dkim_signatures
from app.services.email_authentication import analyze_email_authentication
from app.services.evidence_fusion import fuse_evidence
from app.services.ip_extractor import extract_ip_candidates_from_received_headers
from app.services.ip_intelligence import analyze_ip_candidates
from app.services.live_auth_integration import apply_live_results
from app.services.live_auth_verifier import run_live_authentication
from app.services.model_inference import run_model_inference
from app.services.url_intelligence import analyze_email_extracted_urls

# URL extraction regex for plain text (captures http/https URLs)
URL_REGEX = re.compile(r"https?://[^\s<>'\"{}|\\^`\[\]]+", re.IGNORECASE)


def sanitize_filename(filename: Optional[str]) -> str:
    """
    Sanitizes attachment filename to prevent directory traversal or unsafe names.
    """
    if not filename:
        return "unnamed_attachment"
    # Remove directory separators
    clean_name = os.path.basename(filename.strip().replace("\\", "/"))
    # Strip any control characters
    clean_name = re.sub(r"[\x00-\x1f\x7f]", "", clean_name)
    return clean_name if clean_name else "unnamed_attachment"


def parse_address_list(header_val: Optional[str]) -> List[str]:
    """
    Parses comma-separated or multi-value recipient address headers.
    """
    if not header_val:
        return []
    # Split on commas that are not enclosed in quotes
    parts = [p.strip() for p in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", header_val) if p.strip()]
    return parts if parts else [header_val.strip()]


def extract_text_from_html(html_content: str) -> str:
    """
    Safely parses HTML and extracts readable plain text.
    Strips scripts, styles, and untrusted elements.
    """
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        # Strip executable or styling elements
        for element in soup(["script", "style", "meta", "noscript", "link"]):
            element.decompose()
        extracted_text = soup.get_text(separator="\n", strip=True)
        return extracted_text
    except Exception:
        # Fallback basic tag removal if BeautifulSoup fails
        clean_text = re.sub(r"<[^>]+>", " ", html_content)
        return " ".join(clean_text.split())


def extract_urls(
    plain_text: Optional[str], html_content: Optional[str]
) -> List[ExtractedURL]:
    """
    Extracts and deduplicates genuine navigable URLs from plain-text content and
    HTML anchor <a> tags only.
    Excludes non-hyperlink assets (image src, tracking pixels, css url(), stylesheets,
    fonts, scripts, placeholder links href="#", javascript:, mailto:, tel:, xmlns namespaces,
    and DTD DOCTYPEs).
    Preserves original URL values, source provenance, and anchor text without performing
    any network lookups.
    """
    url_sources: dict[str, Set[str]] = {}
    url_anchors: dict[str, str] = {}
    trailing_punct = ".,;:!?)>\"'}]"

    # 1. Plain text URLs
    if plain_text:
        for match in URL_REGEX.finditer(plain_text):
            raw_url = match.group(0).rstrip(trailing_punct)
            raw_url = html.unescape(raw_url)
            if raw_url and raw_url.lower().startswith(("http://", "https://")):
                url_sources.setdefault(raw_url, set()).add("plain_text")

    # 2. HTML anchor hrefs and naked URLs in visible text
    if html_content:
        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Extract genuine hyperlinks from <a> href attributes
            for a_tag in soup.find_all("a", href=True):
                raw_href = a_tag.get("href")
                if isinstance(raw_href, list):
                    href = " ".join(raw_href).strip()
                elif raw_href is not None:
                    href = raw_href.strip()
                else:
                    continue

                # Exclude placeholder links, in-page anchors, javascript, mailto, tel, data
                if not href or href.startswith("#") or href.lower().startswith((
                    "javascript:", "mailto:", "tel:", "data:", "about:", "sms:", "callto:"
                )):
                    continue

                # Normalize protocol-relative URLs
                if href.startswith("//"):
                    href = "https:" + href

                # Decode HTML entities (e.g. &amp; -> &)
                href = html.unescape(href)

                # Strip trailing punctuation
                href = href.rstrip(trailing_punct)

                if href.lower().startswith(("http://", "https://")):
                    url_sources.setdefault(href, set()).add("html_href")
                    anchor_txt = a_tag.get_text(strip=True)
                    if anchor_txt and href not in url_anchors:
                        url_anchors[href] = anchor_txt

            # Strip non-content and non-navigable elements before extracting visible text
            for element in soup([
                "script", "style", "meta", "noscript", "link", "img", "svg", "iframe", "audio", "video", "head"
            ]):
                element.decompose()

            # Extract genuine naked URLs from visible text ONLY (never raw markup)
            visible_text = soup.get_text(separator=" ", strip=True)
            for match in URL_REGEX.finditer(visible_text):
                raw_url = match.group(0).rstrip(trailing_punct)
                raw_url = html.unescape(raw_url)
                if raw_url and raw_url.lower().startswith(("http://", "https://")):
                    url_sources.setdefault(raw_url, set()).add("html_href")

        except Exception:
            # Fallback if BeautifulSoup parsing completely fails:
            # Only search visible text after stripping HTML tags
            clean_text = re.sub(r"<[^>]+>", " ", html_content)
            for match in URL_REGEX.finditer(clean_text):
                raw_url = match.group(0).rstrip(trailing_punct)
                raw_url = html.unescape(raw_url)
                if raw_url and raw_url.lower().startswith(("http://", "https://")):
                    url_sources.setdefault(raw_url, set()).add("html_href")

    # Construct deduplicated response list
    results: List[ExtractedURL] = []
    for raw_url, sources in url_sources.items():
        if "plain_text" in sources and "html_href" in sources:
            source_label = "both"
        elif "html_href" in sources:
            source_label = "html_href"
        else:
            source_label = "plain_text"

        try:
            parsed = urlparse(raw_url)
            scheme = parsed.scheme if parsed.scheme else None
            domain = parsed.netloc if parsed.netloc else None
        except Exception:
            scheme = None
            domain = None

        results.append(
            ExtractedURL(
                url=raw_url,
                scheme=scheme,
                domain=domain,
                source=source_label,
                anchor_text=url_anchors.get(raw_url),
            )
        )

    return results


def parse_email_message(file_bytes: bytes, filename: str) -> EmailAnalysisResponse:
    """
    Parses a raw .eml byte sequence according to RFC 5322 into an EmailAnalysisResponse.
    Handles malformed encodings, extracts headers, body, URLs, attachments and IP candidates.
    """
    warnings: List[str] = []

    # Parse message with standard RFC 5322 policy
    try:
        msg = email.message_from_bytes(file_bytes, policy=policy.default)
    except Exception as exc:
        warnings.append(f"Standard policy failed: {str(exc)}. Retrying with compat32 policy.")
        msg = email.message_from_bytes(file_bytes, policy=policy.compat32)

    # 1. Headers Extraction
    from_header = msg.get("From")
    to_val = msg.get("To")
    to_headers = parse_address_list(to_val) if to_val else []
    cc_val = msg.get("Cc")
    cc_headers = parse_address_list(cc_val) if cc_val else []
    bcc_val = msg.get("Bcc")
    bcc_headers = parse_address_list(bcc_val) if bcc_val else []

    subject = msg.get("Subject")
    date_header = msg.get("Date")
    message_id = msg.get("Message-ID")
    reply_to = msg.get("Reply-To")
    return_path = msg.get("Return-Path")
    mime_version = msg.get("MIME-Version")
    content_type = msg.get("Content-Type")

    # Multi-value headers
    auth_results_raw = msg.get_all("Authentication-Results", [])
    authentication_results = [str(ar).strip() for ar in auth_results_raw if ar]

    spf_raw = msg.get_all("Received-SPF", [])
    received_spf = [str(s).strip() for s in spf_raw if s]

    received_raw = msg.get_all("Received", [])
    received_headers = [str(r).strip() for r in received_raw if r]

    dkim_raw = msg.get_all("DKIM-Signature", [])
    dkim_signatures = [str(d).strip() for d in dkim_raw if d]

    header_info = EmailHeaderInfo(
        from_header=str(from_header) if from_header else None,
        to_headers=to_headers,
        cc_headers=cc_headers,
        bcc_headers=bcc_headers,
        subject=str(subject) if subject else None,
        date=str(date_header) if date_header else None,
        message_id=str(message_id) if message_id else None,
        reply_to=str(reply_to) if reply_to else None,
        return_path=str(return_path) if return_path else None,
        mime_version=str(mime_version) if mime_version else None,
        content_type=str(content_type) if content_type else None,
        authentication_results=authentication_results,
        received_spf=received_spf,
        dkim_signatures=dkim_signatures,
        received_headers=received_headers,
    )

    # 2. Body and Attachments Traversal
    plain_text_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[AttachmentInfo] = []

    if msg.is_multipart():
        for part in msg.walk():
            # Check for attachment disposition
            content_disposition = str(part.get("Content-Disposition", "")).lower()
            part_filename = part.get_filename()

            is_attachment = (
                "attachment" in content_disposition
                or (part_filename is not None and "inline" not in content_disposition and part.get_content_maintype() != "multipart")
            )

            if is_attachment:
                # Process attachment metadata safely
                try:
                    payload = part.get_payload(decode=True)
                    payload_bytes: bytes
                    if isinstance(payload, bytes):
                        payload_bytes = payload
                    elif isinstance(payload, str):
                        payload_bytes = payload.encode("utf-8", errors="replace")
                    else:
                        payload_bytes = b""
                    att_size = len(payload_bytes)
                    att_hash = hashlib.sha256(payload_bytes).hexdigest()
                    att_filename = sanitize_filename(part_filename or "unnamed_attachment")
                    att_type = part.get_content_type() or "application/octet-stream"

                    attachments.append(
                        AttachmentInfo(
                            filename=att_filename,
                            content_type=att_type,
                            size_bytes=att_size,
                            sha256=att_hash,
                        )
                    )
                except Exception as att_err:
                    warnings.append(f"Failed extracting attachment metadata: {str(att_err)}")
                continue

            # Process body parts
            part_type = part.get_content_type()
            if part_type == "text/plain":
                try:
                    if isinstance(part, EmailMessage):
                        content = part.get_content()
                        if isinstance(content, str):
                            plain_text_parts.append(content)
                        elif isinstance(content, bytes):
                            plain_text_parts.append(content.decode("utf-8", errors="replace"))
                    else:
                        raw = part.get_payload(decode=True)
                        if isinstance(raw, bytes):
                            plain_text_parts.append(raw.decode("utf-8", errors="replace"))
                        elif isinstance(raw, str):
                            plain_text_parts.append(raw)
                except Exception:
                    try:
                        raw = part.get_payload(decode=True)
                        if isinstance(raw, bytes):
                            plain_text_parts.append(raw.decode("utf-8", errors="replace"))
                        elif isinstance(raw, str):
                            plain_text_parts.append(raw)
                    except Exception as err:
                        warnings.append(f"Error decoding text/plain part: {str(err)}")

            elif part_type == "text/html":
                try:
                    if isinstance(part, EmailMessage):
                        content = part.get_content()
                        if isinstance(content, str):
                            html_parts.append(content)
                        elif isinstance(content, bytes):
                            html_parts.append(content.decode("utf-8", errors="replace"))
                    else:
                        raw = part.get_payload(decode=True)
                        if isinstance(raw, bytes):
                            html_parts.append(raw.decode("utf-8", errors="replace"))
                        elif isinstance(raw, str):
                            html_parts.append(raw)
                except Exception:
                    try:
                        raw = part.get_payload(decode=True)
                        if isinstance(raw, bytes):
                            html_parts.append(raw.decode("utf-8", errors="replace"))
                        elif isinstance(raw, str):
                            html_parts.append(raw)
                    except Exception as err:
                        warnings.append(f"Error decoding text/html part: {str(err)}")
    else:
        # Non-multipart message
        main_type = msg.get_content_type()
        part_filename = msg.get_filename()

        if part_filename:
            # Single attachment file message
            payload = msg.get_payload(decode=True)
            payload_bytes: bytes
            if isinstance(payload, bytes):
                payload_bytes = payload
            elif isinstance(payload, str):
                payload_bytes = payload.encode("utf-8", errors="replace")
            else:
                payload_bytes = b""
            attachments.append(
                AttachmentInfo(
                    filename=sanitize_filename(part_filename),
                    content_type=main_type or "application/octet-stream",
                    size_bytes=len(payload_bytes),
                    sha256=hashlib.sha256(payload_bytes).hexdigest(),
                )
            )
        else:
            try:
                if isinstance(msg, EmailMessage):
                    content = msg.get_content()
                    if isinstance(content, str):
                        body_text = content
                    elif isinstance(content, bytes):
                        body_text = content.decode("utf-8", errors="replace")
                    else:
                        body_text = str(content)
                else:
                    raw = msg.get_payload(decode=True)
                    if isinstance(raw, bytes):
                        body_text = raw.decode("utf-8", errors="replace")
                    elif isinstance(raw, str):
                        body_text = raw
                    else:
                        body_text = ""
            except Exception:
                raw = msg.get_payload(decode=True)
                if isinstance(raw, bytes):
                    body_text = raw.decode("utf-8", errors="replace")
                elif isinstance(raw, str):
                    body_text = raw
                else:
                    body_text = ""

            if main_type == "text/html":
                html_parts.append(body_text)
            else:
                plain_text_parts.append(body_text)

    # Consolidate body content
    plain_text_combined = "\n\n".join(plain_text_parts).strip() if plain_text_parts else None
    html_raw_combined = "\n\n".join(html_parts).strip() if html_parts else None

    html_extracted_text = extract_text_from_html(html_raw_combined) if html_raw_combined else None

    body_info = EmailBodyInfo(
        has_plain_text=bool(plain_text_combined),
        plain_text=plain_text_combined,
        has_html=bool(html_raw_combined),
        html_extracted_text=html_extracted_text,
        plain_text_char_count=len(plain_text_combined) if plain_text_combined else 0,
        html_text_char_count=len(html_extracted_text) if html_extracted_text else 0,
    )

    # 3. URL Extraction (Never fetching or opening URLs)
    extracted_urls = extract_urls(plain_text_combined, html_raw_combined)

    # 4. IP Candidate Extraction from Received transit headers
    ip_candidates = extract_ip_candidates_from_received_headers(received_headers)

    # 5. Deterministic URL Intelligence Analysis (Phase 4A)
    try:
        url_analysis = analyze_email_extracted_urls(extracted_urls)
    except Exception as url_err:
        warnings.append(f"URL intelligence analysis non-fatal warning: {str(url_err)}")
        url_analysis = None

    # 6. Email Authentication Evidence Engine (Phase 5A)
    try:
        auth_analysis = analyze_email_authentication(header_info, dkim_signatures)
    except Exception as auth_err:
        warnings.append(f"Email authentication analysis non-fatal warning: {str(auth_err)}")
        auth_analysis = None

    # 6b. Offline cryptographic DKIM verification (body hash + pinned-key signature check)
    if auth_analysis is not None:
        try:
            _keystore = LocalKeyStore(settings.DKIM_KEYSTORE_PATH)
            auth_analysis.dkim_crypto = [
                r.to_dict() for r in verify_dkim_signatures(file_bytes, _keystore)
            ]
        except Exception as crypto_err:
            warnings.append(f"DKIM cryptographic verification non-fatal warning: {str(crypto_err)}")

    # 6c. LIVE (online) SPF / DKIM / DMARC verification against real DNS.
    # Re-computes all three checks itself instead of trusting header claims, and feeds the
    # verified results into scoring / evidence fusion. Disable with PHISHINTEL_ONLINE_AUTH=0.
    if auth_analysis is not None and settings.ONLINE_AUTH_ENABLED:
        try:
            _pinned = LocalKeyStore(settings.DKIM_KEYSTORE_PATH)
            live_report = run_live_authentication(
                file_bytes,
                header_info,
                ip_candidates,
                pinned_keystore=_pinned,
                settings_obj=settings,
            )
            apply_live_results(auth_analysis, live_report)
            if not live_report.get("available", True):
                warnings.append(
                    "Live authentication unavailable: "
                    + str(live_report.get("error", "DNS not reachable"))
                    + " Falling back to header-reported / pinned-key evidence."
                )
        except Exception as live_err:
            warnings.append(f"Live authentication non-fatal warning: {str(live_err)}")

    # 7. IP Intelligence Engine (Phase 6A)
    try:
        ip_analysis = analyze_ip_candidates(
            ip_candidates,
            total_received_headers=len(received_headers),
            raw_received_headers=received_headers,
        )
    except Exception as ip_err:
        warnings.append(f"IP intelligence analysis non-fatal warning: {str(ip_err)}")
        ip_analysis = None

    # 8. DistilBERT Text Inference Engine (Phase 8A)
    # Extracts text for inference, using plain text or falling back to extracted HTML text
    body_for_inference = plain_text_combined if plain_text_combined else html_extracted_text
    try:
        model_result = run_model_inference(
            subject=header_info.subject,
            body=body_for_inference,
        )
        if model_result and model_result.status == ModelInferenceStatus.ERROR:
            warnings.append(f"Model inference non-fatal warning: {model_result.error_message}")
        elif model_result and model_result.status == ModelInferenceStatus.UNAVAILABLE:
            warnings.append(f"Model inference unavailable: {model_result.error_message}")
    except Exception as model_err:
        warnings.append(f"Model inference non-fatal warning: {str(model_err)}")
        model_result = ModelInferenceEvidence(
            uncalibrated_score=None,
            predicted_label=None,
            status=ModelInferenceStatus.ERROR,
            error_message=str(model_err),
        )

    # 9. Evidence Fusion Engine (Phase 7A)
    try:
        fusion_result = fuse_evidence(
            url_analysis=url_analysis,
            authentication_analysis=auth_analysis,
            ip_intelligence=ip_analysis,
            model_inference=model_result,
            header_info=header_info,
            body_info=body_info,
            attachments=attachments,
        )
    except Exception as fuse_err:
        warnings.append(f"Evidence fusion analysis non-fatal warning: {str(fuse_err)}")
        fusion_result = None

    status = "partial_success" if warnings else "success"
    parsed_at_iso = datetime.now(timezone.utc).isoformat()

    return EmailAnalysisResponse(
        filename=filename,
        file_size_bytes=len(file_bytes),
        headers=header_info,
        body=body_info,
        urls=extracted_urls,
        attachments=attachments,
        ip_candidates=ip_candidates,
        url_analysis=url_analysis,
        authentication_analysis=auth_analysis,
        ip_intelligence=ip_analysis,
        evidence_fusion=fusion_result,
        model_inference=model_result,
        parsing_status=status,
        warnings=warnings,
        parsed_at=parsed_at_iso,
    )
