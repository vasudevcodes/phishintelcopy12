"""
Standalone Evidence Fusion Engine for PhishIntel (Phase 7A).
Synthesizes findings from DistilBERT text classification, URL intelligence,
email authentication (SPF/DKIM/DMARC), and IP transit intelligence.

Transparent, deterministic, explainable.
Preserves uncertainty, avoids double-counting correlated signals, and
strictly refrains from outputting uncalibrated overall probabilities.
"""

from typing import Any, Dict, List, Optional, Set, Tuple, Union

from app.schemas.email import AttachmentInfo, EmailBodyInfo, EmailHeaderInfo
from app.schemas.evidence_fusion import (
    AssessmentCategory,
    AuthEvidenceSummary,
    EvidenceCompletenessStatus,
    EvidenceFusionResult,
    IPEvidenceSummary,
    ModelEvidenceInterpretation,
    ModelInferenceEvidence,
    ModelInferenceStatus,
    URLEvidenceSummary,
)
from app.schemas.email_authentication import EmailAuthenticationAnalysis
from app.schemas.ip_intelligence import IPIntelligenceResult
from app.schemas.url_intelligence import URLBatchAnalysisResult
from app.services.scoring_engine import calculate_phishing_risk_score


def _extract_url_evidence(
    url_analysis: Optional[URLBatchAnalysisResult],
) -> Tuple[URLEvidenceSummary, List[str], List[str]]:
    """
    Consolidates URL intelligence evidence and collapses duplicates by hostname
    to prevent double-counting multiple links pointing to the same destination.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if not url_analysis or url_analysis.total_urls == 0:
        missing_or_inconclusive.append("No extracted URLs present to evaluate for structural link risks.")
        summary = URLEvidenceSummary(
            total_urls=0,
            unique_domains=0,
            highest_heuristic_risk="NONE",
            suspicious_indicators=[],
            deduplication_applied=False,
            explanation="No URLs were detected in the email body.",
        )
        return summary, contributing, missing_or_inconclusive

    total_urls = url_analysis.total_urls
    unique_domains_set: Set[str] = set()
    indicators_set: Set[str] = set()
    highest_risk = url_analysis.highest_risk_category.value if hasattr(url_analysis.highest_risk_category, "value") else str(url_analysis.highest_risk_category)

    # Track observations by destination hostname to prevent double counting
    for res in url_analysis.url_results:
        host = res.normalized_hostname or res.features.normalized_host or res.features.raw_host or "unknown-host"
        unique_domains_set.add(host)

        for obs in res.observations:
            if obs.severity.value in ["MEDIUM", "HIGH"]:
                name = getattr(obs, "rule_name", getattr(obs, "title", "Indicator"))
                indicators_set.add(f"{name} ({obs.rule_id})")

    unique_domains = len(unique_domains_set)
    indicators = sorted(list(indicators_set))

    if highest_risk == "HIGH":
        contributing.append(
            f"High-risk URL heuristics detected across {unique_domains} unique destination host(s): "
            + (", ".join(indicators[:3]) if indicators else "Elevated structural risk")
        )
    elif highest_risk == "MEDIUM":
        contributing.append(
            f"Moderate URL heuristic risk detected across {unique_domains} unique destination host(s): "
            + (", ".join(indicators[:2]) if indicators else "Moderate structural indicators")
        )
    else:
        missing_or_inconclusive.append(f"Extracted {total_urls} URL(s) across {unique_domains} domain(s) with negligible heuristic risk.")

    explanation = (
        f"Analyzed {total_urls} URL(s) pointing to {unique_domains} distinct host(s). "
        f"Highest heuristic risk: {highest_risk}. Deduplication applied across repeated link occurrences."
    )

    summary = URLEvidenceSummary(
        total_urls=total_urls,
        unique_domains=unique_domains,
        highest_heuristic_risk=highest_risk,
        suspicious_indicators=indicators,
        deduplication_applied=True,
        explanation=explanation,
    )
    return summary, contributing, missing_or_inconclusive


def _extract_auth_evidence(
    auth_analysis: Optional[EmailAuthenticationAnalysis],
) -> Tuple[AuthEvidenceSummary, List[str], List[str]]:
    """
    Consolidates email authentication evidence (SPF, DKIM, DMARC),
    handling correlated failures (e.g. SPF failure causing downstream DMARC failure),
    and distinguishing reported assertions from independently established evidence.

    Stage A.2: has_valid_authentication now reflects provenance_status.
    For offline .eml uploads, all authentication is REPORTED — even SPF/DKIM/DMARC PASS
    cannot be considered independently verified evidence. has_valid_authentication
    represents "all protocols passed AND provenance is independently established",
    which is never True for offline uploads.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if not auth_analysis or auth_analysis.status.value == "NO_EVIDENCE":
        missing_or_inconclusive.append("No SPF, DKIM, or DMARC authentication headers were recorded by receiving MTAs.")
        summary = AuthEvidenceSummary(
            spf_status="NOT_PRESENT",
            dkim_status="NOT_PRESENT",
            dmarc_status="NOT_PRESENT",
            has_conflicts=False,
            has_valid_authentication=False,
            has_explicit_failure=False,
            correlated_failure_noted=False,
            boundary_authserv_trust="MISSING",
            is_boundary_trusted=False,
            explanation="No authentication results were available in the message headers.",
        )
        return summary, contributing, missing_or_inconclusive

    spf_st = auth_analysis.spf.status.value if hasattr(auth_analysis.spf.status, "value") else str(auth_analysis.spf.status)
    dkim_st = auth_analysis.dkim.status.value if hasattr(auth_analysis.dkim.status, "value") else str(auth_analysis.dkim.status)
    dmarc_st = auth_analysis.dmarc.status.value if hasattr(auth_analysis.dmarc.status, "value") else str(auth_analysis.dmarc.status)
    has_conflicts = auth_analysis.has_conflicts
    is_boundary_trusted = getattr(auth_analysis, "is_boundary_trusted", False)
    boundary_authserv = getattr(auth_analysis, "boundary_authserv_id", None)
    boundary_trust = getattr(auth_analysis, "boundary_authserv_trust", "UNTRUSTED")
    boundary_trust_str = boundary_trust.value if hasattr(boundary_trust, "value") else str(boundary_trust)

    # Stage A.2: Read provenance_status to distinguish reported vs verified authentication.
    provenance_status = getattr(auth_analysis, "provenance_status", None)
    provenance_str = provenance_status.value if hasattr(provenance_status, "value") else str(provenance_status) if provenance_status else "REPORTED_AUTHENTICATION"

    has_pass = any(s == "PASS" for s in [spf_st, dkim_st, dmarc_st])
    has_fail = any(s == "FAIL" for s in [spf_st, dkim_st, dmarc_st])
    live_mode = getattr(auth_analysis, "verification_mode", "OFFLINE_REPORTED") == "LIVE_DNS"

    # Correlate failures: In RFC 7489, DMARC failure often directly results from SPF/DKIM failure
    correlated_failure = False
    if dmarc_st == "FAIL" and (spf_st == "FAIL" or dkim_st in ["FAIL", "NOT_PRESENT"]):
        correlated_failure = True

    all_auth_findings = (
        auth_analysis.spf.findings
        + auth_analysis.dkim.findings
        + auth_analysis.dmarc.findings
    )
    has_any_pass_finding = any(
        (f.result.value if hasattr(f.result, "value") else str(f.result)) == "PASS"
        for f in all_auth_findings
    )

    # Stage A.2: has_valid_authentication = True only when provenance is independently established.
    # For offline .eml uploads provenance_status is REPORTED_AUTHENTICATION or weaker,
    # so has_valid_authentication is always False in that context.
    # This prevents the evidence fusion engine from treating reported PASS as a trust signal.
    if provenance_str == "TRUSTED_RECEIVER_EVIDENCE" and has_pass and is_boundary_trusted:
        has_valid_auth = True
    elif live_mode and dmarc_st == "PASS":
        # Live mode: PhishIntel itself verified an aligned SPF/DKIM pass against live DNS.
        has_valid_auth = True
    else:
        has_valid_auth = False

    if live_mode:
        contributing.append(
            "Authentication was independently re-verified by PhishIntel through live DNS lookups "
            "(SPF check_host, DKIM public-key signature check, DMARC policy and alignment) rather than taken from header claims."
        )

    if has_any_pass_finding and not is_boundary_trusted and not live_mode:
        if boundary_trust_str in ("UNTRUSTED", "SUSPICIOUS"):
            contributing.append(
                f"Authentication results were recorded by an untrusted or unrecognized authserv-id ('{boundary_authserv}')."
            )
        elif boundary_trust_str == "REPORTED":
            # Stage A.2: authserv-id matched a known gateway name but provenance is unverified.
            contributing.append(
                f"Authentication results claim '{boundary_authserv}' as the recording MTA, but this is an offline .eml upload — "
                "the authserv-id string cannot be independently verified as genuine. "
                "Authentication assertions are REPORTED (unverified provenance)."
            )
        else:
            contributing.append(
                "Authentication results were recorded only on upstream or untrusted hops, not at the recipient boundary MTA."
            )

    if has_conflicts:
        contributing.append("Contradictory authentication evidence detected across multiple intermediate receiving MTAs.")
    elif has_fail:
        if correlated_failure:
            contributing.append(f"Explicit authentication failure observed: SPF={spf_st}, DKIM={dkim_st}, with correlated downstream DMARC={dmarc_st}.")
        else:
            contributing.append(f"Explicit authentication failure observed: SPF={spf_st}, DKIM={dkim_st}, DMARC={dmarc_st}.")
    elif has_pass and not has_fail and live_mode:
        missing_or_inconclusive.append(
            f"Live DNS verification: SPF={spf_st}, DKIM={dkim_st}, DMARC={dmarc_st}. "
            "A pass shows the sender controls the authenticated domain; it does not show the message is benign "
            "(attackers can authenticate their own look-alike domains)."
        )
    elif has_pass and not has_fail:
        authserv_info = f" via reported MTA ({boundary_authserv})" if boundary_authserv else ""
        missing_or_inconclusive.append(
            f"Receiver-reported domain authentication passed (SPF={spf_st}, DKIM={dkim_st}, DMARC={dmarc_st}){authserv_info}. "
            f"Provenance: {provenance_str}. "
            "Note: Reported authentication reflects MTA header assertions (RFC 8601) — "
            "these cannot be independently verified in an offline context and do not guarantee benign intent."
        )

    if any(s in ["SOFTFAIL", "NEUTRAL"] for s in [spf_st, dkim_st]):
        contributing.append(f"Ambiguous or permissive SPF policy outcome observed (SPF={spf_st}).")

    explanation = (
        f"Authentication evaluation: SPF={spf_st}, DKIM={dkim_st}, DMARC={dmarc_st}. "
        f"Provenance: {provenance_str}. "
        f"Conflicting headers: {has_conflicts}. Correlated failures accounted for: {correlated_failure}. "
        f"Boundary MTA trusted: {is_boundary_trusted} ({boundary_trust_str})."
    )

    summary = AuthEvidenceSummary(
        spf_status=spf_st,
        dkim_status=dkim_st,
        dmarc_status=dmarc_st,
        has_conflicts=has_conflicts,
        has_valid_authentication=has_valid_auth,
        has_explicit_failure=has_fail,
        correlated_failure_noted=correlated_failure,
        boundary_authserv_trust=boundary_trust_str,
        is_boundary_trusted=is_boundary_trusted,
        verification_mode="LIVE_DNS" if live_mode else "OFFLINE_REPORTED",
        explanation=explanation,
    )
    return summary, contributing, missing_or_inconclusive


def _extract_ip_evidence(
    ip_analysis: Optional[IPIntelligenceResult],
) -> Tuple[IPEvidenceSummary, List[str], List[str]]:
    """
    Consolidates IP intelligence transit findings and provenance.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if not ip_analysis or ip_analysis.total_candidates == 0:
        missing_or_inconclusive.append("No candidate IP addresses were available from Received headers.")
        summary = IPEvidenceSummary(
            apparent_origin_ip=None,
            origin_classification="Unavailable",
            is_routable=False,
            hop_count=0,
            explanation="No Received headers containing IP addresses were detected.",
        )
        return summary, contributing, missing_or_inconclusive

    origin = ip_analysis.origin_candidate
    origin_ip = origin.ip if origin else None
    origin_cls = origin.classification.value if origin and hasattr(origin.classification, "value") else (origin.classification if origin else "Unavailable")
    is_routable = origin.is_routable if origin else False
    hop_count = ip_analysis.total_candidates

    if origin:
        if is_routable:
            missing_or_inconclusive.append(f"Apparent origin relay is a globally routable public IP ({origin_ip}).")
        else:
            missing_or_inconclusive.append(f"Apparent origin relay is classified as non-routable {origin_cls} ({origin_ip}).")

    explanation = f"Analyzed {hop_count} transit hop candidate(s). Apparent origin: {origin_ip or 'None'} ({origin_cls})."

    summary = IPEvidenceSummary(
        apparent_origin_ip=origin_ip,
        origin_classification=origin_cls,
        is_routable=is_routable,
        hop_count=hop_count,
        explanation=explanation,
    )
    return summary, contributing, missing_or_inconclusive


def _extract_model_evidence(
    model_inference: Optional[Union[ModelInferenceEvidence, Dict[str, Any]]],
) -> Tuple[ModelEvidenceInterpretation, List[str], List[str]]:
    """
    Interprets DistilBERT model inference output with explicit calibration caveats.
    """
    contributing: List[str] = []
    missing_or_inconclusive: List[str] = []

    if model_inference is None:
        missing_or_inconclusive.append("DistilBERT Transformer NLP model inference was not executed for this request.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.UNAVAILABLE,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation="Model inference was not supplied or executed.",
        )
        return interpretation, contributing, missing_or_inconclusive

    score = getattr(model_inference, "uncalibrated_score", None)
    label = getattr(model_inference, "predicted_label", None)
    status_override = getattr(model_inference, "status", None)
    error_msg = getattr(model_inference, "error_message", None)
    if isinstance(model_inference, dict):
        score = model_inference.get("uncalibrated_score")
        label = model_inference.get("predicted_label")
        status_override = model_inference.get("status")
        error_msg = model_inference.get("error_message")

    if status_override == ModelInferenceStatus.ERROR or (status_override and str(status_override).upper() == "ERROR"):
        missing_or_inconclusive.append(f"DistilBERT model inference encountered an error: {error_msg or 'Execution failed'}.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.ERROR,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation=f"Model inference failed: {error_msg or 'Execution error'}.",
        )
        return interpretation, contributing, missing_or_inconclusive

    if status_override == ModelInferenceStatus.UNAVAILABLE or (status_override and str(status_override).upper() == "UNAVAILABLE"):
        missing_or_inconclusive.append(f"DistilBERT model inference was unavailable: {error_msg or 'Checkpoint not found'}.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.UNAVAILABLE,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation=f"Model inference unavailable: {error_msg or 'Checkpoint not found'}.",
        )
        return interpretation, contributing, missing_or_inconclusive

    if score is None:
        missing_or_inconclusive.append("DistilBERT model output score is missing or null.")
        interpretation = ModelEvidenceInterpretation(
            status=ModelInferenceStatus.UNAVAILABLE,
            uncalibrated_score=None,
            predicted_label=None,
            interpretation="Model inference output incomplete.",
        )
        return interpretation, contributing, missing_or_inconclusive

    if score >= 0.7:
        contributing.append(f"DistilBERT model indicated elevated textual similarity to phishing lures (uncalibrated score: {score:.3f}).")
        text_interp = f"Model predicts phishing (label {label}) with uncalibrated phishing score {score:.3f}."
    elif score >= 0.4:
        contributing.append(f"DistilBERT model indicated borderline/indeterminate semantic evidence (uncalibrated score: {score:.3f}).")
        text_interp = f"Model indicates borderline text classification (uncalibrated score {score:.3f})."
    else:
        missing_or_inconclusive.append(f"DistilBERT model indicated low textual similarity to phishing lures (uncalibrated score: {score:.3f}).")
        text_interp = f"Model predicts benign text (label {label}) with low phishing similarity ({score:.3f})."

    interpretation = ModelEvidenceInterpretation(
        status=ModelInferenceStatus.EVALUATED,
        uncalibrated_score=score,
        predicted_label=label,
        interpretation=text_interp,
    )
    return interpretation, contributing, missing_or_inconclusive


def _format_forensic_explanation(
    category: AssessmentCategory,
    primary_rationale: str,
    model_summary: ModelEvidenceInterpretation,
    url_summary: URLEvidenceSummary,
    auth_summary: AuthEvidenceSummary,
) -> str:
    """
    Constructs a dynamic, fully evidence-grounded forensic explanation for the assessment.
    Guarantees no invented findings and no hardcoded false conflict statements.
    """
    parts: List[str] = [primary_rationale]

    # Model evidence component
    if model_summary.status == ModelInferenceStatus.EVALUATED and model_summary.uncalibrated_score is not None:
        parts.append(
            f"Model evidence: DistilBERT NLP uncalibrated phishing score {model_summary.uncalibrated_score:.3f} "
            f"(predicted label {model_summary.predicted_label})."
        )
    elif model_summary.status == ModelInferenceStatus.ERROR:
        parts.append("Model evidence: DistilBERT inference encountered an execution error.")
    else:
        parts.append("Model evidence: DistilBERT inference was unavailable or not evaluated.")

    # URL evidence component
    if url_summary.total_urls > 0:
        if url_summary.suspicious_indicators:
            indicators_str = ", ".join(url_summary.suspicious_indicators[:3])
            parts.append(
                f"URL evidence: {url_summary.total_urls} link(s) across {url_summary.unique_domains} domain(s) "
                f"with highest heuristic risk '{url_summary.highest_heuristic_risk}' (indicators: {indicators_str})."
            )
        else:
            parts.append(
                f"URL evidence: {url_summary.total_urls} link(s) across {url_summary.unique_domains} domain(s) "
                f"with negligible structural risk ('{url_summary.highest_heuristic_risk}')."
            )
    else:
        parts.append("URL evidence: No links detected in message body.")

    # Authentication evidence component
    has_any_pass = any(s == "PASS" for s in [auth_summary.spf_status, auth_summary.dkim_status, auth_summary.dmarc_status])
    has_any_results = any(s != "NOT_PRESENT" for s in [auth_summary.spf_status, auth_summary.dkim_status, auth_summary.dmarc_status])

    if auth_summary.has_explicit_failure:
        if auth_summary.is_boundary_trusted:
            parts.append(
                f"Authentication evidence: Explicit failure verified by recipient boundary MTA (SPF={auth_summary.spf_status}, "
                f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})."
            )
        else:
            parts.append(
                f"Authentication evidence: Explicit failure {'verified by live DNS lookup' if getattr(auth_summary, 'verification_mode', '') == 'LIVE_DNS' else 'reported in headers'} (SPF={auth_summary.spf_status}, "
                f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})"
                + ("." if getattr(auth_summary, "verification_mode", "") == "LIVE_DNS" else ", but assertions cannot be independently verified offline.")
            )
    elif auth_summary.has_conflicts:
        parts.append(
            f"Authentication evidence: Conflicting authentication assertions recorded across intermediate MTAs "
            f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})."
        )
    elif auth_summary.is_boundary_trusted and auth_summary.has_valid_authentication:
        parts.append(
            f"Authentication evidence: Cryptographically verified receiver-boundary authentication passed "
            f"(SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})."
        )
    elif has_any_pass and getattr(auth_summary, "verification_mode", "OFFLINE_REPORTED") == "LIVE_DNS":
        parts.append(
            f"Authentication evidence: Live DNS verification passed (SPF={auth_summary.spf_status}, "
            f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}); this confirms control of the authenticated domain, not benign intent."
        )
    elif has_any_pass:
        parts.append(
            f"Authentication evidence: Receiver-reported domain authentication passed (SPF={auth_summary.spf_status}, "
            f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}). Note: In offline analysis, reported authentication "
            "assertions within the file cannot be independently verified."
        )
    elif has_any_results:
        parts.append(
            f"Authentication evidence: Neutral or indeterminate authentication results recorded (SPF={auth_summary.spf_status}, "
            f"DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status})."
        )
    else:
        parts.append("Authentication evidence: No authentication results present in email headers.")

    return " ".join(parts)


def fuse_evidence(
    url_analysis: Optional[URLBatchAnalysisResult] = None,
    authentication_analysis: Optional[EmailAuthenticationAnalysis] = None,
    ip_intelligence: Optional[IPIntelligenceResult] = None,
    model_inference: Optional[Union[ModelInferenceEvidence, Dict[str, Any]]] = None,
    header_info: Optional[EmailHeaderInfo] = None,
    body_info: Optional[EmailBodyInfo] = None,
    attachments: Optional[List[AttachmentInfo]] = None,
) -> EvidenceFusionResult:
    """
    Main entry point for Evidence Fusion Engine.
    Synthesizes multi-modal observations into an explainable 0-100 Phishing Risk Score.
    """
    all_contributing: List[str] = []
    all_missing: List[str] = []

    # 1. Extract component evidence
    url_summary, url_contrib, url_missing = _extract_url_evidence(url_analysis)
    auth_summary, auth_contrib, auth_missing = _extract_auth_evidence(authentication_analysis)
    ip_summary, ip_contrib, ip_missing = _extract_ip_evidence(ip_intelligence)
    model_summary, model_contrib, model_missing = _extract_model_evidence(model_inference)

    all_contributing.extend(url_contrib)
    all_contributing.extend(auth_contrib)
    all_contributing.extend(ip_contrib)
    all_contributing.extend(model_contrib)

    all_missing.extend(url_missing)
    all_missing.extend(auth_missing)
    all_missing.extend(ip_missing)
    all_missing.extend(model_missing)

    # 2. Convert dict model_inference if passed as dict
    parsed_model_evidence: Optional[ModelInferenceEvidence]
    if isinstance(model_inference, dict):
        parsed_model_evidence = ModelInferenceEvidence(**model_inference)
    elif isinstance(model_inference, ModelInferenceEvidence):
        parsed_model_evidence = model_inference
    else:
        parsed_model_evidence = None

    # 3. Calculate 0-100 Phishing Risk Score using Evidence-Based Scoring Engine
    (
        overall_score,
        category,
        breakdown,
        completeness_status,
        completeness_detail,
        pos_evidence,
        neg_evidence,
    ) = calculate_phishing_risk_score(
        header_info=header_info,
        body_info=body_info,
        attachments=attachments,
        url_analysis=url_analysis,
        auth_analysis=authentication_analysis,
        ip_analysis=ip_intelligence,
        model_inference=parsed_model_evidence,
    )

    # 4. Format natural-language reasoning explanation
    reasoning_parts = [
        f"Overall Phishing Risk Score: {overall_score}/100 ({category.value.replace('_', ' ')}).",
        f"Evidence completeness: {completeness_status.value} — {completeness_detail}",
        (
            f"Category contributions: Sender/Auth {breakdown.sender_auth.score}/25, "
            f"URLs {breakdown.url_intelligence.score}/25, Content/Language {breakdown.content_language.score}/20, "
            f"ML Model {breakdown.ml_model.score}/20, Header/IP {breakdown.header_ip.score}/10."
        ),
    ]
    if neg_evidence:
        reasoning_parts.append(f"Risk indicators: {'; '.join(neg_evidence[:3])}.")
    if url_summary.highest_heuristic_risk == "HIGH":
        reasoning_parts.append("Risk assessment driven by severe structural URL heuristics.")
    if pos_evidence:
        reasoning_parts.append(f"Mitigating observations: {'; '.join(pos_evidence[:3])}.")
    if parsed_model_evidence and parsed_model_evidence.uncalibrated_score is not None:
        reasoning_parts.append(
            f"Model evidence: DistilBERT NLP uncalibrated phishing score {parsed_model_evidence.uncalibrated_score:.3f}. {model_summary.interpretation}"
        )
    else:
        reasoning_parts.append(f"Model heuristic interpretation: {model_summary.interpretation}")
    if auth_summary.has_conflicts:
        reasoning_parts.append(f"Authentication evidence: {auth_summary.explanation}")
    else:
        reasoning_parts.append(
            f"Authentication evidence: SPF={auth_summary.spf_status}, DKIM={auth_summary.dkim_status}, DMARC={auth_summary.dmarc_status}."
        )

    reasoning = " ".join(reasoning_parts)

    # 5. Map evidence truthfully according to forensic semantics
    clean_positive = list(dict.fromkeys(pos_evidence))
    clean_negative = list(dict.fromkeys(neg_evidence))
    clean_missing = list(dict.fromkeys(all_missing))

    # Contributing factors represent findings that influenced the category
    if category in (AssessmentCategory.HIGH_RISK_INDICATORS_PRESENT, AssessmentCategory.REVIEW_RECOMMENDED):
        clean_contributing = list(dict.fromkeys(all_contributing + clean_negative))
    elif category == AssessmentCategory.LOW_RISK_INDICATORS:
        clean_contributing = list(dict.fromkeys(clean_positive + all_contributing))
    else:  # INSUFFICIENT_EVIDENCE
        clean_contributing = list(dict.fromkeys(all_contributing)) if all_contributing else [
            "Insufficient conclusive forensic indicators available to assign an elevated risk category."
        ]

    return EvidenceFusionResult(
        overall_category=category,
        overall_risk_score=overall_score,
        risk_score_breakdown=breakdown,
        evidence_completeness=completeness_status,
        evidence_completeness_detail=completeness_detail,
        positive_evidence=clean_positive,
        negative_evidence=clean_negative,
        model_evidence=model_summary,
        url_evidence=url_summary,
        auth_evidence=auth_summary,
        ip_evidence=ip_summary,
        contributing_factors=clean_contributing,
        inconclusive_or_missing_factors=clean_missing,
        reasoning=reasoning,
    )
