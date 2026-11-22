"""The five category scores plus the explicit safety-floor adjustment must equal the overall score."""
from pathlib import Path

import pytest

from app.services.email_parser import parse_email_message

FIXTURES_DIR = Path(__file__).parent / "fixtures"
EMLS = sorted(p for p in FIXTURES_DIR.glob("*.eml") if p.stat().st_size < 1_000_000 and p.stat().st_size > 0)


@pytest.mark.parametrize("path", EMLS, ids=lambda p: p.name)
def test_category_scores_add_up_to_overall(path):
    res = parse_email_message(path.read_bytes(), path.name)
    ef = res.evidence_fusion
    if ef is None or ef.risk_score_breakdown is None:
        pytest.skip("no evidence fusion for this fixture")
    b = ef.risk_score_breakdown
    category_total = (
        b.sender_auth.score + b.url_intelligence.score + b.content_language.score
        + b.ml_model.score + b.header_ip.score
    )
    assert b.category_sum == category_total
    assert category_total + b.floor_adjustment == ef.overall_risk_score
