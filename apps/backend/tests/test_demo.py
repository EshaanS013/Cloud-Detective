from datetime import UTC, datetime
from pathlib import Path

from cloud_detective.demo import demo_context, demo_events
from cloud_detective.detection.engine import DetectionEngine
from cloud_detective.detection.loader import load_rules
from cloud_detective.schemas.events import normalize_cloudtrail_event

RULES_PATH = Path(__file__).parents[3] / "rules" / "catalog.yaml"


def test_presentation_data_matches_every_rule_and_is_labeled_synthetic() -> None:
    now = datetime(2026, 10, 20, 8, 0, tzinfo=UTC)
    rules = load_rules(RULES_PATH)
    assert len(rules) == 21
    for rule in rules:
        engine = DetectionEngine([rule])
        findings = []
        for raw in demo_events(rule.id, now):
            assert raw["additionalEventData"]["simulation"] is True
            assert "000000000000" in raw["userIdentity"]["arn"]
            event = normalize_cloudtrail_event(raw)
            findings.extend(engine.process(event, demo_context(rule.id)))
        assert len(findings) == 1, rule.id
        assert findings[0].rule_id == rule.id
