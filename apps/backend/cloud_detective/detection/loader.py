from pathlib import Path

import yaml

from cloud_detective.detection.models import RuleDefinition


def load_rules(path: Path) -> list[RuleDefinition]:
    """Load and validate every rule document in a file or directory."""
    files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    rules: list[RuleDefinition] = []
    seen_ids: set[str] = set()

    for file in files:
        payload = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        documents = payload.get("rules", []) if isinstance(payload, dict) else payload
        if not isinstance(documents, list):
            raise ValueError(f"{file} must contain a rule list")
        for document in documents:
            rule = RuleDefinition.model_validate(document)
            if rule.id in seen_ids:
                raise ValueError(f"duplicate rule id: {rule.id}")
            seen_ids.add(rule.id)
            rules.append(rule)

    return rules

