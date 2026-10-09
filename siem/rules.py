"""YAML rule loader and validator for PySIEM detection engine."""

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import yaml


@dataclass
class Rule:
    """Detection rule specification."""
    id: str
    name: str
    description: str
    severity: str
    mitre_attack: str
    type: str  # 'threshold', 'distinct_threshold', 'sequence'
    window_seconds: int
    group_by: Union[str, List[str]]
    condition: Dict[str, Any] = field(default_factory=dict)
    threshold: int = 1
    distinct_field: Optional[str] = None
    failure_threshold: int = 3

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Rule":
        return cls(
            id=str(data["id"]),
            name=str(data["name"]),
            description=str(data.get("description", "")),
            severity=str(data.get("severity", "medium")).lower(),
            mitre_attack=str(data.get("mitre_attack", "")),
            type=str(data.get("type", "threshold")),
            window_seconds=int(data.get("window_seconds", 300)),
            group_by=data.get("group_by", "src_ip"),
            condition=dict(data.get("condition", {})),
            threshold=int(data.get("threshold", 1)),
            distinct_field=data.get("distinct_field"),
            failure_threshold=int(data.get("failure_threshold", 3)),
        )


def load_rule_file(filepath: Union[str, Path]) -> Rule:
    """Load and parse a single YAML rule file."""
    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Invalid rule format in {filepath}: expected YAML dictionary")
    return Rule.from_dict(data)


def load_rules(rules_dir: Union[str, Path]) -> List[Rule]:
    """Load all .yaml and .yml rules from the specified directory."""
    rules_path = Path(rules_dir)
    if not rules_path.exists():
        return []

    rules: List[Rule] = []
    for entry in sorted(rules_path.iterdir()):
        if entry.is_file() and entry.suffix.lower() in {".yaml", ".yml"}:
            try:
                rule = load_rule_file(entry)
                rules.append(rule)
            except Exception as e:
                # Log or re-raise without silent masking
                raise RuntimeError(f"Error loading rule file {entry}: {e}") from e
    return rules
