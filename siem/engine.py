"""Detection Engine for PySIEM.

Evaluates security detection rules against normalized event streams,
supporting threshold, distinct value counts, and sequential correlation.
"""

from collections import defaultdict
from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple, Union

from siem import storage
from siem.rules import Rule, load_rules


def _iso_to_epoch(ts: str) -> float:
    """Parse UTC ISO 8601 timestamp string to epoch seconds."""
    clean_ts = ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(clean_ts)
        return dt.timestamp()
    except Exception:
        return 0.0


def _matches_condition(event: Dict[str, Any], condition: Dict[str, Any]) -> bool:
    """Check if an event matches all key-value constraints in rule condition."""
    for key, expected in condition.items():
        actual = event.get(key)
        if isinstance(expected, bool):
            if bool(actual) != expected:
                return False
        elif isinstance(expected, str):
            if str(actual or "").lower() != expected.lower():
                return False
        else:
            if actual != expected:
                return False
    return True


def _get_group_key(event: Dict[str, Any], group_by: Union[str, List[str]]) -> str:
    """Extract a composite string group key from event fields."""
    if isinstance(group_by, str):
        val = event.get(group_by)
        return str(val) if val is not None else "unknown"
    keys = [str(event.get(k) or "unknown") for k in group_by]
    return ":".join(keys)


class DetectionEngine:
    """Detection engine evaluating events against rule definitions."""

    def __init__(self, rules: Optional[List[Rule]] = None, rules_dir: Optional[str] = None):
        if rules is not None:
            self.rules = rules
        elif rules_dir:
            self.rules = load_rules(rules_dir)
        else:
            self.rules = []

    def evaluate_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate a list of events against all configured detection rules."""
        if not events or not self.rules:
            return []

        # Sort events by timestamp ascending for accurate sliding windows
        sorted_events = sorted(events, key=lambda e: _iso_to_epoch(e.get("timestamp", "")))
        generated_alerts: List[Dict[str, Any]] = []

        for rule in self.rules:
            if rule.type == "threshold":
                alerts = self._eval_threshold_rule(rule, sorted_events)
            elif rule.type == "distinct_threshold":
                alerts = self._eval_distinct_threshold_rule(rule, sorted_events)
            elif rule.type == "sequence":
                alerts = self._eval_sequence_rule(rule, sorted_events)
            else:
                alerts = []
            generated_alerts.extend(alerts)

        return generated_alerts

    def _eval_threshold_rule(self, rule: Rule, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect when count of condition-matching events >= threshold within window."""
        alerts: List[Dict[str, Any]] = []
        matching = [e for e in events if _matches_condition(e, rule.condition)]
        if not matching:
            return []

        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in matching:
            grouped[_get_group_key(ev, rule.group_by)].append(ev)

        for group_key, group_events in grouped.items():
            if len(group_events) < rule.threshold:
                continue

            # Sliding window check
            i = 0
            while i < len(group_events):
                start_epoch = _iso_to_epoch(group_events[i]["timestamp"])
                window_evs = [
                    e for e in group_events[i:]
                    if (_iso_to_epoch(e["timestamp"]) - start_epoch) <= rule.window_seconds
                ]

                if len(window_evs) >= rule.threshold:
                    first_seen = window_evs[0]["timestamp"]
                    last_seen = window_evs[-1]["timestamp"]
                    raw_fp = f"{rule.id}_{group_key}"
                    fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()[:16]

                    alerts.append({
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "title": f"{rule.name} [{group_key}]",
                        "description": (
                            f"{len(window_evs)} events detected matching rule "
                            f"within {rule.window_seconds}s (threshold {rule.threshold})"
                        ),
                        "mitre_tag": rule.mitre_attack,
                        "fingerprint": fp,
                        "status": "new",
                        "event_count": len(window_evs),
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "details": {
                            "group_key": group_key,
                            "count": len(window_evs),
                            "usernames": list({e.get("username") for e in window_evs if e.get("username")}),
                            "src_ip": window_evs[0].get("src_ip"),
                        },
                    })
                    # Advance past this window to avoid duplicate sub-windows
                    i += len(window_evs)
                else:
                    i += 1

        return alerts

    def _eval_distinct_threshold_rule(self, rule: Rule, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect when number of distinct values for a field >= threshold within window."""
        alerts: List[Dict[str, Any]] = []
        matching = [e for e in events if _matches_condition(e, rule.condition)]
        if not matching:
            return []

        distinct_field = rule.distinct_field or "username"
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in matching:
            grouped[_get_group_key(ev, rule.group_by)].append(ev)

        for group_key, group_events in grouped.items():
            distinct_all = {e.get(distinct_field) for e in group_events if e.get(distinct_field)}
            if len(distinct_all) < rule.threshold:
                continue

            i = 0
            while i < len(group_events):
                start_epoch = _iso_to_epoch(group_events[i]["timestamp"])
                window_evs = [
                    e for e in group_events[i:]
                    if (_iso_to_epoch(e["timestamp"]) - start_epoch) <= rule.window_seconds
                ]
                distinct_in_window = {e.get(distinct_field) for e in window_evs if e.get(distinct_field)}

                if len(distinct_in_window) >= rule.threshold:
                    first_seen = window_evs[0]["timestamp"]
                    last_seen = window_evs[-1]["timestamp"]
                    raw_fp = f"{rule.id}_{group_key}"
                    fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()[:16]

                    alerts.append({
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "severity": rule.severity,
                        "title": f"{rule.name} [{group_key}]",
                        "description": (
                            f"{len(distinct_in_window)} distinct {distinct_field}s targeted "
                            f"from {group_key} within {rule.window_seconds}s"
                        ),
                        "mitre_tag": rule.mitre_attack,
                        "fingerprint": fp,
                        "status": "new",
                        "event_count": len(window_evs),
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "details": {
                            "group_key": group_key,
                            "distinct_field": distinct_field,
                            "distinct_values": sorted(list(distinct_in_window)),
                            "total_events": len(window_evs),
                            "src_ip": window_evs[0].get("src_ip"),
                        },
                    })
                    i += len(window_evs)
                else:
                    i += 1

        return alerts

    def _eval_sequence_rule(self, rule: Rule, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect multiple failed logins followed by a successful login for the same group."""
        alerts: List[Dict[str, Any]] = []
        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in events:
            if ev.get("activity") == "authentication":
                grouped[_get_group_key(ev, rule.group_by)].append(ev)

        for group_key, group_events in grouped.items():
            recent_failures: List[Dict[str, Any]] = []

            for ev in group_events:
                outcome = (ev.get("outcome") or "").lower()
                ev_epoch = _iso_to_epoch(ev.get("timestamp", ""))

                # Expire failures outside window
                recent_failures = [
                    f for f in recent_failures
                    if (ev_epoch - _iso_to_epoch(f.get("timestamp", ""))) <= rule.window_seconds
                ]

                if outcome == "failure":
                    recent_failures.append(ev)
                elif outcome == "success":
                    if len(recent_failures) >= rule.failure_threshold:
                        first_seen = recent_failures[0]["timestamp"]
                        last_seen = ev["timestamp"]
                        raw_fp = f"{rule.id}_{group_key}_{last_seen}"
                        fp = hashlib.sha256(raw_fp.encode("utf-8")).hexdigest()[:16]

                        alerts.append({
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "severity": rule.severity,
                            "title": f"{rule.name} [{group_key}]",
                            "description": (
                                f"{len(recent_failures)} failed logins followed by successful login "
                                f"for {group_key} within {rule.window_seconds}s"
                            ),
                            "mitre_tag": rule.mitre_attack,
                            "fingerprint": fp,
                            "status": "new",
                            "event_count": len(recent_failures) + 1,
                            "first_seen": first_seen,
                            "last_seen": last_seen,
                            "details": {
                                "group_key": group_key,
                                "failure_count": len(recent_failures),
                                "successful_login": ev,
                                "src_ip": ev.get("src_ip"),
                                "username": ev.get("username"),
                            },
                        })
                        recent_failures.clear()

        return alerts

    def process_and_store(
        self,
        events: List[Dict[str, Any]],
        db_path: str = "pysiem.db",
    ) -> Tuple[List[int], List[Dict[str, Any]]]:
        """
        Store normalized events, run detection, and persist/aggregate alerts.
        """
        if not events:
            return [], []

        # 1. Parameterized batch insert into SQLite
        event_ids = storage.insert_events(events, db_path=db_path)

        # 2. Evaluate detection rules
        alerts = self.evaluate_events(events)

        # 3. Store/deduplicate alerts in SQLite
        persisted_alerts: List[Dict[str, Any]] = []
        for alert in alerts:
            rec, _ = storage.insert_or_update_alert(alert, db_path=db_path)
            persisted_alerts.append(rec)

        return event_ids, persisted_alerts
