"""Log ingestion pipeline for PySIEM.

Provides file ingestion utilities and pipeline execution connecting
raw logs to parser, normalizer, detection engine, and database storage.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from siem.config import DB_PATH, RULES_DIR
from siem.engine import DetectionEngine
from siem.parser import normalize_event, parse_line
from siem import storage


def ingest_log_file(
    filepath: Union[str, Path],
    db_path: str = DB_PATH,
    rules_dir: str = RULES_DIR,
) -> Dict[str, Any]:
    """
    Ingest a local log file, parse, normalize, store, and trigger detection.
    Returns summary metrics.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    storage.init_db(db_path)
    engine = DetectionEngine(rules_dir=rules_dir)

    parsed_events: List[Dict[str, Any]] = []
    ignored_count = 0
    unrecognized_count = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue

            event = parse_line(line_str, normalize=True)
            if event:
                parsed_events.append(event)
            else:
                from siem.parser import is_ignored_line
                if is_ignored_line(line_str):
                    ignored_count += 1
                else:
                    unrecognized_count += 1

    event_ids, alerts = engine.process_and_store(parsed_events, db_path=db_path)

    return {
        "file": str(path),
        "total_lines_parsed": len(parsed_events),
        "ignored_lines": ignored_count,
        "unrecognized_lines": unrecognized_count,
        "events_stored": len(event_ids),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }


def ingest_raw_lines(
    lines: List[str],
    db_path: str = DB_PATH,
    rules_dir: str = RULES_DIR,
) -> Dict[str, Any]:
    """Ingest a batch of raw log lines in memory (e.g. from HTTP ingestion)."""
    storage.init_db(db_path)
    engine = DetectionEngine(rules_dir=rules_dir)

    parsed_events: List[Dict[str, Any]] = []
    ignored_count = 0
    unrecognized_count = 0

    from siem.parser import is_ignored_line

    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        event = parse_line(line_str, normalize=True)
        if event:
            parsed_events.append(event)
        elif is_ignored_line(line_str):
            ignored_count += 1
        else:
            unrecognized_count += 1

    event_ids, alerts = engine.process_and_store(parsed_events, db_path=db_path)

    return {
        "events_stored": len(event_ids),
        "ignored_count": ignored_count,
        "unrecognized_count": unrecognized_count,
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }


def ingest_structured_events(
    raw_events: List[Dict[str, Any]],
    db_path: str = DB_PATH,
    rules_dir: str = RULES_DIR,
) -> Dict[str, Any]:
    """Ingest pre-structured events, normalize them, store, and run detection."""
    storage.init_db(db_path)
    engine = DetectionEngine(rules_dir=rules_dir)

    normalized_events = [normalize_event(e) for e in raw_events]
    event_ids, alerts = engine.process_and_store(normalized_events, db_path=db_path)

    return {
        "events_stored": len(event_ids),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }
