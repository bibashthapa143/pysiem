"""Log parser and event normalizer for PySIEM.

Extracts authentication events from SSH auth.log and normalizes them
into a common event schema.
"""

from datetime import datetime, timezone
import re
from typing import Optional, Tuple

# Compiled once at import time. The pattern is anchored with ^ and built from
# simple, specific pieces: log lines are untrusted input, and vague patterns
# like (.*)(.*) can be slow on crafted input (regex denial of service).
FAILED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<program>\w+)\[(?P<pid>\d+)\]: "
    r"Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?(?P<username>\S+) "
    r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)

# Regex pattern for SSH successful authentication events.
# Capture groups extract the same core fields as failed-password events.
ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<program>\w+)\[(?P<pid>\d+)\]: "
    r"Accepted (?P<method>password|publickey) for (?P<username>\S+) "
    r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)

# Lines we understand but deliberately do not turn into events.
# "Invalid user" duplicates the Failed password line that follows it.
IGNORED_MARKERS = ("Invalid user ", "Received disconnect")


def is_ignored_line(line: str) -> bool:
    """Return True if the line is known noise we skip on purpose."""
    return any(marker in line for marker in IGNORED_MARKERS)


def normalize_timestamp(ts_str: str, default_year: Optional[int] = None) -> str:
    """
    Convert a syslog timestamp (e.g. 'Oct  5 03:29:46' or 'Sep 28 04:27:18')
    or an ISO string to a standard UTC ISO 8601 string (e.g. '2026-10-05T03:29:46Z').
    """
    ts_str = ts_str.strip()
    if not ts_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # If already ISO-like (starts with YYYY-)
    if re.match(r"^\d{4}-\d{2}-\d{2}", ts_str):
        try:
            # Handle trailing Z or offsets
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            dt_utc = dt.astimezone(timezone.utc)
            return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass

    # Normalize multiple whitespace in syslog date (e.g. "Oct  5" -> "Oct 5")
    normalized_spaces = re.sub(r"\s+", " ", ts_str)
    year = default_year or datetime.now(timezone.utc).year

    # Syslog standard without year: prepend year to avoid ambiguous leap year warnings
    try:
        parsed = datetime.strptime(f"{year} {normalized_spaces}", "%Y %b %d %H:%M:%S")
        parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    try:
        parsed = datetime.strptime(normalized_spaces, "%b %d %Y %H:%M:%S")
        parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Fallback to current time if unparseable
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_event(event: dict, raw_line: str = "") -> dict:
    """
    Ensure the event conforms strictly to the common SIEM schema.
    """
    normalized = dict(event)
    normalized["timestamp"] = normalize_timestamp(normalized.get("timestamp", ""))
    normalized["host"] = str(normalized.get("host") or "unknown")
    normalized["program"] = str(normalized.get("program") or "unknown")
    if "pid" in normalized and normalized["pid"] is not None:
        normalized["pid"] = int(normalized["pid"])
    if "src_port" in normalized and normalized["src_port"] is not None:
        normalized["src_port"] = int(normalized["src_port"])
    normalized["username"] = str(normalized.get("username") or "")
    normalized["src_ip"] = str(normalized.get("src_ip") or "")
    normalized["method"] = str(normalized.get("method") or "password")
    normalized["activity"] = str(normalized.get("activity") or "authentication")
    normalized["outcome"] = str(normalized.get("outcome") or "unknown").lower()
    normalized["invalid_user"] = bool(normalized.get("invalid_user", False))
    normalized["raw_message"] = raw_line or normalized.get("raw_message", "")
    return normalized


def parse_failed_password(line: str) -> Optional[dict]:
    """Return a dict of fields if the line is a failed-password event, else None."""
    match = FAILED_PASSWORD_PATTERN.match(line)
    if match is None:
        return None

    event = match.groupdict()
    event["pid"] = int(event["pid"])
    event["src_port"] = int(event["src_port"])
    # Note: username and src_ip are plain text from the log (untrusted input).
    event["invalid_user"] = event.pop("invalid") is not None
    event["activity"] = "authentication"
    event["outcome"] = "failure"
    return event


def parse_accepted_password(line: str) -> Optional[dict]:
    """Return a dict of fields if the line is an accepted-password event, else None."""
    match = ACCEPTED_PASSWORD_PATTERN.match(line)
    if match is None:
        return None

    event = match.groupdict()
    event["pid"] = int(event["pid"])
    event["src_port"] = int(event["src_port"])
    event["invalid_user"] = False
    event["activity"] = "authentication"
    event["outcome"] = "success"
    return event


def parse_line(line: str, normalize: bool = True) -> Optional[dict]:
    """Parse a single raw log line into an event dict if recognized."""
    line_clean = line.strip()
    if not line_clean or is_ignored_line(line_clean):
        return None

    event = parse_failed_password(line_clean) or parse_accepted_password(line_clean)
    if event and normalize:
        return normalize_event(event, raw_line=line_clean)
    return event


def parse_file(path: str, normalize: bool = True) -> Tuple[list[dict], int, int]:
    """Parse a log file and return (events, ignored count, unrecognized count)."""
    events = []
    ignored = 0
    unrecognized = 0
    # errors="replace" keeps a stray bad byte in a log from crashing the parser.
    with open(path, encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            line_str = line.strip()
            if not line_str:
                continue

            event = parse_failed_password(line_str) or parse_accepted_password(line_str)
            if event is not None:
                if normalize:
                    event = normalize_event(event, raw_line=line_str)
                events.append(event)
            elif is_ignored_line(line_str):
                ignored += 1
            else:
                unrecognized += 1
    return events, ignored, unrecognized


def main() -> None:
    events, ignored, unrecognized = parse_file("sample_logs/auth_sample.log", normalize=True)
    print(f"Parsed {len(events)} events")
    print(f"Ignored {ignored} known-noise lines")
    print(f"Unrecognized {unrecognized} lines")

    for event in events:
        print(event)


if __name__ == "__main__":
    main()