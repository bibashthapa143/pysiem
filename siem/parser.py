"""Prototype parser for SSH 'Failed password' lines from auth.log."""

import re
from typing import Optional

# Compiled once at import time. The pattern is anchored with ^ and built from
# simple, specific pieces: log lines are untrusted input, and vague patterns
# like (.*)(.*) can be slow on crafted input (regex denial of service).
FAILED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<program>\w+)\[(?P<pid>\d+)\]: "
    r"Failed password for (?P<invalid>invalid user )?(?P<username>\S+) "
    r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)

# Regex pattern for SSH successful authentication events.
# Capture groups extract the same core fields as failed-password events.
ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+ \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?P<program>\w+)\[(?P<pid>\d+)\]: "
    r"Accepted password for (?P<username>\S+) "
    r"from (?P<src_ip>\S+) port (?P<src_port>\d+)"
)

def parse_failed_password(line: str) -> Optional[dict]:
    """Return a dict of fields if the line is a failed-password event, else None."""
    match = FAILED_PASSWORD_PATTERN.match(line)
    if match is None:
        return None

    event = match.groupdict()
    event["pid"] = int(event["pid"])
    event["src_port"] = int(event["src_port"])
    # Note: username and src_ip are still plain text from the log. The username
    # is attacker-controlled, so never trust it blindly (e.g. in SQL or HTML).
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
    event["activity"] = "authentication"
    event["outcome"] = "success"


    return event

    
def parse_file(path: str) -> tuple[list[dict], int]:
    """Parse a log file and return (failed-password events, skipped line count)."""
    events = []
    skipped = 0
    # errors="replace" keeps a stray bad byte in a log from crashing the parser.
    with open(path, encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            line = line.strip()
            event = parse_failed_password(line) or parse_accepted_password(line)
            if event is not None:
                events.append(event)
            else:
                skipped += 1
    return events, skipped

def main() -> None:
    events, skipped = parse_file("sample_logs/auth_sample.log")
    print(f"Parsed {len(events)} events")
    print(f"Skipped {skipped} lines")
    for event in events:
        print(event["outcome"], event["username"], event["src_ip"])


if __name__ == "__main__":
    main()