from siem.parser import (
    is_ignored_line,
    parse_accepted_password,
    parse_failed_password,
)


def test_failed_password_outcome_is_failure():
    line = (
        "Sep 28 04:27:18 metasploitable sshd[5452]: "
        "Failed password for root from 10.0.2.4 port 35643 ssh2"
    )
    event = parse_failed_password(line)
    assert event["outcome"] == "failure"


def test_accepted_password_is_parsed_as_success():
    line = (
        "Oct  5 03:29:46 metasploitable sshd[5331]: "
        "Accepted password for msfadmin from 192.168.18.176 port 60056 ssh2"
    )
    event = parse_accepted_password(line)
    assert event["username"] == "msfadmin"
    assert event["outcome"] == "success"


def test_parses_failed_password_for_valid_user():
    line = (
        "Sep 28 04:27:18 metasploitable sshd[5452]: "
        "Failed password for root from 10.0.2.4 port 35643 ssh2"
    )
    event = parse_failed_password(line)
    assert event["username"] == "root"
    assert event["src_ip"] == "10.0.2.4"
    assert event["src_port"] == 35643


def test_returns_none_for_unrelated_line():
    assert parse_failed_password("this is not an ssh log line") is None


def test_flags_invalid_user():
    line = (
        "Oct  5 03:37:50 metasploitable sshd[5345]: "
        "Failed password for invalid user fakeuser "
        "from 192.168.18.176 port 54524 ssh2"
    )
    event = parse_failed_password(line)
    assert event["username"] == "fakeuser"
    assert event["invalid_user"] is True


def test_known_noise_is_ignored():
    line = (
        "Oct  5 03:37:39 metasploitable sshd[5345]: "
        "Invalid user fakeuser from 192.168.18.176"
    )
    assert is_ignored_line(line) is True


def test_unknown_line_is_not_ignored():
    assert is_ignored_line("something we have never seen") is False


def test_parses_failed_publickey():
    line = (
        "Oct  5 03:40:00 metasploitable sshd[5400]: "
        "Failed publickey for root from 192.168.18.176 port 50000 ssh2"
    )
    event = parse_failed_password(line)
    assert event["method"] == "publickey"
    assert event["outcome"] == "failure"

def test_parses_accepted_publickey():
    line = (
        "Oct  5 03:45:00 metasploitable sshd[5500]: "
        "Accepted publickey for msfadmin from 192.168.18.176 port 50500 ssh2"
    )
    event = parse_accepted_password(line)
    assert event["method"] == "publickey"
    assert event["outcome"] == "success"


def test_normalize_timestamp_syslog():
    from siem.parser import normalize_timestamp
    iso = normalize_timestamp("Oct  5 03:29:46", default_year=2026)
    assert iso == "2026-10-05T03:29:46Z"


def test_normalize_timestamp_iso():
    from siem.parser import normalize_timestamp
    iso = normalize_timestamp("2026-10-09T04:20:00Z")
    assert iso == "2026-10-09T04:20:00Z"


def test_parse_file_auth_sample():
    from siem.parser import parse_file
    events, ignored, unrecognized = parse_file("sample_logs/auth_sample.log", normalize=True)
    # In auth_sample.log:
    # 5 valid auth lines (failed pwd, accepted pwd, failed pwd invalid user, failed pubkey, accepted pubkey)
    # 2 ignored lines ("Invalid user fakeuser", "Received disconnect")
    # 0 unrecognized lines (empty lines skipped)
    assert len(events) == 5
    assert ignored == 2
    assert unrecognized == 0

    # Check common schema fields on normalized event
    ev = events[0]
    assert "timestamp" in ev and ev["timestamp"].endswith("Z")
    assert ev["host"] == "metasploitable"
    assert ev["program"] == "sshd"
    assert ev["pid"] == 5452
    assert ev["src_ip"] == "10.0.2.4"
    assert ev["src_port"] == 35643
    assert ev["outcome"] == "failure"
    assert ev["activity"] == "authentication"
    assert ev["raw_message"] != ""


