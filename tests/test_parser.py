from siem.parser import parse_accepted_password, parse_failed_password


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