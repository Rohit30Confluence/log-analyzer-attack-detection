from app.parser import parse_line, parse_text


VALID = '198.51.100.4 - - [10/Aug/2026:09:00:01 +0000] "GET /about HTTP/1.1" 200 812 "-" "Mozilla/5.0"'


def test_parses_valid_line():
    rec = parse_line(VALID)
    assert rec is not None
    assert rec["ip"] == "198.51.100.4"
    assert rec["method"] == "GET"
    assert rec["path"] == "/about"
    assert rec["status"] == 200
    assert rec["bytes"] == 812


def test_rejects_malformed_line():
    assert parse_line("this is not a log line") is None


def test_rejects_empty_line():
    assert parse_line("") is None
    assert parse_line("   ") is None


def test_dash_bytes_becomes_none():
    line = '1.2.3.4 - - [10/Aug/2026:09:00:01 +0000] "GET / HTTP/1.1" 304 - "-" "-"'
    rec = parse_line(line)
    assert rec["bytes"] is None


def test_parse_text_skips_bad_lines():
    text = VALID + "\nnot a log line\n" + VALID
    recs = list(parse_text(text))
    assert len(recs) == 2


def test_single_token_request_does_not_crash():
    """A malformed single-token request line (no method/protocol) should
    parse without raising — the token is kept as the path, method is None."""
    line = '1.2.3.4 - - [10/Aug/2026:09:00:01 +0000] "BADREQUEST" 400 0 "-" "-"'
    rec = parse_line(line)
    assert rec is not None
    assert rec["method"] is None
    assert rec["path"] == "BADREQUEST"
