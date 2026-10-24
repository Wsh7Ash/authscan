"""Tests for JWT structural inspection and the CLI wiring."""
import base64
import json
import time

import pytest
from click.testing import CliRunner

from authscan import jwt as jwtlib
from authscan.cli import main


def _b64(obj) -> str:
    raw = json.dumps(obj).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_token(header=None, payload=None, sig="sig") -> str:
    header = header or {"alg": "HS256", "typ": "JWT"}
    now = time.time()
    payload = payload or {"sub": "user-1", "iat": now, "exp": now + 3600}
    return f"{_b64(header)}.{_b64(payload)}.{sig}"


def test_decodes_header_and_payload():
    token = make_token(payload={"sub": "u", "scope": "read"})
    header, payload, signing_input = jwtlib.decode(token)
    assert header["alg"] == "HS256"
    assert payload["sub"] == "u"
    assert signing_input.count(".") == 1


def test_rejects_wrong_segment_count():
    with pytest.raises(jwtlib.JwtError):
        jwtlib.decode("only-one-segment")
    with pytest.raises(jwtlib.JwtError):
        jwtlib.decode("a.b")


def test_alg_none_is_high_severity():
    report = jwtlib.inspect(make_token(header={"alg": "none"}, payload={"sub": "u"}))
    codes = [f["code"] for f in report["findings"]]
    assert "alg-none" in codes
    assert report["worst_severity"] == "high"


def test_missing_exp_is_flagged():
    report = jwtlib.inspect(make_token(payload={"sub": "u"}))
    assert "missing-exp" in [f["code"] for f in report["findings"]]


def test_expired_token_is_flagged():
    now = time.time()
    token = make_token(payload={"sub": "u", "iat": now - 100, "exp": now - 50})
    report = jwtlib.inspect(token, now=now)
    assert "expired" in [f["code"] for f in report["findings"]]
    assert report["worst_severity"] == "info"  # expiry is normal, not a flaw


def test_long_lived_token_is_flagged():
    now = time.time()
    token = make_token(payload={"sub": "u", "iat": now, "exp": now + 400 * 86400})
    report = jwtlib.inspect(token, now=now)
    assert "long-lived" in [f["code"] for f in report["findings"]]


def test_suspicious_kid_is_flagged():
    token = make_token(header={"alg": "HS256", "kid": "../../etc/passwd"})
    report = jwtlib.inspect(token)
    assert "suspicious-kid" in [f["code"] for f in report["findings"]]


def test_inspect_cli_exit_codes():
    runner = CliRunner()
    ok = runner.invoke(main, ["inspect", make_token()])
    assert ok.exit_code == 0, ok.output
    bad = runner.invoke(main, ["inspect", make_token(header={"alg": "none"})])
    assert bad.exit_code == 1, bad.output
    malformed = runner.invoke(main, ["inspect", "not-a-jwt"])
    assert malformed.exit_code == 2, malformed.output


def test_inspect_cli_json_output():
    runner = CliRunner()
    result = runner.invoke(main, ["inspect", make_token(), "--json-out"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["header"]["alg"] == "HS256"
    assert isinstance(data["findings"], list)


def test_matrix_reports_failures_without_network():
    runner = CliRunner()
    spec = {
        "cases": [
            {"method": "GET", "path": "/nope", "role": "anon",
             "expected_status": 404}
        ]
    }
    with runner.isolated_filesystem():
        with open("spec.json", "w") as fh:
            json.dump(spec, fh)
        # nothing is listening on this port -> connection error -> exit 2
        result = runner.invoke(main, ["matrix", "spec.json",
                                      "--base-url", "http://127.0.0.1:1"])
        assert result.exit_code == 2, result.output


def test_matrix_rejects_bad_spec():
    runner = CliRunner()
    with runner.isolated_filesystem():
        with open("spec.json", "w") as fh:
            fh.write("{}")
        result = runner.invoke(main, ["matrix", "spec.json"])
        assert result.exit_code == 2, result.output