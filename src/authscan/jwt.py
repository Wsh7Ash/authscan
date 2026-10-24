"""JWT structural inspection (decode and flag risky claims).

Analysis only: tokens are decoded locally, never sent anywhere.
No signature verification is performed or claimed; this is an audit
helper for tokens you already possess (your own apps, your own logs).
"""
from __future__ import annotations

import base64
import json
import time

# 30 days: a common upper bound for access-token lifetimes.
MAX_RECOMMENDED_LIFE_S = 30 * 24 * 3600


class JwtError(ValueError):
    """Raised when a token cannot be structurally decoded."""


def _b64url_decode(segment: str, label: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + pad)
    except Exception as exc:  # binascii.Error and friends
        raise JwtError(f"invalid base64url in {label}") from exc


def decode(token: str) -> tuple[dict, dict, str]:
    """Decode a JWT without verifying it. Returns (header, payload, signing_input)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JwtError("expected 3 dot-separated segments (header.payload.signature)")
    header_raw, payload_raw, _sig = parts
    try:
        header = json.loads(_b64url_decode(header_raw, "header"))
        payload = json.loads(_b64url_decode(payload_raw, "payload"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtError(f"segment is not valid JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtError("header and payload must be JSON objects")
    return header, payload, f"{header_raw}.{payload_raw}"


def inspect(token: str, now: float | None = None) -> dict:
    """Structurally inspect a token and return a finding report.

    Findings are advisory: they describe token *shape* (algorithm, lifetime,
    claim presence), not signature validity.
    """
    now = time.time() if now is None else now
    header, payload, _signing_input = decode(token)

    findings: list[dict] = []
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3}

    def add(severity: str, code: str, message: str) -> None:
        findings.append({"severity": severity, "code": code, "message": message})

    alg = header.get("alg")
    if alg is None:
        add("high", "missing-alg", "header has no 'alg' field")
    elif alg == "none":
        add("high", "alg-none", "'alg: none' means the token carries no signature")

    typ = header.get("typ")
    if typ is not None and str(typ).upper() not in ("JWT", "JOSE"):
        add("info", "unusual-typ", f"header typ is {typ!r}, expected 'JWT'")

    exp = payload.get("exp")
    iat = payload.get("iat")
    nbf = payload.get("nbf")

    if exp is None:
        add("medium", "missing-exp", "no 'exp' claim: token never expires")
    else:
        try:
            exp_f = float(exp)
        except (TypeError, ValueError):
            add("high", "bad-exp", "'exp' is not a number")
            exp_f = None
        if exp_f is not None:
            if exp_f < now:
                add("info", "expired", "token is already expired")
            else:
                life = exp_f - (float(iat) if isinstance(iat, (int, float)) else exp_f)
                if isinstance(iat, (int, float)) and life > MAX_RECOMMENDED_LIFE_S:
                    add(
                        "medium",
                        "long-lived",
                        f"lifetime of {life / 86400:.0f} days exceeds the "
                        f"{MAX_RECOMMENDED_LIFE_S // 86400}-day guidance",
                    )

    if isinstance(nbf, (int, float)) and float(nbf) > now + 60:
        add("low", "future-nbf", "'nbf' is in the future; token should not be accepted yet")
    if isinstance(iat, (int, float)) and float(iat) > now + 60:
        add("low", "future-iat", "'iat' is in the future (clock skew or backdated issue?)")

    if "sub" not in payload:
        add("info", "missing-sub", "no 'sub' claim: no subject identity")

    for kid in (header.get("kid"), payload.get("kid")):
        if isinstance(kid, str) and ("../" in kid or "/" in kid or "\\" in kid):
            add("medium", "suspicious-kid", f"'kid' contains path characters: {kid!r}")

    findings.sort(key=lambda f: -severity_rank[f["severity"]])
    worst = findings[0]["severity"] if findings else "info"
    return {
        "header": header,
        "claims": sorted(payload.keys()),
        "findings": findings,
        "worst_severity": worst if findings else "none",
    }
