# authscan

**Structural JWT inspection and endpoint × role authorization testing for APIs you own.**

`authscan` answers two questions security reviewers ask constantly: *what does this token
actually contain, and does each endpoint really enforce the roles I think it enforces?*
It does both locally — token inspection never touches the network, and matrix checks only
ever call a base URL you explicitly pass.

## Problem

JWT bugs (`alg:none`, missing `exp`, absurd lifetimes) hide in plain sight inside
base64 blobs, and authorization regressions — an endpoint quietly returning 200 to
the wrong role — only surface after someone reports them. Copy-pasting tokens into
`jwt.io` and hand-curling endpoints doesn't scale to a review.

## Features

- **`inspect`** decodes a JWT locally and flags structural findings: `alg:none`,
  missing/oversized `exp`, future `iat`/`nbf`, path-traversal-looking `kid`, unusual `typ`.
- **`matrix`** runs a declarative endpoint × role × expected-status spec against a
  base URL you supply and reports PASS/FAIL per case, exiting non-zero on mismatch.
- Severity-ranked findings with machine-readable `--json-out` for CI pipelines.
- Zero network I/O in `inspect`; `matrix` never calls any host except `--base-url`
  (default `http://127.0.0.1:8000`).

## Example output

```
$ authscan inspect eyJhbGciOiJub25lIn0...
alg: none   claims: sub
                                  findings
+---------------------------------------------------------------------------+
| severity | code        | message                                          |
|----------+-------------+--------------------------------------------------|
| high     | alg-none    | 'alg: none' means the token carries no signature |
| medium   | missing-exp | no 'exp' claim: token never expires              |
+---------------------------------------------------------------------------+
```

Full transcripts: [`results/demo-output.txt`](results/demo-output.txt).

## Architecture summary

Two independent modules behind one Click CLI:

- `src/authscan/jwt.py` — pure functions: base64url decode → JSON → findings. No I/O.
- `src/authscan/cli.py` — `inspect` (local) and `matrix` (urllib GET/POST/DELETE against
  `--base-url` only, 10 s timeout, no redirects followed off-host by policy of the spec).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Requirements

- Python ≥ 3.10
- `click`, `rich` (installed automatically)

## Installation

```shell
pip install -e .
```

## Quick start

```shell
# 1. inspect a token you already have (no network)
authscan inspect "$TOKEN"

# 2. run an auth matrix against your local dev API
authscan matrix examples/auth-matrix.json --base-url http://127.0.0.1:8000
```

## Usage examples

```shell
# machine-readable findings for CI
authscan inspect "$TOKEN" --json-out

# matrix against a staging service you are authorized to test
authscan matrix examples/auth-matrix.json --base-url https://staging.myapp.example
```

`examples/auth-matrix.json` shows the spec format:

```json
{"cases": [
  {"method": "GET", "path": "/api/me", "role": "anonymous", "expected_status": 401},
  {"method": "GET", "path": "/api/me", "role": "user", "token": "demo-user-token", "expected_status": 200}
]}
```

## Configuration

No config file. Flags only: `--json-out`, `--base-url`. Tokens are passed per-case in
the spec file — never commit real ones (see `.gitignore` and Security notes).

## Testing

```shell
pip install -e . pytest
pytest -q          # 11 tests: decoding, findings, CLI exit codes (0/1/2)
```

## Project structure

```
authscan/
├─ src/authscan/{__init__,cli,jwt}.py
├─ tests/test_scan.py
├─ examples/auth-matrix.json
├─ docs/{ARCHITECTURE,USAGE,PROJECT_SPEC}.md
├─ results/demo-output.txt
├─ RESULTS.md
└─ .github/workflows/ci.yml
```

## Limitations

- `inspect` does **not** verify signatures. It reports token *structure*, not
  authenticity — pair it with your verifier.
- `matrix` sends real requests: cases run sequentially, no request pipelining.
- Only `GET`/`POST`/`PUT`/`PATCH`/`DELETE`-style verbs via urllib; no mTLS or
  custom auth schemes beyond a static token header.

## Roadmap

- Optional HS256 signature verification when a secret is provided locally.
- OpenAPI-driven matrix generation.
- Cookie-based session specs (currently header tokens only).

## Security notes

Authorized use only: `matrix` is for APIs you own or are explicitly authorized to
test. See [SECURITY.md](SECURITY.md). No credentials are stored, logged, or sent
anywhere except `--base-url`.

## License

MIT — see [LICENSE](LICENSE).