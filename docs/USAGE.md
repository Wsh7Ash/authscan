# Usage — authscan

## Install

```shell
pip install -e .
```

## Commands

```shell
authscan --help
```

## Examples

### Inspect a token from your own logs

```shell
authscan inspect "$TOKEN"
```

### JSON findings for CI

```shell
authscan inspect "$TOKEN" --json-out
```

### Run the example matrix locally

```shell
authscan matrix examples/auth-matrix.json --base-url http://127.0.0.1:8000
```

### Check a staging host you are authorized to test

```shell
authscan matrix examples/auth-matrix.json --base-url https://staging.myapp.example
```

## Auth-matrix spec format

`matrix` takes a JSON file:

```json
{{
  "cases": [
    {{"method": "GET", "path": "/api/me", "role": "anonymous", "expected_status": 401},
    {{"method": "GET", "path": "/api/me", "role": "user",
      "token": "demo-user-token", "expected_status": 200}}
  ]
}}
```

Per-case keys: `method`, `path`, `expected_status` (required); `role`, `token`,
`token_header` (default `Authorization`), `token_prefix` (default `Bearer `)
optional. A run exits 1 if any case mismatches its expected status.

## Validation gates

- **install**: `pip install -e . (fresh venv)`
- **unit tests**: `pytest -q`
- **CLI smoke**: `authscan --help; authscan inspect <token>`
- **demo run**: `logs/2026-10-24/run_demos.py -> results/demo-output.txt`
- **secret scan**: `no tokens/keys/.env in tree`

## Exit codes

- `0` — success / no findings at or above threshold
- `1` — findings present, or validation cases failed
- `2` — usage error, unreadable input, or rejected target
