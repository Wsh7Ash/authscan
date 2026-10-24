# Architecture — authscan

## Overview

`authscan` (api-security) is a single-package Python CLI: a `src/authscan/` package
with a pure logic module and a Click command layer, console-script entry point
`authscan = authscan.cli:main`, and no runtime services.

### `src/authscan/jwt.py`

Pure decode + inspection. base64url-decode the three segments, JSON-parse header/payload, then evaluate claims against advisory rules (alg, exp/iat/nbf lifetimes, kid shape, typ). No I/O, no signature verification.

### `src/authscan/cli.py`

Click group with `inspect` (renders findings table, exit 0/1/2 by severity) and `matrix` (reads JSON spec, issues urllib requests strictly against --base-url, compares actual vs expected status, exit 0/1/2).


## Design decisions

- **Logic/rendering separation.** Every decision (parse, match, lint, plan, score)
  lives in a pure module with no console output, so tests assert on data rather than
  on terminal formatting.
- **Exit codes as the CI contract.** 0 = clean/success, 1 = findings or failed
  validation, 2 = usage or read error. `--json-out` switches stdout to machine-readable
  JSON without changing exit codes.
- **Small dependency surface.** Only `click` (CLI) and `rich` (tables); everything
  else is the Python standard library. Fewer dependencies, fewer surprises.

## Data flow

```
input (token / file / URL + flags)
   -> Click command validates arguments
   -> pure module computes findings/verdicts/summary
   -> renderer prints table or JSON
   -> process exits 0 / 1 / 2
```

## Testing strategy

tests/test_scan.py covers decode round-trip, malformed input, each finding code, CLI exit codes (0 clean, 1 medium+, 2 usage) and matrix failure paths without a live server.
