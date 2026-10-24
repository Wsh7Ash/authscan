# PROJECT SPEC — authscan

| Field | Value |
|---|---|
| Name | `authscan` |
| Category | api-security |
| Target user | Developers and reviewers auditing APIs they own |
| Problem | JWT flaws and authorization regressions are found late because token inspection is manual and role checks are ad-hoc curl. |
| Solution | A CLI that structurally inspects JWTs locally and runs a declarative endpoint x role matrix against a chosen base URL. |
| Core workflow | inspect a token -> write/adjust a matrix spec -> run matrix -> fix findings |
| Stack | Python >=3.10, click, rich |
| Test strategy | tests/test_scan.py covers decode round-trip, malformed input, each finding code, CLI exit codes (0 clean, 1 medium+, 2 usage) and matrix failure paths without a live server. |
| Demo strategy | `logs/2026-10-24/run_demos.py` runs the real workflow and captures `results/demo-output.txt` with asserted exit codes |
| Safety | inspect never touches the network. matrix only ever contacts --base-url (default http://127.0.0.1:8000); tokens travel only to that host. No signature cracking, no brute force. |
| Definition of done | install + pytest + CLI smoke + demo transcript + secret scan all pass; docs (README, ARCHITECTURE, USAGE, CHANGELOG, CONTRIBUTING, SECURITY) present; pushed with green CI |

## Must-have features

- authscan inspect "$TOKEN"
- authscan inspect "$TOKEN" --json-out
- Exit-code contract (0/1/2) usable from CI
- `--json-out` machine-readable output

## Nice-to-have (deferred)

- See README Roadmap.
