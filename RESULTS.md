# Results

## Environment
- OS: Windows-10-10.0.19044-SP0
- Python: 3.14.3 (C:/Users/0/AppData/Local/Temp/fv-20261024/bin/python.exe)
- Dependency manager: pip 25.3 from C:/Users/0/AppData/Local/Temp/fv-20261024/lib/python3.14/site-packages/pip (python 3.14)
- Venv: C:/Users/0/AppData/Local/Temp/fv-20261024

## Validation performed
- install: PASS
- build: N/A (pure-Python package, no build step beyond setuptools install)
- unit tests: PASS (11 passed, 2 warnings in 2.22s)
- integration tests: N/A (CLI demo covers end-to-end behavior)
- lint: N/A (not configured for this project)
- type check: N/A (not configured for this project)
- demo run: PASS

## Commands executed
```shell
python -m pip install -e .
python -m pytest -q
authscan --help
authscan inspect bad-token
python ../../logs/2026-10-24/run_demos.py   # writes results/demo-output.txt
```

## Observed result

- `pip install -e .` exited 0 in a clean venv; console script `authscan` resolves.
- `pytest -q` exited 0: 11 passed, 2 warnings in 2.22s
- CLI smoke: [{"cmd": ["authscan", "--help"], "expected": 0, "actual": 0}, {"cmd": ["authscan", "inspect", "bad-token"], "expected": 2, "actual": 2}]
- Demo harness ran every workflow with asserted exit codes; full transcript in
  [`results/demo-output.txt`](results/demo-output.txt).

## Generated artifacts
- `results/demo-output.txt` — captured demo transcript with per-command exit codes
- `docs/ARCHITECTURE.md`, `docs/USAGE.md`, `docs/PROJECT_SPEC.md`
- `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`
- `SECURITY.md`

## Known limitations

See the Limitations section of [README.md](README.md).
