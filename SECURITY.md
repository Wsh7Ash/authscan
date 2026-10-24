# Security Policy

## Authorized use

`authscan` is a **defensive tool for systems you own or are explicitly authorized to
test**. Do not point it at third-party infrastructure without written permission;
unauthorized security testing violates computer-misuse laws in most jurisdictions.

`inspect` performs no network requests — tokens are decoded locally and never transmitted. `matrix` sends requests only to the `--base-url` you pass (default `http://127.0.0.1:8000`); your tokens travel only to that host. There is no brute-force, stuffing, or credential-stuffing functionality.

## Reporting a vulnerability

If you find a vulnerability or unsafe default in `authscan` itself, please open a
private security advisory on the GitHub repository (or open an issue describing the
problem at a high level if you cannot use advisories). We will acknowledge within
72 hours and coordinate a fix before public disclosure.

## Secrets

`authscan` stores no credentials and requires none. Do not commit real tokens, cookies
or keys to the spec/example files in this repository; `.gitignore` excludes `.env`
and common key material.
