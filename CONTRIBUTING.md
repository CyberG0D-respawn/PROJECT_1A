# Contributing to PROJECT_1A

Thanks for your interest. This is an educational vulnerability scanner (`scanner/cli.py`, Flask dashboard in `dashboard/app.py`).

Please read this fully before opening a PR — **this project is not open-source.**

## 1. License and ownership

Copyright (c) 2026 CyberG0D-respawn. All Rights Reserved. See `LICENSE`.

- Code is visible for learning/portfolio review only.
- No copying, forking for reuse, redistribution, or commercial use without written permission.
- **By submitting an Issue, PR, or patch, you agree:**
  1. You assign all copyright in your contribution to CyberG0D-respawn,
  2. You grant a perpetual, worldwide, irrevocable, royalty-free license to use, modify, sublicense, and commercialize it,
  3. You confirm you wrote it yourself or have the right to submit it, and it does not violate any employer agreement or third-party license.

If you cannot agree to the above, do not contribute. For formal tracking a maintainer may ask you to confirm with an `I agree to the CLA` comment (via CLA Assistant).

## 2. Ethics — authorized targets only

This tool sends active payloads (`scanner/detectors/sql_injection.py`, `xss.py`). Never test systems you do not own or lack explicit written permission to test.

- Allowed by default in `scanner/config.py:31-36`: `localhost`, `127.0.0.1`, `webgoat`, `nodegoat`.
- Any other host triggers `confirm_authorization()` in `scanner/cli.py:44-57` requiring `I AM AUTHORIZED`.
- Do not submit PRs that weaken this safeguard, add evasive payloads, brute-force, DoS, or credential harvesting.
- Do not submit real scan data with victim URLs, credentials, or tokens. Use mocked HTML like in `test/test_detectors.py:21-29`.

Reports of misuse will lead to removal of contributions and access bans.

## 3. Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m pytest test/ -v
python -m scanner.cli --url http://localhost:8080 --out report.json
python dashboard/app.py
# then open http://localhost:5000
```

Stack: `requests==2.34.2`, `beautifulsoup4`, `Flask==3.1.3`, `pytest==9.1.1` — see `requirements.txt`. Do not bump versions without reason.

## 4. What to work on

- New checks in `scanner/detectors/` + severity entry in `scanner/config.py:52-57` + rendering in `scanner/report.py`.
- Crawler improvements in `scanner/crawler.py` respecting `MAX_CRAWL_DEPTH`, `MAX_PAGES`, `REQUEST_DELAY` from `scanner/config.py`.
- Dashboard read-only views in `dashboard/app.py`, `dashboard/templates/`, `dashboard/static/` (must stay mobile-responsive, no write actions).
- Tests in `test/test_detectors.py` — mock `requests.Session` with `MagicMock`, no live network calls.

Do not commit: `data/*.db`, `report.json`, `.env`, `__pycache__/`, `.pytest_cache/` — already covered by `.gitignore`.

## 5. Workflow

1. Fork, then branch from `main`: `feat/xss-context-check`, `fix/crawler-normalize-url`.
2. Keep changes narrow. Match existing style: docstrings, `snake_case`, no unused imports.
3. Add/extend tests for every detector change. Run before pushing:
   ```powershell
   python -m pytest test/ -v
   ```
4. Manual check if you touched scanning: run CLI against `http://localhost:8080` and dashboard locally.
5. Push and open PR to `main` with: problem, approach, files changed, test output, target used (must be local/training target).

## 6. PR review expectations

- Maintainer checks ownership/CLA, ethics impact, scope fit (`SCAN_SCOPE` in `scanner/config.py:14-19`), tests, and no secrets/data leaks.
- You may be asked to relicense your patch wording or squash commits.
- Merged contributions become property of the project per Section 1.

## 7. Reporting vulnerabilities in this repo itself

Do not open a public Issue with exploit details. Contact the maintainer privately with steps to reproduce against a local target, expected vs actual behavior, and your environment.
