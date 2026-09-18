"""
cli.py
------
Command-line entry point. Wires together every project step:

    1-2. config.py            (scope + authorized targets)
    3-4. crawler.py            (collect + preprocess)
    5-7. detectors/*           (rule-based detection + payloads + analysis)
    8.   report.py             (severity report)
    9.   database.py           (persistence)
    10.  manual review reminder (printed in every report)

Usage:
    python -m scanner.cli --url http://localhost:8080 --out report.json
"""

import argparse
import sys
from urllib.parse import urlparse

import requests

from . import config, database, report
from .crawler import crawl
from .detectors import sql_injection, xss, csrf, headers as headers_detector


def is_pre_authorized(url):
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return False
    if not hostname:
        return False
    return any(
        hostname == domain.lower() or hostname.endswith("." + domain.lower())
        for domain in config.KNOWN_TRAINING_DOMAINS
    )


def confirm_authorization(url):
    """
    Refuse to scan anything the user hasn't explicitly confirmed they
    are authorized to test. Scanning systems without permission is
    illegal in most jurisdictions - this project is scoped to test
    targets (OWASP WebGoat / NodeGoat) or localhost.
    """
    if is_pre_authorized(url):
        return True

    print(f"\nTarget '{url}' is not in the known training-target list.")
    print("Only scan systems you own or are explicitly authorized to test.")
    response = input(f"Type '{config.CONFIRMATION_PHRASE}' to continue: ").strip()
    return response == config.CONFIRMATION_PHRASE


def run_scan(target_url):
    session = requests.Session()
    session.headers.update({"User-Agent": config.USER_AGENT})

    print(f"[*] Crawling {target_url} (max depth={config.MAX_CRAWL_DEPTH}, "
          f"max pages={config.MAX_PAGES}) ...")
    crawl_result = crawl(target_url, session=session)
    print(f"[*] Crawled {len(crawl_result.pages)} page(s), "
          f"found {len(crawl_result.attack_surfaces)} attack surface(s).")

    findings = []

    # Per-attack-surface checks (need to submit test input into params).
    for surface in crawl_result.attack_surfaces:
        findings.extend(sql_injection.check(session, surface))
        findings.extend(xss.check(session, surface))

    # Per-page checks (operate on the already-fetched HTML/headers).
    for url, response in crawl_result.pages.items():
        findings.extend(csrf.check_page(url, response))
        findings.extend(headers_detector.check_page(url, response))

    report.assign_severity(findings)

    scan_id = database.create_scan(
        target_url,
        pages_crawled=len(crawl_result.pages),
        surfaces_tested=len(crawl_result.attack_surfaces),
    )
    database.save_findings(scan_id, findings)

    return findings, scan_id


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Rule-based vulnerability scanner for educational use "
                     "against authorized test targets."
    )
    parser.add_argument("--url", required=True, help="Target URL, e.g. http://localhost:8080")
    parser.add_argument("--out", default=None, help="Optional path to write a JSON report")
    args = parser.parse_args(argv)

    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print(f"Invalid target URL '{args.url}'. Use http(s)://host[:port][/path].")
        sys.exit(2)

    if not confirm_authorization(args.url):
        print("Authorization not confirmed. Aborting scan.")
        sys.exit(1)

    database.init_db()
    findings, scan_id = run_scan(args.url)

    print("\n" + report.to_console(args.url, findings))
    print(f"\n[*] Scan #{scan_id} saved to {config.DB_PATH}")

    if args.out:
        report.to_json_file(args.url, findings, args.out)
        print(f"[*] JSON report written to {args.out}")


if __name__ == "__main__":
    main()
