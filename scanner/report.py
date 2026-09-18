"""
report.py
---------
Implements project step 8: "Generate vulnerability severity reports."

Takes the raw Finding objects produced by the detectors, assigns a
severity from config.SEVERITY, and can render the result either as a
console-friendly summary or a JSON file for the dashboard / write-up.
"""

import json
from collections import Counter

from . import config


SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}


def sort_findings(findings):
    """Sort High -> Medium -> Low -> Info, then by type and URL."""
    return sorted(
        findings,
        key=lambda f: (
            SEVERITY_ORDER.get(f.severity, 99),
            f.vuln_type,
            f.url,
            f.parameter or "",
        ),
    )


def assign_severity(findings):
    for f in findings:
        f.severity = config.SEVERITY.get(f.vuln_type, "Info")
    return findings


def summarize(findings):
    """Return counts by severity and by vulnerability type."""
    by_severity = Counter(f.severity for f in findings)
    by_type = Counter(f.vuln_type for f in findings)
    return {
        "total_findings": len(findings),
        "by_severity": dict(by_severity),
        "by_type": dict(by_type),
    }


def to_console(target_url, findings):
    lines = []
    lines.append("=" * 60)
    lines.append(f"Vulnerability Scan Report - {target_url}")
    lines.append("=" * 60)

    summary = summarize(findings)
    lines.append(f"Total findings: {summary['total_findings']}")
    for sev in ("High", "Medium", "Low", "Info"):
        if sev in summary["by_severity"]:
            lines.append(f"  {sev}: {summary['by_severity'][sev]}")
    lines.append("-" * 60)

    if not findings:
        lines.append("No issues detected by the automated checks.")
    else:
        for f in sort_findings(findings):
            status = "CONFIRMED" if f.confirmed else "NEEDS MANUAL REVIEW"
            lines.append(f"[{f.severity}] {f.vuln_type} - {status}")
            lines.append(f"  URL:       {f.url}")
            lines.append(f"  Parameter: {f.parameter}")
            lines.append(f"  Evidence:  {f.evidence}")
            lines.append("")

    lines.append(
        "NOTE: All findings should be validated manually before acting on them "
        "(project step 10). Automated detectors can produce false positives."
    )
    return "\n".join(lines)


def to_json_file(target_url, findings, path):
    payload = {
        "target_url": target_url,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in sort_findings(findings)],
    }
    with open(path, "w") as fh:
        json.dump(payload, fh, indent=2)
    return path
