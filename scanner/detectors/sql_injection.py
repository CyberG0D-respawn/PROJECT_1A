"""
sql_injection.py
-----------------
Error-based SQL Injection detection.

Approach: for each parameter on an AttackSurface, resend the request
with a single benign probe character (a quote) appended to the
existing value, then look for common database error strings in the
response. This is the same non-destructive technique taught in most
intro security courses and used by tools like OWASP ZAP's baseline
scan - it identifies a *likely* issue for a human to confirm, it does
not attempt to extract or modify data.
"""

import requests

from .finding import Finding
from .. import config

# A single quote is enough to break naive string-concatenated queries
# and surface a database error message. Kept intentionally minimal and
# non-destructive (no UNION/stacked-query payloads).
PROBES = ["'", "\""]

# Substrings that commonly appear in raw database error output.
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",   # MySQL
    "warning: mysql",
    "unclosed quotation mark",                 # MSSQL
    "quoted string not properly terminated",   # Oracle
    "sqlite3.operationalerror",                # SQLite
    "sqlite syntax error",
    "pg_query()",                               # PostgreSQL (PHP driver)
    "psql: error",
    "org.postgresql.util.psqlexception",
    "syntax error at or near",                  # PostgreSQL
    "odbc sql server driver",
    "microsoft ole db provider for sql server",
]


def _looks_like_sql_error(text):
    lowered = text.lower()
    return any(sig in lowered for sig in ERROR_SIGNATURES)


def check(session, surface):
    findings = []

    for param_name, original_value in surface.params.items():
        for probe in PROBES:
            test_params = dict(surface.params)
            test_params[param_name] = f"{original_value}{probe}"

            try:
                if surface.method == "POST":
                    resp = session.post(
                        surface.url, data=test_params, timeout=config.REQUEST_TIMEOUT
                    )
                else:
                    resp = session.get(
                        surface.url, params=test_params, timeout=config.REQUEST_TIMEOUT
                    )
            except requests.RequestException:
                continue

            if _looks_like_sql_error(resp.text):
                findings.append(
                    Finding(
                        vuln_type="sql_injection",
                        url=surface.url,
                        parameter=param_name,
                        evidence=(
                            f"Injecting {probe!r} into '{param_name}' produced a "
                            "database error message in the response."
                        ),
                        confirmed=True,
                    )
                )
                break  # one confirmed probe per parameter is enough

    return findings
