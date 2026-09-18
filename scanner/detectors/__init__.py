"""
detectors
=========
Each module in this package implements one rule-based vulnerability
check (project steps 5-7: apply detection rules, simulate payloads,
analyze responses). Every detector exposes a single function:

    check(session, surface) -> list[Finding]

so that scanner/cli.py can run them uniformly over every AttackSurface
the crawler discovers.
"""

from .finding import Finding  # noqa: F401
