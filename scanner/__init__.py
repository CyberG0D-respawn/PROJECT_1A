"""
scanner
=======
A lightweight, rule-based web vulnerability scanner built for the
"Vulnerability Scanner for Websites" minor project.

It is intentionally scoped to a small set of well-understood checks:
    - SQL Injection (error-based detection)
    - Reflected Cross-Site Scripting (XSS)
    - Missing Cross-Site Request Forgery (CSRF) protection
    - Insecure / missing HTTP security headers

IMPORTANT: This tool is for educational use against applications you own
or are explicitly authorized to test (e.g. OWASP WebGoat, OWASP NodeGoat,
or other deliberately vulnerable local test targets). See README.md.
"""

__version__ = "1.0.0"
