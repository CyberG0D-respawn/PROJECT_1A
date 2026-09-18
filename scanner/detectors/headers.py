"""
headers.py
----------
Insecure / missing HTTP security header detection.

Approach: check a fetched page's response headers against a small
checklist of well-known security headers. This mirrors the "security
headers" checks in tools like Mozilla Observatory and OWASP ZAP.
"""

from .finding import Finding

REQUIRED_HEADERS = {
    "X-Content-Type-Options": "Prevents MIME-type sniffing.",
    "X-Frame-Options": "Mitigates clickjacking via iframes.",
    "Content-Security-Policy": "Restricts sources scripts/styles can load from.",
    "Strict-Transport-Security": "Forces HTTPS on future visits.",
    "Referrer-Policy": "Controls how much referrer info is leaked on navigation.",
}


def check_page(page_url, response):
    findings = []
    present = {k.lower(): v for k, v in response.headers.items()}

    for header, purpose in REQUIRED_HEADERS.items():
        value = present.get(header.lower())
        if value is None or not str(value).strip():
            findings.append(
                Finding(
                    vuln_type="insecure_headers",
                    url=page_url,
                    parameter=header,
                    evidence=f"Missing '{header}' header. {purpose}",
                    confirmed=True,
                )
            )

    # Flag an overly permissive CORS policy while we're looking at headers.
    acao = present.get("access-control-allow-origin")
    if acao == "*":
        findings.append(
            Finding(
                vuln_type="insecure_headers",
                url=page_url,
                parameter="Access-Control-Allow-Origin",
                evidence="CORS header allows any origin ('*'), which is overly permissive.",
                confirmed=True,
            )
        )

    return findings
