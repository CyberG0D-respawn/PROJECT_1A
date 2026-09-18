"""
csrf.py
-------
Missing CSRF-protection detection.

Approach: this check operates on the raw HTML of a page (not on
AttackSurface objects) because CSRF is a property of a *form*, not of
an individual parameter. A POST form is flagged if none of its hidden
fields look like an anti-CSRF token AND the response has no
SameSite=Strict/Lax cookie as a mitigating control.
"""

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from .finding import Finding

TOKEN_NAME_HINTS = ("csrf", "token", "authenticity", "_token", "nonce")


def _form_has_token(form):
    for field in form.find_all("input"):
        if (field.get("type") or "").lower() != "hidden":
            continue
        name = (field.get("name") or "").lower()
        if any(hint in name for hint in TOKEN_NAME_HINTS):
            return True
    return False


def _has_samesite_cookie(response):
    """True if a SameSite=Strict/Lax cookie mitigates CSRF on this page."""
    candidates = []
    try:
        headers = getattr(response, "headers", None)
        get = getattr(headers, "get", None)
        if callable(get):
            single = get("Set-Cookie")
            if isinstance(single, str):
                candidates.append(single)
    except Exception:
        pass
    try:
        raw_headers = getattr(getattr(response, "raw", None), "headers", None)
        get_all = getattr(raw_headers, "get_all", None) or getattr(
            raw_headers, "getlist", None
        )
        if callable(get_all):
            vals = get_all("Set-Cookie", [])
            if isinstance(vals, (list, tuple)):
                candidates.extend(v for v in vals if isinstance(v, str))
    except Exception:
        pass
    return any(
        "samesite=strict" in v.lower() or "samesite=lax" in v.lower()
        for v in candidates
    )


def check_page(page_url, response):
    """Scan a single fetched page's HTML for unprotected POST forms."""
    findings = []
    soup = BeautifulSoup(response.text, "html.parser")
    samesite_mitigated = _has_samesite_cookie(response)

    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue  # CSRF is primarily a concern for state-changing (POST) forms

        if not _form_has_token(form):
            if samesite_mitigated:
                continue  # SameSite=Strict/Lax cookie mitigates CSRF
            action = urljoin(page_url, form.get("action") or page_url)
            findings.append(
                Finding(
                    vuln_type="csrf",
                    url=page_url,
                    parameter=action,
                    evidence=(
                        "POST form has no hidden field resembling a CSRF token "
                        "(e.g. csrf_token, authenticity_token, nonce)."
                    ),
                    confirmed=False,  # flagged for manual validation (step 10)
                )
            )

    return findings
