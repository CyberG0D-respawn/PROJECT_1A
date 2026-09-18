"""
xss.py
------
Reflected Cross-Site Scripting detection.

Approach: submit a unique marker wrapped in a harmless script-like tag
for each parameter, then check whether the marker comes back in the
response *unescaped* (i.e. still as real HTML rather than as
&lt;...&gt; entities). Reflection in unescaped form means the browser
would execute it - a strong signal of a reflected XSS vulnerability.
"""

import uuid

import requests

from .finding import Finding
from .. import config


def _build_payload():
    marker = uuid.uuid4().hex[:8]
    payload = f"<script>edu_xss_{marker}</script>"
    return marker, payload


def check(session, surface):
    findings = []

    for param_name in surface.params:
        marker, payload = _build_payload()
        test_params = dict(surface.params)
        test_params[param_name] = payload

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

        # Unescaped reflection: the literal payload string appears intact.
        if payload in resp.text:
            findings.append(
                Finding(
                    vuln_type="xss",
                    url=surface.url,
                    parameter=param_name,
                    evidence=(
                        f"Input for '{param_name}' was reflected back in the "
                        "response unescaped, without HTML-encoding."
                    ),
                    confirmed=True,
                )
            )
        elif marker in resp.text:
            # The marker text survived but the tag was stripped/escaped -
            # worth a manual look, but not a confirmed hit.
            findings.append(
                Finding(
                    vuln_type="xss",
                    url=surface.url,
                    parameter=param_name,
                    evidence=(
                        f"Input for '{param_name}' was reflected in the response; "
                        "encoding could not be fully verified automatically."
                    ),
                    confirmed=False,
                )
            )

    return findings
