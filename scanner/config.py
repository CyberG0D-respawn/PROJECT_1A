"""
config.py
---------
Central configuration for the scanner: request behaviour, crawl limits,
and the authorization safeguard that keeps the tool pointed at test
targets rather than arbitrary live websites.

Step 1 of the project brief ("Define the scope of scanning") and
Step 2 ("Select target URLs for testing - test websites only") are
implemented here.
"""

# --- Scope: which vulnerability classes this scanner looks for ------------
SCAN_SCOPE = [
    "sql_injection",
    "xss",
    "csrf",
    "insecure_headers",
]

# --- HTTP behaviour ---------------------------------------------------------
REQUEST_TIMEOUT = 8          # seconds, per request
MAX_CRAWL_DEPTH = 2          # how many link-hops the crawler will follow
MAX_PAGES = 40                # hard ceiling so a scan can't run forever
USER_AGENT = "EduVulnScanner/1.0 (+student cybersecurity project)"
REQUEST_DELAY = 0.3           # polite delay between requests, seconds

# --- Authorization safeguard -------------------------------------------------
# Domains that are always considered safe/intended targets for this project
# (deliberately vulnerable training applications) without extra confirmation.
KNOWN_TRAINING_DOMAINS = [
    "localhost",
    "127.0.0.1",
    "webgoat",
    "nodegoat",
]

# If a target does not match one of the training domains above, the CLI
# will require the user to type an explicit confirmation phrase before a
# scan is allowed to proceed (see scanner/cli.py: confirm_authorization).
CONFIRMATION_PHRASE = "I AM AUTHORIZED"

# --- Database ---------------------------------------------------------------
# Absolute path anchored at the project root so the scanner and dashboard
# share one DB no matter which working directory they are launched from.
import os as _os

_PROJECT_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
DB_PATH = _os.path.join(_PROJECT_ROOT, "data", "scan_results.db")

# --- Severity mapping (used by report.py) -----------------------------------
SEVERITY = {
    "sql_injection": "High",
    "xss": "High",
    "csrf": "Medium",
    "insecure_headers": "Low",
}
