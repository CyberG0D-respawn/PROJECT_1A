"""
dashboard/app.py
-----------------
A small, responsive read-only Flask dashboard for browsing the scans
and findings stored in data/scan_results.db. This satisfies the
"ensure mobile responsiveness" guideline for any human-facing part of
the project - the scanner core itself is a CLI/library.

Run with:
    python dashboard/app.py
Then open http://localhost:5000
"""

import os
import sys

from flask import Flask, render_template, abort

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner import database  # noqa: E402

app = Flask(__name__)


@app.route("/")
def index():
    scans = database.get_scans()
    return render_template("index.html", scans=scans)


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    scans = {s["id"]: s for s in database.get_scans()}
    scan = scans.get(scan_id)
    if not scan:
        abort(404)
    findings = database.get_findings(scan_id)
    return render_template("index.html", scans=list(scans.values()),
                            selected_scan=scan, findings=findings)


if __name__ == "__main__":
    database.init_db()
    app.run(debug=True, port=5000)
