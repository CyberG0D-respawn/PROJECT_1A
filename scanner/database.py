"""
database.py
-----------
Implements project step 9: "Store scan results in a database or file
system." Uses SQLite (stdlib, zero setup) with two tables:

    scans     - one row per scan run (target, timestamp, page count)
    findings  - one row per vulnerability finding, linked to a scan
"""

import sqlite3
import os
from datetime import datetime, timezone

from . import config


def _connect():
    parent = os.path.dirname(os.path.abspath(config.DB_PATH))
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT NOT NULL,
            started_at TEXT NOT NULL,
            pages_crawled INTEGER DEFAULT 0,
            surfaces_tested INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            vuln_type TEXT NOT NULL,
            url TEXT NOT NULL,
            parameter TEXT,
            evidence TEXT,
            severity TEXT,
            confirmed INTEGER,
            timestamp TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans (id)
        );
        """
    )
    conn.commit()
    conn.close()


def create_scan(target_url, pages_crawled=0, surfaces_tested=0):
    conn = _connect()
    cur = conn.execute(
        "INSERT INTO scans (target_url, started_at, pages_crawled, surfaces_tested) "
        "VALUES (?, ?, ?, ?)",
        (target_url, datetime.now(timezone.utc).isoformat(), pages_crawled, surfaces_tested),
    )
    conn.commit()
    scan_id = cur.lastrowid
    conn.close()
    return scan_id


def save_findings(scan_id, findings):
    conn = _connect()
    conn.executemany(
        """
        INSERT INTO findings
            (scan_id, vuln_type, url, parameter, evidence, severity, confirmed, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                scan_id,
                f.vuln_type,
                f.url,
                f.parameter,
                f.evidence,
                f.severity,
                int(f.confirmed),
                f.timestamp,
            )
            for f in findings
        ],
    )
    conn.commit()
    conn.close()


def get_scans():
    conn = _connect()
    rows = conn.execute("SELECT * FROM scans ORDER BY started_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_findings(scan_id=None):
    severity_order = (
        "CASE severity "
        "WHEN 'High' THEN 0 WHEN 'Medium' THEN 1 "
        "WHEN 'Low' THEN 2 ELSE 3 END"
    )
    conn = _connect()
    if scan_id is not None:
        rows = conn.execute(
            f"SELECT * FROM findings WHERE scan_id = ? ORDER BY {severity_order}, vuln_type",
            (scan_id,),
        ).fetchall()
    else:
        rows = conn.execute(
            f"SELECT * FROM findings ORDER BY scan_id DESC, {severity_order}"
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]
