"""
finding.py
----------
A small, uniform data container each detector uses to report a result.
Keeping this shared across detectors is what lets report.py and
database.py stay generic instead of special-casing each check type.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Finding:
    vuln_type: str          # e.g. "sql_injection", "xss", "csrf", "insecure_headers"
    url: str                 # endpoint tested
    parameter: str            # parameter/field name involved (or "" for header checks)
    evidence: str              # short, human-readable reason this was flagged
    severity: str = "Info"     # filled in by report.py from config.SEVERITY
    confirmed: bool = False    # detectors set True only for strong signals
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self):
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "severity": self.severity,
            "confirmed": self.confirmed,
            "timestamp": self.timestamp,
        }
