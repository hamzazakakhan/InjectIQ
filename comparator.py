"""
InjectIQ Comparator — Equivalent to sqlmap's comparison.py
But uses: AI response analysis + statistical timing + structural DOM diff
instead of just difflib SequenceMatcher.
"""
import difflib
import re
import statistics
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class ComparisonResult:
    is_different: bool
    ratio: float  # 0.0 = identical, 1.0 = completely different
    timing_anomaly: bool
    error_detected: bool
    error_type: str
    dbms_hint: str
    ai_verdict: Optional[dict]


class Comparator:
    """Replaces sqlmap's comparison() function with multi-signal analysis."""

    # DBMS error patterns — updated from sqlmap's settings.py DBMS_ERRORS
    ERROR_PATTERNS = {
        "mysql": [
            r"you have an error in your sql syntax",
            r"mysql_fetch",
            r"mysql_num_rows",
            r"supplied argument is not a valid mysql",
            r"warning.*mysql",
            r"check the manual.*mysql server version",
            r"unknown column",
            r"table.*doesn't exist",
        ],
        "postgresql": [
            r"postgresql.*error",
            r"warning.*pg_",
            r"unterminated quoted string",
            r"psql.*error",
            r"current transaction is aborted",
        ],
        "mssql": [
            r"microsoft.*odbc.*sql server",
            r"sql server.*error",
            r"unclosed quotation mark",
            r"syntax error.*sql server",
            r"sqlstate",
        ],
        "oracle": [
            r"ora-\d{5}",
            r"oracle.*error",
            r"oracle.*jdbc",
        ],
        "sqlite": [
            r"sqlite_?",
            r"sqlite3::",
            r"near.*syntax error",
        ],
        "mongodb": [
            r"mongo(db)? error",
            r"MongoError",
            r"Mongo::Error",
            r"bson",
        ],
    }

    def __init__(self, baseline_response=None, baseline_timing=None):
        self.baseline = baseline_response
        self.baseline_timing = baseline_timing
        self.baseline_text = baseline_response.text if baseline_response else ""
        self.baseline_length = len(self.baseline_text)
        self.timing_samples = []

    def compare(self, response, timing: float = None,
                technique: str = None, ai_client=None) -> ComparisonResult:
        """Multi-signal comparison — like sqlmap's comparison() but with:
        1. Page similarity (difflib, same as sqlmap)
        2. Timing analysis (statistical, not just threshold)
        3. Error detection (regex + AI)
        4. Structural DOM diff
        """
        if response is None:
            return ComparisonResult(False, 0.0, False, False, "", "", None)

        test_text = response.text if hasattr(response, 'text') else str(response)
        test_length = len(test_text)

        # Signal 1: Page similarity ratio (sqlmap's approach)
        ratio = self._page_ratio(test_text)

        # Signal 2: Timing anomaly detection
        timing_anomaly = False
        if timing is not None and self.baseline_timing is not None:
            timing_anomaly = self._detect_timing_anomaly(timing, technique)

        # Signal 3: DBMS error detection
        error_detected, error_type, dbms_hint = self._detect_errors(test_text)

        # Signal 4: Structural difference (status code, headers, length)
        structural_diff = self._structural_diff(response, test_length)

        # Combine signals
        is_different = (
            ratio > 0.05  # More than 5% content change
            or timing_anomaly
            or error_detected
            or structural_diff
        )

        return ComparisonResult(
            is_different=is_different,
            ratio=ratio,
            timing_anomaly=timing_anomaly,
            error_detected=error_detected,
            error_type=error_type,
            dbms_hint=dbms_hint,
            ai_verdict=None,  # Filled by async AI analysis
        )

    def _page_ratio(self, test_text: str) -> float:
        """Like sqlmap's _comparison() using SequenceMatcher.
        Returns difference ratio (0.0 = same, 1.0 = completely different)."""
        if not self.baseline_text:
            return 0.0
        seq = difflib.SequenceMatcher(None, self.baseline_text, test_text)
        return 1.0 - seq.ratio()

    def _detect_timing_anomaly(self, timing: float, technique: str = None) -> bool:
        """Statistical timing analysis — better than sqlmap's fixed threshold.
        sqlmap uses: if response_time > SLEEP_TIME_MARKER * 0.5 → True
        InjectIQ uses: statistical outlier detection from baseline distribution."""
        self.timing_samples.append(timing)

        if len(self.timing_samples) < 3:
            # Not enough samples — use simple threshold
            if technique in ("time_blind", "stacked"):
                return timing > self.baseline_timing + 3.0  # 3s above baseline
            return False

        # Statistical outlier: timing is > mean + 2*stddev
        mean = statistics.mean(self.timing_samples[:-1])  # Exclude current
        stdev = statistics.stdev(self.timing_samples[:-1]) if len(self.timing_samples) > 2 else 0.5
        threshold = mean + 2 * max(stdev, 0.5)

        return timing > threshold

    def _detect_errors(self, text: str) -> tuple[bool, str, str]:
        """Detect DBMS error messages — like sqlmap's wasLastResponseDBMSError()."""
        for dbms, patterns in self.ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.I | re.S):
                    return True, "dbms_error", dbms
        return False, "", ""

    def _structural_diff(self, response, test_length: int) -> bool:
        """Detect structural differences beyond content."""
        if not self.baseline:
            return False
        # Status code change
        if hasattr(response, 'status_code') and hasattr(self.baseline, 'status_code'):
            if response.status_code != self.baseline.status_code:
                return True
        # Length change > 20%
        if abs(test_length - self.baseline_length) > self.baseline_length * 0.2:
            return True
        return False
