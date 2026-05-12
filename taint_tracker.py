"""
QuantumShield — Layer 2: Taint Tracker

Tracks user-controlled data through quantum SDK code.
Flags any path where TAINTED data reaches a dangerous sink
without passing through the QuantumShield sanitizer first.

This is a lightweight runtime taint tracker for demonstration.
For production use, see the Semgrep/CodeQL rules (Phase 3)
which do this statically without runtime overhead.
"""

from enum import Enum
from typing import Any


class Taint(Enum):
    CLEAN   = 0  # safe: constant or sanitized
    TAINTED = 1  # unsafe: from user input or derived from it


class TaintedValue:
    """
    A wrapper that carries taint metadata alongside any value.

    In production quantum SDK code, user inputs would be wrapped
    in TaintedValue at API boundaries (HTTP request handlers,
    file upload handlers, CLI argument parsers).
    """

    def __init__(self, value: Any, taint: Taint, source: str = ""):
        self.value = value
        self.taint = taint
        self.source = source  # where the taint came from (for error messages)

    def is_tainted(self) -> bool:
        return self.taint == Taint.TAINTED

    def __repr__(self):
        return (f"TaintedValue({self.value!r}, "
                f"taint={self.taint.name}, source={self.source!r})")


class TaintTracker:
    """
    Tracks taint propagation through quantum SDK operations.

    Usage:
        tracker = TaintTracker()
        user_input = tracker.taint(qasm_string, source="HTTP request")
        sanitized = tracker.sanitize(user_input, sanitizer=validate_qasm)
        tracker.check_sink(sanitized, sink_name="from_qasm_str")
    """

    def __init__(self):
        self._alerts = []

    def taint(self, value: Any, source: str = "user input") -> TaintedValue:
        """Mark a value as TAINTED (coming from user input)."""
        return TaintedValue(value, Taint.TAINTED, source=source)

    def constant(self, value: Any) -> TaintedValue:
        """Mark a value as CLEAN (internal constant)."""
        return TaintedValue(value, Taint.CLEAN, source="constant")

    def propagate(self, *sources: TaintedValue,
                  result_value: Any) -> TaintedValue:
        """
        Propagate taint from source values to a result.
        If ANY source is TAINTED, the result is TAINTED.
        (This is the join operation in the taint lattice.)
        """
        if any(s.is_tainted() for s in sources):
            tainted_sources = [s.source for s in sources if s.is_tainted()]
            return TaintedValue(
                result_value, Taint.TAINTED,
                source=f"derived from: {', '.join(tainted_sources)}"
            )
        return TaintedValue(result_value, Taint.CLEAN, source="derived")

    def sanitize(self, value: TaintedValue,
                 sanitizer=None) -> TaintedValue:
        """
        Declassify a TAINTED value to CLEAN after sanitization.

        The sanitizer function must raise an exception if the value
        is unsafe. If it returns normally, the value is marked CLEAN.

        This is the ONLY operation that lowers taint from TAINTED to CLEAN.
        """
        if sanitizer is not None:
            # Run the sanitizer — raises if unsafe
            sanitizer(value.value)

        return TaintedValue(
            value.value, Taint.CLEAN,
            source=f"sanitized from: {value.source}"
        )

    def check_sink(self, value: TaintedValue,
                   sink_name: str) -> None:
        """
        Check that a value is CLEAN before passing to a dangerous sink.
        Raises TaintAlert if TAINTED data reaches the sink.
        """
        if value.is_tainted():
            alert = TaintAlert(
                sink=sink_name,
                source=value.source,
                value_preview=str(value.value)[:100]
            )
            self._alerts.append(alert)
            raise alert

    def get_alerts(self):
        return self._alerts.copy()


class TaintAlert(Exception):
    """
    Raised when TAINTED data reaches a dangerous sink.
    This is the evidence for Section 5 of your paper.
    """
    def __init__(self, sink: str, source: str, value_preview: str):
        self.sink = sink
        self.source = source
        self.value_preview = value_preview
        super().__init__(
            f"TAINT ALERT: Tainted data from '{source}' "
            f"reached sink '{sink}'. "
            f"Value preview: {value_preview!r}"
        )