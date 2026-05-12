"""
QuantumShield Phase 2 — Test Suite
Run: python test_phase2.py

Tests that every layer of the defence works correctly.
"""

from grammar_validator import validate_qasm, safe_from_qasm_str, QASMValidationError
from safe_eval import safe_eval_expression, UnsafeExpressionError
from taint_tracker import TaintTracker, TaintAlert
import math

passed = 0
failed = 0


def _expect_error(fn, error_class):
    try:
        fn()
        raise AssertionError(f"Expected {error_class.__name__} but no error raised")
    except error_class:
        pass  # expected


def assert_close(a, b, tol=1e-10):
    if abs(a - b) > tol:
        raise AssertionError(f"{a} != {b} (tolerance {tol})")


def test(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  PASS: {name}")
        passed += 1
    except Exception as e:
        print(f"  FAIL: {name}")
        print(f"        {type(e).__name__}: {e}")
        failed += 1

print("="*60)
print("Layer 1: Grammar Validator Tests")
print("="*60)

VALID_QASM = """
OPENQASM 2.0;
include "qelib1.inc";
qreg q[4];
creg c[4];
h q[0];
cx q[0], q[1];
measure q -> c;
"""

test("Valid QASM passes",
     lambda: validate_qasm(VALID_QASM))

test("Malicious gate name blocked",
     lambda: __import__('pytest').raises(QASMValidationError,
         match="grammar") if False else
     _expect_error(lambda: validate_qasm("""
         OPENQASM 2.0;
         include "qelib1.inc";
         qreg q[1];
         gate __import__os q[0];
     """), QASMValidationError))

test("CWE-400: 35 qubits blocked",
     lambda: _expect_error(lambda: validate_qasm("""
         OPENQASM 2.0;
         qreg q[35];
     """), QASMValidationError))

test("CWE-400: 4 qubits allowed",
     lambda: validate_qasm("""
         OPENQASM 2.0;
         qreg q[4];
     """))

test("Path traversal in include blocked",
     lambda: _expect_error(lambda: validate_qasm("""
         OPENQASM 2.0;
         include "../../etc/passwd";
     """), QASMValidationError))

print()
print("="*60)
print("Layer 3: Safe Expression Evaluator Tests")
print("="*60)

test("pi/2 evaluates correctly",
     lambda: assert_close(safe_eval_expression("pi/2"), math.pi/2))

test("2*pi evaluates correctly",
     lambda: assert_close(safe_eval_expression("2*pi"), 2*math.pi))

test("0.5 evaluates correctly",
     lambda: assert_close(safe_eval_expression("0.5"), 0.5))

test("pi**2/4 evaluates correctly",
     lambda: assert_close(safe_eval_expression("pi**2/4"), math.pi**2/4))

test("CWE-94: __import__ blocked",
     lambda: _expect_error(
         lambda: safe_eval_expression("__import__('os')"),
         UnsafeExpressionError))

test("CWE-94: function call blocked",
     lambda: _expect_error(
         lambda: safe_eval_expression("open('/etc/passwd')"),
         UnsafeExpressionError))

test("CWE-94: attribute access blocked",
     lambda: _expect_error(
         lambda: safe_eval_expression("os.system('calc')"),
         UnsafeExpressionError))

test("CWE-94: PWNED name blocked",
     lambda: _expect_error(
         lambda: safe_eval_expression("PWNED"),
         UnsafeExpressionError))

print()
print("="*60)
print("Layer 2: Taint Tracker Tests")
print("="*60)

def test_taint_clean_path():
    from grammar_validator import validate_qasm
    tracker = TaintTracker()
    user_input = tracker.taint(VALID_QASM, source="HTTP request")
    sanitized = tracker.sanitize(user_input, sanitizer=validate_qasm)
    tracker.check_sink(sanitized, sink_name="from_qasm_str")  # should not raise

test("Clean path: sanitized input passes sink check", test_taint_clean_path)

def test_taint_dirty_path():
    tracker = TaintTracker()
    user_input = tracker.taint("MALICIOUS QASM", source="HTTP request")
    # No sanitization — send directly to sink
    try:
        tracker.check_sink(user_input, sink_name="from_qasm_str")
        raise AssertionError("Should have raised TaintAlert")
    except TaintAlert:
        pass  # Expected

test("Dirty path: unsanitized input raises TaintAlert", test_taint_dirty_path)

print()
print("="*60)
print(f"Results: {passed} passed, {failed} failed")
print("="*60)
if failed == 0:
    print("All tests passed. Phase 2 implementation complete.")
else:
    print(f"{failed} tests failed. Debug above before moving to Phase 3.")

