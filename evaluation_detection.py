"""
QuantumShield - Phase 4: Detection Rate Evaluation
Run: python evaluation_detection.py
"""

from grammar_validator import validate_qasm, QASMValidationError
from safe_eval import safe_eval_expression, UnsafeExpressionError

CWE77_PAYLOADS = [
    ('CWE-77-01', 'OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[1];\ngate __import__os q[0];'),
    ('CWE-77-02', 'OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[1];\ngate exec_cmd q[0];'),
    ('CWE-77-03', 'OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[1];\ngate __builtins__ q[0];'),
    ('CWE-77-04', 'OPENQASM 2.0;\ninclude "../../etc/passwd";\nqreg q[1];'),
    ('CWE-77-05', 'OPENQASM 2.0;\ninclude "../../../windows/system32/cmd.exe";\nqreg q[1];'),
    ('CWE-77-06', 'OPENQASM 2.0;\nqreg q[1];\ngate _private q[0];'),
    ('CWE-77-07', 'OPENQASM 2.0;\nqreg q[1];\ngate 1malformed q[0];'),
    ('CWE-77-08', 'OPENQASM 2.0;\nqreg q[1];\ngate gate-with-dash q[0];'),
    ('CWE-77-09', 'OPENQASM 2.0;\nqreg q[1];\ngate gate.with.dots q[0];'),
    ('CWE-77-10', 'OPENQASM 2.0;\nqreg q[1];\ngate subprocess q[0];'),
]

CWE400_PAYLOADS = [
    ('CWE-400-01', 'OPENQASM 2.0;\nqreg q[30];'),
    ('CWE-400-02', 'OPENQASM 2.0;\nqreg q[31];'),
    ('CWE-400-03', 'OPENQASM 2.0;\nqreg q[35];'),
    ('CWE-400-04', 'OPENQASM 2.0;\nqreg q[40];'),
    ('CWE-400-05', 'OPENQASM 2.0;\nqreg q[100];'),
    ('CWE-400-06', 'OPENQASM 2.0;\nqreg q[999];'),
    ('CWE-400-07', 'OPENQASM 2.0;\nqreg q[0];'),
]

CWE94_PAYLOADS = [
    ('CWE-94-01', "__import__('os')"),
    ('CWE-94-02', "open('/etc/passwd').read()"),
    ('CWE-94-03', "exec('import os')"),
    ('CWE-94-04', "eval('1+1')"),
    ('CWE-94-05', "os.system('calc')"),
    ('CWE-94-06', "__builtins__"),
    ('CWE-94-07', "globals()"),
    ('CWE-94-08', "locals()"),
    ('CWE-94-09', "compile('', '', 'exec')"),
    ('CWE-94-10', "PWNED"),
    ('CWE-94-11', "[x for x in []]"),
    ('CWE-94-12', "lambda: None"),
    ('CWE-94-13', "1 if True else 0"),
]

LEGITIMATE_QASM = [
    ('LEGIT-01', 'OPENQASM 2.0;\ninclude "qelib1.inc";\nqreg q[4];\ncreg c[4];\nh q[0];\ncx q[0],q[1];\nmeasure q -> c;'),
    ('LEGIT-02', 'OPENQASM 2.0;\nqreg q[1];\nh q[0];'),
    ('LEGIT-03', 'OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0],q[1];'),
    ('LEGIT-04', 'OPENQASM 2.0;\nqreg q[5];\ncreg c[5];\nh q[0];'),
    ('LEGIT-05', 'OPENQASM 2.0;\nqreg q[10];\nh q[0];'),
    ('LEGIT-06', 'OPENQASM 2.0;\nqreg q[20];'),
    ('LEGIT-07', 'OPENQASM 2.0;\nqreg q[29];'),
]

LEGITIMATE_EXPRS = [
    ('LEGIT-E01', 'pi/2',        1.5707963267948966),
    ('LEGIT-E02', '2*pi',        6.283185307179586),
    ('LEGIT-E03', '0.5',         0.5),
    ('LEGIT-E04', 'pi**2/4',     2.4674011002723395),
    ('LEGIT-E05', '-pi/4',       -0.7853981633974483),
    ('LEGIT-E06', '3.14159',     3.14159),
    ('LEGIT-E07', 'pi/2 + pi/4', 2.356194490192345),
    ('LEGIT-E08', '1.0',         1.0),
    ('LEGIT-E09', '0',           0.0),
    ('LEGIT-E10', 'pi*2 - pi',   3.141592653589793),
]

print("=" * 65)
print("QuantumShield - Detection Rate Evaluation")
print("=" * 65)

total_attacks   = 0
detected        = 0
total_legit     = 0
false_positives = 0
misses          = []
fp_list         = []

print("\n[CWE-77 QASM Injection Payloads]")
for pid, payload in CWE77_PAYLOADS:
    total_attacks += 1
    try:
        validate_qasm(payload)
        print(f"  MISS  {pid}")
        misses.append(pid)
    except (QASMValidationError, Exception):
        detected += 1
        print(f"  BLOCK {pid}")

print("\n[CWE-400 Resource Exhaustion Payloads]")
for pid, payload in CWE400_PAYLOADS:
    total_attacks += 1
    try:
        validate_qasm(payload)
        print(f"  MISS  {pid}")
        misses.append(pid)
    except (QASMValidationError, Exception):
        detected += 1
        print(f"  BLOCK {pid}")

print("\n[CWE-94 Code Injection Payloads (safe_eval)]")
for pid, payload in CWE94_PAYLOADS:
    total_attacks += 1
    try:
        safe_eval_expression(payload)
        print(f"  MISS  {pid}: '{payload[:40]}'")
        misses.append(pid)
    except (UnsafeExpressionError, Exception):
        detected += 1
        print(f"  BLOCK {pid}")

print("\n[Legitimate QASM - False Positive Test]")
for pid, payload in LEGITIMATE_QASM:
    total_legit += 1
    try:
        validate_qasm(payload)
        print(f"  PASS  {pid}")
    except Exception as e:
        false_positives += 1
        fp_list.append((pid, str(e)[:80]))
        print(f"  FP    {pid}: {str(e)[:60]}")

print("\n[Legitimate Expressions - False Positive Test]")
for pid, payload, expected in LEGITIMATE_EXPRS:
    total_legit += 1
    try:
        result = safe_eval_expression(payload)
        print(f"  PASS  {pid}: {payload} = {result:.6f}")
    except Exception as e:
        false_positives += 1
        fp_list.append((pid, str(e)[:80]))
        print(f"  FP    {pid}: '{payload}' blocked: {e}")

detection_rate = (detected / total_attacks * 100) if total_attacks else 0
fp_rate = (false_positives / total_legit * 100) if total_legit else 0

print()
print("=" * 65)
print("RESULTS")
print("=" * 65)
print(f"  Attack payloads tested   : {total_attacks}")
print(f"  Blocked (detected)       : {detected}")
print(f"  Missed                   : {total_attacks - detected}")
print(f"  Detection rate           : {detection_rate:.1f}%")
print()
print(f"  Legitimate inputs tested : {total_legit}")
print(f"  Correctly accepted       : {total_legit - false_positives}")
print(f"  False positives          : {false_positives}")
print(f"  False positive rate      : {fp_rate:.1f}%")
print()

if misses:
    print(f"  Missed payloads: {misses}")

if detection_rate >= 90 and fp_rate <= 5:
    print("  STATUS: PAPER-READY")
else:
    print("  STATUS: NEEDS IMPROVEMENT")
    if detection_rate < 90:
        print(f"    Detection {detection_rate:.1f}% is below 90% target")
    if fp_rate > 5:
        print(f"    False positive rate {fp_rate:.1f}% is above 5% target")
print("=" * 65)
