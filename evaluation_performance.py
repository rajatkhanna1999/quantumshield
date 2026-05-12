"""
QuantumShield - Phase 4: Performance Overhead Evaluation
Run: python evaluation_performance.py

Compares:
  Baseline  : grammar_validator only (no Qiskit needed)
  Shield    : validate_qasm() call overhead measurement

Target: overhead < 10ms per circuit
"""

import time
import statistics
from pathlib import Path
from grammar_validator import validate_qasm, QASMValidationError

# Built-in test circuits of increasing complexity
# (also picks up QASMbench small circuits if available)
BUILTIN_CIRCUITS = [
    ("Bell pair (2q, 3 gates)", """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q -> c;"""),

    ("GHZ state (5q, 8 gates)", """OPENQASM 2.0;
include "qelib1.inc";
qreg q[5];
creg c[5];
h q[0];
cx q[0],q[1];
cx q[1],q[2];
cx q[2],q[3];
cx q[3],q[4];
measure q -> c;"""),

    ("QFT-like (10q, 20 gates)", """OPENQASM 2.0;
include "qelib1.inc";
qreg q[10];
creg c[10];
h q[0];
h q[1];
h q[2];
h q[3];
h q[4];
cx q[0],q[5];
cx q[1],q[6];
cx q[2],q[7];
cx q[3],q[8];
cx q[4],q[9];
measure q -> c;"""),

    ("VQE-like (20q, 40 gates)", """OPENQASM 2.0;
include "qelib1.inc";
qreg q[20];
creg c[20];
h q[0];
h q[2];
h q[4];
h q[6];
h q[8];
h q[10];
h q[12];
h q[14];
h q[16];
h q[18];
cx q[0],q[1];
cx q[2],q[3];
cx q[4],q[5];
cx q[6],q[7];
cx q[8],q[9];
cx q[10],q[11];
cx q[12],q[13];
cx q[14],q[15];
cx q[16],q[17];
cx q[18],q[19];
measure q -> c;"""),
]

REPEATS = 500

print("=" * 65)
print("QuantumShield - Performance Overhead Evaluation")
print(f"Timing grammar validation over {REPEATS} iterations per circuit")
print("=" * 65)

# Collect QASMbench small circuits if available
qasmbench_circuits = []
qasmbench_dir = Path("QASMbench/small")
if qasmbench_dir.exists():
    for qasm_file in sorted(qasmbench_dir.rglob("*.qasm"))[:10]:
        try:
            content = qasm_file.read_text(encoding='utf-8', errors='ignore')
            validate_qasm(content)  # only use circuits our grammar accepts
            qasmbench_circuits.append((f"QASMbench/{qasm_file.name}", content))
        except Exception:
            pass

all_circuits = BUILTIN_CIRCUITS + qasmbench_circuits
validation_times = []

print(f"\n{'Circuit':<40} {'Mean (ms)':>10} {'Median (ms)':>12} {'Max (ms)':>10}")
print("-" * 75)

for name, circuit in all_circuits:
    times = []
    for _ in range(REPEATS):
        t0 = time.perf_counter()
        try:
            validate_qasm(circuit)
        except QASMValidationError:
            pass
        times.append((time.perf_counter() - t0) * 1000)

    mean_ms   = statistics.mean(times)
    median_ms = statistics.median(times)
    max_ms    = max(times)
    validation_times.extend(times)

    label = name[:38]
    print(f"  {label:<38} {mean_ms:>10.3f} {median_ms:>12.3f} {max_ms:>10.3f}")

overall_mean   = statistics.mean(validation_times)
overall_median = statistics.median(validation_times)
overall_p99    = sorted(validation_times)[int(len(validation_times) * 0.99)]

print()
print("=" * 65)
print("RESULTS")
print("=" * 65)
print(f"  Circuits tested        : {len(all_circuits)}")
print(f"  Iterations per circuit : {REPEATS}")
print(f"  Total measurements     : {len(validation_times)}")
print()
print(f"  Overall mean latency   : {overall_mean:.3f} ms")
print(f"  Overall median latency : {overall_median:.3f} ms")
print(f"  99th percentile        : {overall_p99:.3f} ms")
print()

# Context: Qiskit from_qasm_str() typically takes 5-50ms for small circuits
# So grammar validation adding <5ms = <10-100% overhead, well within target
QISKIT_BASELINE_MS = 10.0  # conservative estimate for Qiskit parse time
overhead_pct = (overall_mean / QISKIT_BASELINE_MS) * 100

print(f"  Validation overhead vs ~{QISKIT_BASELINE_MS:.0f}ms Qiskit baseline:")
print(f"    +{overall_mean:.2f}ms  (~{overhead_pct:.0f}% of parse time)")
print()

if overall_mean < 10.0:
    print("  STATUS: PAPER-READY - validation adds <10ms per circuit")
elif overall_mean < 50.0:
    print("  STATUS: ACCEPTABLE - consider switching to LALR(1) parser for speed")
else:
    print("  STATUS: SLOW - grammar optimisation needed")
print("=" * 65)
