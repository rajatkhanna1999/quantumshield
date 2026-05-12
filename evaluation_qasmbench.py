"""
QuantumShield - Phase 4: QASMbench False Positive Rate Evaluation
Run: python evaluation_qasmbench.py
Requires: git clone https://github.com/pnnl/QASMbench.git
"""

import os
from grammar_validator import validate_qasm, QASMValidationError

QASMBENCH_PATH = "QASMbench"

if not os.path.exists(QASMBENCH_PATH):
    print("ERROR: QASMbench not found.")
    print("Run: git clone https://github.com/pnnl/QASMbench.git")
    exit(1)

total = 0
passed = 0
policy_rejected = 0   # >30 qubits or >1MB — intentional by design
grammar_fp = 0        # valid circuits the grammar wrongly rejects
grammar_fp_files = []

print("=" * 65)
print("QuantumShield - QASMbench False Positive Rate Evaluation")
print("=" * 65)
print(f"\nScanning circuits in {QASMBENCH_PATH}...\n")

for root, dirs, files in os.walk(QASMBENCH_PATH):
    for fname in sorted(files):
        if not fname.endswith('.qasm'):
            continue
        fpath = os.path.join(root, fname)
        total += 1
        short = fpath.replace(QASMBENCH_PATH, '').lstrip('\\/').replace('\\', '/')
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            validate_qasm(content)
            passed += 1
            print(f"  PASS   {short}")
        except QASMValidationError as e:
            reason = str(e)
            # Distinguish policy rejections from grammar bugs
            if "exceeds MAX_QUBITS" in reason or "exceeds maximum allowed size" in reason:
                policy_rejected += 1
                print(f"  POLICY {short}  ({reason[:50]})")
            else:
                grammar_fp += 1
                grammar_fp_files.append((short, reason[:80]))
                print(f"  FP     {short}")
                print(f"         {reason[:80]}")
        except Exception as e:
            grammar_fp += 1
            reason = f"{type(e).__name__}: {str(e)[:60]}"
            grammar_fp_files.append((short, reason))
            print(f"  ERR    {short}")
            print(f"         {reason}")

# False positive rate = grammar bugs only (policy rejections are intentional)
in_scope = total - policy_rejected
fp_rate = (grammar_fp / in_scope * 100) if in_scope > 0 else 0

print()
print("=" * 65)
print("RESULTS")
print("=" * 65)
print(f"  Total circuits in QASMbench  : {total}")
print(f"  Passed (accepted)            : {passed}")
print(f"  Policy rejected (>30q/>1MB)  : {policy_rejected}  [intentional by design]")
print(f"  Grammar false positives      : {grammar_fp}  [actual FP]")
print(f"")
print(f"  In-scope circuits            : {in_scope}  (excludes policy rejections)")
print(f"  False positive rate          : {fp_rate:.2f}%  (grammar FP / in-scope)")

if grammar_fp_files:
    print(f"\n  Grammar false positive details:")
    for fpath, reason in grammar_fp_files:
        print(f"    {fpath}")
        print(f"      -> {reason}")

print()
if grammar_fp == 0:
    print("  STATUS: PERFECT - 0 grammar false positives")
elif fp_rate <= 5.0:
    print(f"  STATUS: GOOD - {fp_rate:.2f}% FP rate within acceptable range")
else:
    print(f"  STATUS: NEEDS WORK - {fp_rate:.2f}% FP rate exceeds 5% target")
print("=" * 65)
