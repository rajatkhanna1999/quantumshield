# QuantumShield

**A Defense Framework Against Quantum SDK Injection Vulnerabilities  
in Human and Agentic Development Workflows**

> Companion artifact repository for the paper submitted to  
> ACSAC 2026. Anonymous submission — author information  
> withheld for double-blind review.

---

## What is QuantumShield?

QuantumShield is the first systematic defense framework for  
open-source quantum computing simulator SDKs, addressing four  
confirmed vulnerability classes (CWE-77, CWE-400, CWE-94,  
CWE-502) across Qiskit, Cirq, PennyLane, and qibo.

It provides four complementary layers:

| Layer | Component | Defends Against |
|-------|-----------|-----------------|
| 1 | Lark grammar pre-validator | CWE-77 QASM Injection, CWE-400 Resource Exhaustion |
| 2 | TaintedValue taint tracker | Unsanitized flows to dangerous sinks |
| 3 | AST-whitelist expression evaluator | CWE-94 Code Injection via eval() |
| 4 | Semgrep CI/CD rules (8 rules) | All four CWE classes in agent-generated code |

---

## Repository Structure
quantumshield/
├── grammar_validator.py       # Layer 1: Lark LALR(1) QASM grammar
├── taint_tracker.py           # Layer 2: TaintedValue taint model
├── safe_eval.py               # Layer 3: AST-whitelist evaluator
├── z3_proofs.py               # SMT-backed policy validation (6 theorems)
├── quantum-shield-rules.yaml  # Layer 4: 8 Semgrep rules
├── agent_prompts/             # 40 prompts used in agent experiment
├── eval/
│   ├── evaluation_detection.py    # 30-payload detection evaluation
│   ├── evaluation_performance.py  # Latency measurement (4 circuits)
│   ├── evaluation_qasmbench.py    # QASMbench false-positive evaluation
│   └── agent_experiment.py        # 3-model LLM agent experiment
├── poc/
│   ├── poc_cwe94_qibo.py          # Live CWE-94 PoC (three-stream)
│   └── poc_output.txt             # Confirmed PoC output
└── results/
├── initialresults.txt         # Vulnerability reproduction results
└── qasmbench_results.txt      # QASMbench evaluation output

---

## Quick Start

```bash
pip install lark z3-solver semgrep

# Run detection evaluation (30 payloads)
python eval/evaluation_detection.py

# Run performance evaluation
python eval/evaluation_performance.py

# Run Z3 policy validation proofs
python z3_proofs.py

# Run Semgrep rules against a codebase
semgrep --config quantum-shield-rules.yaml .
```

---

## Key Results

| Metric | Result |
|--------|--------|
| Detection rate (30 hand-crafted payloads) | **100%** (30/30) |
| Parsing accuracy (127 in-scope QASMbench circuits) | **100%** |
| Mean validation overhead | **4.1 ms** |
| Agent-generated code detection (120 artifacts, 3 models) | **56.7%** [95% CI: 48–65%] |
| Z3 constraint-consistency proofs | **6/6 UNSAT** |

---

## CI/CD Integration

One line to add QuantumShield scanning to any pipeline:

```bash
semgrep --config quantum-shield-rules.yaml .
```

---

## License

Apache 2.0 — see LICENSE file.

---

*Author information withheld for double-blind review.  
Will be updated upon paper acceptance.*