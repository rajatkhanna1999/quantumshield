"""
QuantumShield — Layer 1: QASM Safe Grammar Validator

Drop-in safe replacement for:
  - qiskit.QuantumCircuit.from_qasm_str()
  - qiskit.QuantumCircuit.from_qasm_file()

Usage:
  from grammar_validator import safe_from_qasm_str, safe_from_qasm_file
  circuit = safe_from_qasm_str(user_input)  # raises ValueError if unsafe
"""

from lark import Lark, exceptions

MAX_QUBITS = 30  # Decision 2: based on Phase 1 findings

QASM_SAFE_GRAMMAR = r"""
    program      : header statement*
    header       : version_line include*
    version_line : "OPENQASM" VERSION ";"
    VERSION      : /[23]\.[0-9]/
    include      : "include" SAFE_FILENAME ";"
    SAFE_FILENAME : /\"[a-zA-Z0-9_]+\.inc\"/

    statement    : reg_decl | gate_decl | gate_op | barrier | measure | reset | if_stmt

    if_stmt      : "if" "(" SAFE_IDENT "==" SAFE_INT ")" gate_op

    reg_decl     : ("qreg" | "creg") SAFE_IDENT "[" SAFE_INT "]" ";"

    gate_decl    : "gate" SAFE_IDENT gate_params? gate_qubits "{" gate_op* "}"
    gate_params  : "(" SAFE_IDENT ("," SAFE_IDENT)* ")"
    gate_qubits  : SAFE_IDENT ("," SAFE_IDENT)*

    gate_op      : SAFE_IDENT gate_args? qubit_list ";"
    gate_args    : "(" param_list ")"
    param_list   : param_expr ("," param_expr)*

    qubit_list   : qubit_ref ("," qubit_ref)*
    qubit_ref    : SAFE_IDENT ("[" SAFE_INT "]")?

    barrier      : "barrier" qubit_list ";"
    measure      : "measure" qubit_ref "->" qubit_ref ";"
    reset        : "reset" qubit_ref ";"

    param_expr   : param_term
                 | param_expr "+" param_term
                 | param_expr "-" param_term
    param_term   : param_power
                 | param_term "*" param_power
                 | param_term "/" param_power
    param_power  : param_atom
                 | param_atom "**" param_atom
    param_atom   : NUMBER
                 | "pi"
                 | "-" param_atom
                 | "(" param_expr ")"

    SAFE_IDENT   : /[a-zA-Z][a-zA-Z0-9_]*/
    SAFE_INT     : /[0-9]+/
    NUMBER       : /[0-9]+(\.[0-9]+)?([eE][+-]?[0-9]+)?/

    %ignore /[ \t\r\n]+/
    %ignore /\/\/[^\n]*/
"""

# LALR(1) is O(n) vs Earley's O(n^3) — critical for large circuits.
# The contextual lexer resolves keyword/identifier conflicts automatically.
_parser = Lark(QASM_SAFE_GRAMMAR, parser='lalr', lexer='contextual', start='program')


class QASMValidationError(ValueError):
    """Raised when QASM input fails safety validation."""
    pass


def validate_qasm(qasm_string: str) -> bool:
    """
    Validate a QASM string against the safe grammar.

    Returns True if safe.
    Raises QASMValidationError with reason if not safe.

    This is the core of Layer 1.
    """
    if not isinstance(qasm_string, str):
        raise QASMValidationError(
            f"Expected string, got {type(qasm_string).__name__}")

    if len(qasm_string) > 1_000_000:  # 1MB limit
        raise QASMValidationError(
            "QASM string exceeds maximum allowed size (1MB)")

    # Step 1: Grammar check
    try:
        tree = _parser.parse(qasm_string)
    except exceptions.LarkError as e:
        raise QASMValidationError(
            f"QASM grammar violation: {e}") from e

    # Step 2: Semantic checks (things the grammar can't express)
    _check_semantic_rules(tree, qasm_string)

    return True


def _check_semantic_rules(tree, original: str) -> None:
    """
    Semantic validations beyond what the grammar can express.
    Currently checks: qubit count < MAX_QUBITS
    """
    for subtree in tree.iter_subtrees():
        # Check all SAFE_INT tokens
        for token in subtree.children:
            if hasattr(token, 'type') and token.type == 'SAFE_INT':
                val = int(str(token))
                # Check if this int is a register size
                if subtree.data == 'reg_decl':
                    if val >= MAX_QUBITS:
                        raise QASMValidationError(
                            f"Qubit/bit count {val} exceeds MAX_QUBITS={MAX_QUBITS}. "
                            f"This limit prevents resource exhaustion attacks (CWE-400).")
                    if val == 0:
                        raise QASMValidationError(
                            "Register size must be at least 1.")


def safe_from_qasm_str(qasm_string: str):
    """
    Safe drop-in replacement for QuantumCircuit.from_qasm_str().

    Validates input against safe grammar before passing to Qiskit.
    Raises QASMValidationError if input is unsafe.
    Raises ImportError if Qiskit is not installed.
    """
    validate_qasm(qasm_string)  # raises if unsafe

    # Only import Qiskit if validation passed
    try:
        from qiskit import QuantumCircuit
        return QuantumCircuit.from_qasm_str(qasm_string)
    except ImportError:
        raise ImportError(
            "Qiskit not installed. Install with: pip install qiskit")


def safe_from_qasm_file(filepath: str):
    """
    Safe drop-in replacement for QuantumCircuit.from_qasm_file().

    Reads file, validates content, then passes to Qiskit.
    Raises QASMValidationError if content is unsafe.
    """
    import os
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"QASM file not found: {filepath}")

    # Limit file size before reading
    file_size = os.path.getsize(filepath)
    if file_size > 1_000_000:  # 1MB
        raise QASMValidationError(
            f"QASM file exceeds maximum allowed size (1MB): {file_size} bytes")

    with open(filepath, 'r', encoding='utf-8') as f:
        qasm_string = f.read()

    return safe_from_qasm_str(qasm_string)