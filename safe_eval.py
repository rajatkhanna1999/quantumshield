"""
QuantumShield — Layer 3: Safe Expression Evaluator

Replaces eval() in quantum SDK gate parameter processing.
Only allows numeric arithmetic — no function calls, no imports.

Fixes: CWE-94 Code Injection (qibo _openqasm.py line 237)

The vulnerable pattern this replaces:
    arg = eval(arg.replace("pi", "np.pi"))  # DANGEROUS

The safe replacement:
    arg = safe_eval_expression(arg)          # SAFE
"""

import ast
import math
import operator
from typing import Union

# The only names allowed in expressions
# pi is the only named constant in QASM
SAFE_CONSTANTS = {
    'pi': math.pi,
    'e': math.e,    # sometimes used in quantum rotations
}

# The only operators allowed
# Maps AST node types to their Python operator functions
SAFE_OPERATORS = {
    ast.Add:  operator.add,
    ast.Sub:  operator.sub,
    ast.Mult: operator.mul,
    ast.Div:  operator.truediv,
    ast.Pow:  operator.pow,
    ast.USub: operator.neg,   # unary minus
    ast.UAdd: operator.pos,   # unary plus
}

# The only AST node types allowed anywhere in the expression
ALLOWED_NODES = (
    ast.Expression,  # top-level wrapper
    ast.BinOp,       # a + b, a * b, etc.
    ast.UnaryOp,     # -a, +a
    ast.Constant,    # number literals: 0.5, 2, 3.14
    ast.Name,        # names: pi, e (checked against SAFE_CONSTANTS)
    ast.Load,        # context node attached to ast.Name (not executable)
    # Operator types
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Pow,
    ast.USub, ast.UAdd,
)


class UnsafeExpressionError(ValueError):
    """Raised when an expression contains unsafe constructs."""
    pass


def _validate_ast_node(node: ast.AST) -> None:
    """
    Walk every node in the AST and verify it is in the whitelist.
    Raises UnsafeExpressionError on first unsafe node found.

    This is the core security check. Any node type not in ALLOWED_NODES
    (function calls, imports, subscripts, attributes, etc.) is blocked.
    """
    for n in ast.walk(node):
        if not isinstance(n, ALLOWED_NODES):
            raise UnsafeExpressionError(
                f"Unsafe construct in expression: {type(n).__name__}. "
                f"Only numeric arithmetic is allowed in gate parameters."
            )
        # Additional check: only allow safe named constants
        if isinstance(n, ast.Name):
            if n.id not in SAFE_CONSTANTS:
                raise UnsafeExpressionError(
                    f"Unknown name '{n.id}' in expression. "
                    f"Only {list(SAFE_CONSTANTS.keys())} are allowed."
                )


def _eval_node(node: ast.AST) -> float:
    """
    Recursively evaluate a validated AST node.
    Only called after _validate_ast_node passes.
    """
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)

    if isinstance(node, ast.Constant):
        if not isinstance(node.value, (int, float)):
            raise UnsafeExpressionError(
                f"Non-numeric constant: {node.value}")
        return float(node.value)

    if isinstance(node, ast.Name):
        # Already validated above that name is in SAFE_CONSTANTS
        return SAFE_CONSTANTS[node.id]

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in SAFE_OPERATORS:
            raise UnsafeExpressionError(f"Unsafe operator: {op_type}")
        left = _eval_node(node.left)
        right = _eval_node(node.right)
        # Guard against division by zero
        if op_type == ast.Div and right == 0:
            raise UnsafeExpressionError("Division by zero in gate parameter")
        # Guard against enormous exponents
        if op_type == ast.Pow and abs(right) > 1000:
            raise UnsafeExpressionError(
                f"Exponent {right} too large in gate parameter")
        return SAFE_OPERATORS[op_type](left, right)

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in SAFE_OPERATORS:
            raise UnsafeExpressionError(f"Unsafe unary operator: {op_type}")
        operand = _eval_node(node.operand)
        return SAFE_OPERATORS[op_type](operand)

    raise UnsafeExpressionError(
        f"Cannot evaluate node type: {type(node).__name__}")


def safe_eval_expression(expr_str: str) -> float:
    """
    Safely evaluate a QASM gate parameter expression.

    This is the drop-in replacement for:
        eval(arg.replace("pi", "np.pi"))  # VULNERABLE

    Only allows: numbers, pi, +, -, *, /, **(power), parentheses.
    Blocks: function calls, imports, attribute access, subscripts,
            comparisons, boolean ops, comprehensions, lambdas,
            and everything else that isn't pure arithmetic.

    Examples:
        safe_eval_expression("pi/2")     -> 1.5707963...
        safe_eval_expression("0.5")      -> 0.5
        safe_eval_expression("2*pi")     -> 6.2831853...
        safe_eval_expression("pi**2/4")  -> 2.4674011...

    Raises UnsafeExpressionError for any non-arithmetic expression.
    """
    if not isinstance(expr_str, str):
        raise UnsafeExpressionError(
            f"Expression must be a string, got {type(expr_str).__name__}")

    expr_str = expr_str.strip()

    if not expr_str:
        raise UnsafeExpressionError("Empty expression")

    if len(expr_str) > 1000:
        raise UnsafeExpressionError(
            f"Expression too long ({len(expr_str)} chars). Max 1000.")

    # Parse to AST
    try:
        tree = ast.parse(expr_str, mode='eval')
    except SyntaxError as e:
        raise UnsafeExpressionError(
            f"Invalid expression syntax: {e}") from e

    # Validate every node in the AST against the whitelist
    _validate_ast_node(tree)

    # All nodes are safe — evaluate
    result = _eval_node(tree)

    # Sanity check on result
    if not isinstance(result, (int, float)):
        raise UnsafeExpressionError(
            f"Expression did not produce a number: {result}")
    if math.isnan(result) or math.isinf(result):
        raise UnsafeExpressionError(
            f"Expression produced invalid number: {result}")

    return result