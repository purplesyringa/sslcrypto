import os
import pytest
import sslcrypto
import sslcrypto.fallback
from sslcrypto.fallback._util import bytes_to_int, int_to_bytes
from collections import defaultdict


# Parse test cases
def fromhex(s):
    return bytes.fromhex("0" * (len(s) % 2) + s)

curve_tests = defaultdict(lambda: [])
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ecdsa.txt")) as f:
    name = None
    msg, d, qx, qy, k, r, s = None, None, None, None, None, None, None
    for line in f:
        if line.startswith("Curve: "):
            name = line.split()[1]
        elif line.startswith("Msg = "):
            msg = fromhex(line.split()[2])
        elif line.startswith("d = "):
            d = fromhex(line.split()[2])
        elif line.startswith("Qx = "):
            qx = fromhex(line.split()[2])
        elif line.startswith("Qy = "):
            qy = fromhex(line.split()[2])
        elif line.startswith("k = "):
            k = fromhex(line.split()[2])
        elif line.startswith("R = "):
            r = fromhex(line.split()[2])
        elif line.startswith("S = "):
            s = fromhex(line.split()[2])
            curve_tests[name].append((msg, d, qx, qy, k, r, s))


# Show different curves as different testcases
for name in curve_tests:
    def _gen(name):  # Closure
        # Pure-Python implementation
        curve = sslcrypto.fallback.ecc.get_curve(name)

        def test():
            for msg, d, qx, qy, k, r, s in curve_tests[name]:
                inv_s = int_to_bytes(curve._backend.n - bytes_to_int(s), len(s))
                signature = curve.sign(msg, d, hash=None, entropy=k)
                assert signature[:len(r)] == r
                assert signature[len(r):] in (s, inv_s)
                assert curve.verify(signature, msg, b"\x04" + qx + qy, hash=None)

        globals()["test_{}".format(name)] = test


        # Try testing native version as well
        if sslcrypto.ecc is not sslcrypto.fallback.ecc:
            native_curve = sslcrypto.ecc.get_curve(name)

            def test():
                for msg, d, qx, qy, k, r, s in curve_tests[name]:
                    inv_s = int_to_bytes(curve._backend.n - bytes_to_int(s), len(s))
                    signature = native_curve.sign(msg, d, hash=None, entropy=k)
                    assert signature[:len(r)] == r
                    assert signature[len(r):] in (s, inv_s)
                    assert native_curve.verify(signature, msg, b"\x04" + qx + qy, hash=None)

            globals()["test_native_{}".format(name)] = test



    _gen(name)
