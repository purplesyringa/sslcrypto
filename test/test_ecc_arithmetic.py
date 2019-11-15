import os
import pytest
import sslcrypto.fallback
from collections import defaultdict


# Parse test cases
curve_tests = defaultdict(lambda: [])
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "arithmetic.txt")) as f:
    name = None
    k, x, y = None, None, None
    for line in f:
        if line.startswith("Curve: "):
            name = line.split()[1]
        elif line.startswith("k = "):
            k = int(line.split()[2])
        elif line.startswith("x = "):
            x = int(line.split()[2], 16)
        elif line.startswith("y = "):
            y = int(line.split()[2], 16)
            curve_tests[name].append((k, x, y))


# Show different curves as different testcases
for name in curve_tests:
    def _gen(name):  # Closure
        curve = sslcrypto.fallback.ecc.get_curve(name)
        jacobian = curve._backend.jacobian

        def test():
            for k, x, y in curve_tests[name]:
                assert jacobian.fast_multiply(jacobian.g, k) == (x, y)

        globals()["test_{}".format(name)] = test

    _gen(name)
