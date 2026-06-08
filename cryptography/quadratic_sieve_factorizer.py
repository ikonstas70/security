#!/usr/bin/env python3
"""
Quadratic Sieve integer factorizer.
Author: Ioannis Konstas — IT Solutions USA

Implements the Quadratic Sieve (QS) algorithm for factoring large composite
integers. Uses Miller-Rabin primality testing, smooth-number relation
collection over a factor base, and Gaussian elimination over GF(2) to find
congruences of squares that reveal non-trivial factors.

Practical range: integers up to ~100 bits. For numbers above that range,
the General Number Field Sieve (GNFS) is required.

Usage:
    python3 quadratic_sieve_factorizer.py
    python3 quadratic_sieve_factorizer.py --n 8051
    python3 quadratic_sieve_factorizer.py --n 8051 --limit 200
"""

import argparse
import math
import random
from collections import defaultdict
from math import gcd


# ---------------------------------------------------------------------------
# Miller-Rabin probabilistic primality test
# ---------------------------------------------------------------------------

def miller_rabin(n, k=5):
    """Returns True if n is probably prime (k rounds of testing)."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    def is_composite(a):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            return False
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return False
        return True

    for _ in range(k):
        a = random.randint(2, n - 2)
        if is_composite(a):
            return False
    return True


# ---------------------------------------------------------------------------
# AdvancedFactorizer
# ---------------------------------------------------------------------------

class AdvancedFactorizer:
    """
    Factors a composite integer n using the Quadratic Sieve algorithm.

    Steps:
      1. Build a factor base of primes up to factor_base_limit.
      2. Search for smooth numbers: values x near sqrt(n) where x^2 mod n
         factors completely over the factor base (B-smooth relations).
      3. Represent each relation as a binary vector of prime exponents mod 2.
      4. Gaussian elimination over GF(2) finds a linear dependency —
         a subset of relations whose combined exponent vector is all zeros.
      5. That dependency gives X and Y satisfying X^2 ≡ Y^2 (mod n).
      6. gcd(X-Y, n) yields a non-trivial factor.
    """

    def __init__(self, n, factor_base_limit=100):
        self.n = n
        self.factor_base = [p for p in range(2, factor_base_limit)
                            if miller_rabin(p)]

    def _factorize_over_base(self, m):
        """
        Attempts to factor m completely over the factor base.
        Returns a dict {prime: exponent} if fully smooth, else None.
        """
        factors = defaultdict(int)
        temp = m
        for p in self.factor_base:
            while temp % p == 0:
                factors[p] += 1
                temp //= p
        return factors if temp == 1 else None

    def factorize(self):
        """
        Returns a non-trivial factor of self.n, or an explanatory string
        if the algorithm cannot find one with the current parameters.
        """
        # Trivial cases
        if miller_rabin(self.n):
            return self.n  # Already prime

        for p in self.factor_base:
            if self.n % p == 0:
                return p

        # ---- Relation collection ----------------------------------------
        # Search for x values near sqrt(n) such that x^2 mod n is B-smooth.
        relations = []
        start = math.isqrt(self.n) + 1
        search_window = max(2000, len(self.factor_base) * 10)

        for x in range(start, start + search_window):
            y_sq = (x * x) % self.n
            factors = self._factorize_over_base(y_sq)
            if factors:
                relations.append((x, factors))
            if len(relations) > len(self.factor_base) + 2:
                break

        if not relations:
            return (
                "Failed to collect enough smooth relations. "
                "Try increasing --limit (factor_base_limit)."
            )

        # ---- Build binary exponent matrix over GF(2) ---------------------
        matrix = []
        for _, factors in relations:
            row = [factors.get(p, 0) % 2 for p in self.factor_base]
            matrix.append(row)

        n_rel   = len(matrix)
        m_base  = len(self.factor_base)

        # ---- Gaussian elimination ----------------------------------------
        pivot_map = {}  # column -> (row, index_set)

        for i in range(n_rel):
            row     = list(matrix[i])
            indices = {i}

            for j in range(m_base):
                if row[j] == 1:
                    if j in pivot_map:
                        prev_row, prev_indices = pivot_map[j]
                        row     = [row[k] ^ prev_row[k] for k in range(m_base)]
                        indices ^= prev_indices
                    else:
                        pivot_map[j] = (row, indices)
                        break
            else:
                # Entire row reduced to zero — linear dependency found.
                # Reconstruct X and Y from the contributing relations.
                X = 1
                combined = defaultdict(int)
                for idx in indices:
                    x_val, f_map = relations[idx]
                    X = (X * x_val) % self.n
                    for p, exp in f_map.items():
                        combined[p] += exp

                Y = 1
                for p, exp in combined.items():
                    Y = (Y * pow(p, exp // 2, self.n)) % self.n

                factor = gcd(X - Y, self.n)
                if 1 < factor < self.n:
                    return factor

        return (
            "No non-trivial factor found. "
            "Try increasing --limit or re-running (algorithm is probabilistic)."
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Quadratic Sieve integer factorizer — IT Solutions USA"
    )
    parser.add_argument("--n",     type=int, default=8051,
                        help="Integer to factor (default: 8051)")
    parser.add_argument("--limit", type=int, default=100,
                        help="Factor base prime limit (default: 100)")
    args = parser.parse_args()

    n     = args.n
    limit = args.limit

    print(f"[*] Target : {n}")
    print(f"[*] Factor base limit : {limit}")
    print(f"[*] Bit length : {n.bit_length()} bits")
    print()

    factorizer = AdvancedFactorizer(n, factor_base_limit=limit)
    result = factorizer.factorize()

    if isinstance(result, int):
        other = n // result
        print(f"[+] Factor found : {result}")
        print(f"[+] Other factor : {other}")
        print(f"[+] Verification : {result} × {other} = {result * other} "
              f"({'✓' if result * other == n else '✗'})")
    else:
        print(f"[-] {result}")


if __name__ == "__main__":
    main()
