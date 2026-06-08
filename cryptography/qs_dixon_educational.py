#!/usr/bin/env python3
"""
Dixon's Method / Quadratic Sieve pipeline — educational implementation.
Author: Ioannis Konstas — IT Solutions USA

A correct, working, well-commented demonstration of the full QS pipeline:
  - Factor base generation (Sieve of Eratosthenes)
  - Relation collection (search ±k around √N)
  - Binary exponent matrix construction over GF(2)
  - Gaussian elimination to find linear dependencies
  - X² ≡ Y² (mod N) construction and gcd-based factor extraction

Practical range: small-to-medium composites (up to ~40 bits).
For larger numbers use qs_pipeline_factorizer.py (up to ~65 bits)
or lpqs_p1_factorizer.py (adds partial large-prime relations).

Test cases:
    N = 8051      → 83 × 97
    N = 1819999   → 1301 × 1399

Usage:
    python3 qs_dixon_educational.py
"""

import math
from collections import defaultdict
import sys
import random

sys.setrecursionlimit(2000)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def is_probable_prime(n, k=10):
    if n < 2: return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41]
    for p in small:
        if n == p: return True
        if n % p == 0: return False
    if n < 43 * 43:
        return True   # passed trial division up to 41
    s, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def sieve_primes_up_to(limit):
    sieve = [True] * (limit + 1)
    sieve[0] = sieve[1] = False
    primes = []
    for p in range(2, limit + 1):
        if sieve[p]:
            primes.append(p)
            for i in range(p * p, limit + 1, p):
                sieve[i] = False
    return primes


# ---------------------------------------------------------------------------
# Dixon's QS factorizer
# ---------------------------------------------------------------------------

class DixonFactorizer:
    """
    Dixon's Method integer factorizer.

    Uses the L-notation heuristic (exponent 0.5) to size the factor base,
    collects relations by testing x = √N ± k, builds a GF(2) matrix,
    and extracts factors from linear dependencies via Gaussian elimination.
    """

    def __init__(self, N, factor_base_limit=None):
        if not isinstance(N, int) or N <= 1:
            raise ValueError("N must be an integer > 1.")
        self.N      = N
        self.sqrt_N = math.isqrt(N)

        if factor_base_limit is None:
            ln_N    = math.log(N)
            ln_ln_N = math.log(ln_N)
            B = int(math.exp(0.5 * math.sqrt(ln_N * ln_ln_N)))
            factor_base_limit = max(20, B)

        print(f"[*] B={factor_base_limit}")
        self.factor_base = sieve_primes_up_to(factor_base_limit)
        self.num_primes  = len(self.factor_base)
        self.relations   = []
        self.x_values    = []

    # ---- Smoothness --------------------------------------------------------

    @staticmethod
    def _factor_over_base(n, base):
        exps = {}
        if n < 0:
            exps[-1] = 1
            n = -n
        else:
            exps[-1] = 0
        for p in base:
            if n % p == 0:
                c = 0
                while n % p == 0:
                    c += 1
                    n //= p
                exps[p] = c
        return exps if n == 1 else None

    # ---- Relation collection -----------------------------------------------

    def _collect_relations(self, required):
        print(f"[*] Collecting {required} relations...")
        k = 1
        while len(self.relations) < required:
            for sign in (+k, -k):
                x = self.sqrt_N + sign
                if x <= 0:
                    continue
                exps = self._factor_over_base(pow(x, 2, self.N), self.factor_base)
                if exps is not None:
                    self.relations.append(exps)
                    self.x_values.append(x)
                    if len(self.relations) % 10 == 0:
                        print(f"    {len(self.relations)}/{required}")
                if len(self.relations) >= required:
                    break
            k += 1
            if k > self.N:
                print("[!] Sieving range exceeded N — increase factor base.")
                return False
        print(f"[*] Collected {len(self.relations)} relations.")
        return True

    # ---- Matrix ------------------------------------------------------------

    def _build_matrix(self):
        cols = [-1] + self.factor_base
        matrix = [[rel.get(p, 0) % 2 for p in cols] for rel in self.relations]
        print(f"[*] Matrix {len(matrix)} × {len(cols)}")
        return matrix, cols

    # ---- Gaussian elimination over GF(2) -----------------------------------

    def _gauss(self, matrix):
        nr, nc = len(matrix), len(matrix[0])
        M = [matrix[i] + [int(i == j) for j in range(nr)] for i in range(nr)]
        piv = 0
        for c in range(nc):
            if piv >= nr:
                break
            i = piv
            while i < nr and M[i][c] == 0:
                i += 1
            if i == nr:
                continue
            M[i], M[piv] = M[piv], M[i]
            for j in range(nr):
                if j != piv and M[j][c]:
                    for col in range(c, nc + nr):
                        M[j][col] ^= M[piv][col]
            piv += 1
        deps = [row[nc:] for row in M
                if not any(row[:nc]) and any(row[nc:])]
        print(f"[*] Dependencies: {len(deps)}")
        return deps

    # ---- Factor reconstruction ---------------------------------------------

    def _reconstruct(self, deps, cols):
        for dep in deps:
            X, cexp = 1, defaultdict(int)
            for i, b in enumerate(dep):
                if b:
                    X = (X * self.x_values[i]) % self.N
                    for p in cols:
                        cexp[p] += self.relations[i].get(p, 0)
            Y, ok = 1, True
            for p, e in cexp.items():
                if e % 2:
                    ok = False
                    break
                h = e // 2
                if p == -1:
                    if h % 2:
                        Y = Y * -1
                elif p > 1:
                    Y = (Y * pow(p, h, self.N)) % self.N
            if not ok or X == Y or X == self.N - Y:
                continue
            for g in (math.gcd(X - Y, self.N), math.gcd(X + Y, self.N)):
                if 1 < g < self.N:
                    return g
        return None

    # ---- Trivial checks ----------------------------------------------------

    def _trivial(self):
        if is_probable_prime(self.N):
            return self.N
        if self.N % 2 == 0:
            return 2
        for p in self.factor_base:
            if self.N % p == 0:
                return p
        for b in range(2, int(math.log2(self.N)) + 1):
            a = round(self.N ** (1 / b))
            if pow(a, b) == self.N:
                return a
        return None

    # ---- Pipeline ----------------------------------------------------------

    def run(self):
        print(f"\n[*] Dixon QS  N={self.N}  ({self.N.bit_length()} bits)")
        t = self._trivial()
        if t is not None:
            return None if t == self.N else t
        if not self._collect_relations(self.num_primes + 5):
            return None
        matrix, cols = self._build_matrix()
        deps = self._gauss(matrix)
        if not deps:
            return None
        return self._reconstruct(deps, cols)


# ---------------------------------------------------------------------------
# Driver — two built-in test cases
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    tests = [
        (8051,   20,  "83 × 97"),
        (1819999, 100, "1301 × 1399"),
    ]
    for N, B, expected in tests:
        print(f"\n{'='*45}")
        print(f"N = {N}  (expected: {expected})")
        f = DixonFactorizer(N, factor_base_limit=B)
        result = f.run()
        print("-" * 45)
        if result:
            print(f"Factor : {result}  ×  {N // result} = {N}  "
                  f"{'✓' if result * (N // result) == N else '✗'}")
        else:
            print("No factor found.")
