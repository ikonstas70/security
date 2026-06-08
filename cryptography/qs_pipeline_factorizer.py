#!/usr/bin/env python3
"""
Quadratic Sieve pipeline — Dixon's method with 100-bit capability push.
Author: Ioannis Konstas — IT Solutions USA

Implements the basic Quadratic Sieve (no large-prime partial relations)
with an aggressive heuristic factor-base sizing, an 80-relation buffer,
and a safety sieving limit scaled to N's bit length. Targets numbers up
to approximately 65 bits; may succeed on harder 90-bit inputs with a
sufficiently large factor base.

This variant uses a static _factor_over_base method and a cols-based
dependency processor. See lpqs_p1_factorizer.py for the P1 upgrade
that adds partial relation support.

Usage:
    python3 qs_pipeline_factorizer.py
    (interactive — prompts for N)
"""

import math
from collections import defaultdict
import sys
import random

sys.setrecursionlimit(3000)


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
        return True
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
# QS pipeline factorizer
# ---------------------------------------------------------------------------

class QSPipelineFactorizer:
    """
    Basic Quadratic Sieve with aggressive heuristic parameters.

    Differences from quadratic_sieve_factorizer.py:
      - Factor base capped at 5,000 (rather than a search window)
      - Relations collected symmetrically around sqrt(N) (±k)
      - Safety sieving limit scales with N.bit_length() ** 3
      - Dependency processor receives the full column list as a parameter
      - Buffer target is 80 over the prime count (vs 2000-relation window)
    """

    def __init__(self, N, factor_base_limit=None):
        if not isinstance(N, int) or N <= 1:
            raise ValueError("N must be an integer > 1.")
        self.N      = N
        self.sqrt_N = math.isqrt(N)

        if factor_base_limit is None:
            ln_N    = math.log(N)
            ln_ln_N = math.log(ln_N)
            B = int(math.exp(0.55 * math.sqrt(ln_N * ln_ln_N)))
            factor_base_limit = max(1200, B)

        self.factor_base_limit = min(5000, factor_base_limit)
        self.factor_base       = sieve_primes_up_to(self.factor_base_limit)
        self.num_primes        = len(self.factor_base)

        print(f"[*] B={self.factor_base_limit}  ({self.num_primes} primes)")

        self.relations = []   # list of exponent dicts
        self.x_values  = []

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

    def _collect_relations(self, required):
        print(f"[*] Collecting {required} relations...")
        k, safety = 1, self.N.bit_length() ** 3
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
            if k > safety:
                print("[!] Safety limit reached.")
                return False
        print(f"[*] Collected {len(self.relations)} relations.")
        return True

    def _build_matrix(self):
        all_cols = [-1] + self.factor_base
        nc       = len(all_cols)
        matrix   = [[rel.get(p, 0) % 2 for p in all_cols]
                    for rel in self.relations]
        print(f"[*] Matrix {len(matrix)} × {nc}")
        return matrix, all_cols

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
                        Y = (Y * -1)
                elif p > 1:
                    Y = (Y * pow(p, h, self.N)) % self.N
            if not ok or X == Y or X == self.N - Y:
                continue
            for g in (math.gcd(abs(X - Y), self.N), math.gcd(X + Y, self.N)):
                if 1 < g < self.N:
                    return g
        return None

    def _trivial(self):
        if is_probable_prime(self.N):
            return self.N
        if self.N % 2 == 0:
            return 2
        for p in self.factor_base:
            if self.N % p == 0:
                return p
        for b in range(2, min(int(math.log2(self.N)) + 1, 100)):
            a = round(self.N ** (1 / b))
            if pow(a, b) == self.N:
                return a
        return None

    def run(self):
        print(f"\n[*] QS Pipeline  N={self.N}  ({self.N.bit_length()} bits)")
        t = self._trivial()
        if t is not None:
            return None if t == self.N else t
        if not self._collect_relations(self.num_primes + 80):
            return None
        matrix, cols = self._build_matrix()
        deps = self._gauss(matrix)
        if not deps:
            return None
        return self._reconstruct(deps, cols)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("QS Pipeline Factorizer — IT Solutions USA")
    print("Enter a composite integer N.  Type 'q' to exit.\n")
    while True:
        try:
            raw = input("N: ").strip()
            if raw.lower() in ("q", "quit"):
                break
            N = int(raw)
            if N <= 1:
                print("Enter an integer > 1.")
                continue
            f = QSPipelineFactorizer(N)
            result = f.run()
            print("-" * 40)
            if result:
                print(f"Factor : {result}")
                print(f"Other  : {N // result}")
            else:
                print("No factor found.")
            print("-" * 40)
        except ValueError:
            print("Invalid input.")
        except (EOFError, KeyboardInterrupt):
            break
