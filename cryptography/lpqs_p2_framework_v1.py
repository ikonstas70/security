#!/usr/bin/env python3
"""
Large Prime Quadratic Sieve — P2 (two-large-prime) framework, version 1.
Author: Ioannis Konstas — IT Solutions USA

Extends the P1 variant to allow relations with up to two large primes
(L1, L2 ≤ P_max). P2 relations yield significantly more usable partial
relations per sieving unit, which is critical for scaling toward 250-bit N.

This version includes a working dense Gaussian elimination solver for
prototype-scale testing (N up to ~64 bits). For 250-bit N the dense
solver must be replaced by Block Lanczos or Wiedemann (see v2).

Test case: N = 2_616_719  (factors: 1129 × 2317)

Usage:
    python3 lpqs_p2_framework_v1.py
"""

import math
from collections import defaultdict
import sys
import random
from typing import List, Dict, Tuple, Optional, Set

sys.setrecursionlimit(5000)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def is_probable_prime(n: int, k: int = 10) -> bool:
    if n < 2: return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for p in small:
        if n == p: return True
        if n % p == 0: return False
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


def sieve_primes_up_to(limit: int) -> List[int]:
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
# LPQS P2 Framework — version 1 (working, dense solver)
# ---------------------------------------------------------------------------

class LPQS_P2_Framework:
    """
    Large Prime Quadratic Sieve with P2 (two-large-prime) relation support.
    Prototype scale: up to ~64-bit N with the bundled dense GF(2) solver.
    """

    def __init__(self, N: int, is_prototype_run: bool = True):
        if not isinstance(N, int) or N <= 1:
            raise ValueError("N must be an integer > 1.")
        self.N = N
        self.sqrt_N = math.isqrt(N)

        if is_prototype_run:
            self.factor_base_limit = 1000
            self.large_prime_limit = 5000
        else:
            self.factor_base_limit = 100_000
            self.large_prime_limit = 10 * self.factor_base_limit

        self.factor_base = sieve_primes_up_to(self.factor_base_limit)
        self.num_primes  = len(self.factor_base)

        print(f"\n[*] LPQS P2 v1  N={N}  ({N.bit_length()} bits)")
        print(f"    B={self.factor_base_limit}  P_max={self.large_prime_limit}"
              f"  |base|={self.num_primes}")

        self.relations: List[Tuple[Dict[int,int], Set[int]]] = []
        self.x_values:  List[int] = []
        self.unique_lps: Set[int] = set()

    # ---- P2 smoothness check -----------------------------------------------

    def _factor_over_base(self, n: int) -> Tuple[Optional[Dict[int,int]], Optional[Set[int]]]:
        exps: Dict[int,int] = defaultdict(int)
        lps: List[int] = []

        if n < 0:
            exps[-1] = 1
            n = -n

        temp = n
        for p in self.factor_base:
            if temp % p == 0:
                c = 0
                while temp % p == 0:
                    c += 1
                    temp //= p
                exps[p] = c

        if temp == 1:
            return dict(exps), set()           # Full relation

        # Single large prime L1 ≤ P_max
        if temp <= self.large_prime_limit and is_probable_prime(temp):
            exps[temp] = 1
            return dict(exps), {temp}          # P1 relation

        # Two large primes: search for L1 | temp
        limit = min(math.isqrt(temp), self.large_prime_limit)
        L1 = None
        for p in sieve_primes_up_to(limit):
            if temp % p == 0:
                L1 = p
                break

        if L1 is not None:
            L2 = temp // L1
            if (L1 <= self.large_prime_limit and
                    is_probable_prime(L2) and L2 <= self.large_prime_limit):
                exps[L1] = exps.get(L1, 0) + 1
                exps[L2] = exps.get(L2, 0) + 1
                return dict(exps), {L1, L2}    # P2 relation

        return None, None                       # Discard

    # ---- Relation collection -----------------------------------------------

    def _collect_relations(self, buffer: int = 100) -> bool:
        target = self.num_primes + buffer
        print(f"[*] Targeting {target} relations...")
        k, limit = 1, 100_000

        while len(self.relations) < target and k < limit:
            for sign in (+k, -k):
                x = self.sqrt_N + sign
                if x <= 0:
                    continue
                exps, lps = self._factor_over_base(pow(x, 2, self.N))
                if lps is not None:
                    self.unique_lps.update(lps)
                    self.relations.append((exps, lps))
                    self.x_values.append(x)
                    if len(self.relations) % 100 == 0:
                        print(f"    {len(self.relations)} relations  "
                              f"({len(self.unique_lps)} unique LPs)")
                if len(self.relations) >= target:
                    break
            k += 1

        print(f"[*] Collected {len(self.relations)} relations.")
        return True

    # ---- Matrix construction -----------------------------------------------

    def _build_matrix(self) -> Tuple[List[List[int]], List[int]]:
        all_cols  = [-1] + self.factor_base + sorted(self.unique_lps)
        col_idx   = {p: i for i, p in enumerate(all_cols)}
        nc        = len(all_cols)
        matrix    = []
        for exps, _ in self.relations:
            row = [0] * nc
            for p, c in exps.items():
                if p in col_idx:
                    row[col_idx[p]] = c % 2
            matrix.append(row)
        print(f"[*] Matrix {len(matrix)} × {nc}")
        return matrix, all_cols

    # ---- Dense GF(2) solver (prototype only) --------------------------------

    def _solve_dense(self, matrix: List[List[int]]) -> List[List[int]]:
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
        deps = []
        for row in M:
            if not any(row[:nc]):
                v = row[nc:]
                if any(v):
                    deps.append(v)
        print(f"[*] Dependencies: {len(deps)}")
        return deps

    # ---- Factor reconstruction ---------------------------------------------

    def _reconstruct(self, deps: List[List[int]]) -> Optional[int]:
        for dep in deps:
            X, cexp = 1, defaultdict(int)
            for i, b in enumerate(dep):
                if b:
                    exps, _ = self.relations[i]
                    X = (X * self.x_values[i]) % self.N
                    for p, c in exps.items():
                        cexp[p] += c
            Y, ok = 1, True
            for p, e in cexp.items():
                if e % 2:
                    ok = False
                    break
                h = e // 2
                if p == -1:
                    if h % 2:
                        Y = (self.N - Y) % self.N
                elif p > 1:
                    Y = (Y * pow(p, h, self.N)) % self.N
            if not ok or X == Y or X == self.N - Y:
                continue
            for g in (math.gcd(abs(X - Y), self.N), math.gcd(X + Y, self.N)):
                if 1 < g < self.N:
                    return g
        return None

    # ---- Pipeline ----------------------------------------------------------

    def run(self) -> Optional[int]:
        if is_probable_prime(self.N):
            print("[*] N is prime.")
            return None
        for p in self.factor_base:
            if self.N % p == 0:
                return p
        self._collect_relations()
        matrix, _ = self._build_matrix()
        deps = self._solve_dense(matrix)
        if not deps:
            return None
        return self._reconstruct(deps)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    TEST_N = 2_616_719   # 1129 × 2317
    print(f"[*] Test case: N = {TEST_N}")
    f = LPQS_P2_Framework(TEST_N, is_prototype_run=True)
    result = f.run()
    if result and TEST_N % result == 0:
        print(f"\n[+] Factor: {result}  ×  {TEST_N // result} = {TEST_N}  ✓")
    else:
        print(f"\n[-] No factor found.")
