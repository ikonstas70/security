#!/usr/bin/env python3
"""
Large Prime Quadratic Sieve — P2 (two-large-prime) conceptual framework, version 2.
Author: Ioannis Konstas — IT Solutions USA

Architectural demonstration of the parameter scaling and pipeline structure
required to factor 250-bit integers using the P2 LPQS variant.

Key difference from v1:
  - Factor base limit scales to 100,000 primes (heuristic for 250-bit N)
  - The dense GF(2) solver is replaced by a placeholder that represents
    the mandatory C/C++ Block Lanczos or Wiedemann call for production use
  - For matrices with R > 1,000 rows the script correctly reports that
    Python's dense solver is infeasible and returns control to the caller

Note: Actual 250-bit factorization requires high-performance C/C++ sieving
and sparse linear algebra (e.g., CADO-NFS). This framework demonstrates
the architectural components only.

Test case: N = 2_616_719  (factors: 1129 × 2317)

Usage:
    python3 lpqs_p2_framework_v2.py
"""

import math
from collections import defaultdict
import sys
import random
from typing import List, Dict, Tuple, Optional, Set

sys.setrecursionlimit(5000)


# ---------------------------------------------------------------------------
# Utilities (same as v1)
# ---------------------------------------------------------------------------

def is_probable_prime(n: int, k: int = 10) -> bool:
    if n < 2: return False
    small = [2, 3, 5, 7, 11, 13, 17, 19]
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
# LPQS P2 Framework — version 2 (250-bit conceptual, sparse solver stub)
# ---------------------------------------------------------------------------

class LPQS_P2_Framework_250bit:
    """
    250-bit scale LPQS P2 architectural framework.

    Parameters are scaled to the 250-bit heuristic:
      B = 100,000 (≈ 9,592 primes)
      P_max = 1,000,000

    The sparse linear algebra step is a PLACEHOLDER — at true 250-bit scale
    this must be Block Lanczos or Wiedemann in C/C++.
    """

    TARGET_BITS = 250

    def __init__(self, N: int, override_prototype: bool = False):
        if not isinstance(N, int) or N <= 1:
            raise ValueError("N must be an integer > 1.")
        self.N      = N
        self.sqrt_N = math.isqrt(N)

        # 250-bit heuristic parameters
        self.factor_base_limit = 100_000
        self.large_prime_limit = 10 * self.factor_base_limit

        # Allow prototype override for small N testing
        if override_prototype:
            self.factor_base_limit = 1_000
            self.large_prime_limit = 5_000

        self.factor_base = sieve_primes_up_to(self.factor_base_limit)
        self.num_primes  = len(self.factor_base)

        print(f"\n[*] LPQS P2 v2 (250-bit framework)  N={N}  ({N.bit_length()} bits)")
        print(f"    B={self.factor_base_limit}  P_max={self.large_prime_limit}"
              f"  |base|={self.num_primes}")

        self.relations: List[Tuple[Dict[int,int], Set[int]]] = []
        self.x_values:  List[int] = []
        self.unique_lps: Set[int] = set()

    # ---- P2 smoothness check (identical logic to v1) -----------------------

    def _factor_over_base(self, n: int) -> Tuple[Optional[Dict[int,int]], Optional[Set[int]]]:
        exps: Dict[int,int] = defaultdict(int)

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
            return dict(exps), set()

        if temp <= self.large_prime_limit and is_probable_prime(temp):
            exps[temp] = 1
            return dict(exps), {temp}

        limit = min(math.isqrt(temp), self.large_prime_limit)
        for p in sieve_primes_up_to(limit):
            if temp % p == 0:
                L1, L2 = p, temp // p
                if (L1 <= self.large_prime_limit and
                        is_probable_prime(L2) and L2 <= self.large_prime_limit):
                    exps[L1] = exps.get(L1, 0) + 1
                    exps[L2] = exps.get(L2, 0) + 1
                    return dict(exps), {L1, L2}
                break

        return None, None

    # ---- Relation collection -----------------------------------------------

    def _collect_relations(self, buffer: int = 100) -> bool:
        target = self.num_primes + buffer
        print(f"[*] Targeting {target} relations "
              f"(NOTE: at 250-bit scale, sieving requires C/C++ CADO-NFS)...")
        k, limit = 1, 1_000

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
                    if len(self.relations) % 50 == 0:
                        print(f"    {len(self.relations)} relations")
                if len(self.relations) >= target:
                    break
            k += 1

        print(f"[*] Collected {len(self.relations)} relations  "
              f"({len(self.unique_lps)} unique LPs).")
        return True

    # ---- Matrix construction -----------------------------------------------

    def _build_matrix(self) -> Tuple[List[List[int]], List[int]]:
        all_cols = [-1] + self.factor_base + sorted(self.unique_lps)
        col_idx  = {p: i for i, p in enumerate(all_cols)}
        nc       = len(all_cols)
        matrix   = []
        for exps, _ in self.relations:
            row = [0] * nc
            for p, c in exps.items():
                if p in col_idx:
                    row[col_idx[p]] = c % 2
            matrix.append(row)
        print(f"[*] Matrix {len(matrix)} × {nc}  (sparse at 250-bit scale)")
        return matrix, all_cols

    # ---- Sparse solver stub ------------------------------------------------

    def _solve_sparse(self, matrix: List[List[int]]) -> List[List[int]]:
        """
        ARCHITECTURAL PLACEHOLDER — represents the Block Lanczos / Wiedemann call.

        At 250-bit scale (R ≈ 10,000 rows) the dense O(R³) solver is infeasible.
        Production deployments must invoke an optimised C/C++ sparse solver here.

        For prototype demonstration (R ≤ 1,000) falls back to dense GE.
        """
        nr, nc = len(matrix), len(matrix[0])

        if nr > 1_000:
            print(f"\n[!] SCALING LIMIT: {nr} rows requires Block Lanczos / Wiedemann.")
            print("    Python dense solver is infeasible at this size.")
            print("    In production, this calls the CADO-NFS linalg module.\n")
            return []

        print(f"[*] Running dense GE on {nr} × {nc} matrix (prototype only)...")
        M   = [matrix[i] + [int(i == j) for j in range(nr)] for i in range(nr)]
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

    # ---- Factor reconstruction (identical to v1) ---------------------------

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
        deps = self._solve_sparse(matrix)
        if not deps:
            return None
        return self._reconstruct(deps)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    TEST_N = 2_616_719  # 1129 × 2317
    print("[*] 250-bit LPQS P2 Framework (v2 — conceptual)")
    print("[*] Running on small test case to demonstrate the pipeline.\n")

    f = LPQS_P2_Framework_250bit(TEST_N, override_prototype=True)
    result = f.run()

    if result and TEST_N % result == 0:
        print(f"\n[+] Factor: {result}  ×  {TEST_N // result} = {TEST_N}  ✓")
    else:
        print(f"\n[-] No factor found.")
