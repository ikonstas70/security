#!/usr/bin/env python3
"""
Large Prime Quadratic Sieve — P1 (one-large-prime) variant.
Author: Ioannis Konstas — IT Solutions USA

Improves on the basic Quadratic Sieve by accepting partial relations:
values that are smooth over the factor base (B) except for exactly one
large prime L ≤ P_max. Partial relations are included as extra columns
in the GF(2) matrix, increasing the number of usable relations and
improving factorization success rate.

Factor base limit B is auto-tuned from N's size via a sub-exponential
heuristic. P_max defaults to 10× the largest prime in B.

Usage:
    python3 lpqs_p1_factorizer.py
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
# LPQS P1 Factorizer
# ---------------------------------------------------------------------------

class LPQSFactorizer:
    """
    Large Prime Quadratic Sieve (P1 variant).

    Extends the basic QS by allowing relations with exactly one large prime
    L ≤ P_max remaining after trial division. These partial relations are
    added as extra columns in the binary exponent matrix, providing more
    linear dependencies for the same sieving range.
    """

    def __init__(self, N, factor_base_limit=None):
        if not isinstance(N, int) or N <= 1:
            raise ValueError("N must be an integer > 1.")
        self.N = N
        self.sqrt_N = math.isqrt(N)

        # Auto-tune B from N's bit size using the QS sub-exponential heuristic
        if factor_base_limit is None:
            ln_N   = math.log(N)
            ln_ln_N = math.log(ln_N)
            B = int(math.exp(0.55 * math.sqrt(ln_N * ln_ln_N)))
            factor_base_limit = max(1200, B)

        self.factor_base_limit = min(5000, factor_base_limit)
        self.factor_base       = sieve_primes_up_to(self.factor_base_limit)
        self.num_primes        = len(self.factor_base)
        self.large_prime_limit = self.factor_base[-1] * 10

        print(f"[*] B-limit  : {self.factor_base_limit}  "
              f"({self.num_primes} primes in base)")
        print(f"[*] P_max    : {self.large_prime_limit}")

        self.relations = []   # (exponent_dict, large_prime_or_1)
        self.x_values  = []

    # ---- Smoothness check --------------------------------------------------

    def _factor_over_base(self, n):
        exps = {}
        if n < 0:
            exps[-1] = 1
            n = -n
        else:
            exps[-1] = 0

        for p in self.factor_base:
            if n % p == 0:
                c = 0
                while n % p == 0:
                    c += 1
                    n //= p
                exps[p] = c

        if n == 1:
            return exps, 1  # Full relation

        if n <= self.large_prime_limit and is_probable_prime(n):
            exps[n] = 1
            return exps, n  # Partial relation (one large prime)

        return None, None   # Discard

    # ---- Relation collection -----------------------------------------------

    def _collect_relations(self, buffer=180):
        target = self.num_primes + 2 * buffer
        print(f"[*] Targeting {target} relations (full + partial)...")
        k = 1
        safety = self.N.bit_length() ** 4

        while len(self.relations) < target:
            for sign in (+k, -k):
                x = self.sqrt_N + sign
                if x <= 0:
                    continue
                exps, lp = self._factor_over_base(pow(x, 2, self.N))
                if exps is not None:
                    self.relations.append((exps, lp))
                    self.x_values.append(x)
                    if len(self.relations) % 50 == 0:
                        print(f"    {len(self.relations)}/{target} relations")
                if len(self.relations) >= target:
                    break
            k += 1
            if k > safety:
                print("[!] Safety limit reached.")
                break

        print(f"[*] Collected {len(self.relations)} relations.")
        return True

    # ---- Matrix construction -----------------------------------------------

    def _build_matrix(self):
        lps = sorted({lp for _, lp in self.relations if lp > 1})
        all_cols    = [-1] + self.factor_base + lps
        col_idx     = {p: i for i, p in enumerate(all_cols)}
        num_cols    = len(all_cols)
        full = sum(1 for _, lp in self.relations if lp == 1)
        print(f"[*] Matrix: {len(self.relations)} rows × {num_cols} cols  "
              f"({full} full, {len(self.relations)-full} partial)")
        matrix = []
        for exps, _ in self.relations:
            row = [0] * num_cols
            for p, c in exps.items():
                if p in col_idx:
                    row[col_idx[p]] = c % 2
            matrix.append(row)
        return matrix, all_cols

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
        deps = []
        for row in M:
            if not any(row[:nc]):
                v = row[nc:]
                if any(v):
                    deps.append(v)
        print(f"[*] Dependencies found: {len(deps)}")
        return deps

    # ---- Factor reconstruction ---------------------------------------------

    def _reconstruct(self, deps):
        for dep in deps:
            X, cexp = 1, defaultdict(int)
            for i, b in enumerate(dep):
                if b:
                    exps, _ = self.relations[i]
                    X = (X * self.x_values[i]) % self.N
                    for p, c in exps.items():
                        cexp[p] += c
            Y = 1
            ok = True
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

    # ---- Trivial checks ----------------------------------------------------

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

    # ---- Pipeline ----------------------------------------------------------

    def run(self):
        print(f"\n[*] LPQS P1  N = {self.N}  ({self.N.bit_length()} bits)")
        t = self._trivial()
        if t is not None:
            return None if t == self.N else t
        self._collect_relations()
        matrix, cols = self._build_matrix()
        deps = self._gauss(matrix)
        if not deps:
            return None
        return self._reconstruct(deps)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Large Prime Quadratic Sieve (P1) — IT Solutions USA")
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
            f = LPQSFactorizer(N)
            result = f.run()
            print("-" * 40)
            if result:
                print(f"Factor : {result}")
                print(f"Other  : {N // result}")
                print(f"Check  : {result} × {N // result} = {result * (N // result)}")
            else:
                print("No factor found. Try a larger --limit.")
            print("-" * 40)
        except ValueError:
            print("Invalid input.")
        except (EOFError, KeyboardInterrupt):
            break
