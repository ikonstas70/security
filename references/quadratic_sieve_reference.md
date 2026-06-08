# Advanced Integer Factorization Using the Quadratic Sieve Algorithm

**Author:** Ioannis Konstas — IT Solutions USA

## Executive Summary

This document covers the design and implementation of an efficient integer factorization tool using the Quadratic Sieve (QS) algorithm. The implementation — `quadratic_sieve_factorizer.py` — leverages probabilistic primality testing (Miller-Rabin), smooth-number relation collection using a factor base, and Gaussian elimination over GF(2) to find congruences of squares that reveal non-trivial factors.

---

## Introduction

Integer factorization is the foundation of RSA security. The difficulty of factoring large composite integers is what makes public-key cryptography viable. Efficient factoring algorithms are used both for testing the robustness of cryptographic systems and for attacking weakly generated keys.

The Quadratic Sieve is one of the most effective general-purpose factoring algorithms for numbers up to ~100 digits. It works by finding a set of congruences that can be combined to reveal factors of the target integer N.

---

## Key Components

### 1. Miller-Rabin Probabilistic Primality Test

Used to build the factor base and to short-circuit factorization if N itself is prime.

```python
def miller_rabin(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False

    s, d = 0, n - 1
    while d % 2 == 0:
        s, d = s + 1, d // 2

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
```

### 2. Relation Collection

For values `x` slightly above `√N`, compute `y² = x² mod N` and attempt to factor `y²` completely over the factor base. Values that factor completely are called **B-smooth** and form valid relations.

```python
start = math.isqrt(self.n) + 1
for x in range(start, start + search_window):
    y_sq = (x * x) % self.n
    factors = self._factorize_over_base(y_sq)
    if factors:
        relations.append((x, factors))
```

> **Why search near √N?** Because `x² - N` is smallest there, making it more likely to be smooth over the factor base.

### 3. Matrix Operations over GF(2)

Each relation is encoded as a binary row vector of prime exponents mod 2. Gaussian elimination over GF(2) finds a linear dependency — a subset of rows that XOR to the zero vector. This dependency identifies a subset of relations whose combined prime exponents are all even, forming a perfect square.

---

## The Congruence of Squares

The goal is to find integers X and Y such that:

```
X² ≡ Y²  (mod N)
```

This implies N divides `X² − Y² = (X − Y)(X + Y)`. Unless the solution is trivial (`X ≡ ±Y mod N`), the GCD `gcd(X − Y, N)` yields a **non-trivial factor**.

The algorithm achieves this by:
1. Collecting smooth numbers whose exponent vectors span GF(2)ᵐ
2. Using Gaussian elimination to find a dependency (subset with all-even combined exponents)
3. Computing X as the product of the x-values and Y as the square root of the combined factorization

---

## Test Execution

```python
n = 8051
factorizer = AdvancedFactorizer(n, factor_base_limit=100)
result = factorizer.factorize()
# Output: Factor found: 97  |  Other factor: 83  |  97 × 83 = 8051 ✓
```

Run from the command line:
```bash
python3 quadratic_sieve_factorizer.py --n 8051
python3 quadratic_sieve_factorizer.py --n 8051 --limit 200
```

---

## Performance Analysis

### Strengths

| Property | Detail |
|---|---|
| Speed vs trial division | Far superior for integers above 50 bits |
| Mathematical elegance | Reduces a number theory problem to linear algebra over GF(2) |
| Tunability | Increasing `factor_base_limit` directly improves smoothness probability |

### Known Limitations

| Issue | Explanation |
|---|---|
| Square root logic | The square root is constructed from the factor base — not computed directly from N |
| Relation range | Searching from 2 to √N is inefficient; modern sieves search in a window around √(kN) |
| Scale ceiling | Numbers above ~100 bits require GNFS — see `cado_nfs_factorizer.py` |

### Complexity

| Method | Complexity |
|---|---|
| Trial Division | O(√N) |
| Quadratic Sieve | exp(√(ln N · ln ln N)) — sub-exponential |
| GNFS | exp(c · (ln N)^(1/3) · (ln ln N)^(2/3)) — asymptotically faster |

---

## Conclusion

The Quadratic Sieve is an excellent educational and practical tool for integers up to ~100 bits. It demonstrates how linear algebra over a finite field can solve a hard arithmetic problem. For numbers above that threshold — such as 2048-bit RSA keys — the General Number Field Sieve (GNFS) is required. See `factoring_algorithms_reference.md` for a full comparison of the factoring cascade.

---

*© Ioannis Konstas — IT Solutions USA*
