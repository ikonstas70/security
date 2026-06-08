# Galois Fields in AES — Reference

**Author:** Ioannis Konstas — IT Solutions USA

Mathematical reference for the Galois Field arithmetic that underpins AES encryption. Covers GF(2⁸) structure, polynomial representation, the AES irreducible polynomial, and the Extended Euclidean Algorithm for computing multiplicative inverses.

---

## What is GF(2⁸)?

AES operates over **GF(2⁸)** — a Galois Field with 256 elements. Every element in GF(2⁸) is represented as a polynomial of degree ≤ 7 with coefficients in GF(2) (i.e., each coefficient is either 0 or 1).

### Polynomial Representation

An element looks like:

```
a₇x⁷ + a₆x⁶ + a₅x⁵ + a₄x⁴ + a₃x³ + a₂x² + a₁x + a₀
```

where each `aᵢ ∈ {0, 1}`.

Each polynomial maps exactly to one **8-bit byte**, with each bit representing a coefficient. This alignment with computer memory is why GF(2⁸) was chosen for AES.

### Why GF(2⁸)?

| Property | Benefit |
|---|---|
| Byte alignment | Each field element = 1 byte — natural fit for CPU architecture |
| Closed arithmetic | Addition, subtraction, multiplication, and division always stay within the field |
| Finite and deterministic | Results are always predictable — essential for a cryptographic standard |

---

## The Irreducible Polynomial

AES uses the following irreducible polynomial as the modulus for all multiplication:

```
P(x) = x⁸ + x⁴ + x³ + x + 1
```

**Why irreducible?** Just as prime numbers are the foundation of modular integer arithmetic, irreducible polynomials are the foundation of Galois Field arithmetic. Multiplying two polynomials can produce a result of degree > 7, which falls outside GF(2⁸). The irreducible polynomial is used to reduce that result back into the field via modulo operation — analogous to clock arithmetic (e.g., 10 + 5 = 3 on a 12-hour clock).

---

## Extended Euclidean Algorithm — Finding Inverses in GF(2ᵐ)

The MixColumns step in AES requires the **multiplicative inverse** of field elements. The Extended Euclidean Algorithm computes these efficiently.

### Goal

Given element A(x) in GF(2ᵐ) and irreducible polynomial P(x), find A⁻¹(x) such that:

```
A⁻¹(x) · A(x) ≡ 1  (mod P(x))
```

### Algorithm

The Extended Euclidean Algorithm iteratively applies polynomial division, tracking intermediate values to find polynomials U(x) and V(x) satisfying:

```
U(x) · A(x) + V(x) · P(x) = GCD(A(x), P(x))
```

Since A(x) and P(x) are both elements of a Galois Field built from an irreducible polynomial, their GCD is always 1:

```
U(x) · A(x) + V(x) · P(x) = 1
```

Taking this equation modulo P(x):

```
U(x) · A(x) ≡ 1  (mod P(x))
```

Therefore **U(x) is the multiplicative inverse of A(x)**.

---

## Worked Example — GF(2³), P(x) = x³ + x + 1

Find the inverse of **A(x) = x² + 1**.

### Initialization

| Variable | Value |
|---|---|
| r₀ | x³ + x + 1 (= P(x)) |
| r₁ | x² + 1 (= A(x)) |
| s₀ | 1 |
| s₁ | 0 |
| t₀ | 0 |
| t₁ | 1 |

### Iteration 1 — Divide r₀ by r₁

```
(x³ + x + 1) ÷ (x² + 1)  →  quotient = x,  remainder = x + 1
```

Update:
```
r₂ = x + 1
s₂ = s₀ − x · s₁ = 1 − x · 0 = 1
t₂ = t₀ − x · t₁ = 0 − x · 1 = −x  ≡  x  (in GF(2), −1 = 1)
```

### Iteration 2 — Divide r₁ by r₂

```
(x² + 1) ÷ (x + 1)  →  quotient = x + 1,  remainder = 0
```

Remainder is 0 — algorithm terminates.

### Result

The last non-zero remainder is r₂ = x + 1, confirming GCD = 1 (as expected).

The inverse is:

```
A⁻¹(x) = t₂ = x
```

**Verification:**

```
x · (x² + 1) = x³ + x
x³ + x  mod  (x³ + x + 1) = (x³ + x) − (x³ + x + 1) = 1  ✓
```

---

## Connection to AES

The operations described here are used directly in the **SubBytes** and **MixColumns** steps of AES:

| AES Step | GF(2⁸) Operation |
|---|---|
| SubBytes (S-box) | Compute multiplicative inverse of each byte in GF(2⁸), then apply affine transformation |
| MixColumns | Multiply each column's bytes by a fixed polynomial over GF(2⁸) |
| AddRoundKey | XOR — equivalent to polynomial addition in GF(2⁸) |

The security of AES relies on the non-linearity introduced by S-box inversion in GF(2⁸), making it resistant to linear and differential cryptanalysis.

---

*© Ioannis Konstas — IT Solutions USA*
