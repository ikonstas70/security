#!/usr/bin/env python3
"""
CADO-NFS factorization workflow.
Author: Ioannis Konstas — IT Solutions USA

Automates integer factorization using CADO-NFS (General Number Field Sieve).
Performs a preliminary cascade check (primality, small primes) before
invoking CADO-NFS, and auto-tunes the factor base size based on the bit
length of the input number.

Prerequisites:
  - CADO-NFS installed and cado-nfs.py in PATH
    Install: https://cado-nfs.org
  - Python 3.7+

Usage:
  python3 cado_nfs_factorizer.py
  python3 cado_nfs_factorizer.py --n 123456789101112 --threads 4
"""

import argparse
import math
import os
import random
import shutil
import subprocess
import sys


# ---------------------------------------------------------------------------
# Primality
# ---------------------------------------------------------------------------

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                53, 59, 61, 67, 71, 73, 79, 83, 89, 97]


def miller_rabin(n, k=10):
    """Probabilistic primality test (Miller-Rabin, k rounds)."""
    if n < 2:
        return False
    for p in SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
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


# ---------------------------------------------------------------------------
# Trivial factor cascade
# ---------------------------------------------------------------------------

def check_trivial(n):
    """
    Returns a trivial factor if one is found via primality check or
    trial division against small primes, otherwise returns None.
    """
    if miller_rabin(n):
        print(f"[*] {n} is prime — no factorization needed.")
        return n
    if n % 2 == 0:
        return 2
    for p in SMALL_PRIMES:
        if n % p == 0:
            return p
    return None


# ---------------------------------------------------------------------------
# CADO-NFS
# ---------------------------------------------------------------------------

def find_cado_nfs():
    """Returns the path to cado-nfs.py, or None if not installed."""
    return shutil.which("cado-nfs.py") or shutil.which("cado-nfs")


def auto_params(bits):
    """Returns a dict of CADO-NFS parameters tuned to the bit length of N."""
    if bits < 100:
        return {"factorbase-size": 150, "lim0": 50000,  "lim1": 100000}
    elif bits < 150:
        return {"factorbase-size": 300, "lim0": 100000, "lim1": 500000}
    elif bits < 200:
        return {"factorbase-size": 600, "lim0": 500000, "lim1": 2000000}
    else:
        return {}  # Let CADO-NFS choose defaults for large numbers


def run_cado_nfs(n, threads=2, output_dir="cado_output"):
    """
    Invokes CADO-NFS to factor n.
    Returns a list of integer factors, or None on failure.
    """
    cado = find_cado_nfs()
    if not cado:
        print("[!] CADO-NFS not found in PATH.")
        print("    Install from: https://cado-nfs.org")
        return None

    os.makedirs(output_dir, exist_ok=True)
    number_file  = os.path.join(output_dir, "number.txt")
    results_file = os.path.join(output_dir, "factors.txt")

    with open(number_file, "w") as f:
        f.write(str(n) + "\n")

    bits   = n.bit_length()
    params = auto_params(bits)

    param_flags = " ".join(f"--{k} {v}" for k, v in params.items())
    cmd = f"{cado} --threads {threads} {param_flags} {number_file}"

    print(f"[*] Running: {cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output = result.stdout.decode()
        print(output)

        # Try to parse factors from stdout (space-separated integers on last line)
        for line in reversed(output.strip().splitlines()):
            parts = line.split()
            if all(p.isdigit() for p in parts) and len(parts) >= 2:
                factors = [int(p) for p in parts]
                print(f"[+] Factors from stdout: {factors}")
                return factors

    except subprocess.CalledProcessError as e:
        print(f"[!] CADO-NFS error: {e.stderr.decode().strip()}")

    # Fallback: check for a factors.txt output file
    if os.path.exists(results_file):
        with open(results_file) as f:
            factors = [int(line.strip()) for line in f if line.strip().isdigit()]
        if factors:
            print(f"[+] Factors from file: {factors}")
            return factors

    print("[-] No factors found.")
    return None


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="CADO-NFS factorization workflow — IT Solutions USA"
    )
    parser.add_argument("--n",       type=int, default=None,
                        help="Integer to factor (prompted if omitted)")
    parser.add_argument("--threads", type=int, default=4,
                        help="CPU threads to pass to CADO-NFS (default: 4)")
    parser.add_argument("--outdir",  default="cado_output",
                        help="Working directory for CADO-NFS output")
    args = parser.parse_args()

    if args.n is None:
        raw = input("Enter the integer to factor: ").strip()
        try:
            n = int(raw)
        except ValueError:
            print("[!] Invalid input.")
            sys.exit(1)
    else:
        n = args.n

    print(f"\n[*] Target   : {n}")
    print(f"[*] Bit length: {n.bit_length()} bits\n")

    trivial = check_trivial(n)
    if trivial:
        if trivial == n:
            print(f"[+] {n} is prime.")
        else:
            print(f"[+] Trivial factor: {trivial}  (other: {n // trivial})")
        return

    factors = run_cado_nfs(n, threads=args.threads, output_dir=args.outdir)
    if factors:
        print(f"\n[+] Factorization of {n}:")
        for f in factors:
            print(f"    {f}")
    else:
        print(f"\n[-] Factorization failed for {n}.")


if __name__ == "__main__":
    main()
