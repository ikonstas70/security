#!/usr/bin/env python3
"""
AES-256-CBC large file encryptor/decryptor.
Author: Ioannis Konstas — IT Solutions USA

Optimized for servers with large memory and large files:
  - Processes data in 1MB chunks to avoid loading the entire file into RAM
  - Elevates process priority for maximum CPU allocation
  - On Linux: supports ionice for disk I/O priority (run via wrapper below)

Usage:
  python3 aes_large_file_encryptor.py encrypt <input_file> <output_file> [--key <hex_key>]
  python3 aes_large_file_encryptor.py decrypt <input_file> <output_file> --key <hex_key>

  If --key is omitted on encrypt, a new AES-256 key is generated and printed.
  The key is 64 hex characters (32 bytes = AES-256).

Linux high-priority launch:
  nice -n -10 ionice -c 2 -n 0 python3 aes_large_file_encryptor.py encrypt large.bin out.enc
"""

import os
import sys
import time
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

CHUNK_SIZE = 1024 * 1024  # 1 MB


def elevate_priority():
    """Raises process priority. Uses psutil on all platforms."""
    try:
        import psutil
        proc = psutil.Process(os.getpid())
        if sys.platform == "win32":
            proc.nice(psutil.HIGH_PRIORITY_CLASS)
        else:
            proc.nice(-10)
        print("[*] Process priority elevated.")
    except ImportError:
        print("[!] psutil not installed — running at default priority.")
        print("    Install with: pip install psutil")
    except PermissionError:
        print("[!] Permission denied for priority elevation — run with sudo/admin.")


def format_size(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def encrypt_file(input_path, output_path, key_bytes):
    """
    Encrypts input_path to output_path using AES-256-CBC.

    File format: [16-byte IV] [encrypted data]

    All chunks are encrypted with the same cipher instance.
    Padding (PKCS7) is applied only to the final chunk so block
    alignment is correct and decryption is lossless.
    """
    file_size = os.path.getsize(input_path)
    print(f"[*] Encrypting: {input_path} ({format_size(file_size)})")

    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

    start = time.time()
    bytes_written = 0

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        f_out.write(iv)  # Write IV once at the start

        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                break
            next_chunk = f_in.read(0)  # Peek — always returns b"" but we use EOF check below

            # Re-read correctly: check if this is the last chunk
            remaining = f_in.read(1)
            if remaining:
                # Not the last chunk — push the byte back by seeking
                f_in.seek(-1, 1)
                encrypted = cipher.encrypt(chunk)
            else:
                # Last chunk — pad to block boundary
                encrypted = cipher.encrypt(pad(chunk, AES.block_size))

            f_out.write(encrypted)
            bytes_written += len(encrypted)

    elapsed = time.time() - start
    print(f"[+] Done. Output: {output_path} ({format_size(bytes_written + 16)})")
    print(f"[+] Time: {elapsed:.2f}s  |  Speed: {format_size(file_size / elapsed)}/s")


def decrypt_file(input_path, output_path, key_bytes):
    """
    Decrypts input_path to output_path using AES-256-CBC.

    Reads the 16-byte IV from the start of the file, then decrypts
    all chunks. PKCS7 unpadding is applied only to the final chunk.
    """
    file_size = os.path.getsize(input_path)
    if file_size < 16:
        print("[!] File too small to contain a valid IV. Aborting.")
        sys.exit(1)

    print(f"[*] Decrypting: {input_path} ({format_size(file_size)})")

    start = time.time()

    with open(input_path, "rb") as f_in, open(output_path, "wb") as f_out:
        iv = f_in.read(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)

        prev_chunk = None
        while True:
            chunk = f_in.read(CHUNK_SIZE)
            if not chunk:
                if prev_chunk is not None:
                    # Final chunk — unpad
                    f_out.write(unpad(cipher.decrypt(prev_chunk), AES.block_size))
                break

            if prev_chunk is not None:
                f_out.write(cipher.decrypt(prev_chunk))

            prev_chunk = chunk

    elapsed = time.time() - start
    out_size = os.path.getsize(output_path)
    print(f"[+] Done. Output: {output_path} ({format_size(out_size)})")
    print(f"[+] Time: {elapsed:.2f}s  |  Speed: {format_size(out_size / elapsed)}/s")


def main():
    parser = argparse.ArgumentParser(
        description="AES-256-CBC large file encryptor/decryptor — IT Solutions USA"
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"],
                        help="Operation mode")
    parser.add_argument("input_file", help="Path to the input file")
    parser.add_argument("output_file", help="Path to the output file")
    parser.add_argument("--key", metavar="HEX",
                        help="AES-256 key as 64 hex characters. "
                             "Generated automatically if omitted (encrypt only).")
    parser.add_argument("--no-priority", action="store_true",
                        help="Skip process priority elevation")

    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print(f"[!] Input file not found: {args.input_file}")
        sys.exit(1)

    # Resolve key
    if args.key:
        if len(args.key) != 64:
            print("[!] Key must be exactly 64 hex characters (32 bytes for AES-256).")
            sys.exit(1)
        try:
            key_bytes = bytes.fromhex(args.key)
        except ValueError:
            print("[!] Invalid hex string in --key.")
            sys.exit(1)
    elif args.mode == "encrypt":
        key_bytes = get_random_bytes(32)
        print(f"[*] Generated key (save this to decrypt later):")
        print(f"    {key_bytes.hex()}")
    else:
        print("[!] --key is required for decryption.")
        sys.exit(1)

    if not args.no_priority:
        elevate_priority()

    if args.mode == "encrypt":
        encrypt_file(args.input_file, args.output_file, key_bytes)
    else:
        decrypt_file(args.input_file, args.output_file, key_bytes)


if __name__ == "__main__":
    main()
