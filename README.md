# Security Scripts

**Author:** Ioannis Konstas — IT Solutions USA

> **Disclaimer:** All scripts in this repository are provided strictly for **educational and research purposes**. They are intended to support learning, authorized testing, and the study of security techniques. Do not use these tools on systems, networks, or accounts you do not own or have explicit written permission to test. The author assumes no liability for unauthorized or unlawful use.

A collection of shell and Python scripts organized into five groups: web server monitoring, SSH hardening and regression testing, system auditing, cryptographic tools, and reference documents.

---

## `monitoring/` — Web Server & Intrusion Detection

Scripts for real-time monitoring of Apache web server traffic and OSSEC intrusion detection logs.

| Script | Description |
|---|---|
| `apache_post_attack_monitor.sh` | Monitors Apache SSL logs every 5 minutes — counts POST requests per IP and URL, saves results to `attack.txt` |
| `apache_access_log_monitor.sh` | Tails Apache access log in real time — renders each request in a colored box showing IP, method, OS, device, and URL |
| `apache_log_ip_grep.sh` | Prompts for an IP prefix and queries the Apache log — shows hit counts and accessed URLs for matching addresses |
| `ripe_whois_ip_lookup.sh` | Queries RIPE NCC WHOIS for an IP address and shows inetnum, netname, country, and Apache access counts in a centered box |
| `ossec_log_monitor.sh` | Tails OSSEC `ossec.log` and `alerts.log` simultaneously — simple compact view or detailed 500-line history with full field layout |

---

## `ssh/` — SSH Hardening & Regression Tests

OpenSSH regression test suites (OpenBSD, public domain) and SSH connection shortcuts.

| Script | Description |
|---|---|
| `ssh_allowdeny_users_test.sh` | Regression tests for OpenSSH AllowUsers/DenyUsers — validates all access control combinations |
| `ssh_port_forwarding_tests.sh` | Regression tests for OpenSSH -L/-R port forwarding — chains, ClearAllForwardings, stdio proxy, Unix socket forwards |
| `ssh_hostkey_rotation_test.sh` | Regression tests for OpenSSH UpdateHostkeys — learning, replacing, adding, and rotating host keys across all key types |
| `ssh_pubkey_type_restriction_test.sh` | Regression tests for OpenSSH PubkeyAcceptedKeyTypes — Ed25519, RSA, DSA, and certificate auth under Match blocks |
| `ssh_reexec_regression_test.sh` | Regression tests for OpenSSH sshd re-exec — config passing, fallback when binary is deleted, with/without privsep |
| `ssh_rekey_regression_test.sh` | Regression tests for OpenSSH session rekeying — volume and time limits across all KEx algorithms, ciphers, and MACs |
| `scp_regression_test.sh` | Regression tests for SCP — all copy modes, recursive transfers, shell metacharacter injection, and bad-server detection |
| `ssh_connect_itsusa.sh` | SSH shortcut to the IT Solutions USA cPanel server |
| `ssh_connect_bitcoin_core.sh` | SSH to a Bitcoin Core node with 60-second keepalive to prevent session timeout |

---

## `auditing/` — System & Network Auditing

macOS security auditing, network inspection, Tor management, and utility scripts.

| Script | Description |
|---|---|
| `mac_audit.sh` | Audits macOS system security settings and configurations |
| `network_audit.sh` | Audits network configuration and reports on open services and exposure |
| `ipv6_privacy_fix.sh` | Disables persistent hardware-based IPv6 identifiers by fixing IPv6 privacy address settings on macOS |
| `generate_pdf_reports.sh` | Converts raw audit output into formatted PDF security reports |
| `macos_tor_log_finder.sh` | Searches the entire macOS filesystem for `tor.log` files to detect Tor daemon activity |
| `tor_service_manager.sh` | Interactive Tor management menu — start/stop/restart Tor, verify IP over Tor vs real IP, check process status |
| `owasp_terminal_prompt.sh` | Sets the terminal PS1 prompt to `OWASP Scripting >` for a dedicated OWASP scripting environment |

---

## `cryptography/` — Encryption & Integer Factorization

AES-256 encryption and a full suite of integer factorization implementations from basic Quadratic Sieve to CADO-NFS (GNFS).

| Script | Description |
|---|---|
| `aes_large_file_encryptor.py` | AES-256-CBC large file encryptor/decryptor — 1MB chunked I/O, elevated process priority, speed reporting |
| `qs_dixon_educational.py` | Dixon's Method educational implementation — two built-in test cases (N=8051, N=1,819,999), fully commented pipeline |
| `quadratic_sieve_factorizer.py` | Basic Quadratic Sieve — auto-tuned factor base, window search near √N, CLI with --n and --limit flags |
| `qs_pipeline_factorizer.py` | QS pipeline pushing ~65-bit capability — symmetric ±k sieve, 80-relation buffer, bit-length safety limit |
| `lpqs_p1_factorizer.py` | Large Prime QS (P1) — accepts partial relations with one large prime L ≤ P_max; improves relation yield per sieving unit |
| `lpqs_p2_framework_v1.py` | LPQS P2 v1 — working two-large-prime pipeline with dense GF(2) solver; test case N = 2,616,719 |
| `lpqs_p2_framework_v2.py` | LPQS P2 v2 — 250-bit architectural demo; dense GE for small N, sparse solver stub for 250-bit scale |
| `cado_nfs_factorizer.py` | CADO-NFS Python workflow — trivial cascade check, auto-tunes parameters by bit length, parses factor output |
| `cado_nfs_params.conf` | CADO-NFS 3.0.0 parameter file — factor base, sieving, linear algebra, and square root task settings |

---

## `references/` — Technical Reference Documents

Mathematical and research references supporting the cryptographic tools in this repository.

| Document | Description |
|---|---|
| `aes_galois_fields_reference.md` | GF(2⁸) arithmetic in AES — irreducible polynomial, Extended Euclidean Algorithm for inverses, worked example in GF(2³) |
| `factoring_algorithms_reference.md` | Factoring cascade — Pollard's Rho, ECM, QS, SNFS, GNFS, and Shor's algorithm compared by complexity and RSA key impact |
| `quadratic_sieve_reference.md` | Quadratic Sieve technical report — relation collection, GF(2) matrix, congruence of squares, strengths, and limitations |
| `gnfs_energy_efficiency_review.md` | Expert review of energy-efficient GNFS for 830-bit RSA — Joules/relation metric, polynomial selection, and responsible disclosure |

---

*© Ioannis Konstas — IT Solutions USA*
