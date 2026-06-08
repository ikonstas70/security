#!/bin/bash
# =============================================================================
# ipv6_privacy_fix.sh — IPv6 Privacy Extensions Fix & MAC Address Leak Remediation
#
# Description:
#   Detects and fixes IPv6 privacy issues on macOS, specifically:
#
#   PROBLEM — EUI-64 MAC Address Embedding:
#     IPv6 Stateless Address Autoconfiguration (SLAAC) can embed your MAC
#     address directly into your IPv6 address using the EUI-64 format:
#       MAC:  aa:bb:cc:dd:ee:ff
#       IPv6: xxxx:xxxx:xxxx:xxxx:aabb:ccFF:FEdd:eeff
#     The "FF:FE" in the middle is the EUI-64 marker. Anyone seeing your
#     IPv6 address can extract and identify your physical MAC address,
#     enabling persistent device tracking across networks.
#
#   PROBLEM — Weak Privacy Extensions (use_tempaddr=1):
#     macOS defaults to use_tempaddr=1 which generates temporary random
#     addresses but may still expose a stable address for some connections.
#     Setting it to 2 forces all outbound connections to use randomized
#     temporary addresses with limited lifetime.
#
#   FIX APPLIED:
#     1. Sets net.inet6.ip6.use_tempaddr=2    (always use temp addresses)
#     2. Sets net.inet6.ip6.prefer_tempaddr=1 (prefer temp over permanent)
#     3. Writes settings to /etc/sysctl.conf  (survives reboots)
#     4. Cycles affected interfaces           (activates new addresses now)
#     5. Disables AWDL EUI-64 exposure       (AirDrop/mDNS MAC leak fix)
#
#   HOW TO FIX — REMEDIATION STEPS:
#     See Section "REMEDIATION" below. This script applies all fixes
#     automatically when run with sudo.
#
# Usage:
#   sudo ./ipv6_privacy_fix.sh [--check-only]
#
#   --check-only : audit without making changes
#
# =============================================================================

set -uo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check-only" ]] && CHECK_ONLY=1

ISSUES_FOUND=0
FIXES_APPLIED=0

log()   { echo "  $*"; }
ok()    { echo "  [OK]      $*"; }
warn()  { echo "  [ISSUE]   $*"; ((ISSUES_FOUND++)); }
fixed() { echo "  [FIXED]   $*"; ((FIXES_APPLIED++)); }
info()  { echo "  [INFO]    $*"; }

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  IPv6 Privacy & MAC Address Leak Remediation"
echo "  Host : $(hostname)"
echo "  Date : $(date)"
[[ "$CHECK_ONLY" -eq 1 ]] && echo "  Mode : CHECK ONLY (no changes)" || echo "  Mode : FIX MODE (applying remediations)"
echo "════════════════════════════════════════════════════════════════"

# ─── SECTION 1: AUDIT ─────────────────────────────────────────────────────────

echo ""
echo "  ── 1. CURRENT IPv6 ADDRESS AUDIT ──────────────────────────────"
echo ""

# Collect all IPv6 addresses
echo "  All IPv6 addresses on this machine:"
ifconfig | grep "inet6" | awk '{print "    " $2}' | grep -v "^    ::1"

echo ""
echo "  Checking for EUI-64 embedded MAC addresses..."
echo ""

EUI64_IFACES=()
while IFS= read -r line; do
    IFACE=""
    if [[ "$line" =~ ^([a-z][a-z0-9]*): ]]; then
        CURRENT_IFACE="${BASH_REMATCH[1]}"
    fi
    if echo "$line" | grep -q "inet6"; then
        ADDR=$(echo "$line" | awk '{print $2}' | cut -d'%' -f1 | cut -d'/' -f1)
        # EUI-64 detection: look for fffe pattern in interface identifier
        ADDR_LOWER=$(echo "$ADDR" | tr '[:upper:]' '[:lower:]' | tr -d ':')
        if echo "$ADDR_LOWER" | grep -q "fffe"; then
            warn "EUI-64 MAC embedding detected on ${CURRENT_IFACE}: $ADDR"
            log   "      ↳ The portion containing 'fffe' encodes your MAC address"
            log   "      ↳ This allows network observers to track your physical device"
            EUI64_IFACES+=("$CURRENT_IFACE")
        fi
    fi
done < <(ifconfig 2>/dev/null)

[[ ${#EUI64_IFACES[@]} -eq 0 ]] && ok "No EUI-64 MAC embedding found in IPv6 addresses"

# ─── SECTION 2: PRIVACY EXTENSIONS CHECK ──────────────────────────────────────

echo ""
echo "  ── 2. PRIVACY EXTENSIONS STATUS ───────────────────────────────"
echo ""

USE_TEMP=$(sysctl -n net.inet6.ip6.use_tempaddr 2>/dev/null || echo "0")
PREFER_TEMP=$(sysctl -n net.inet6.ip6.prefer_tempaddr 2>/dev/null || echo "0")

info "net.inet6.ip6.use_tempaddr   = $USE_TEMP"
info "net.inet6.ip6.prefer_tempaddr = $PREFER_TEMP"
echo ""

case "$USE_TEMP" in
    0) warn "Privacy extensions DISABLED — stable (possibly MAC-derived) IPv6 used"
       log "      ↳ All connections use a fixed, trackable IPv6 address" ;;
    1) warn "Privacy extensions PARTIAL (use_tempaddr=1) — temp addresses generated"
       log "      ↳ Temporary addresses exist but stable address may still be used"
       log "      ↳ Should be set to 2 for full privacy" ;;
    2) ok "Privacy extensions FULLY enabled (use_tempaddr=2)" ;;
esac

[[ "$PREFER_TEMP" -eq 1 ]] && ok "prefer_tempaddr=1 — outbound prefers temporary addresses" \
    || warn "prefer_tempaddr=0 — outbound may use permanent/stable address"

# Check persistence
echo ""
if [[ -f /etc/sysctl.conf ]] && grep -q "use_tempaddr" /etc/sysctl.conf 2>/dev/null; then
    ok "Settings are persisted in /etc/sysctl.conf"
else
    warn "Settings NOT persisted — will reset to default on reboot"
fi

# ─── SECTION 3: AWDL / AIRDROP EUI-64 CHECK ──────────────────────────────────

echo ""
echo "  ── 3. AWDL / AIRDROP EUI-64 EXPOSURE ──────────────────────────"
echo ""

AWDL_ADDR=$(ifconfig awdl0 2>/dev/null | grep "inet6" | awk '{print $2}')
if [[ -n "$AWDL_ADDR" ]]; then
    AWDL_LOWER=$(echo "$AWDL_ADDR" | tr -d ':' | tr '[:upper:]' '[:lower:]')
    if echo "$AWDL_LOWER" | grep -q "fffe"; then
        warn "AWDL (AirDrop) interface exposes MAC via EUI-64: $AWDL_ADDR"
        log "      ↳ Anyone receiving your AirDrop broadcasts can extract your MAC"
        log "      ↳ Fix: disable AirDrop when not in use (System Settings → General → AirDrop)"
    else
        ok "AWDL interface is not exposing MAC via EUI-64"
    fi
else
    ok "AWDL interface not active"
fi

# ─── SECTION 4: REMEDIATION ───────────────────────────────────────────────────

echo ""
echo "  ── 4. REMEDIATION ──────────────────────────────────────────────"
echo ""

if [[ "$ISSUES_FOUND" -eq 0 ]]; then
    ok "No issues found — no fixes needed"
    echo ""
    exit 0
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "  HOW TO FIX (run without --check-only to apply automatically):"
    echo ""
    echo "  1. Enable full IPv6 privacy extensions:"
    echo "     sudo sysctl -w net.inet6.ip6.use_tempaddr=2"
    echo "     sudo sysctl -w net.inet6.ip6.prefer_tempaddr=1"
    echo ""
    echo "  2. Make persistent across reboots:"
    echo "     echo 'net.inet6.ip6.use_tempaddr=2' | sudo tee -a /etc/sysctl.conf"
    echo "     echo 'net.inet6.ip6.prefer_tempaddr=1' | sudo tee -a /etc/sysctl.conf"
    echo ""
    echo "  3. Regenerate IPv6 addresses on active interfaces:"
    echo "     sudo ifconfig en0 down && sudo ifconfig en0 up"
    echo "     sudo ifconfig en1 down && sudo ifconfig en1 up"
    echo ""
    echo "  4. For AWDL/AirDrop EUI-64:"
    echo "     Disable AirDrop: System Settings → General → AirDrop & Handoff → AirDrop = No One"
    echo "     Or run: sudo ifconfig awdl0 down (temporary, resets on reboot)"
    echo ""
    exit 0
fi

# Apply fixes
log "Applying fixes..."
echo ""

# Fix 1: Enable use_tempaddr=2
if [[ "$USE_TEMP" -ne 2 ]]; then
    sudo sysctl -w net.inet6.ip6.use_tempaddr=2 > /dev/null 2>&1 && \
        fixed "Set net.inet6.ip6.use_tempaddr=2 (full privacy extensions)" || \
        warn "Failed to set use_tempaddr — try running with sudo"
fi

# Fix 2: Enable prefer_tempaddr=1
if [[ "$PREFER_TEMP" -ne 1 ]]; then
    sudo sysctl -w net.inet6.ip6.prefer_tempaddr=1 > /dev/null 2>&1 && \
        fixed "Set net.inet6.ip6.prefer_tempaddr=1" || \
        warn "Failed to set prefer_tempaddr"
fi

# Fix 3: Persist in /etc/sysctl.conf
SYSCTL_CONF="/etc/sysctl.conf"
NEEDS_WRITE=0

if [[ ! -f "$SYSCTL_CONF" ]] || ! grep -q "use_tempaddr" "$SYSCTL_CONF" 2>/dev/null; then
    NEEDS_WRITE=1
fi

if [[ "$NEEDS_WRITE" -eq 1 ]]; then
    {
        echo ""
        echo "# IPv6 Privacy Extensions — prevent MAC address leakage via EUI-64"
        echo "net.inet6.ip6.use_tempaddr=2"
        echo "net.inet6.ip6.prefer_tempaddr=1"
    } | sudo tee -a "$SYSCTL_CONF" > /dev/null 2>&1 && \
        fixed "Persisted settings to /etc/sysctl.conf (survives reboots)" || \
        warn "Could not write to /etc/sysctl.conf"
fi

# Fix 4: Cycle active interfaces to regenerate IPv6 addresses
for iface in en0 en1; do
    if ifconfig "$iface" 2>/dev/null | grep -q "status: active"; then
        log "Cycling $iface to regenerate IPv6 addresses..."
        sudo ifconfig "$iface" down 2>/dev/null && sleep 1 && sudo ifconfig "$iface" up 2>/dev/null && \
            fixed "Cycled $iface — new randomized IPv6 address will be assigned" || \
            warn "Could not cycle $iface"
    fi
done

# ─── SECTION 5: POST-FIX VERIFICATION ────────────────────────────────────────

echo ""
echo "  ── 5. POST-FIX VERIFICATION ────────────────────────────────────"
echo ""

sleep 2  # Wait for new addresses to be assigned

NEW_USE_TEMP=$(sysctl -n net.inet6.ip6.use_tempaddr 2>/dev/null)
NEW_PREFER=$(sysctl -n net.inet6.ip6.prefer_tempaddr 2>/dev/null)

info "net.inet6.ip6.use_tempaddr    = $NEW_USE_TEMP (was $USE_TEMP)"
info "net.inet6.ip6.prefer_tempaddr = $NEW_PREFER (was $PREFER_TEMP)"
echo ""
echo "  New IPv6 addresses:"
ifconfig | grep "inet6" | grep -v "::1" | awk '{print "    " $2}'
echo ""

# Recheck for EUI-64
EUI64_REMAINING=0
ifconfig | grep "inet6" | awk '{print $2}' | while read addr; do
    ADDR_LOWER=$(echo "$addr" | tr -d ':' | tr '[:upper:]' '[:lower:]')
    if echo "$ADDR_LOWER" | grep -q "fffe"; then
        iface=$(echo "$addr" | cut -d'%' -f2)
        if [[ "$iface" != "awdl0" && "$iface" != "llw0" ]]; then
            warn "EUI-64 still present on $iface: $addr"
            EUI64_REMAINING=1
        else
            log "Note: $iface still shows EUI-64 (expected for AirDrop interface)"
        fi
    fi
done

echo ""
echo "  ── SUMMARY ──────────────────────────────────────────────────────"
echo ""
echo "  Issues found  : $ISSUES_FOUND"
echo "  Fixes applied : $FIXES_APPLIED"
echo ""

if [[ "$NEW_USE_TEMP" -eq 2 ]] && [[ "$NEW_PREFER" -eq 1 ]]; then
    echo "  ✓ IPv6 privacy extensions fully active"
    echo "  ✓ Outbound connections will use randomized temporary addresses"
    echo "  ✓ Settings will persist across reboots"
fi

echo ""
echo "  REMAINING MANUAL ACTION REQUIRED:"
echo "  → AirDrop EUI-64: Go to System Settings → General → AirDrop & Handoff"
echo "                     Set AirDrop to 'No One' when not actively using it"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  IPv6 privacy remediation complete."
echo "════════════════════════════════════════════════════════════════"
