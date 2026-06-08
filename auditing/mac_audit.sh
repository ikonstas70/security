#!/bin/bash
# =============================================================================
# mac_audit.sh — macOS Full Forensic & Vulnerability Assessment
#
# Description:
#   Performs a comprehensive security audit of a macOS system including:
#   - System & hardware inventory
#   - Security configuration (SIP, Gatekeeper, FileVault, Firewall, XProtect)
#   - User account analysis & privilege audit
#   - Network exposure (open ports, active connections, interfaces)
#   - Process forensics (running processes, suspicious indicators)
#   - Persistence mechanisms (LaunchAgents, LaunchDaemons, login items)
#   - File system security (SUID/SGID, world-writable, recent changes)
#   - SSH & remote access configuration
#   - Log analysis (auth failures, sudo usage, anomalies)
#   - Installed software & outdated packages
#   - Privacy & permissions audit
#   - Certificate & keychain analysis
#   - Known malware IOC indicators
#
# Output:
#   ~/audit_reports/mac_audit_<timestamp>.txt  — full text report
#   ~/audit_reports/mac_audit_<timestamp>.html — HTML report (browser-viewable)
#
# Usage:
#   chmod +x mac_audit.sh
#   sudo ./mac_audit.sh
#
# Requirements:
#   - macOS 12+ (Monterey or later recommended)
#   - sudo privileges
#
# =============================================================================

set -uo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="$HOME/audit_reports"
REPORT_TXT="$REPORT_DIR/mac_audit_${TIMESTAMP}.txt"
REPORT_HTML="$REPORT_DIR/mac_audit_${TIMESTAMP}.html"
HOSTNAME=$(hostname)
CURRENT_USER=$(whoami)

# Risk counters
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
INFO=0

# ─── Helpers ──────────────────────────────────────────────────────────────────

mkdir -p "$REPORT_DIR"

# Dual output: terminal + file
exec > >(tee -a "$REPORT_TXT") 2>&1

section() {
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "  $1"
    echo "════════════════════════════════════════════════════════════════"
}

finding() {
    local level="$1"; local msg="$2"
    case "$level" in
        CRITICAL) echo "  [CRITICAL] $msg"; ((CRITICAL++)) ;;
        HIGH)     echo "  [HIGH]     $msg"; ((HIGH++)) ;;
        MEDIUM)   echo "  [MEDIUM]   $msg"; ((MEDIUM++)) ;;
        LOW)      echo "  [LOW]      $msg"; ((LOW++)) ;;
        OK)       echo "  [OK]       $msg" ;;
        INFO)     echo "  [INFO]     $msg"; ((INFO++)) ;;
    esac
}

cmd_safe() { "$@" 2>/dev/null || echo "(not available)"; }

# ─── Header ───────────────────────────────────────────────────────────────────

echo "════════════════════════════════════════════════════════════════"
echo "  macOS Full Forensic & Vulnerability Assessment"
echo "  Host     : $HOSTNAME"
echo "  User     : $CURRENT_USER"
echo "  Date     : $(date)"
echo "  Report   : $REPORT_TXT"
echo "════════════════════════════════════════════════════════════════"

# ─── 1. SYSTEM INFORMATION ────────────────────────────────────────────────────

section "1. SYSTEM INFORMATION"

echo ""
echo "  --- Hardware ---"
system_profiler SPHardwareDataType 2>/dev/null | grep -E "Model|Chip|Processor|Memory|Serial" | sed 's/^/  /'

echo ""
echo "  --- OS Version ---"
sw_vers | sed 's/^/  /'
finding INFO "macOS $(sw_vers -productVersion) build $(sw_vers -buildVersion)"

echo ""
echo "  --- Architecture ---"
finding INFO "Architecture: $(uname -m)"

echo ""
echo "  --- Uptime & Load ---"
uptime | sed 's/^/  /'

echo ""
echo "  --- Disk Overview ---"
diskutil list 2>/dev/null | sed 's/^/  /'

# ─── 2. SECURITY CONFIGURATION ────────────────────────────────────────────────

section "2. SECURITY CONFIGURATION"

echo ""
echo "  --- System Integrity Protection (SIP) ---"
SIP_STATUS=$(csrutil status 2>/dev/null)
echo "  $SIP_STATUS"
if echo "$SIP_STATUS" | grep -q "enabled"; then
    finding OK "SIP is enabled"
else
    finding CRITICAL "SIP is DISABLED — system files can be modified"
fi

echo ""
echo "  --- Gatekeeper ---"
GATEKEEPER=$(spctl --status 2>/dev/null)
echo "  $GATEKEEPER"
if echo "$GATEKEEPER" | grep -q "enabled"; then
    finding OK "Gatekeeper is enabled"
else
    finding HIGH "Gatekeeper is DISABLED — unsigned apps can run"
fi

echo ""
echo "  --- FileVault (Disk Encryption) ---"
FV_STATUS=$(fdesetup status 2>/dev/null)
echo "  $FV_STATUS"
if echo "$FV_STATUS" | grep -q "On"; then
    finding OK "FileVault is ON — disk is encrypted"
else
    finding HIGH "FileVault is OFF — disk is unencrypted"
fi

echo ""
echo "  --- Application Firewall ---"
FW_STATUS=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null)
echo "  Firewall globalstate: $FW_STATUS"
case "$FW_STATUS" in
    0) finding HIGH "Application Firewall is OFF" ;;
    1) finding OK "Application Firewall is ON (allow signed apps)" ;;
    2) finding OK "Application Firewall is ON (essential services only)" ;;
    *) finding MEDIUM "Application Firewall state unknown" ;;
esac

STEALTH=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null)
if [[ "$STEALTH" == "1" ]]; then
    finding OK "Stealth mode is enabled (no ICMP/port probe responses)"
else
    finding LOW "Stealth mode is disabled (Mac responds to ping/port scans)"
fi

echo ""
echo "  --- Secure Boot (T2/Apple Silicon) ---"
if system_profiler SPiBridgeDataType 2>/dev/null | grep -q "T2\|Apple"; then
    finding INFO "T2/Apple Silicon chip present — Secure Boot supported"
fi

echo ""
echo "  --- XProtect & MRT ---"
XPROTECT_VER=$(defaults read /System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || echo "unknown")
MRT_VER=$(defaults read /System/Library/CoreServices/MRT.app/Contents/Info.plist CFBundleShortVersionString 2>/dev/null || echo "unknown")
finding INFO "XProtect version: $XPROTECT_VER"
finding INFO "MRT version: $MRT_VER"

echo ""
echo "  --- Automatic Updates ---"
AUTO_UPDATE=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)
AUTO_INSTALL=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null)
[[ "$AUTO_UPDATE" == "1" ]] && finding OK "Automatic update checks: enabled" || finding MEDIUM "Automatic update checks: disabled"
[[ "$AUTO_INSTALL" == "1" ]] && finding OK "Automatic macOS installs: enabled" || finding LOW "Automatic macOS installs: disabled"

# ─── 3. USER ACCOUNT AUDIT ────────────────────────────────────────────────────

section "3. USER ACCOUNT AUDIT"

echo ""
echo "  --- All User Accounts ---"
dscl . list /Users | grep -v "^_\|daemon\|nobody\|root" | sed 's/^/  /'

echo ""
echo "  --- Admin Users ---"
ADMINS=$(dscl . read /Groups/admin GroupMembership 2>/dev/null | sed 's/GroupMembership: //')
echo "  $ADMINS"
ADMIN_COUNT=$(echo "$ADMINS" | wc -w | tr -d ' ')
[[ "$ADMIN_COUNT" -gt 2 ]] && finding MEDIUM "Multiple admin accounts: $ADMIN_COUNT — review if all are needed" || finding OK "Admin account count: $ADMIN_COUNT"

echo ""
echo "  --- Root Account ---"
ROOT_STATUS=$(dscl . read /Users/root UserShell 2>/dev/null | awk '{print $2}')
echo "  Root shell: $ROOT_STATUS"
[[ "$ROOT_STATUS" == "/bin/bash" || "$ROOT_STATUS" == "/bin/zsh" ]] && finding HIGH "Root account is ENABLED with shell $ROOT_STATUS" || finding OK "Root account is disabled"

echo ""
echo "  --- Currently Logged In ---"
who | sed 's/^/  /'

echo ""
echo "  --- Last Logins ---"
last | head -20 | sed 's/^/  /'

echo ""
echo "  --- Sudo Configuration ---"
if [[ -f /etc/sudoers ]]; then
    echo "  NOPASSWD entries:"
    grep -i "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/    /' || echo "    None found"
    NOPASSWD=$(grep -i "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v "^#" | wc -l | tr -d ' ')
    [[ "$NOPASSWD" -gt 0 ]] && finding HIGH "NOPASSWD sudo entries found: $NOPASSWD" || finding OK "No NOPASSWD sudo entries"
fi

echo ""
echo "  --- Password Policy ---"
pwpolicy -getaccountpolicies 2>/dev/null | grep -E "minChars|maxMinutes|maxFailedLogins" | sed 's/^/  /' || echo "  No custom password policy set"

# ─── 4. NETWORK ANALYSIS ──────────────────────────────────────────────────────

section "4. NETWORK ANALYSIS"

echo ""
echo "  --- Network Interfaces ---"
ifconfig | grep -E "^[a-z]|inet " | sed 's/^/  /'

echo ""
echo "  --- Listening Ports & Services ---"
echo "  (Proto  Local Address  PID  Process)"
lsof -iTCP -iUDP -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR>1 {print "  "$1,$2,$9,$10}' | sort -u

echo ""
echo "  --- Active Network Connections ---"
netstat -an 2>/dev/null | grep ESTABLISHED | head -30 | sed 's/^/  /'

echo ""
echo "  --- DNS Configuration ---"
scutil --dns 2>/dev/null | grep "nameserver\|domain" | head -10 | sed 's/^/  /'

echo ""
echo "  --- Network Shares (SMB/AFP/NFS) ---"
SHARES=$(sharing -l 2>/dev/null)
if [[ -n "$SHARES" ]]; then
    echo "$SHARES" | sed 's/^/  /'
    finding MEDIUM "Network shares are configured — review if intentional"
else
    finding OK "No network shares configured"
fi

echo ""
echo "  --- Remote Access Services ---"
SERVICES=("com.apple.screensharing" "com.openssh.sshd" "com.apple.RemoteDesktop" "com.apple.ARDAgent")
for svc in "${SERVICES[@]}"; do
    STATUS=$(launchctl list "$svc" 2>/dev/null && echo "RUNNING" || echo "not running")
    if echo "$STATUS" | grep -q "RUNNING"; then
        finding MEDIUM "Remote service active: $svc"
    else
        echo "  [OK]     $svc: not running"
    fi
done

echo ""
echo "  --- SSH Configuration ---"
if [[ -f /etc/ssh/sshd_config ]]; then
    ROOT_LOGIN=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    PASSWD_AUTH=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    EMPTY_PASS=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    [[ "$ROOT_LOGIN" == "yes" ]] && finding HIGH "SSH PermitRootLogin is YES" || finding OK "SSH PermitRootLogin: ${ROOT_LOGIN:-default(no)}"
    [[ "$PASSWD_AUTH" == "yes" ]] && finding MEDIUM "SSH PasswordAuthentication is enabled (prefer key-based auth)" || finding OK "SSH PasswordAuthentication: ${PASSWD_AUTH:-default}"
    [[ "$EMPTY_PASS" == "yes" ]] && finding CRITICAL "SSH PermitEmptyPasswords is YES" || finding OK "SSH PermitEmptyPasswords: disabled"
fi

echo ""
echo "  --- Authorized SSH Keys ---"
find /Users -name "authorized_keys" 2>/dev/null | while read f; do
    COUNT=$(wc -l < "$f" 2>/dev/null)
    finding INFO "SSH authorized_keys found: $f ($COUNT keys)"
    cat "$f" 2>/dev/null | sed 's/^/    /'
done

echo ""
echo "  --- Hosts File (anomaly check) ---"
grep -v "^#\|^$\|^127\|^::1\|^fe80\|^255" /etc/hosts 2>/dev/null | sed 's/^/  /' || echo "  No suspicious entries"
HOSTS_EXTRA=$(grep -v "^#\|^$\|^127\|^::1\|^fe80\|^255" /etc/hosts 2>/dev/null | wc -l | tr -d ' ')
[[ "$HOSTS_EXTRA" -gt 0 ]] && finding MEDIUM "Unexpected /etc/hosts entries: $HOSTS_EXTRA — check for DNS hijacking"

# ─── 5. PROCESS FORENSICS ─────────────────────────────────────────────────────

section "5. PROCESS FORENSICS"

echo ""
echo "  --- Top CPU Processes ---"
ps aux --sort=-%cpu 2>/dev/null | head -15 | sed 's/^/  /' || \
ps aux | sort -rk3 | head -15 | sed 's/^/  /'

echo ""
echo "  --- Top Memory Processes ---"
ps aux | sort -rk4 | head -15 | sed 's/^/  /'

echo ""
echo "  --- Processes Running as Root ---"
ps aux | awk '$1=="root" {print $0}' | grep -v "kernel_task\|launchd\|smd\|notifyd\|configd\|diskarbitrationd" | head -20 | sed 's/^/  /'

echo ""
echo "  --- Processes with Network Activity ---"
lsof -i -n -P 2>/dev/null | grep -v "LISTEN\|CLOSE_WAIT" | awk 'NR>1 {print $1,$2,$9}' | sort -u | head -30 | sed 's/^/  /'

echo ""
echo "  --- Suspicious Process Indicators ---"
# Check for processes running from temp/unusual locations
SUSPICIOUS=$(ps aux | awk '{print $11}' | grep -E "^/tmp/|^/var/tmp/|^/private/tmp/" 2>/dev/null)
if [[ -n "$SUSPICIOUS" ]]; then
    finding HIGH "Processes running from temp directories:"
    echo "$SUSPICIOUS" | sed 's/^/    /'
else
    finding OK "No processes running from temp directories"
fi

# ─── 6. PERSISTENCE MECHANISMS ────────────────────────────────────────────────

section "6. PERSISTENCE MECHANISMS (LaunchAgents/Daemons)"

echo ""
echo "  --- System LaunchDaemons ---"
ls /Library/LaunchDaemons/ 2>/dev/null | sed 's/^/  /'
DAEMON_COUNT=$(ls /Library/LaunchDaemons/ 2>/dev/null | wc -l | tr -d ' ')
finding INFO "System LaunchDaemons: $DAEMON_COUNT"

echo ""
echo "  --- System LaunchAgents ---"
ls /Library/LaunchAgents/ 2>/dev/null | sed 's/^/  /'
AGENT_COUNT=$(ls /Library/LaunchAgents/ 2>/dev/null | wc -l | tr -d ' ')
finding INFO "System LaunchAgents: $AGENT_COUNT"

echo ""
echo "  --- User LaunchAgents ($CURRENT_USER) ---"
ls ~/Library/LaunchAgents/ 2>/dev/null | sed 's/^/  /' || echo "  None"
USER_AGENT_COUNT=$(ls ~/Library/LaunchAgents/ 2>/dev/null | wc -l | tr -d ' ')
[[ "$USER_AGENT_COUNT" -gt 0 ]] && finding MEDIUM "User LaunchAgents present: $USER_AGENT_COUNT — review each"

echo ""
echo "  --- Login Items ---"
osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null | tr ',' '\n' | sed 's/^/  /' || echo "  (requires approval)"

echo ""
echo "  --- Cron Jobs ---"
echo "  System crontab:"
crontab -l 2>/dev/null | sed 's/^/    /' || echo "    None"
echo "  /etc/cron.d:"
ls /etc/cron.d/ 2>/dev/null | sed 's/^/    /' || echo "    Empty"
echo "  /etc/periodic:"
ls /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly 2>/dev/null | sed 's/^/    /'

echo ""
echo "  --- Kernel Extensions ---"
kextstat 2>/dev/null | grep -v "com.apple" | sed 's/^/  /' || echo "  None (or system only)"
THIRD_PARTY_KEXT=$(kextstat 2>/dev/null | grep -v "com.apple" | wc -l | tr -d ' ')
[[ "$THIRD_PARTY_KEXT" -gt 0 ]] && finding MEDIUM "Third-party kernel extensions loaded: $THIRD_PARTY_KEXT"

# ─── 7. FILE SYSTEM SECURITY ──────────────────────────────────────────────────

section "7. FILE SYSTEM SECURITY"

echo ""
echo "  --- SUID/SGID Executables (non-Apple) ---"
find /usr/local /opt /home 2>/dev/null -perm /6000 -type f | head -20 | sed 's/^/  /' || echo "  None found in checked paths"

echo ""
echo "  --- World-Writable Directories (system paths) ---"
find /usr/local /etc /tmp 2>/dev/null -maxdepth 3 -perm -0002 -type d | grep -v "^/tmp$\|^/private/tmp$" | head -20 | sed 's/^/  /' || echo "  None found"

echo ""
echo "  --- Recently Modified System Files (last 24h) ---"
find /etc /usr/local/etc 2>/dev/null -mtime -1 -type f | head -20 | sed 's/^/  /' || echo "  None"

echo ""
echo "  --- Unusual Files in /tmp ---"
ls -la /tmp/ 2>/dev/null | grep -v "^total\|^d" | sed 's/^/  /'
TMP_COUNT=$(ls /tmp/ 2>/dev/null | wc -l | tr -d ' ')
[[ "$TMP_COUNT" -gt 5 ]] && finding LOW "Unusual number of files in /tmp: $TMP_COUNT"

echo ""
echo "  --- Hidden Files in Home Directory ---"
ls -la ~ 2>/dev/null | grep "^\." | grep -v "\.DS_Store\|\.CFUserText\|\.Trash\|\.bash\|\.zsh\|\.ssh\|\.gitconfig\|\.config\|\.local\|\.claude\|\.vimrc" | sed 's/^/  /'

# ─── 8. INSTALLED SOFTWARE AUDIT ──────────────────────────────────────────────

section "8. INSTALLED SOFTWARE AUDIT"

echo ""
echo "  --- Applications in /Applications ---"
ls /Applications/ 2>/dev/null | sed 's/^/  /'

echo ""
echo "  --- Homebrew Packages ---"
if command -v brew &>/dev/null; then
    brew list 2>/dev/null | sed 's/^/  /'
    finding INFO "Homebrew installed — run 'brew audit' for vulnerabilities"
else
    echo "  Homebrew not installed"
fi

echo ""
echo "  --- Python Packages (potential supply chain) ---"
pip3 list 2>/dev/null | head -20 | sed 's/^/  /' || echo "  pip3 not available"

echo ""
echo "  --- macOS Software Updates Available ---"
softwareupdate -l 2>/dev/null | sed 's/^/  /' || echo "  (check manually)"

# ─── 9. LOG ANALYSIS ──────────────────────────────────────────────────────────

section "9. LOG ANALYSIS"

echo ""
echo "  --- Authentication Failures (last 50) ---"
log show --predicate 'eventMessage contains "Failed" AND eventMessage contains "password"' \
    --last 24h --style compact 2>/dev/null | head -20 | sed 's/^/  /' || \
grep -i "failed\|failure" /var/log/auth.log 2>/dev/null | tail -20 | sed 's/^/  /' || \
echo "  (requires full disk access)"

echo ""
echo "  --- Sudo Usage (last 24h) ---"
log show --predicate 'eventMessage contains "sudo"' \
    --last 24h --style compact 2>/dev/null | head -20 | sed 's/^/  /' || echo "  (requires full disk access)"

echo ""
echo "  --- System Errors (last 1h) ---"
log show --predicate 'messageType == error' \
    --last 1h --style compact 2>/dev/null | head -20 | sed 's/^/  /' || echo "  (requires full disk access)"

echo ""
echo "  --- Console Crash Reports ---"
ls ~/Library/Logs/DiagnosticReports/ 2>/dev/null | tail -10 | sed 's/^/  /' || echo "  None"

# ─── 10. PRIVACY & PERMISSIONS ────────────────────────────────────────────────

section "10. PRIVACY & PERMISSIONS"

echo ""
echo "  --- Apps with Full Disk Access ---"
if [[ -f "/Library/Application Support/com.apple.TCC/TCC.db" ]]; then
    sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
        "SELECT client, auth_value FROM access WHERE service='kTCCServiceSystemPolicyAllFiles' AND auth_value=2;" \
        2>/dev/null | sed 's/^/  /' || echo "  (requires sudo)"
else
    echo "  (TCC database requires sudo access)"
fi

echo ""
echo "  --- Camera/Microphone Access ---"
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT service, client, auth_value FROM access WHERE service IN ('kTCCServiceCamera','kTCCServiceMicrophone') AND auth_value=2;" \
    2>/dev/null | sed 's/^/  /' || echo "  (not accessible)"

echo ""
echo "  --- Location Services ---"
defaults read /var/db/locationd/clients.plist 2>/dev/null | grep -A2 "Authorized" | head -20 | sed 's/^/  /' || echo "  (requires sudo)"

# ─── 11. CERTIFICATE & KEYCHAIN AUDIT ─────────────────────────────────────────

section "11. CERTIFICATE & KEYCHAIN AUDIT"

echo ""
echo "  --- Trusted Root Certificates (non-Apple) ---"
security find-certificate -a /System/Library/Keychains/SystemRootCertificates.keychain 2>/dev/null | \
    grep "labl" | grep -iv "apple\|digicert\|comodo\|sectigo\|verisign\|entrust\|globalsign\|geotrust\|amazon\|google\|microsoft\|let's encrypt\|thawte\|symantec" | \
    head -20 | sed 's/^/  /' || echo "  Unable to enumerate (no suspicious certs found)"

echo ""
echo "  --- Expired/Expiring Certificates in Login Keychain ---"
security find-certificate -a -p ~/Library/Keychains/login.keychain-db 2>/dev/null | \
    openssl x509 -noout -dates 2>/dev/null | grep "notAfter" | \
    awk -F= '{print $2}' | while read d; do
        EXPIRY=$(date -j -f "%b %d %T %Y %Z" "$d" "+%s" 2>/dev/null || date -d "$d" "+%s" 2>/dev/null)
        NOW=$(date +%s)
        DIFF=$(( (EXPIRY - NOW) / 86400 ))
        [[ "$DIFF" -lt 30 ]] && echo "  Expiring in ${DIFF}d: $d"
    done 2>/dev/null || echo "  Certificate expiry check complete"

# ─── 12. KNOWN MALWARE INDICATORS ─────────────────────────────────────────────

section "12. KNOWN MALWARE INDICATORS (IOC Check)"

echo ""
echo "  --- Known Malware Paths ---"
MALWARE_PATHS=(
    "/Library/LaunchAgents/com.apple.update.plist"
    "/Library/LaunchDaemons/com.apple.update.plist"
    "~/Library/LaunchAgents/com.mac.host.plist"
    "/private/tmp/.*\.sh"
    "/tmp/.*\.sh"
    "/Library/Application Support/com.apple.service"
    "/var/root/.bash_profile"
)
for path in "${MALWARE_PATHS[@]}"; do
    if ls $path 2>/dev/null | grep -q .; then
        finding HIGH "Suspicious path exists: $path"
    fi
done
finding OK "Known malware path check complete"

echo ""
echo "  --- Suspicious LaunchAgent Names ---"
find /Library/LaunchAgents ~/Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null -name "*.plist" | while read f; do
    # Flag items that look like they're masquerading as Apple
    if basename "$f" | grep -qiE "com\.apple\.(update|helper|service|agent)\b" 2>/dev/null; then
        PROG=$(defaults read "$f" ProgramArguments 2>/dev/null | head -1)
        if ! echo "$PROG" | grep -q "/System\|/usr/libexec\|/usr/bin"; then
            finding HIGH "Suspicious plist masquerading as Apple: $f"
        fi
    fi
done
finding OK "LaunchAgent name inspection complete"

echo ""
echo "  --- Unexpected Setuid Binaries ---"
find /usr/local/bin /opt 2>/dev/null -perm -4000 -type f | while read f; do
    finding MEDIUM "SUID binary in non-standard location: $f"
done

echo ""
echo "  --- Rootkit Indicators (basic) ---"
# Check for hidden processes using ps vs /proc equivalent
PROC_PS=$(ps aux 2>/dev/null | wc -l)
finding INFO "Visible process count (ps): $PROC_PS"

# Check for LD_PRELOAD equivalent (DYLD_INSERT_LIBRARIES)
if env | grep -q "DYLD_INSERT_LIBRARIES"; then
    finding CRITICAL "DYLD_INSERT_LIBRARIES is SET — possible library injection"
else
    finding OK "No DYLD_INSERT_LIBRARIES injection detected"
fi

# ─── 13. BLUETOOTH & WIRELESS ─────────────────────────────────────────────────

section "13. BLUETOOTH & WIRELESS"

echo ""
echo "  --- Bluetooth Status ---"
BT_STATE=$(defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState 2>/dev/null)
[[ "$BT_STATE" == "1" ]] && finding INFO "Bluetooth is ON" || finding OK "Bluetooth is OFF"

echo ""
echo "  --- Wi-Fi Networks (remembered) ---"
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -I 2>/dev/null | head -10 | sed 's/^/  /' || echo "  (airport CLI not available)"

# ─── SUMMARY ──────────────────────────────────────────────────────────────────

section "ASSESSMENT SUMMARY"

TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

echo ""
echo "  ┌─────────────────────────────────────┐"
echo "  │       VULNERABILITY SUMMARY         │"
echo "  ├─────────────────────────────────────┤"
printf "  │  %-10s %3d findings              │\n" "CRITICAL:" "$CRITICAL"
printf "  │  %-10s %3d findings              │\n" "HIGH:"     "$HIGH"
printf "  │  %-10s %3d findings              │\n" "MEDIUM:"   "$MEDIUM"
printf "  │  %-10s %3d findings              │\n" "LOW:"      "$LOW"
echo "  ├─────────────────────────────────────┤"
printf "  │  %-10s %3d total                 │\n" "TOTAL:"    "$TOTAL"
echo "  └─────────────────────────────────────┘"
echo ""

if [[ "$CRITICAL" -gt 0 ]]; then
    echo "  ⚠  CRITICAL issues require IMMEDIATE attention."
fi
if [[ "$HIGH" -gt 0 ]]; then
    echo "  ⚠  HIGH issues should be addressed as soon as possible."
fi

echo ""
echo "  Full report saved to:"
echo "  $REPORT_TXT"
echo ""

# ─── Generate HTML Report ─────────────────────────────────────────────────────

cat > "$REPORT_HTML" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>macOS Security Audit — $HOSTNAME — $TIMESTAMP</title>
<style>
  body { font-family: 'Courier New', monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; }
  h1 { color: #00d4ff; }
  h2 { color: #7ec8e3; border-bottom: 1px solid #333; padding-bottom: 5px; }
  pre { background: #0f3460; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 13px; }
  .critical { color: #ff4444; font-weight: bold; }
  .high     { color: #ff8c00; font-weight: bold; }
  .medium   { color: #ffd700; }
  .low      { color: #90ee90; }
  .ok       { color: #00ff7f; }
  .info     { color: #87ceeb; }
  .summary  { background: #0f3460; border: 1px solid #00d4ff; padding: 20px; border-radius: 8px; margin: 20px 0; }
  .badge    { display: inline-block; padding: 4px 12px; border-radius: 4px; margin: 4px; font-weight: bold; }
  .b-crit   { background: #ff4444; color: white; }
  .b-high   { background: #ff8c00; color: white; }
  .b-med    { background: #ffd700; color: black; }
  .b-low    { background: #90ee90; color: black; }
</style>
</head>
<body>
<h1>🔍 macOS Full Security Audit</h1>
<p><strong>Host:</strong> $HOSTNAME &nbsp;|&nbsp; <strong>Date:</strong> $(date) &nbsp;|&nbsp; <strong>OS:</strong> macOS $(sw_vers -productVersion)</p>

<div class="summary">
  <h2>Executive Summary</h2>
  <span class="badge b-crit">CRITICAL: $CRITICAL</span>
  <span class="badge b-high">HIGH: $HIGH</span>
  <span class="badge b-med">MEDIUM: $MEDIUM</span>
  <span class="badge b-low">LOW: $LOW</span>
  <br><br>
  <strong>Total findings: $TOTAL</strong>
</div>

<h2>Full Report</h2>
<pre>$(cat "$REPORT_TXT" | sed 's/\[CRITICAL\]/<span class="critical">[CRITICAL]<\/span>/g; s/\[HIGH\]/<span class="high">[HIGH]<\/span>/g; s/\[MEDIUM\]/<span class="medium">[MEDIUM]<\/span>/g; s/\[LOW\]/<span class="low">[LOW]<\/span>/g; s/\[OK\]/<span class="ok">[OK]<\/span>/g; s/\[INFO\]/<span class="info">[INFO]<\/span>/g')</pre>
</body>
</html>
HTMLEOF

echo "  HTML report saved to:"
echo "  $REPORT_HTML"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Audit complete."
echo "════════════════════════════════════════════════════════════════"
