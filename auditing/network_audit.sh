#!/bin/bash
# =============================================================================
# network_audit.sh — Full Network Forensics & Traffic Analysis
#
# Description:
#   Comprehensive network investigation covering:
#   - All active interfaces (IPv4 + IPv6)
#   - IPv6 privacy analysis — detects if MAC address is embedded in IPv6
#     using EUI-64 (a known privacy leak in SLAAC-configured addresses)
#   - All listening ports and bound services
#   - Incoming and outgoing active connections with process attribution
#   - DNS configuration and leak detection
#   - ARP table and neighbor cache
#   - Routing table analysis
#   - Network shares and remote access exposure
#   - mDNS/Bonjour service broadcasting (what this Mac advertises)
#   - Firewall rules (pf + application firewall)
#   - VPN/tunnel interface detection
#   - Suspicious/unexpected outbound connections
#
# Output:
#   ~/audit_reports/network_audit_<timestamp>.txt
#   ~/audit_reports/network_audit_<timestamp>.html
#
# Usage:
#   sudo ./network_audit.sh
#
# =============================================================================

set -uo pipefail

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="$HOME/audit_reports"
REPORT_TXT="$REPORT_DIR/network_audit_${TIMESTAMP}.txt"
REPORT_HTML="$REPORT_DIR/network_audit_${TIMESTAMP}.html"

CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0

mkdir -p "$REPORT_DIR"
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
        INFO)     echo "  [INFO]     $msg" ;;
    esac
}

echo "════════════════════════════════════════════════════════════════"
echo "  Network Forensics & Traffic Analysis"
echo "  Host   : $(hostname)"
echo "  Date   : $(date)"
echo "  Report : $REPORT_TXT"
echo "════════════════════════════════════════════════════════════════"

# ─── 1. INTERFACE INVENTORY ───────────────────────────────────────────────────

section "1. NETWORK INTERFACES (IPv4 + IPv6)"

echo ""
echo "  --- All Interfaces ---"
ifconfig 2>/dev/null | sed 's/^/  /'

echo ""
echo "  --- IPv4 Addresses ---"
ifconfig | grep "inet " | grep -v "127.0.0.1" | awk '{print "  "$2, "("$NF")"}'

echo ""
echo "  --- IPv6 Addresses ---"
ifconfig | grep "inet6" | grep -v "::1\|fe80" | awk '{print "  "$2}'
echo ""
echo "  --- Link-Local IPv6 (fe80) ---"
ifconfig | grep "inet6 fe80" | awk '{print "  "$2, "interface:", $NF}'

# ─── 2. IPv6 PRIVACY / MAC ADDRESS LEAK ANALYSIS ─────────────────────────────

section "2. IPv6 PRIVACY ANALYSIS — MAC ADDRESS LEAK DETECTION"

echo ""
echo "  EUI-64 embeds your MAC address in the IPv6 address."
echo "  Format: xxxx:xxFF:FExx:xxxx where FF:FE is the EUI-64 marker."
echo ""

# Get all MAC addresses on active interfaces
declare -A MAC_MAP
while IFS= read -r line; do
    if [[ "$line" =~ ^[a-z] ]]; then
        CURRENT_IFACE=$(echo "$line" | cut -d: -f1)
    fi
    if [[ "$line" =~ "ether " ]]; then
        MAC=$(echo "$line" | awk '{print $2}')
        MAC_MAP[$CURRENT_IFACE]="$MAC"
    fi
done < <(ifconfig 2>/dev/null)

echo "  --- Interface MACs ---"
for iface in "${!MAC_MAP[@]}"; do
    echo "  $iface : ${MAC_MAP[$iface]}"
done

echo ""
echo "  --- EUI-64 Leak Check ---"
LEAK_FOUND=0

ifconfig 2>/dev/null | grep "inet6" | grep -v "::1" | while read -r line; do
    IPV6=$(echo "$line" | awk '{print $2}' | cut -d'/' -f1 | cut -d'%' -f1)

    # EUI-64 detection: check for fffe in the interface identifier
    if echo "$IPV6" | grep -qiE "ff:fe|fffe"; then
        finding HIGH "EUI-64 IPv6 detected — MAC address EMBEDDED in address: $IPV6"
        LEAK_FOUND=1
    fi

    # Check if any known MAC matches within the IPv6 address
    for iface in "${!MAC_MAP[@]}"; do
        MAC="${MAC_MAP[$iface]}"
        # Convert MAC to EUI-64 format for comparison
        MAC_CLEAN=$(echo "$MAC" | tr -d ':' | tr '[:upper:]' '[:lower:]')
        # Flip 7th bit of first byte (universal/local bit)
        FIRST=$(echo "${MAC_CLEAN:0:2}")
        FIRST_FLIPPED=$(printf '%02x' $((16#$FIRST ^ 0x02)) 2>/dev/null)
        EUI64="${FIRST_FLIPPED}${MAC_CLEAN:2:2}:${MAC_CLEAN:4:2}ff:fe${MAC_CLEAN:6:2}:${MAC_CLEAN:8:2}${MAC_CLEAN:10:2}"
        EUI64_COMPACT=$(echo "$EUI64" | tr -d ':' | tr '[:upper:]' '[:lower:]')
        IPV6_COMPACT=$(echo "$IPV6" | tr -d ':' | tr '[:upper:]' '[:lower:]')

        if [[ "${#EUI64_COMPACT}" -ge 16 ]] && echo "$IPV6_COMPACT" | grep -q "${EUI64_COMPACT:8:8}" 2>/dev/null; then
            finding HIGH "MAC address from $iface ($MAC) is traceable in IPv6: $IPV6"
        fi
    done
done

echo ""
echo "  --- IPv6 Privacy Extensions Status ---"
# Check if privacy extensions are enabled (randomized temporary addresses)
for iface in en0 en1 en2; do
    PRIV=$(networksetup -getinfo "$iface" 2>/dev/null | grep -i "IPv6" || true)
    STATUS=$(sysctl net.inet6.ip6.use_tempaddr 2>/dev/null | awk '{print $2}')
done

TEMPADDR=$(sysctl net.inet6.ip6.use_tempaddr 2>/dev/null | awk '{print $2}')
PREFER_TEMP=$(sysctl net.inet6.ip6.prefer_tempaddr 2>/dev/null | awk '{print $2}')

echo "  use_tempaddr   (privacy extensions) : ${TEMPADDR:-unknown}"
echo "  prefer_tempaddr (prefer random addr) : ${PREFER_TEMP:-unknown}"

if [[ "${TEMPADDR:-0}" == "2" ]] && [[ "${PREFER_TEMP:-0}" == "1" ]]; then
    finding OK "IPv6 privacy extensions enabled — temporary randomized addresses in use"
elif [[ "${TEMPADDR:-0}" == "0" ]]; then
    finding HIGH "IPv6 privacy extensions DISABLED — stable (possibly MAC-derived) address used"
else
    finding MEDIUM "IPv6 privacy extensions partially configured (use_tempaddr=$TEMPADDR prefer_tempaddr=$PREFER_TEMP)"
fi

echo ""
echo "  --- Recommendation ---"
echo "  To enable IPv6 privacy extensions permanently, add to /etc/sysctl.conf:"
echo "    net.inet6.ip6.use_tempaddr=2"
echo "    net.inet6.ip6.prefer_tempaddr=1"

# ─── 3. LISTENING PORTS ───────────────────────────────────────────────────────

section "3. LISTENING PORTS & BOUND SERVICES"

echo ""
echo "  --- TCP Listening Ports ---"
echo "  Port    Proto  PID    Process         Address"
echo "  ──────────────────────────────────────────────"
lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR>1 {
    split($9, addr, ":")
    port = addr[length(addr)]
    printf "  %-7s %-6s %-6s %-15s %s\n", port, $8, $2, $1, $9
}' | sort -n

echo ""
echo "  --- UDP Bound Ports ---"
lsof -iUDP -n -P 2>/dev/null | awk 'NR>1 {printf "  %-7s %-6s %-6s %s\n", $9, $8, $2, $1}' | sort -u | head -30

echo ""
echo "  --- High Risk Open Ports Check ---"
RISKY_PORTS=(21 22 23 25 53 80 110 135 139 143 443 445 512 513 514 3306 3389 5432 5900 6379 8080 8443 27017)
for port in "${RISKY_PORTS[@]}"; do
    if lsof -iTCP:$port -sTCP:LISTEN -n -P 2>/dev/null | grep -q LISTEN; then
        PROC=$(lsof -iTCP:$port -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR>1{print $1}' | head -1)
        case $port in
            21)  finding HIGH "FTP port 21 open ($PROC) — unencrypted file transfer" ;;
            22)  finding MEDIUM "SSH port 22 open ($PROC) — verify this is intentional" ;;
            23)  finding CRITICAL "Telnet port 23 open ($PROC) — cleartext protocol" ;;
            3389) finding HIGH "RDP port 3389 open ($PROC) — remote desktop exposed" ;;
            5900) finding HIGH "VNC port 5900 open ($PROC) — screen sharing exposed" ;;
            445)  finding HIGH "SMB port 445 open ($PROC) — Windows file sharing" ;;
            3306) finding HIGH "MySQL port 3306 open ($PROC) — database exposed" ;;
            6379) finding CRITICAL "Redis port 6379 open ($PROC) — often unauthenticated" ;;
            27017) finding HIGH "MongoDB port 27017 open ($PROC) — database exposed" ;;
            *)   finding LOW "Port $port open ($PROC)" ;;
        esac
    fi
done
finding OK "High-risk port scan complete"

# ─── 4. ACTIVE CONNECTIONS ────────────────────────────────────────────────────

section "4. ACTIVE CONNECTIONS (Incoming & Outgoing)"

echo ""
echo "  --- All Established Connections ---"
echo "  Local Address                Remote Address               State       PID  Process"
echo "  ────────────────────────────────────────────────────────────────────────────────"
lsof -i -n -P 2>/dev/null | grep "ESTABLISHED\|CLOSE_WAIT\|SYN_SENT" | \
    awk '{printf "  %-28s %-28s %-11s %-5s %s\n", $9, $9, $10, $2, $1}' | \
    sed 's/->.*->/->/g' | sort -u | head -40

echo ""
echo "  --- Outgoing by Process ---"
lsof -i -n -P 2>/dev/null | grep "ESTABLISHED" | \
    awk '{print $1, $2, $9}' | sort -u | \
    while read proc pid conn; do
        echo "  [$pid] $proc → $conn"
    done | head -30

echo ""
echo "  --- Incoming Connections (LISTEN + ESTABLISHED to local) ---"
netstat -an 2>/dev/null | grep -E "LISTEN|ESTABLISHED" | \
    awk '$4 !~ /127\.0\.0\.1|::1/' | head -30 | sed 's/^/  /'

echo ""
echo "  --- Connection Count by Remote IP ---"
netstat -an 2>/dev/null | grep ESTABLISHED | \
    awk '{print $5}' | cut -d'.' -f1-4 | sort | uniq -c | sort -rn | head -20 | sed 's/^/  /'

# ─── 5. DNS ANALYSIS ──────────────────────────────────────────────────────────

section "5. DNS CONFIGURATION & LEAK ANALYSIS"

echo ""
echo "  --- Configured DNS Servers ---"
scutil --dns 2>/dev/null | grep -E "nameserver|domain|search" | sort -u | sed 's/^/  /'

echo ""
echo "  --- DNS Resolver Test ---"
dig +short apple.com @8.8.8.8 2>/dev/null | head -3 | while read ip; do
    echo "  apple.com → $ip (via 8.8.8.8)"
done

echo ""
echo "  --- mDNS / Bonjour Services Advertised (what this Mac broadcasts) ---"
dns-sd -B _services._dns-sd._udp local 2>/dev/null &
DNS_PID=$!
sleep 3
kill $DNS_PID 2>/dev/null || true

# Use avahi or system tools instead
lsof -i UDP:5353 -n 2>/dev/null | awk 'NR>1{print "  "$1, $2, $9}' | sort -u

echo ""
echo "  --- /etc/hosts Anomaly Check ---"
EXTRA=$(grep -v "^#\|^$\|^127\|^::1\|^fe80\|^255" /etc/hosts 2>/dev/null)
if [[ -n "$EXTRA" ]]; then
    finding MEDIUM "Non-standard /etc/hosts entries (possible DNS hijack):"
    echo "$EXTRA" | sed 's/^/    /'
else
    finding OK "No suspicious /etc/hosts entries"
fi

# ─── 6. ROUTING & ARP TABLE ───────────────────────────────────────────────────

section "6. ROUTING TABLE & ARP/NEIGHBOR CACHE"

echo ""
echo "  --- IPv4 Routing Table ---"
netstat -rn -f inet 2>/dev/null | sed 's/^/  /'

echo ""
echo "  --- IPv6 Routing Table ---"
netstat -rn -f inet6 2>/dev/null | head -30 | sed 's/^/  /'

echo ""
echo "  --- ARP Table (known LAN devices) ---"
arp -a 2>/dev/null | sed 's/^/  /'

echo ""
echo "  --- IPv6 Neighbor Cache ---"
ndp -a 2>/dev/null | sed 's/^/  /' || echo "  (not available)"

echo ""
echo "  --- Default Gateway ---"
GW=$(netstat -rn 2>/dev/null | grep "^default\|^0.0.0.0" | awk '{print $2}' | head -1)
finding INFO "Default gateway: ${GW:-not found}"

# ─── 7. FIREWALL STATUS ───────────────────────────────────────────────────────

section "7. FIREWALL CONFIGURATION"

echo ""
echo "  --- Application Firewall (socketfilterfw) ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | sed 's/^/  /'
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | sed 's/^/  /'
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null | sed 's/^/  /'
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | sed 's/^/  /' | head -30

echo ""
echo "  --- PF (Packet Filter) Status ---"
pfctl -s info 2>/dev/null | head -10 | sed 's/^/  /' || echo "  pf not loaded"

echo ""
echo "  --- PF Rules ---"
pfctl -s rules 2>/dev/null | head -20 | sed 's/^/  /' || echo "  No pf rules loaded"

echo ""
echo "  --- PF NAT Rules ---"
pfctl -s nat 2>/dev/null | head -10 | sed 's/^/  /' || echo "  No NAT rules"

# ─── 8. VPN & TUNNEL DETECTION ────────────────────────────────────────────────

section "8. VPN & TUNNEL INTERFACES"

echo ""
VPN_FOUND=0
for iface in $(ifconfig -l 2>/dev/null); do
    case "$iface" in
        utun*|tun*|tap*|ipsec*|ppp*|wireguard*)
            STATUS=$(ifconfig "$iface" 2>/dev/null | grep -E "inet|status" | head -2)
            if ifconfig "$iface" 2>/dev/null | grep -q "UP"; then
                echo "  [ACTIVE] $iface:"
                echo "$STATUS" | sed 's/^/    /'
                finding INFO "VPN/tunnel interface active: $iface"
                VPN_FOUND=1
            fi
            ;;
    esac
done
[[ "$VPN_FOUND" -eq 0 ]] && finding INFO "No active VPN/tunnel interfaces detected"

echo ""
echo "  --- WireGuard Check ---"
which wg 2>/dev/null && wg show 2>/dev/null | sed 's/^/  /' || echo "  WireGuard not installed"

# ─── 9. NETWORK SHARING & EXPOSURE ───────────────────────────────────────────

section "9. NETWORK SHARING & EXPOSURE"

echo ""
echo "  --- File Sharing (SMB/AFP) ---"
sharing -l 2>/dev/null | sed 's/^/  /'
SHARE_COUNT=$(sharing -l 2>/dev/null | grep "^name:" | wc -l | tr -d ' ')
[[ "$SHARE_COUNT" -gt 0 ]] && finding MEDIUM "Network shares active: $SHARE_COUNT — verify guest access settings" || finding OK "No network shares"

echo ""
echo "  --- Bonjour/mDNS Advertising ---"
dns-sd -B _http._tcp local. 2>/dev/null &
sleep 2; kill %% 2>/dev/null || true
scutil --get LocalHostName 2>/dev/null | sed 's/^/  LocalHostName: /'
scutil --get ComputerName 2>/dev/null | sed 's/^/  ComputerName: /'

echo ""
echo "  --- Remote Login (SSH daemon) ---"
systemsetup -getremotelogin 2>/dev/null | sed 's/^/  /'

echo ""
echo "  --- Screen Sharing ---"
launchctl list com.apple.screensharing 2>/dev/null | sed 's/^/  /' || echo "  Screen sharing: not running"

echo ""
echo "  --- Remote Management (ARD) ---"
launchctl list com.apple.RemoteDesktop 2>/dev/null | sed 's/^/  /' || echo "  Remote Desktop: not running"

# ─── 10. SUSPICIOUS TRAFFIC ANALYSIS ─────────────────────────────────────────

section "10. SUSPICIOUS TRAFFIC ANALYSIS"

echo ""
echo "  --- Connections to Non-Standard Ports (potential C2/exfil) ---"
lsof -i -n -P 2>/dev/null | grep "ESTABLISHED" | \
    awk '{print $9}' | grep -v ":443\|:80\|:993\|:465\|:587\|:5223\|:5228\|:8080\|:8443" | \
    grep ">" | head -20 | while read conn; do
        finding LOW "Non-standard port connection: $conn"
    done

echo ""
echo "  --- Processes with Unexpected Network Access ---"
lsof -i -n -P 2>/dev/null | grep "ESTABLISHED" | \
    awk '{print $1}' | sort | uniq -c | sort -rn | head -15 | sed 's/^/  /'

echo ""
echo "  --- Long-lived Connections (possible persistent callbacks) ---"
netstat -an 2>/dev/null | grep ESTABLISHED | wc -l | \
    xargs -I{} echo "  Total established connections: {}"

# ─── SUMMARY ──────────────────────────────────────────────────────────────────

section "NETWORK AUDIT SUMMARY"

TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))

echo ""
echo "  ┌─────────────────────────────────────┐"
echo "  │     NETWORK VULNERABILITY SUMMARY   │"
echo "  ├─────────────────────────────────────┤"
printf "  │  %-10s %3d findings              │\n" "CRITICAL:" "$CRITICAL"
printf "  │  %-10s %3d findings              │\n" "HIGH:"     "$HIGH"
printf "  │  %-10s %3d findings              │\n" "MEDIUM:"   "$MEDIUM"
printf "  │  %-10s %3d findings              │\n" "LOW:"      "$LOW"
echo "  ├─────────────────────────────────────┤"
printf "  │  %-10s %3d total                 │\n" "TOTAL:"    "$TOTAL"
echo "  └─────────────────────────────────────┘"
echo ""
echo "  Full report : $REPORT_TXT"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Network audit complete."
echo "════════════════════════════════════════════════════════════════"

# ─── HTML Report ──────────────────────────────────────────────────────────────

cat > "$REPORT_HTML" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Audit — $(hostname) — $TIMESTAMP</title>
<style>
  body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
  h1 { color: #58a6ff; } h2 { color: #79c0ff; border-bottom: 1px solid #30363d; padding-bottom: 5px; }
  pre { background: #161b22; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; border: 1px solid #30363d; }
  .critical { color: #ff4444; font-weight: bold; }
  .high { color: #ff8c00; font-weight: bold; }
  .medium { color: #ffd700; }
  .low { color: #90ee90; }
  .ok { color: #3fb950; }
  .info { color: #58a6ff; }
  .summary { background: #161b22; border: 1px solid #58a6ff; padding: 20px; border-radius: 8px; margin: 20px 0; }
  .badge { display: inline-block; padding: 4px 12px; border-radius: 4px; margin: 4px; font-weight: bold; }
  .b-crit { background: #ff4444; color: white; } .b-high { background: #ff8c00; color: white; }
  .b-med { background: #ffd700; color: black; } .b-low { background: #3fb950; color: black; }
</style>
</head>
<body>
<h1>🌐 Network Forensics & Traffic Analysis</h1>
<p><strong>Host:</strong> $(hostname) &nbsp;|&nbsp; <strong>Date:</strong> $(date) &nbsp;|&nbsp; <strong>OS:</strong> macOS $(sw_vers -productVersion)</p>
<div class="summary">
  <h2>Summary</h2>
  <span class="badge b-crit">CRITICAL: $CRITICAL</span>
  <span class="badge b-high">HIGH: $HIGH</span>
  <span class="badge b-med">MEDIUM: $MEDIUM</span>
  <span class="badge b-low">LOW: $LOW</span>
</div>
<h2>Full Report</h2>
<pre>$(cat "$REPORT_TXT" | sed 's/\[CRITICAL\]/<span class="critical">[CRITICAL]<\/span>/g; s/\[HIGH\]/<span class="high">[HIGH]<\/span>/g; s/\[MEDIUM\]/<span class="medium">[MEDIUM]<\/span>/g; s/\[LOW\]/<span class="low">[LOW]<\/span>/g; s/\[OK\]/<span class="ok">[OK]<\/span>/g; s/\[INFO\]/<span class="info">[INFO]<\/span>/g')</pre>
</body></html>
HTMLEOF

echo "  HTML report : $REPORT_HTML"
