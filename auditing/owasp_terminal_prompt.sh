#!/bin/bash
# =============================================================================
# OWASP Security Terminal — Laptop Code & File Scanner
# Scans new/modified files against OWASP Top 10 patterns + online signatures
# Author: Ioannis Konstas — IT Solutions USA
# =============================================================================

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; BRED='\033[1;31m'
GREEN='\033[0;32m'; BGREEN='\033[1;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BCYAN='\033[1;36m'; MAGENTA='\033[0;35m'
BMAGENTA='\033[1;35m'; WHITE='\033[1;37m'
DIM='\033[2m'; RESET='\033[0m'

# ── Config ────────────────────────────────────────────────────────────────────
OWASP_LOG="$HOME/.owasp_scan.log"
OWASP_REPORT_DIR="$HOME/.owasp_reports"
SCAN_EXTENSIONS="py|sh|js|ts|php|rb|go|java|c|cpp|h|sql|html|xml|yaml|yml|json|env|cfg|conf|ini"
WATCH_PATHS="$HOME/Desktop $HOME/Documents $HOME/Downloads $HOME/Projects $HOME/dev $HOME/code"
VT_API_KEY="${VIRUSTOTAL_API_KEY:-}"          # set VIRUSTOTAL_API_KEY in env for online checks
BLOCK_ON_CRITICAL="${OWASP_BLOCK:-false}"     # set OWASP_BLOCK=true to auto-quarantine

mkdir -p "$OWASP_REPORT_DIR"

# ── Banner ────────────────────────────────────────────────────────────────────
owasp_banner() {
  clear
  echo -e "${BRED}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║          OWASP SECURITY TERMINAL  —  IT Solutions USA     ║"
  echo "  ║         Laptop File & Code Scanner  |  Top 10 Engine      ║"
  echo "  ╚═══════════════════════════════════════════════════════════╝${RESET}"
  echo -e "  ${DIM}Log: $OWASP_LOG   Reports: $OWASP_REPORT_DIR${RESET}"
  echo -e "  ${DIM}VT Online Check: $([ -n "$VT_API_KEY" ] && echo "ENABLED" || echo "DISABLED — set VIRUSTOTAL_API_KEY")${RESET}"
  echo ""
}

# ── Logging ───────────────────────────────────────────────────────────────────
log() {
  local level="$1"; shift
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" >> "$OWASP_LOG"
}

# ── OWASP Top 10 Pattern Definitions ─────────────────────────────────────────
# Each entry: "CATEGORY|SEVERITY|DESCRIPTION|GREP_PATTERN"
declare -a OWASP_PATTERNS=(
  # A01 — Broken Access Control
  "A01|CRITICAL|Hardcoded admin bypass|admin.*=.*true\|is_admin.*=.*1\|role.*=.*admin"
  "A01|HIGH|Directory traversal pattern|\.\./\.\./\|\.\.%2F"
  "A01|HIGH|Insecure direct object ref|user_id.*=.*request\|uid.*=.*params\|id.*=.*GET"

  # A02 — Cryptographic Failures
  "A02|CRITICAL|Hardcoded secret/key/password|password\s*=\s*['\"][^'\"]\{4,\}['\"]\\|secret\s*=\s*['\"]\\|api_key\s*=\s*['\"]"
  "A02|CRITICAL|Private key in file|BEGIN RSA PRIVATE\|BEGIN EC PRIVATE\|BEGIN PRIVATE KEY"
  "A02|HIGH|Weak hash algorithm|md5(\|sha1(\|hashlib\.md5\|hashlib\.sha1"
  "A02|HIGH|Weak cipher usage|DES\b\|RC4\b\|3DES\b\|ECB\b"
  "A02|MEDIUM|Base64 encoded secret|[A-Za-z0-9+/]\{40,\}={0,2}"

  # A03 — Injection
  "A03|CRITICAL|SQL injection risk|SELECT.*+.*\|query.*+.*input\|execute.*%s\|cursor\.execute.*format\|f\"SELECT\|f'SELECT"
  "A03|CRITICAL|Command injection risk|os\.system(\|subprocess.*shell=True\|eval(\|exec(\|popen("
  "A03|CRITICAL|LDAP injection pattern|ldap.*search.*input\|filter.*cn=.*user"
  'A03|HIGH|Shell injection via variable|`\$|system(\$|`.*\${'
  "A03|HIGH|Template injection|\{\{.*request\|jinja.*render.*user\|render_template.*input"
  "A03|MEDIUM|Prompt injection pattern|ignore previous\|ignore all instructions\|you are now\|new system prompt\|disregard your"

  # A04 — Insecure Design
  "A04|HIGH|Debug mode enabled|DEBUG.*=.*True\|debug.*=.*true\|APP_DEBUG.*=.*true"
  "A04|MEDIUM|Insecure randomness|random\.random(\|Math\.random(\|rand()"

  # A05 — Security Misconfiguration
  "A05|CRITICAL|AWS credentials in code|AKIA[0-9A-Z]\{16\}\|aws_secret\|AWS_SECRET"
  "A05|HIGH|Wildcard CORS|Access-Control-Allow-Origin.*\*\|cors.*origin.*\*"
  "A05|HIGH|Disabled SSL verification|verify=False\|ssl_verify.*false\|InsecureRequestWarning\|VERIFY_SSL.*false"
  "A05|MEDIUM|World-writable file permission|chmod.*777\|chmod.*o+w"
  "A05|MEDIUM|Exposed .env pattern|\.env\b.*load\|dotenv"

  # A06 — Vulnerable Components
  "A06|HIGH|Outdated hash in requirements|==.*0\.[0-9]\|==1\.[0-9]\."
  "A06|MEDIUM|Direct use of pickle|import pickle\|pickle\.loads\|pickle\.load("

  # A07 — Auth Failures
  "A07|CRITICAL|JWT none algorithm|alg.*none\|algorithm.*none\|HS256.*none"
  "A07|HIGH|Hardcoded token/bearer|Bearer [A-Za-z0-9_\-\.]\{20,\}\|token.*=.*['\"][a-f0-9]\{32,\}"
  "A07|HIGH|Insecure session config|SESSION_COOKIE_SECURE.*False\|httponly.*false\|secure.*false"
  "A07|MEDIUM|Weak password policy|len(password).*[<][[:space:]]*[1-7]\b"

  # A08 — Software Integrity
  "A08|HIGH|Unvalidated deserialization|yaml\.load(\|pickle\.loads(\|unserialize(\|ObjectInputStream"
  "A08|HIGH|Eval on external data|eval(request\|eval(input\|eval(data\|eval(body"

  # A09 — Logging Failures
  "A09|MEDIUM|Password logged|log.*password\|print.*password\|logger.*secret"
  "A09|MEDIUM|Sensitive data in log|log.*credit_card\|log.*ssn\|log.*cvv"

  # A10 — SSRF
  "A10|HIGH|SSRF risk — user-controlled URL|requests\.get.*input\|urllib.*open.*user\|fetch.*request\[url\]\|curl.*\$url"
  "A10|MEDIUM|Internal metadata endpoint|169\.254\.169\.254\|metadata\.google\|169\.254\.170\.2"
)

# ── Scan a single file ─────────────────────────────────────────────────────────
scan_file() {
  local file="$1"
  local report_file="$OWASP_REPORT_DIR/$(basename "$file")_$(date +%Y%m%d_%H%M%S).txt"
  local findings=0
  local critical=0

  # skip binary files
  file --mime "$file" 2>/dev/null | grep -q "charset=binary" && return

  echo -e "\n${BCYAN}━━━ Scanning: ${WHITE}$file${RESET}"
  echo "OWASP SCAN REPORT — $file" > "$report_file"
  echo "Scanned: $(date)" >> "$report_file"
  echo "========================================" >> "$report_file"

  for pattern_entry in "${OWASP_PATTERNS[@]}"; do
    IFS='|' read -r category severity description pattern <<< "$pattern_entry"

    matches=$(grep -nEi "$pattern" "$file" 2>/dev/null)
    if [ -n "$matches" ]; then
      findings=$((findings + 1))
      [ "$severity" = "CRITICAL" ] && critical=$((critical + 1))

      # color by severity
      case "$severity" in
        CRITICAL) color="${BRED}" ;;
        HIGH)     color="${YELLOW}" ;;
        MEDIUM)   color="${CYAN}" ;;
        *)        color="${WHITE}" ;;
      esac

      echo -e "  ${color}[$severity]${RESET} ${BMAGENTA}[$category]${RESET} $description"
      echo "$matches" | head -3 | while IFS= read -r line; do
        echo -e "    ${DIM}→ $line${RESET}"
      done

      echo "[$severity] [$category] $description" >> "$report_file"
      echo "$matches" >> "$report_file"
      echo "" >> "$report_file"

      log "FINDING" "$severity | $category | $description | file=$file"
    fi
  done

  # ── Online signature checks ──────────────────────────────────────────────────
  local hash
  hash=$(shasum -a 256 "$file" 2>/dev/null | awk '{print $1}')
  local md5hash
  md5hash=$(md5 -q "$file" 2>/dev/null)
  local sha1hash
  sha1hash=$(shasum -a 1 "$file" 2>/dev/null | awk '{print $1}')

  if [ -n "$hash" ]; then
    echo -e "  ${DIM}[ONLINE] Checking hash: ${hash:0:20}...${RESET}"
    echo "--- ONLINE SIGNATURE CHECKS ---" >> "$report_file"
    echo "SHA256: $hash" >> "$report_file"

    # 1. VirusTotal (requires VIRUSTOTAL_API_KEY)
    if [ -n "$VT_API_KEY" ]; then
      local vt_result
      vt_result=$(curl -s --max-time 8 \
        -H "x-apikey: $VT_API_KEY" \
        "https://www.virustotal.com/api/v3/files/$hash")
      local malicious
      malicious=$(echo "$vt_result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  print(d['data']['attributes']['last_analysis_stats']['malicious'])
except: print(0)
" 2>/dev/null)
      if [ "${malicious:-0}" -gt 0 ] 2>/dev/null; then
        echo -e "  ${BRED}[VIRUSTOTAL] MALICIOUS — $malicious/70+ engines flagged!${RESET}"
        echo "[VIRUSTOTAL] MALICIOUS — $malicious engines flagged" >> "$report_file"
        log "VIRUSTOTAL" "MALICIOUS | $malicious engines | hash=$hash | file=$file"
        critical=$((critical + 1))
      else
        echo -e "  ${GREEN}[VIRUSTOTAL] Clean${RESET}"
        echo "[VIRUSTOTAL] Clean" >> "$report_file"
      fi
    else
      echo -e "  ${DIM}[VIRUSTOTAL] Skipped — set VIRUSTOTAL_API_KEY to enable${RESET}"
    fi

    # 2. CIRCL HASHLOOKUP (free, no key needed)
    local circl_result
    circl_result=$(curl -s --max-time 8 \
      "https://hashlookup.circl.lu/lookup/sha256/$hash")
    local circl_known
    circl_known=$(echo "$circl_result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  print(d.get('KnownMalicious','0'))
except: print('unknown')
" 2>/dev/null)
    local circl_name
    circl_name=$(echo "$circl_result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  print(d.get('FileName', d.get('ProductName','')))
except: print('')
" 2>/dev/null)
    if echo "$circl_result" | grep -q '"KnownMalicious"'; then
      echo -e "  ${BRED}[CIRCL HASHLOOKUP] KNOWN MALICIOUS — $circl_name${RESET}"
      echo "[CIRCL HASHLOOKUP] KNOWN MALICIOUS: $circl_name" >> "$report_file"
      log "CIRCL" "MALICIOUS | $circl_name | hash=$hash | file=$file"
      critical=$((critical + 1))
    elif echo "$circl_result" | grep -q '"FileName"'; then
      echo -e "  ${GREEN}[CIRCL HASHLOOKUP] Known clean — $circl_name${RESET}"
      echo "[CIRCL HASHLOOKUP] Known clean: $circl_name" >> "$report_file"
    else
      echo -e "  ${DIM}[CIRCL HASHLOOKUP] Hash not in database${RESET}"
      echo "[CIRCL HASHLOOKUP] Not found in database" >> "$report_file"
    fi

    # 3. MalwareBazaar (free, no key needed)
    local mb_result
    mb_result=$(curl -s --max-time 8 -X POST \
      -d "query=get_info&hash=$hash" \
      "https://mb-api.abuse.ch/api/v1/")
    local mb_status
    mb_status=$(echo "$mb_result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  print(d.get('query_status',''))
except: print('')
" 2>/dev/null)
    local mb_tags
    mb_tags=$(echo "$mb_result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  data=d.get('data',[{}])
  tags=data[0].get('tags',[]) if data else []
  print(', '.join(tags) if tags else '')
except: print('')
" 2>/dev/null)
    if [ "$mb_status" = "ok" ]; then
      echo -e "  ${BRED}[MALWAREBAZAAR] MALWARE SAMPLE FOUND — tags: ${mb_tags:-none}${RESET}"
      echo "[MALWAREBAZAAR] MALWARE FOUND — tags: $mb_tags" >> "$report_file"
      log "MALWAREBAZAAR" "MALWARE | tags=$mb_tags | hash=$hash | file=$file"
      critical=$((critical + 1))
    elif [ "$mb_status" = "hash_not_found" ]; then
      echo -e "  ${GREEN}[MALWAREBAZAAR] Not in malware database${RESET}"
      echo "[MALWAREBAZAAR] Clean — not found" >> "$report_file"
    else
      echo -e "  ${DIM}[MALWAREBAZAAR] No response${RESET}"
      echo "[MALWAREBAZAAR] No response" >> "$report_file"
    fi

    # 4. NIST NVD — CVE check by filename/extension (package name heuristic)
    local pkg_name
    pkg_name=$(basename "$file" | sed 's/[-_][0-9].*//' | sed 's/\..*//')
    if [ -n "$pkg_name" ] && [ ${#pkg_name} -gt 3 ]; then
      local nvd_result
      nvd_result=$(curl -s --max-time 8 \
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$pkg_name&resultsPerPage=3")
      local cve_count
      cve_count=$(echo "$nvd_result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  print(d.get('totalResults',0))
except: print(0)
" 2>/dev/null)
      local cve_ids
      cve_ids=$(echo "$nvd_result" | python3 -c "
import sys,json
try:
  d=json.load(sys.stdin)
  ids=[v['cve']['id'] for v in d.get('vulnerabilities',[])[:3]]
  print(', '.join(ids))
except: print('')
" 2>/dev/null)
      if [ "${cve_count:-0}" -gt 0 ] 2>/dev/null; then
        echo -e "  ${YELLOW}[NIST NVD] $cve_count CVE(s) for '$pkg_name' — $cve_ids${RESET}"
        echo "[NIST NVD] $cve_count CVEs for $pkg_name: $cve_ids" >> "$report_file"
        log "NISTNVD" "CVEs=$cve_count | pkg=$pkg_name | file=$file"
        findings=$((findings + 1))
      else
        echo -e "  ${GREEN}[NIST NVD] No CVEs found for '$pkg_name'${RESET}"
        echo "[NIST NVD] No CVEs for $pkg_name" >> "$report_file"
      fi
    fi
  fi

  # ── Summary ─────────────────────────────────────────────────────────────────
  if [ "$findings" -eq 0 ]; then
    echo -e "  ${BGREEN}✓ No OWASP issues found${RESET}"
    echo "RESULT: CLEAN" >> "$report_file"
  else
    echo -e "  ${YELLOW}⚠ $findings issue(s) found — $critical critical${RESET}"
    echo -e "  ${DIM}Report saved: $report_file${RESET}"
    echo "RESULT: $findings ISSUES ($critical CRITICAL)" >> "$report_file"
    log "SUMMARY" "$findings issues ($critical critical) in $file"

    # auto-quarantine critical files if blocking enabled
    if [ "$BLOCK_ON_CRITICAL" = "true" ] && [ "$critical" -gt 0 ]; then
      local quarantine="$OWASP_REPORT_DIR/quarantine"
      mkdir -p "$quarantine"
      mv "$file" "$quarantine/" && \
        echo -e "  ${BRED}⛔ FILE QUARANTINED → $quarantine/$(basename "$file")${RESET}"
      log "QUARANTINE" "Moved $file to quarantine"
    fi
  fi
}

# ── Scan a directory ──────────────────────────────────────────────────────────
scan_dir() {
  local dir="${1:-.}"
  echo -e "\n${BMAGENTA}⟳ Scanning directory: ${WHITE}$dir${RESET}"
  local count=0
  while IFS= read -r -d '' file; do
    scan_file "$file"
    count=$((count + 1))
  done < <(find "$dir" -type f -regextype posix-extended \
    -regex ".*\.(${SCAN_EXTENSIONS})" -not -path "*/.git/*" \
    -not -path "*/node_modules/*" -not -path "*/__pycache__/*" -print0)
  echo -e "\n${GREEN}Scan complete — $count file(s) checked.${RESET}"
}

# ── Git hook integration — scan only changed files ────────────────────────────
scan_git_changes() {
  local repo="${1:-.}"
  echo -e "\n${BMAGENTA}⟳ Scanning git changes in: ${WHITE}$repo${RESET}"
  git -C "$repo" diff --name-only HEAD 2>/dev/null | while IFS= read -r f; do
    [ -f "$repo/$f" ] && scan_file "$repo/$f"
  done
  git -C "$repo" diff --cached --name-only 2>/dev/null | while IFS= read -r f; do
    [ -f "$repo/$f" ] && scan_file "$repo/$f"
  done
}

# ── Live file system watcher ──────────────────────────────────────────────────
start_watcher() {
  if ! command -v fswatch &>/dev/null; then
    echo -e "${YELLOW}fswatch not installed. Install with: brew install fswatch${RESET}"
    echo -e "${YELLOW}Watcher not started — use 'oscan <file>' or 'odir <path>' manually.${RESET}"
    return
  fi

  local watch_targets=()
  for p in $WATCH_PATHS; do
    [ -d "$p" ] && watch_targets+=("$p")
  done

  if [ ${#watch_targets[@]} -eq 0 ]; then
    echo -e "${YELLOW}No watch paths found. Edit WATCH_PATHS in script.${RESET}"
    return
  fi

  echo -e "${BGREEN}⟳ Live watcher started on:${RESET}"
  for p in "${watch_targets[@]}"; do echo -e "  ${DIM}$p${RESET}"; done
  echo -e "${DIM}(Ctrl+C to stop watcher)${RESET}\n"

  fswatch -0 -e ".*" -i "\.(${SCAN_EXTENSIONS})$" "${watch_targets[@]}" | \
    while IFS= read -r -d '' changed_file; do
      [ -f "$changed_file" ] && scan_file "$changed_file"
    done
}

# ── Show recent scan log ──────────────────────────────────────────────────────
owasp_log() {
  echo -e "${BCYAN}Recent scan findings:${RESET}"
  tail -50 "$OWASP_LOG" 2>/dev/null | grep -E "CRITICAL|HIGH|MEDIUM|VIRUSTOTAL"
}

# ── OWASP-themed PS1 prompt ───────────────────────────────────────────────────
setup_prompt() {
  export PS1='\[\033[1;31m\][OWASP]\[\033[0m\] \[\033[1;36m\]\w\[\033[0m\] \[\033[1;33m\]$(git branch 2>/dev/null | grep "^*" | sed "s/* //")\[\033[0m\]\[\033[1;31m\] ⚔ \[\033[0m\]'
}

# ── Aliases ───────────────────────────────────────────────────────────────────
setup_aliases() {
  alias oscan='scan_file'
  alias odir='scan_dir'
  alias ogit='scan_git_changes'
  alias owatch='start_watcher'
  alias olog='owasp_log'
  alias ohelp='owasp_help'
  export -f scan_file scan_dir scan_git_changes start_watcher owasp_log owasp_banner
}

# ── Help ──────────────────────────────────────────────────────────────────────
owasp_help() {
  echo -e "${BCYAN}OWASP Terminal Commands:${RESET}"
  echo -e "  ${WHITE}oscan <file>${RESET}     — Scan a single file for OWASP Top 10 issues"
  echo -e "  ${WHITE}odir  <path>${RESET}     — Scan all code files in a directory"
  echo -e "  ${WHITE}ogit  [repo]${RESET}     — Scan only git-changed files"
  echo -e "  ${WHITE}owatch${RESET}           — Start live file system watcher"
  echo -e "  ${WHITE}olog${RESET}             — Show recent findings from log"
  echo -e ""
  echo -e "  ${DIM}Reports saved to: $OWASP_REPORT_DIR${RESET}"
  echo -e "  ${DIM}Log file:         $OWASP_LOG${RESET}"
  echo -e "  ${DIM}Set VIRUSTOTAL_API_KEY for online hash checks${RESET}"
  echo -e "  ${DIM}Set OWASP_BLOCK=true to auto-quarantine critical files${RESET}"
}

# ── Entry point ───────────────────────────────────────────────────────────────
main() {
  owasp_banner
  setup_prompt
  setup_aliases

  echo -e "${BGREEN}OWASP Terminal ready.${RESET} Type ${WHITE}ohelp${RESET} for commands.\n"

  # if an argument is passed, treat it as a direct scan target
  if [ -n "$1" ]; then
    if [ -d "$1" ]; then
      scan_dir "$1"
    elif [ -f "$1" ]; then
      scan_file "$1"
    fi
  fi

  log "STARTUP" "OWASP Terminal session started"
}

main "$@"
