#!/bin/zsh
export PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin

REPORT=~/clec/security/reports/vuln-assessment-$(date +%Y%m%d).txt
mkdir -p ~/clec/security/reports

{
echo "============================================================"
echo "  VULNERABILITY ASSESSMENT REPORT"
echo "  IT Solutions USA — Mac Mini Local Stack"
echo "  Date: $(date)"
echo "============================================================"
echo ""

echo "=== 1. OPEN PORTS ==="
lsof -iTCP -sTCP:LISTEN -P 2>/dev/null | awk 'NR>1 {print $1, $9}' | sort -u
echo ""

echo "=== 2. HTTP SECURITY HEADERS — HQ Site (8081) ==="
curl -sI http://localhost:8081/ | grep -iE "x-frame|x-content|x-xss|strict-transport|content-security|referrer|permissions|server:|x-powered"
echo ""

echo "=== 3. HTTP SECURITY HEADERS — VCE App (8082) ==="
curl -sI http://localhost:8082/ | grep -iE "x-frame|x-content|x-xss|strict-transport|content-security|referrer|permissions|server:|x-powered"
echo ""

echo "=== 4. SERVER VERSION DISCLOSURE ==="
echo "HQ (8081):"
curl -sI http://localhost:8081/ | grep -iE "^server:|^x-powered-by" || echo "  None disclosed (good)"
echo "VCE (8082):"
curl -sI http://localhost:8082/ | grep -iE "^server:|^x-powered-by" || echo "  None disclosed (good)"
echo "WTS Docs (3000):"
curl -skI https://localhost:3000/ | grep -iE "^server:|^x-powered-by" || echo "  None disclosed (good)"
echo ""

echo "=== 5. DIRECTORY TRAVERSAL / PATH PROBES (via proxy 8081) ==="
for path in "/../etc/passwd" "/.env" "/.git/config" "/wp-login.php" "/wp-admin" "/phpinfo.php" "/../../../etc/shadow" "/.aws/credentials" "/.ssh/id_rsa" "/admin" "/config.php" "/.htaccess"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8081${path}")
  echo "  $code  $path"
done
echo ""

echo "=== 6. HTTP METHODS ALLOWED — HQ (8081) ==="
for method in GET POST PUT DELETE PATCH OPTIONS TRACE HEAD; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" http://localhost:8081/)
  echo "  $method → $code"
done
echo ""

echo "=== 7. TLS — WTS DOCS (3000) ==="
echo | openssl s_client -connect localhost:3000 2>&1 | grep -E "Protocol|Cipher|subject|issuer|Verify|CONNECTED|error" | head -15
echo ""

echo "=== 8. SENSITIVE FILES NEAR WEB ROOTS ==="
find ~/replit-restore/IT-Solutions-USA -maxdepth 3 \( -name ".env" -o -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" \) 2>/dev/null | grep -v node_modules | grep -v ".git" || echo "  None found"
echo ""

echo "=== 9. CORS HEADERS ==="
echo "HQ (8081) — Origin: evil.com:"
curl -sI -H "Origin: https://evil.com" http://localhost:8081/ | grep -i "access-control" || echo "  No CORS headers (good — not an API)"
echo "VCE (8082) — Origin: evil.com:"
curl -sI -H "Origin: https://evil.com" http://localhost:8082/ | grep -i "access-control" || echo "  No CORS headers"
echo ""

echo "=== 10. CLICKJACKING — X-Frame-Options ==="
result=$(curl -sI http://localhost:8081/ | grep -i "x-frame-options")
if [ -n "$result" ]; then
  echo "  HQ: $result"
else
  echo "  HQ: MISSING X-Frame-Options"
fi
result=$(curl -sI http://localhost:8082/ | grep -i "x-frame-options")
if [ -n "$result" ]; then
  echo "  VCE: $result"
else
  echo "  VCE: MISSING X-Frame-Options"
fi
echo ""

echo "=== 11. INFORMATION DISCLOSURE — ERROR PAGES ==="
echo "HQ — bad request:"
curl -sI http://localhost:8081/this-page-does-not-exist-12345 | head -3
echo "VCE — bad request:"
curl -sI http://localhost:8082/this-page-does-not-exist-12345 | head -3
echo ""

echo "=== 12. LAUNCHAGENT FILE PERMISSIONS ==="
ls -la ~/Library/LaunchAgents/*.plist | awk '{print $1, $3, $4, $NF}'
echo ""

echo "=== 13. LOG FILE PERMISSIONS ==="
ls -la ~/replit-restore/IT-Solutions-USA/logs/
echo ""

echo "=== 14. FIREWALL STATUS ==="
sudo pfctl -s rules 2>/dev/null || echo "  PF not enabled (run: sudo pfctl -f ~/clec/firewall/pf-itsusa.conf -e)"
echo ""

echo "=== 15. PROCESS EXPOSURE ==="
echo "Cloudflare tunnel:"
ps aux | grep cloudflared | grep -v grep | awk '{print $11, $12}'
echo "Node processes:"
ps aux | grep node | grep -v grep | awk '{print $11, $12, $13}'
echo ""

echo "=== 16. LARGE OPEN PORTS (potential exposure) ==="
echo "Ports binding to * (all interfaces — visible on network):"
lsof -iTCP -sTCP:LISTEN -P 2>/dev/null | awk 'NR>1 && $9 ~ /^\*:/ {print $1, $9}' | sort -u
echo ""

echo "============================================================"
echo "  END OF REPORT"
echo "============================================================"
} > "$REPORT" 2>&1

echo "$REPORT"
