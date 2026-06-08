#!/usr/bin/env python3
"""
OWASP Security Control Dashboard — IT Solutions USA
HTTPS localhost dashboard for running scans and viewing results
"""

import os, subprocess, json, glob, threading, time, re, hashlib, urllib.request, urllib.parse
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, Response

app = Flask(__name__)

SCRIPT    = os.path.expanduser("~/owasp_terminal_prompt.sh")
LOG_FILE  = os.path.expanduser("~/.owasp_scan.log")
REPORTS   = os.path.expanduser("~/.owasp_reports")
SSL_CERT  = os.path.expanduser("~/.owasp_ssl/cert.pem")
SSL_KEY   = os.path.expanduser("~/.owasp_ssl/key.pem")

SCAN_TARGETS = {
    "Desktop":   os.path.expanduser("~/Desktop"),
    "Documents": os.path.expanduser("~/Documents"),
    "Downloads": os.path.expanduser("~/Downloads"),
}

# ── HTML template ─────────────────────────────────────────────────────────────
HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP Security Control — IT Solutions USA</title>
<style>
  :root {
    --red: #e53e3e; --orange: #dd6b20; --yellow: #d69e2e;
    --green: #38a169; --cyan: #00b5d8; --purple: #805ad5;
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; font-size: 14px; }

  header {
    background: linear-gradient(135deg, #1a0000 0%, #0d1117 60%);
    border-bottom: 2px solid var(--red);
    padding: 16px 32px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-icon { font-size: 28px; }
  .brand-title { font-size: 20px; font-weight: bold; color: var(--red); letter-spacing: 2px; }
  .brand-sub { font-size: 11px; color: var(--muted); }
  .status-dot { width: 10px; height: 10px; border-radius: 50%; background: var(--green); display: inline-block; margin-right: 6px; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

  .layout { display: grid; grid-template-columns: 280px 1fr; min-height: calc(100vh - 65px); }

  .sidebar {
    background: var(--surface); border-right: 1px solid var(--border);
    padding: 24px 16px; display: flex; flex-direction: column; gap: 8px;
  }
  .sidebar h3 { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }

  .btn {
    width: 100%; padding: 10px 14px; border: 1px solid var(--border);
    background: var(--bg); color: var(--text); border-radius: 6px;
    cursor: pointer; font-family: inherit; font-size: 13px;
    text-align: left; display: flex; align-items: center; gap: 8px;
    transition: all .15s;
  }
  .btn:hover { background: #21262d; border-color: var(--cyan); color: var(--cyan); }
  .btn.danger:hover { border-color: var(--red); color: var(--red); }
  .btn.running { border-color: var(--yellow); color: var(--yellow); animation: pulse 1s infinite; }

  .main { padding: 24px 32px; overflow-y: auto; }

  .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 16px; text-align: center;
  }
  .stat-card .num { font-size: 32px; font-weight: bold; }
  .stat-card .lbl { font-size: 11px; color: var(--muted); text-transform: uppercase; margin-top: 4px; }
  .critical .num { color: var(--red); }
  .high .num     { color: var(--orange); }
  .medium .num   { color: var(--yellow); }
  .clean .num    { color: var(--green); }

  .section { margin-bottom: 28px; }
  .section-title {
    font-size: 13px; font-weight: bold; color: var(--muted);
    text-transform: uppercase; letter-spacing: 1px;
    border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 16px;
  }

  .terminal {
    background: #0a0a0a; border: 1px solid var(--border); border-radius: 8px;
    padding: 16px; font-size: 13px; line-height: 1.6;
    max-height: 400px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;
  }
  .terminal .CRITICAL { color: var(--red); font-weight: bold; }
  .terminal .HIGH     { color: var(--orange); }
  .terminal .MEDIUM   { color: var(--yellow); }
  .terminal .FINDING  { color: var(--cyan); }
  .terminal .STARTUP  { color: var(--muted); }
  .terminal .SUMMARY  { color: var(--purple); }

  .reports-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
  .report-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px; cursor: pointer;
    transition: border-color .15s;
  }
  .report-card:hover { border-color: var(--cyan); }
  .report-card .rname { font-size: 12px; color: var(--cyan); word-break: break-all; }
  .report-card .rmeta { font-size: 11px; color: var(--muted); margin-top: 4px; }
  .report-card .rbadge {
    display: inline-block; padding: 2px 6px; border-radius: 3px;
    font-size: 10px; font-weight: bold; margin-top: 6px;
  }
  .badge-critical { background: #3d0000; color: var(--red); border: 1px solid var(--red); }
  .badge-clean    { background: #0d2400; color: var(--green); border: 1px solid var(--green); }
  .badge-issue    { background: #2d1a00; color: var(--orange); border: 1px solid var(--orange); }

  .modal-overlay {
    display: none; position: fixed; inset: 0;
    background: rgba(0,0,0,.8); z-index: 100; align-items: center; justify-content: center;
  }
  .modal-overlay.open { display: flex; }
  .modal {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 24px; max-width: 800px; width: 90%; max-height: 80vh;
    overflow-y: auto;
  }
  .modal-title { font-size: 15px; color: var(--cyan); margin-bottom: 16px; }
  .modal-close { float: right; cursor: pointer; color: var(--muted); font-size: 18px; }
  .modal pre { background: #0a0a0a; padding: 12px; border-radius: 6px; font-size: 12px; white-space: pre-wrap; }

  .scan-progress { display: none; color: var(--yellow); padding: 8px 0; font-size: 13px; }
  .scan-progress.active { display: block; }
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-icon">⚔</div>
    <div>
      <div class="brand-title">OWASP SECURITY CONTROL</div>
      <div class="brand-sub">IT Solutions USA — Laptop File & Code Scanner</div>
    </div>
  </div>
  <div><span class="status-dot"></span><span style="color:var(--green);font-size:12px">HTTPS ACTIVE — localhost:8443</span></div>
</header>

<div class="layout">
  <div class="sidebar">
    <h3>Scan Targets</h3>
    <button class="btn" onclick="runScan('Desktop')">📁 Desktop</button>
    <button class="btn" onclick="runScan('Documents')">📄 Documents</button>
    <button class="btn" onclick="runScan('Downloads')">⬇ Downloads</button>
    <button class="btn" onclick="runScan('ALL')">🔍 Scan All Three</button>

    <h3 style="margin-top:16px">Custom Scan</h3>
    <input id="custom-path" type="text" placeholder="/path/to/scan"
      style="width:100%;padding:8px;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:6px;font-family:inherit;font-size:12px">
    <button class="btn" onclick="runCustomScan()" style="margin-top:4px">▶ Run Custom Scan</button>

    <h3 style="margin-top:16px">Tools</h3>
    <button class="btn" onclick="refreshLog()">↻ Refresh Log</button>
    <button class="btn" onclick="refreshReports()">↻ Refresh Reports</button>
    <button class="btn danger" onclick="clearLog()">🗑 Clear Log</button>
  </div>

  <div class="main">
    <div class="stats">
      <div class="stat-card critical"><div class="num" id="cnt-critical">–</div><div class="lbl">Critical</div></div>
      <div class="stat-card high">   <div class="num" id="cnt-high">–</div>    <div class="lbl">High</div></div>
      <div class="stat-card medium"> <div class="num" id="cnt-medium">–</div>  <div class="lbl">Medium</div></div>
      <div class="stat-card clean">  <div class="num" id="cnt-files">–</div>   <div class="lbl">Files Scanned</div></div>
    </div>

    <div class="section">
      <div class="section-title">Scan Output</div>
      <div class="scan-progress" id="scan-progress">⟳ Scan running…</div>
      <div class="terminal" id="terminal">Ready. Select a target to begin scanning.</div>
    </div>

    <div class="section">
      <div class="section-title">Live Log</div>
      <div class="terminal" id="log-view">Loading…</div>
    </div>

    <div class="section">
      <div class="section-title">Online Signature Check</div>
      <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">
        <input id="hash-input" type="text" placeholder="SHA256 hash or paste file path"
          style="flex:1;min-width:260px;padding:8px;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:6px;font-family:inherit;font-size:12px">
        <button class="btn" style="width:auto;padding:8px 18px" onclick="checkHash()">🔍 Check All Databases</button>
      </div>
      <div id="online-results" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px"></div>
    </div>

    <div class="section">
      <div class="section-title">Reports</div>
      <div class="reports-grid" id="reports-grid">Loading…</div>
    </div>
  </div>
</div>

<!-- Modal for report content -->
<div class="modal-overlay" id="modal">
  <div class="modal">
    <span class="modal-close" onclick="closeModal()">✕</span>
    <div class="modal-title" id="modal-title"></div>
    <pre id="modal-body"></pre>
  </div>
</div>

<script>
const SEVERITY_ORDER = ['CRITICAL','HIGH','MEDIUM','FINDING','SUMMARY','STARTUP'];

function colorize(text) {
  return text
    .replace(/CRITICAL/g, '<span class="CRITICAL">CRITICAL</span>')
    .replace(/\bHIGH\b/g,  '<span class="HIGH">HIGH</span>')
    .replace(/\bMEDIUM\b/g,'<span class="MEDIUM">MEDIUM</span>')
    .replace(/\[FINDING\]/g,'<span class="FINDING">[FINDING]</span>')
    .replace(/\[SUMMARY\]/g,'<span class="SUMMARY">[SUMMARY]</span>')
    .replace(/\[STARTUP\]/g,'<span class="STARTUP">[STARTUP]</span>');
}

async function runScan(target) {
  const btn = event.target;
  btn.classList.add('running');
  document.getElementById('scan-progress').classList.add('active');
  document.getElementById('terminal').innerHTML = '⟳ Scanning ' + target + '…';
  try {
    const r = await fetch('/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target})});
    const d = await r.json();
    document.getElementById('terminal').innerHTML = colorize(d.output || 'No output.');
    updateStats(d.stats);
    refreshReports();
    refreshLog();
  } catch(e) {
    document.getElementById('terminal').textContent = 'Error: ' + e;
  }
  btn.classList.remove('running');
  document.getElementById('scan-progress').classList.remove('active');
}

async function runCustomScan() {
  const path = document.getElementById('custom-path').value.trim();
  if (!path) return;
  document.getElementById('scan-progress').classList.add('active');
  document.getElementById('terminal').innerHTML = '⟳ Scanning ' + path + '…';
  try {
    const r = await fetch('/scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target:'CUSTOM', path})});
    const d = await r.json();
    document.getElementById('terminal').innerHTML = colorize(d.output || 'No output.');
    updateStats(d.stats);
    refreshReports();
    refreshLog();
  } catch(e) {
    document.getElementById('terminal').textContent = 'Error: ' + e;
  }
  document.getElementById('scan-progress').classList.remove('active');
}

function updateStats(s) {
  if (!s) return;
  document.getElementById('cnt-critical').textContent = s.critical || 0;
  document.getElementById('cnt-high').textContent     = s.high || 0;
  document.getElementById('cnt-medium').textContent   = s.medium || 0;
  document.getElementById('cnt-files').textContent    = s.files || 0;
}

async function refreshLog() {
  const r = await fetch('/log');
  const d = await r.json();
  document.getElementById('log-view').innerHTML = colorize(d.log || '(empty)');
  document.getElementById('log-view').scrollTop = 999999;
}

async function refreshReports() {
  const r = await fetch('/reports');
  const d = await r.json();
  const grid = document.getElementById('reports-grid');
  if (!d.reports || !d.reports.length) { grid.innerHTML = '<span style="color:var(--muted)">No reports yet.</span>'; return; }
  grid.innerHTML = d.reports.map(rp => {
    let badge = '<span class="rbadge badge-clean">CLEAN</span>';
    if (rp.result.includes('CRITICAL')) badge = '<span class="rbadge badge-critical">CRITICAL</span>';
    else if (rp.result.includes('ISSUE')) badge = '<span class="rbadge badge-issue">ISSUES FOUND</span>';
    return `<div class="report-card" onclick="showReport('${rp.file}')">
      <div class="rname">${rp.name}</div>
      <div class="rmeta">${rp.date}</div>
      ${badge}
    </div>`;
  }).join('');
}

async function showReport(file) {
  const r = await fetch('/report?file=' + encodeURIComponent(file));
  const d = await r.json();
  document.getElementById('modal-title').textContent = d.name;
  document.getElementById('modal-body').textContent  = d.content;
  document.getElementById('modal').classList.add('open');
}

function closeModal() { document.getElementById('modal').classList.remove('open'); }

async function clearLog() {
  await fetch('/clear-log', {method:'POST'});
  refreshLog();
}

async function checkHash() {
  const val = document.getElementById('hash-input').value.trim();
  if (!val) return;
  const box = document.getElementById('online-results');
  box.innerHTML = '<span style="color:var(--muted)">⟳ Querying databases…</span>';
  const r = await fetch('/check-hash', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({value: val})
  });
  const d = await r.json();
  box.innerHTML = d.results.map(res => {
    const color = res.status === 'MALICIOUS' ? 'var(--red)' :
                  res.status === 'CLEAN'     ? 'var(--green)' :
                  res.status === 'WARNING'   ? 'var(--yellow)' : 'var(--muted)';
    const icon  = res.status === 'MALICIOUS' ? '⛔' :
                  res.status === 'CLEAN'     ? '✓'  :
                  res.status === 'WARNING'   ? '⚠'  : '–';
    return `<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:14px">
      <div style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">${res.source}</div>
      <div style="font-size:20px;color:${color};font-weight:bold">${icon} ${res.status}</div>
      <div style="font-size:11px;color:var(--muted);margin-top:4px">${res.detail}</div>
    </div>`;
  }).join('');
}

// auto-refresh log every 10s
refreshLog();
refreshReports();
fetch('/stats').then(r=>r.json()).then(updateStats);
setInterval(() => { refreshLog(); refreshReports(); fetch('/stats').then(r=>r.json()).then(updateStats); }, 10000);
</script>
</body>
</html>
"""

# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/scan", methods=["POST"])
def scan():
    data    = request.json or {}
    target  = data.get("target", "")
    custom  = data.get("path", "")

    paths = []
    if target == "ALL":
        paths = list(SCAN_TARGETS.values())
    elif target in SCAN_TARGETS:
        paths = [SCAN_TARGETS[target]]
    elif target == "CUSTOM" and custom:
        paths = [os.path.expanduser(custom)]

    if not paths:
        return jsonify({"output": "No valid target.", "stats": {}})

    all_output = []
    stats = {"critical": 0, "high": 0, "medium": 0, "files": 0}

    for path in paths:
        if not os.path.exists(path):
            all_output.append(f"Path not found: {path}")
            continue
        cmd = f'source "{SCRIPT}" && scan_dir "{path}"'
        result = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True, text=True, timeout=120
        )
        raw = result.stdout + result.stderr
        # strip ANSI
        import re
        clean = re.sub(r'\x1b\[[0-9;]*m', '', raw)
        all_output.append(clean)

    # parse log for stats
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            lines = f.readlines()
        for line in lines:
            if "CRITICAL" in line and "FINDING" in line: stats["critical"] += 1
            elif "HIGH" in line and "FINDING" in line:   stats["high"] += 1
            elif "MEDIUM" in line and "FINDING" in line: stats["medium"] += 1
        stats["files"] = sum(1 for l in lines if "SUMMARY" in l)

    return jsonify({"output": "\n".join(all_output), "stats": stats})


@app.route("/log")
def get_log():
    if not os.path.exists(LOG_FILE):
        return jsonify({"log": "(no log yet)"})
    with open(LOG_FILE) as f:
        lines = f.readlines()
    return jsonify({"log": "".join(lines[-100:])})


@app.route("/reports")
def get_reports():
    files = sorted(glob.glob(os.path.join(REPORTS, "*.txt")), key=os.path.getmtime, reverse=True)
    reports = []
    for fp in files[:30]:
        result = "CLEAN"
        try:
            with open(fp) as f:
                content = f.read()
            for line in content.splitlines():
                if line.startswith("RESULT:"):
                    result = line.replace("RESULT:", "").strip()
                    break
        except Exception:
            pass
        reports.append({
            "file": fp,
            "name": os.path.basename(fp),
            "date": datetime.fromtimestamp(os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M"),
            "result": result
        })
    return jsonify({"reports": reports})


@app.route("/report")
def get_report():
    fp = request.args.get("file", "")
    if not fp or not os.path.exists(fp) or not fp.startswith(REPORTS):
        return jsonify({"content": "Not found.", "name": ""})
    with open(fp) as f:
        content = f.read()
    return jsonify({"content": content, "name": os.path.basename(fp)})


@app.route("/stats")
def get_stats():
    stats = {"critical": 0, "high": 0, "medium": 0, "files": 0}
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE) as f:
            lines = f.readlines()
        for line in lines:
            if "CRITICAL" in line and "FINDING" in line: stats["critical"] += 1
            elif "HIGH" in line and "FINDING" in line:   stats["high"] += 1
            elif "MEDIUM" in line and "FINDING" in line: stats["medium"] += 1
        stats["files"] = sum(1 for l in lines if "SUMMARY" in l)
    return jsonify(stats)


@app.route("/clear-log", methods=["POST"])
def clear_log():
    open(LOG_FILE, "w").close()
    return jsonify({"ok": True})


@app.route("/check-hash", methods=["POST"])
def check_hash():
    import urllib.request, urllib.parse, urllib.error
    data  = request.json or {}
    value = data.get("value", "").strip()
    results = []

    # if it's a file path, compute its hash
    sha256 = value
    if os.path.exists(os.path.expanduser(value)):
        fp = os.path.expanduser(value)
        h  = hashlib.sha256()
        with open(fp, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        sha256 = h.hexdigest()

    # 1. CIRCL HASHLOOKUP (free, no key)
    try:
        url  = f"https://hashlookup.circl.lu/lookup/sha256/{sha256}"
        req  = urllib.request.Request(url, headers={"User-Agent": "owasp-scanner/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        d    = json.loads(resp.read())
        if "KnownMalicious" in d:
            results.append({"source": "CIRCL HASHLOOKUP", "status": "MALICIOUS",
                            "detail": d.get("FileName", "Known malicious hash")})
        elif "FileName" in d or "ProductName" in d:
            results.append({"source": "CIRCL HASHLOOKUP", "status": "CLEAN",
                            "detail": d.get("FileName", d.get("ProductName", "Known file"))})
        else:
            results.append({"source": "CIRCL HASHLOOKUP", "status": "UNKNOWN", "detail": "Not in database"})
    except Exception as e:
        results.append({"source": "CIRCL HASHLOOKUP", "status": "UNKNOWN", "detail": str(e)[:60]})

    # 2. MalwareBazaar (free, no key)
    try:
        post_data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        req  = urllib.request.Request("https://mb-api.abuse.ch/api/v1/",
                                      data=post_data,
                                      headers={"User-Agent": "owasp-scanner/1.0"})
        resp = urllib.request.urlopen(req, timeout=8)
        d    = json.loads(resp.read())
        status = d.get("query_status", "")
        if status == "ok":
            tags   = d.get("data", [{}])[0].get("tags", [])
            family = d.get("data", [{}])[0].get("signature", "unknown")
            results.append({"source": "MALWAREBAZAAR", "status": "MALICIOUS",
                            "detail": f"Family: {family} | Tags: {', '.join(tags) if tags else 'none'}"})
        elif status == "hash_not_found":
            results.append({"source": "MALWAREBAZAAR", "status": "CLEAN", "detail": "Not in malware database"})
        else:
            results.append({"source": "MALWAREBAZAAR", "status": "UNKNOWN", "detail": status})
    except Exception as e:
        results.append({"source": "MALWAREBAZAAR", "status": "UNKNOWN", "detail": str(e)[:60]})

    # 3. VirusTotal (requires API key)
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if vt_key:
        try:
            req  = urllib.request.Request(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": vt_key, "User-Agent": "owasp-scanner/1.0"})
            resp = urllib.request.urlopen(req, timeout=8)
            d    = json.loads(resp.read())
            mal  = d["data"]["attributes"]["last_analysis_stats"]["malicious"]
            tot  = sum(d["data"]["attributes"]["last_analysis_stats"].values())
            if mal > 0:
                results.append({"source": "VIRUSTOTAL", "status": "MALICIOUS",
                                "detail": f"{mal}/{tot} engines flagged"})
            else:
                results.append({"source": "VIRUSTOTAL", "status": "CLEAN",
                                "detail": f"0/{tot} engines flagged"})
        except Exception as e:
            results.append({"source": "VIRUSTOTAL", "status": "UNKNOWN", "detail": str(e)[:60]})
    else:
        results.append({"source": "VIRUSTOTAL", "status": "UNKNOWN",
                        "detail": "Set VIRUSTOTAL_API_KEY env var to enable"})

    # 4. NIST NVD CVE lookup by keyword (package name heuristic)
    pkg = re.sub(r'[-_][0-9].*', '', os.path.basename(value))
    pkg = re.sub(r'\..*', '', pkg)
    if len(pkg) > 3:
        try:
            url  = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={urllib.parse.quote(pkg)}&resultsPerPage=5"
            req  = urllib.request.Request(url, headers={"User-Agent": "owasp-scanner/1.0"})
            resp = urllib.request.urlopen(req, timeout=10)
            d    = json.loads(resp.read())
            total = d.get("totalResults", 0)
            ids   = [v["cve"]["id"] for v in d.get("vulnerabilities", [])[:3]]
            if total > 0:
                results.append({"source": "NIST NVD", "status": "WARNING",
                                "detail": f"{total} CVE(s) for '{pkg}': {', '.join(ids)}"})
            else:
                results.append({"source": "NIST NVD", "status": "CLEAN",
                                "detail": f"No CVEs found for '{pkg}'"})
        except Exception as e:
            results.append({"source": "NIST NVD", "status": "UNKNOWN", "detail": str(e)[:60]})
    else:
        results.append({"source": "NIST NVD", "status": "UNKNOWN", "detail": "Name too short to query"})

    return jsonify({"hash": sha256, "results": results})


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════════════╗")
    print("  ║  OWASP Security Control — IT Solutions USA       ║")
    print("  ║  https://localhost:8443                          ║")
    print("  ╚══════════════════════════════════════════════════╝\n")
    app.run(
        host="127.0.0.1",
        port=8443,
        ssl_context=(SSL_CERT, SSL_KEY),
        debug=False
    )
