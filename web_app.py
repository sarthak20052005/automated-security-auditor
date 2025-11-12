# web_app.py
"""
Improved Web UI for Automated Security Auditor
- Dark theme (Bootstrap 5)
- Modern layout with spinner overlay, confirmation modal, toasts
- Better input validation and UX for running scans
"""

import os
import json
import datetime
from pathlib import Path
from flask import Flask, request, redirect, url_for, send_file, render_template_string, abort

from modules.core_scanner import get_target_info, get_hostname, parse_robots_txt, gather_extras
from modules.header_analyzer import analyze_headers, analyze_cookies
from modules.ssl_scanner import scan_ssl
from modules.vuln_scanner import check_basic_xss, check_clickjacking, check_cors
from modules.reporting import generate_html_report

# Setup
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__)


# ----------- HTML Templates -----------

INDEX_HTML = """
<!doctype html>
<html data-bs-theme="dark" lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Automated Security Auditor</title>

  <!-- Bootstrap 5 CSS -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="" crossorigin="anonymous">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css" rel="stylesheet">

  <style>
    :root {
      --bg-dark: #0f1720;
      --card-bg: #0b1220;
      --muted: #9aa4b2;
    }
    body { background: linear-gradient(180deg,#06070a 0%, var(--bg-dark) 100%); color: #e6eef6; min-height:100vh; }
    .container { max-width: 960px; padding-top: 28px; padding-bottom: 48px; }
    .card { background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01)); border: 1px solid rgba(255,255,255,0.03); }
    .spinner-overlay { display: none; position: fixed; inset: 0; background: rgba(2,6,23,0.85); z-index: 1080; align-items:center; justify-content:center; gap:1rem; flex-direction:column; color:#fff; }
    /* Table layout improvements: fixed layout for predictable truncation and responsive wrapping on narrow screens */
    .report-table { table-layout: fixed; width: 100%; }
    .report-table td, .report-table th { color: #dfe8f2; vertical-align: middle; }
    /* report-name provides a single-line ellipsis on wide screens, and falls back to multi-line wrap on small devices */
    .report-name {
      display: inline-block;
      max-width: 100%;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      vertical-align: middle;
    }
    @media (max-width: 575px) {
      .report-name {
        white-space: normal;
        word-break: break-word;
      }
    }
    footer { margin-top: 2.5rem; text-align:center; font-size:0.9em; color:var(--muted); }
    .small-muted { color: var(--muted); font-size:0.9rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-transparent">
  <div class="container">
    <a class="navbar-brand d-flex align-items-center" href="/">
      <i class="bi bi-shield-lock-fill fs-4 me-2"></i>
      <div>
        <div style="line-height:1;">Automated Security Auditor</div>
        <div class="small-muted">Passive web app security scanner</div>
      </div>
    </a>
    <div class="ms-auto">
      <button class="btn btn-outline-light btn-sm" id="refreshReports" title="Refresh reports"><i class="bi bi-arrow-clockwise"></i> Refresh</button>
    </div>
  </div>
</nav>

<div class="container">
  <div class="row g-4">
    <div class="col-12">
      <div class="card p-3 shadow-sm">
        <div class="d-flex align-items-center justify-content-between mb-2">
          <h3 class="m-0">Run a Scan</h3>
        </div>

        <form id="scanForm" method="post" action="/scan" class="row g-2" novalidate>
          <div class="col-md-9">
            <label class="form-label visually-hidden" for="urlInput">Target URL</label>
            <input id="urlInput" name="url" type="url" class="form-control form-control-lg" placeholder="https://example.com" required
                   pattern="https?://.+"
                   title="Enter a full URL starting with http:// or https://">
            <div class="invalid-feedback">Please enter a valid URL (must start with http:// or https://).</div>
          </div>

          <div class="col-md-3 d-grid">
            <button id="scanButton" class="btn btn-primary btn-lg" type="submit" aria-live="polite">
              <i class="bi bi-play-fill me-2"></i> Start Scan
            </button>
          </div>

          <div class="col-12">
            <div class="form-check form-switch">
              <input class="form-check-input" type="checkbox" id="skipExtras" name="skip_extras">
              <label class="form-check-label" for="skipExtras">Skip WHOIS / DNS / Port extras</label>
            </div>
          </div>

          <div class="col-12">
            <div class="small-muted">By scanning you confirm you have permission to test this target.</div>
          </div>
        </form>
      </div>
    </div>

    <div class="col-12">
      <div class="card p-3 shadow-sm">
        <div class="d-flex justify-content-between align-items-center mb-2">
          <h4 class="m-0">Recent Reports</h4>
          <div class="small-muted">Click View to open a report</div>
        </div>

        <div class="table-responsive">
          <table class="table table-dark table-hover report-table mb-0">
            <thead>
              <tr><th style="width:56%;">Report</th><th style="width:24%;">Date</th><th style="width:20%;"></th></tr>
            </thead>
            <tbody id="reportsBody">
              {% for item in reports %}
                <tr>
                  <td title="{{ item.name }}"><span class="report-name">{{ item.name }}</span></td>
                  <td class="small-muted" style="width:24%;">{{ item.date }}</td>
                  <td class="text-end" style="width:20%;">
                    <a href="{{ item.html_path }}" class="btn btn-sm btn-outline-info me-1" role="button"><i class="bi bi-eye"></i> View</a>
                    {% if item.json_path %}
                      <a href="{{ item.json_path }}" download="{{ item.json_name }}" class="btn btn-sm btn-outline-secondary">
                        <i class="bi bi-file-earmark-arrow-down"></i> Download JSON
                      </a>
                    {% else %}
                      <button class="btn btn-sm btn-outline-secondary" disabled title="JSON not available">
                        <i class="bi bi-file-earmark-arrow-down"></i> JSON
                      </button>
                    {% endif %}
                  </td>
                </tr>
              {% else %}
                <tr><td colspan="3" class="text-center small-muted py-4"><em>No reports yet</em></td></tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>

  </div>

  <footer>
    © 2025 Automated Security Auditor — Built for safe, passive checks only.
  </footer>
</div>

<!-- Spinner overlay -->
<div class="spinner-overlay" id="spinner" role="status" aria-hidden="true" aria-live="polite">
  <div class="text-center">
    <div class="spinner-border text-light" role="status" style="width:4rem;height:4rem;"></div>
    <div class="mt-2"><strong id="spinnerText">Running scan...</strong></div>
    <div class="small-muted mt-1">This may take up to 30 seconds. The page will redirect to the report when finished.</div>
  </div>
</div>

<!-- Confirmation modal -->
<div class="modal fade" id="confirmScanModal" tabindex="-1" aria-labelledby="confirmScanLabel" aria-hidden="true">
  <div class="modal-dialog modal-dialog-centered">
    <div class="modal-content bg-dark text-light">
      <div class="modal-header">
        <h5 class="modal-title" id="confirmScanLabel">Confirm Scan</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        You are about to run a passive scan. Ensure you have permission to test this target. Continue?
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary btn-sm" data-bs-dismiss="modal">Cancel</button>
        <button id="confirmScanBtn" type="button" class="btn btn-primary btn-sm">Yes, start scan</button>
      </div>
    </div>
  </div>
</div>

<!-- Toast container -->
<div class="position-fixed bottom-0 end-0 p-3" style="z-index: 1100;">
  <div id="liveToast" class="toast align-items-center text-bg-dark border-0" role="alert" aria-live="assertive" aria-atomic="true">
    <div class="d-flex">
      <div class="toast-body" id="toastBody">Scanning started</div>
      <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
    </div>
  </div>
</div>

<!-- Bootstrap JS (bundle includes Popper) -->
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" integrity="" crossorigin="anonymous"></script>

<script>
(function(){
  const form = document.getElementById('scanForm');
  const urlInput = document.getElementById('urlInput');
  const scanButton = document.getElementById('scanButton');
  const spinner = document.getElementById('spinner');
  const spinnerText = document.getElementById('spinnerText');
  const confirmModal = new bootstrap.Modal(document.getElementById('confirmScanModal'), {backdrop:'static'});
  const confirmBtn = document.getElementById('confirmScanBtn');
  const toastEl = document.getElementById('liveToast');
  const toast = new bootstrap.Toast(toastEl);

  // Simple URL validation helper
  function isValidURL(value) {
    try {
      const u = new URL(value);
      return u.protocol === 'http:' || u.protocol === 'https:';
    } catch (e) {
      return false;
    }
  }

  // Intercept submit to show confirmation modal first
  form.addEventListener('submit', function(evt){
    if (!isValidURL(urlInput.value)) {
      urlInput.classList.add('is-invalid');
      evt.preventDefault();
      evt.stopPropagation();
      return;
    }
    evt.preventDefault();
    confirmModal.show();
  });

  confirmBtn.addEventListener('click', function(){
    confirmModal.hide();
    // show spinner and submit
    spinner.style.display = 'flex';
    scanButton.setAttribute('disabled', 'disabled');
    scanButton.innerHTML = '<i class="bi bi-hourglass-split me-2"></i>Scanning...';
    toastBodyText('Scan queued — running now');
    toast.show();

    // submit the form normally (will navigate on redirect)
    form.submit();
  });

  // quick refresh button
  document.getElementById('refreshReports').addEventListener('click', function(){
    location.reload();
  });

  function toastBodyText(msg){
    document.getElementById('toastBody').textContent = msg;
  }

  // hide spinner automatically after some time (in case of unexpected failure)
  window.addEventListener('beforeunload', function(){ spinner.style.display = 'none'; });

})();
</script>
</body>
</html>
"""


# ----------- Helper Functions -----------

def _timestamp():
    return datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def _safe_basename(hostname: str):
    return hostname.replace(":", "_").replace("/", "_") + "_" + _timestamp()

def _list_reports():
    """
    Return recent reports with both HTML view path and JSON download path (if present).
    """
    files = sorted(REPORTS_DIR.glob("report_*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    data = []
    for f in files:
        dt = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        json_candidate = f.with_suffix('.json')
        html_path = "/reports/" + f.name
        json_path = "/reports/" + json_candidate.name if json_candidate.exists() else ""
        data.append({
            "name": f.name,
            "date": dt,
            "html_path": html_path,
            "json_path": json_path,
            "json_name": json_candidate.name if json_candidate.exists() else ""
        })
    return data


# ----------- Routes -----------

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML, reports=_list_reports())


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "").strip()
    skip_extras = bool(request.form.get("skip_extras"))

    if not url.startswith(("http://", "https://")):
        return "Invalid URL (must start with http/https)", 400

    host = get_hostname(url)
    base = _safe_basename(host or "target")
    html_file = REPORTS_DIR / f"report_{base}.html"
    json_file = REPORTS_DIR / f"report_{base}.json"

    result = {
        'meta': {'started': _timestamp()},
        'general': {},
        'headers': {},
        'cookies': {},
        'ssl': {},
        'vulnerabilities': {},
        'extras': {}
    }

    core = get_target_info(url)
    result['general'] = {
        'url': url,
        'server': core.get('server_tech', 'Unknown'),
        'robots_txt': core.get('robots_txt'),
        'sitemap_xml': core.get('sitemap_xml'),
        'disallowed_paths': parse_robots_txt(core.get('robots_txt'))
    }
    result['headers'] = analyze_headers(core.get('headers') or {})
    result['cookies'] = analyze_cookies(core.get('cookies') or [])
    result['ssl'] = scan_ssl(host)
    result['vulnerabilities'] = {
        'xss': check_basic_xss(url),
        'clickjacking': check_clickjacking(url, core.get('headers') or {}),
        'cors': check_cors(core.get('headers') or {})
    }

    if not skip_extras:
        try:
            result['extras'] = gather_extras(host)
        except Exception as e:
            result['extras'] = {'error': str(e)}
    else:
        result['extras'] = {'skipped': True}

    result['meta']['finished'] = _timestamp()

    # Compute an overall grade for web UI runs if not already present
    try:
        header_score = result['headers'].get('score', 0) if result.get('headers') else 0
        cookie_score = result['cookies'].get('score', 100) if result.get('cookies') else 100
        ssl = result.get('ssl', {}) or {}
        tls_good = bool(ssl.get('supports_tls_1_2') or ssl.get('supports_tls_1_3'))
        tls_component = 100 if tls_good else 0

        penalty = 0
        vuln = result.get('vulnerabilities', {}) or {}
        if vuln.get('xss', {}).get('vulnerable') or vuln.get('reflected_xss', {}).get('vulnerable'):
            penalty += 30
        if vuln.get('clickjacking', {}).get('vulnerable'):
            penalty += 20
        if vuln.get('cors', {}).get('issue'):
            penalty += 8

        csp_weak = result.get('headers', {}).get('csp_weaknesses') or []
        penalty += 4 * len(csp_weak)

        insecure = result.get('cookies', {}).get('insecure_cookies') or []
        penalty += min(15, len(insecure) * 3)

        total = int((header_score * 0.4) + (cookie_score * 0.2) + (tls_component * 0.4) - penalty)
        total = max(0, min(100, total))

        if header_score >= 80 and penalty <= 10:
            total = min(100, total + 8)

        if total >= 90:
            letter = "A+"
        elif total >= 80:
            letter = "A"
        elif total >= 70:
            letter = "B"
        elif total >= 60:
            letter = "C"
        elif total >= 40:
            letter = "D"
        else:
            letter = "F"
        result['meta']['overall_grade'] = {'numeric': total, 'letter': letter}
    except Exception:
        pass

    with open(json_file, "w", encoding="utf-8") as jf:
        json.dump(result, jf, indent=2)

    generate_html_report(result, str(html_file))
    return redirect("/reports/" + html_file.name)


@app.route("/reports/<path:filename>")
def serve_report(filename):
    file_path = REPORTS_DIR / filename
    if not file_path.exists():
        abort(404)
    return send_file(str(file_path))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
