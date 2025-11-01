# web_app.py
"""
Improved Web UI for Automated Security Auditor
- Dark theme (Bootstrap 5)
- Modern layout with spinner overlay
- Reports table
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
<html data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <title>Automated Security Auditor</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding: 2rem; background-color: #121212; color: #e0e0e0; }
    .container { max-width: 800px; }
    .spinner-overlay {
      display: none; position: fixed; top:0; left:0; width:100%; height:100%;
      background: rgba(0,0,0,0.75); z-index: 9999; justify-content:center; align-items:center;
      color:white; flex-direction:column;
    }
    .spinner-border { width: 3rem; height: 3rem; margin-bottom: 1rem; }
    .report-table td, .report-table th { color: #fff; }
    footer { margin-top: 3rem; text-align:center; font-size:0.9em; color:#888; }
  </style>
</head>
<body>
<div class="spinner-overlay" id="spinner">
  <div class="text-center">
    <div class="spinner-border" role="status"></div>
    <p>Running scan... this may take up to 30 seconds.</p>
  </div>
</div>

<div class="container">
  <h1 class="mb-4">Automated Security Auditor</h1>
  <form method="post" action="/scan" onsubmit="showSpinner()">
    <div class="input-group mb-3">
      <input name="url" type="text" class="form-control" placeholder="https://example.com" required>
      <button class="btn btn-primary" type="submit">Scan</button>
    </div>
    <div class="form-check">
      <input class="form-check-input" type="checkbox" name="skip_extras" id="skipExtras">
      <label class="form-check-label" for="skipExtras">Skip WHOIS/DNS/Port extras</label>
    </div>
  </form>

  <h3 class="mt-5">Recent Reports</h3>
  <table class="table table-dark table-hover report-table mt-3">
    <thead><tr><th>Report</th><th>Date</th><th></th></tr></thead>
    <tbody>
      {% for item in reports %}
        <tr>
          <td>{{ item.name }}</td>
          <td>{{ item.date }}</td>
          <td><a href="{{ item.path }}" class="btn btn-sm btn-outline-info">View</a></td>
        </tr>
      {% else %}
        <tr><td colspan="3" class="text-center"><em>No reports yet</em></td></tr>
      {% endfor %}
    </tbody>
  </table>

  <footer>© 2025 Automated Security Auditor</footer>
</div>

<script>
function showSpinner(){
  document.getElementById('spinner').style.display='flex';
}
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
    files = sorted(REPORTS_DIR.glob("report_*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
    data = []
    for f in files:
        dt = datetime.datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        data.append({"name": f.name, "date": dt, "path": "/reports/" + f.name})
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
        'robots_found': bool(core.get('robots_txt')),
        'sitemap_found': bool(core.get('sitemap_xml')),
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
