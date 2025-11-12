# main.py
import argparse
import json
import datetime
from modules.core_scanner import get_target_info, get_hostname, parse_robots_txt, gather_extras
from modules.header_analyzer import analyze_headers, analyze_cookies
from modules.ssl_scanner import scan_ssl
from modules.vuln_scanner import check_basic_xss, check_clickjacking, check_cors
from modules.reporting import generate_html_report

def compute_overall_grade(scan_results):
    header_score = scan_results.get('headers', {}).get('score', 0) or 0
    cookie_score = scan_results.get('cookies', {}).get('score', 100) or 100
    ssl = scan_results.get('ssl', {}) or {}
    tls_good = bool(ssl.get('supports_tls_1_2') or ssl.get('supports_tls_1_3'))
    tls_component = 100 if tls_good else 0

    penalty = 0
    vuln = scan_results.get('vulnerabilities', {}) or {}
    if vuln.get('reflected_xss', {}).get('vulnerable') or vuln.get('xss', {}).get('vulnerable'):
        penalty += 30
    if vuln.get('clickjacking', {}).get('vulnerable'):
        penalty += 20
    if vuln.get('cors', {}).get('issue'):
        penalty += 8

    csp_weak = scan_results.get('headers', {}).get('csp_weaknesses') or []
    penalty += 4 * len(csp_weak)

    insecure = scan_results.get('cookies', {}).get('insecure_cookies') or []
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

    return {'numeric': total, 'letter': letter}

def main():
    parser = argparse.ArgumentParser(description="Automated Security Auditing Tool")
    parser.add_argument("url", help="The target URL to scan (e.g., https://example.com)")
    parser.add_argument("-o", "--output", help="Output HTML file name (default report.html)", default="report.html")
    parser.add_argument("-j", "--json", help="Save JSON output to this file (optional)", default=None)
    parser.add_argument("--skip-extras", action="store_true", help="Skip WHOIS/DNS/Port extras")
    args = parser.parse_args()

    if not args.url.startswith('http'):
        print("Error: URL must start with http:// or https://")
        return

    print(f"[*] Starting scan on {args.url}...")
    scan_results = {
        'meta': {},
        'general': {},
        'headers': {},
        'cookies': {},
        'ssl': {},
        'vulnerabilities': {},
        'extras': {}
    }

    scan_results['meta']['started_at'] = datetime.datetime.utcnow().isoformat() + "Z"

    # 1. Core reconnaissance
    print("[1/6] Performing core reconnaissance...")
    core_info = get_target_info(args.url)
    if core_info.get('error'):
        err = core_info.get('error')
        print(f"[!] Critical error fetching target: {err}")
        # Populate minimal results so HTML report shows the failure
        scan_results['general'] = {
            'url': args.url,
            'server': core_info.get('server_tech', 'Unknown'),
            'robots_txt_found': f"Fatal Error: {err}",
            'robots_disallowed_paths': [],
            'sitemap_xml_found': f"Fatal Error: {err}"
        }

        # keep other sections empty/flagged so the report renders
        scan_results['headers'] = scan_results.get('headers', {})
        scan_results['cookies'] = scan_results.get('cookies', {})
        scan_results['vulnerabilities'] = scan_results.get('vulnerabilities', {})
        scan_results['extras'] = {'error': err}

        # finish meta and force failing grade
        scan_results['meta']['finished_at'] = datetime.datetime.utcnow().isoformat() + "Z"
        scan_results['meta']['overall_grade'] = {'numeric': 0, 'letter': 'F'}

        # generate a partial report showing the error, then exit
        try:
            generate_html_report(scan_results, args.output)
            print(f"[!] Generated partial report to {args.output} due to error")
        except Exception as e:
            print(f"[!] Failed to write partial report: {e}")
        return

    scan_results['general'] = {
        'url': args.url,
        'server': core_info.get('server_tech', 'Unknown'),
        'robots_txt': core_info.get('robots_txt'),
        'robots_disallowed_paths': parse_robots_txt(core_info.get('robots_txt')),
        'sitemap_xml': core_info.get('sitemap_xml')
    }

    # 2. Headers & Cookies
    print("[2/6] Analyzing headers and cookies...")
    scan_results['headers'] = analyze_headers(core_info.get('headers') or {})
    scan_results['cookies'] = analyze_cookies(core_info.get('cookies') or [])

    # 3. SSL/TLS
    print("[3/6] Performing SSL/TLS scan...")
    hostname = get_hostname(args.url)
    if hostname:
        scan_results['ssl'] = scan_ssl(hostname)
    else:
        scan_results['ssl'] = {'error': 'Could not parse hostname from URL.'}

    # 4. Vulnerability checks
    print("[4/6] Running vulnerability checks...")
    scan_results['vulnerabilities']['reflected_xss'] = check_basic_xss(args.url)
    scan_results['vulnerabilities']['clickjacking'] = check_clickjacking(args.url, core_info.get('headers') or {})
    scan_results['vulnerabilities']['cors'] = check_cors(core_info.get('headers') or {})

    # 5. Extras (WHOIS / DNS / Port scan)
    if not args.skip_extras:
        print("[5/6] Gathering extras (WHOIS, DNS, common ports)...")
        try:
            scan_results['extras'] = gather_extras(hostname)
        except Exception as e:
            scan_results['extras'] = {'error': str(e)}
    else:
        scan_results['extras'] = {'skipped': True}

    # 6. Reporting
    print("[6/6] Generating report...")
    scan_results['meta']['finished_at'] = datetime.datetime.utcnow().isoformat() + "Z"
    grade = compute_overall_grade(scan_results)
    scan_results['meta']['overall_grade'] = grade

    generate_html_report(scan_results, args.output)

    if args.json:
        try:
            with open(args.json, 'w', encoding='utf-8') as jf:
                json.dump(scan_results, jf, indent=2)
            print(f"[+] JSON saved to {args.json}")
        except Exception as e:
            print(f"[!] Failed to write JSON: {e}")

    print("[+] Scan complete.")

if __name__ == "__main__":
    main()
