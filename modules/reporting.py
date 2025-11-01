from jinja2 import Environment, FileSystemLoader, select_autoescape
import os, datetime

def _format_subject(subject):
    if not subject: return ""
    if isinstance(subject, str): return subject
    if isinstance(subject, dict): return ", ".join(f"{k}={v}" for k, v in subject.items())
    return str(subject)

def generate_html_report(scan_results, output_filename):
    template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape(['html','xml']))
    template = env.get_template('report.html')

    ssl = scan_results.get('ssl', {})
    cert = ssl.get('certificate_details', {})
    cert_display = {
        'subject': _format_subject(cert.get('subject')),
        'issuer': _format_subject(cert.get('issuer')),
        'not_valid_after': cert.get('not_valid_after', ''),
        'is_expired': cert.get('is_expired', False)
    }

    enriched = {
        **scan_results,
        'computed': {
            'ssl_cert_display': cert_display,
            'header_score': scan_results.get('headers', {}).get('score', 0),
            'cookie_score': scan_results.get('cookies', {}).get('score', 100),
            'grade': scan_results.get('meta', {}).get('overall_grade', {})
        }
    }

    html = template.render(
        results=enriched,
        generated_at=scan_results.get('meta', {}).get('finished_at', datetime.datetime.utcnow().isoformat() + "Z")
    )

    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] Wrote HTML report to {output_filename}")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")
