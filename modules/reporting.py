from jinja2 import Environment, FileSystemLoader, select_autoescape
import os, datetime

def _format_subject(subject):
    if not subject: return ""
    if isinstance(subject, str): return subject
    if isinstance(subject, dict): return ", ".join(f"{k}={v}" for k, v in subject.items())
    if isinstance(subject, (list, tuple)):
        return ", ".join(_format_subject(x) for x in subject if x)
    return str(subject)

def _normalize_header_value(v):
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in v)
    if isinstance(v, dict):
        return _format_subject(v)
    return str(v)

def _normalize_cookie_item(c):
    # Best-effort normalization for different cookie representations
    name = ""
    value = ""
    secure = False
    httponly = False
    samesite = ""
    try:
        if isinstance(c, dict):
            name = c.get('name') or c.get('Name') or c.get('key') or c.get('cookie')
            value = c.get('value') or c.get('Value') or c.get('val') or ""
            secure = bool(c.get('secure') or c.get('Secure'))
            httponly = bool(c.get('httponly') or c.get('HttpOnly') or c.get('httpOnly'))
            samesite = c.get('samesite') or c.get('SameSite') or ""
        else:
            # cookiejar or similar
            name = getattr(c, 'name', '') or getattr(c, 'key', '')
            value = getattr(c, 'value', '') or getattr(c, 'val', '')
            secure = bool(getattr(c, 'secure', False))
            # some cookie objects expose rest/_rest
            rest = getattr(c, 'rest', None) or getattr(c, '_rest', None) or {}
            if isinstance(rest, dict):
                httponly = bool(rest.get('httponly') or rest.get('HttpOnly'))
                samesite = rest.get('SameSite') or rest.get('samesite') or samesite
    except Exception:
        pass
    return {
        'name': name or '',
        'value': value or '',
        'secure': bool(secure),
        'httponly': bool(httponly),
        'samesite': samesite or ''
    }

def _compute_fallback_grade(scan_results):
    """
    Forgiving fallback grade:
    - headers weight 40%, cookies 20%, TLS 40% (TLS = 100 if modern TLS exists)
    - minor penalties for CSP weak items and non-critical cookie issues
    """
    header_score = scan_results.get('headers', {}).get('score', 0) or 0
    cookie_score = scan_results.get('cookies', {}).get('score', 100) or 100
    ssl = scan_results.get('ssl', {}) or {}
    tls_good = bool(ssl.get('supports_tls_1_2') or ssl.get('supports_tls_1_3'))
    tls_component = 100 if tls_good else 0

    penalty = 0
    vuln = scan_results.get('vulnerabilities', {}) or {}

    # Critical issues
    if vuln.get('reflected_xss', {}).get('vulnerable') or vuln.get('xss', {}).get('vulnerable'):
        penalty += 30
    if vuln.get('clickjacking', {}).get('vulnerable'):
        penalty += 20
    if vuln.get('cors', {}).get('issue'):
        penalty += 8

    # CSP weaknesses: small penalty per finding (unsafe-inline -> minor)
    csp_weak = scan_results.get('headers', {}).get('csp_weaknesses') or []
    penalty += 4 * len(csp_weak)

    # Cookie issues: light penalty per insecure cookie, capped
    insecure = scan_results.get('cookies', {}).get('insecure_cookies') or []
    penalty += min(15, len(insecure) * 3)

    total = int((header_score * 0.4) + (cookie_score * 0.2) + (tls_component * 0.4) - penalty)
    total = max(0, min(100, total))

    # small bonus if headers are strong and minimal penalties
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

    return {"numeric": total, "letter": letter}

def generate_html_report(scan_results, output_filename):
    template_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape(['html','xml']))
    template = env.get_template('report.html')

    ssl = scan_results.get('ssl', {})
    cert = ssl.get('certificate_details', {}) or {}
    cert_display = {
        'subject': _format_subject(cert.get('subject')),
        'issuer': _format_subject(cert.get('issuer')),
        'not_valid_after': cert.get('not_valid_after', ''),
        'is_expired': cert.get('is_expired', False)
    }

    # Format generated timestamp to a human-friendly form
    gen_raw = scan_results.get('meta', {}).get('finished_at') or scan_results.get('meta', {}).get('started_at') or (datetime.datetime.utcnow().isoformat() + "Z")
    gen_formatted = gen_raw
    try:
        # Accept ISO-like strings ending with Z
        iso = gen_raw
        if isinstance(iso, str) and iso.endswith("Z"):
            iso = iso[:-1] + "+00:00"
        dt = datetime.datetime.fromisoformat(iso)
        gen_formatted = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        # fallback: try parsing common formats
        try:
            dt = datetime.datetime.strptime(gen_raw, "%Y-%m-%dT%H:%M:%S.%fZ")
            gen_formatted = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            # leave raw string if parsing fails
            gen_formatted = gen_raw

    # Ensure a grade is present so the template shows something useful
    grade = scan_results.get('meta', {}).get('overall_grade')
    if not grade:
        grade = _compute_fallback_grade(scan_results)
        # attach back so callers / saved JSON also get it
        scan_results.setdefault('meta', {})['overall_grade'] = grade

    # Extras formatting (DNS / Ports / Whois) -> produce human-friendly structure
    extras = scan_results.get('extras') or {}
    dns = extras.get('dns') or {}
    ports = extras.get('ports') or []
    whois = extras.get('whois') or {}

    extras_display = {}
    extras_display['resolved_ip'] = dns.get('resolved_ip')
    extras_display['resolved_ip_error'] = dns.get('resolved_ip_error')

    # Normalize MX records into list of strings (skip empty)
    mx_raw = dns.get('mx') or []
    mx_list = []
    if isinstance(mx_raw, (list, tuple)):
        for m in mx_raw:
            try:
                if isinstance(m, (list, tuple)) and len(m) >= 2:
                    entry = f"{m[0]} {m[1]}"
                else:
                    entry = str(m)
                entry = entry.strip()
                if entry and entry != ".":
                    mx_list.append(entry)
            except Exception:
                continue
    else:
        # single string maybe
        if mx_raw and str(mx_raw).strip() and str(mx_raw).strip() != ".":
            mx_list.append(str(mx_raw).strip())
    extras_display['mx'] = mx_list

    # Normalize ports list and count open ports
    ports_list = []
    open_ports = []
    if isinstance(ports, list):
        for p in ports:
            if isinstance(p, dict):
                portnum = p.get('port') or p.get('port_num') or p.get('number')
                is_open = bool(p.get('open') or p.get('is_open'))
                try:
                    portnum = int(portnum) if portnum is not None else portnum
                except Exception:
                    pass
                ports_list.append({'port': portnum, 'open': is_open})
                if is_open:
                    open_ports.append(portnum)
    else:
        # if ports returned as dict (error), preserve raw
        ports_list = ports
    extras_display['ports'] = ports_list
    extras_display['open_ports_count'] = len([p for p in ports_list if isinstance(p, dict) and p.get('open')])

    # Whois: pick common useful fields for summary
    whois_summary = {}
    whois_error = None
    if isinstance(whois, dict):
        if whois.get('error'):
            whois_error = whois.get('error')
        else:
            for k in ('registrar', 'creation_date', 'expiration_date', 'updated_date', 'name_servers', 'emails', 'org', 'organization'):
                v = whois.get(k) or whois.get(k.capitalize())
                if v:
                    whois_summary[k] = _format_subject(v)
    else:
        # unexpected format, stringify
        whois_error = str(whois)

    extras_display['whois_summary'] = whois_summary
    extras_display['whois_error'] = whois_error

    # Normalize headers to human-friendly pairs (avoid raw JSON brackets showing)
    headers_src = scan_results.get('headers') or {}
    headers_display = []
    if isinstance(headers_src, dict):
        for k, v in headers_src.items():
            headers_display.append((k, _normalize_header_value(v)))
    else:
        # if unexpected type, stringify
        try:
            headers_display = [("headers", _format_subject(headers_src))]
        except Exception:
            headers_display = []

    # Normalize cookies to list of dicts for template and provide count
    cookies_src = scan_results.get('cookies') or []
    cookies_list = []
    try:
        if isinstance(cookies_src, dict) and cookies_src.get('cookies'):
            cookies_items = cookies_src.get('cookies')
        elif isinstance(cookies_src, list):
            cookies_items = cookies_src
        elif isinstance(cookies_src, dict):
            # possibly contains 'insecure_cookies' etc; no raw cookie list
            cookies_items = []
        else:
            cookies_items = []
        for c in cookies_items:
            cookies_list.append(_normalize_cookie_item(c))
    except Exception:
        cookies_list = []

    cookies_count = len(cookies_list)

    enriched = {
        **scan_results,
        'computed': {
            'ssl_cert_display': cert_display,
            'header_score': scan_results.get('headers', {}).get('score', 0),
            'cookie_score': scan_results.get('cookies', {}).get('score', 100),
            'grade': grade,
            # human-friendly header pairs
            'headers_display': headers_display,
            # normalized cookies list for template
            'cookies_raw': cookies_list,
            'cookies_count': cookies_count,
            'extras_display': extras_display
        }
    }

    html = template.render(
        results=enriched,
        generated_at=gen_formatted
    )

    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"[+] Wrote HTML report to {output_filename}")
    except Exception as e:
        print(f"[!] Failed to write report: {e}")
