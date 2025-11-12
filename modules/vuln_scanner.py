# modules/vuln_scanner.py
import requests
from urllib.parse import urlparse, urlencode, parse_qsl
from typing import Optional, Dict, Any
import uuid
from requests import Session
from requests.structures import CaseInsensitiveDict

def check_basic_xss(url: str, timeout: int = 8, session: Optional[Session] = None) -> Dict[str, Any]:
    """
    Non-destructive reflected XSS test: appends a unique test param and checks reflection.
    Uses a short unique marker to avoid heavy payloads and performs a case-insensitive check.
    """
    payload_marker = f"A_UNIQUE_TEST_{uuid.uuid4().hex[:8]}"
    payload = f"<script>{payload_marker}</script>"
    results: Dict[str, Any] = {
        'vulnerable': False,
        'tested_url': '',
        'status_code': None,
        'content_type': None,
        'error': None,
    }

    sess = session or requests.Session()
    close_session = session is None

    try:
        parsed = urlparse(url)
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        query_params.append(('test_xss', payload))
        new_query = urlencode(query_params, doseq=True)
        test_url = parsed._replace(query=new_query).geturl()
        results['tested_url'] = test_url

        r = sess.get(test_url, headers={'User-Agent': 'AutomatedSecurityAuditor/1.0'}, timeout=timeout)
        results['status_code'] = r.status_code
        results['content_type'] = r.headers.get('Content-Type')
        body = r.text or ''
        # case-insensitive marker check
        if payload_marker.lower() in body.lower():
            results['vulnerable'] = True
    except requests.RequestException as e:
        results['error'] = str(e)
    finally:
        if close_session:
            try:
                sess.close()
            except Exception:
                pass

    return results

def check_clickjacking(url: str, headers: Optional[Dict[str, str]]) -> Dict[str, Any]:
    """
    Checks presence of X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk.
    Accepts headers (dict) and handles case-insensitive header names.
    """
    findings = {'vulnerable': False, 'reasons': []}
    ci_headers = CaseInsensitiveDict(headers or {})

    has_xfo = 'x-frame-options' in {k.lower() for k in ci_headers.keys()}
    csp = ci_headers.get('Content-Security-Policy') or ci_headers.get('content-security-policy') or ''
    if not has_xfo and not csp:
        findings['vulnerable'] = True
        findings['reasons'].append('Missing X-Frame-Options and frame-ancestors CSP')
        return findings

    # If CSP present, check for frame-ancestors directive
    if csp:
        if 'frame-ancestors' not in csp.lower():
            findings['vulnerable'] = True
            findings['reasons'].append('CSP present but missing frame-ancestors directive')

    return findings

def check_cors(headers: Optional[Dict[str, str]]) -> Dict[str, Any]:
    """
    Simple CORS check: if Access-Control-Allow-Origin: * present when sensitive auth headers are allowed.
    Returns details and is case-insensitive.
    """
    findings = {'issue': False, 'details': []}
    ci_headers = CaseInsensitiveDict(headers or {})

    aco = ci_headers.get('Access-Control-Allow-Origin')
    aca = ci_headers.get('Access-Control-Allow-Credentials')

    if aco == '*':
        findings['issue'] = True
        findings['details'].append("Access-Control-Allow-Origin is '*' (allow all)")
        if aca and isinstance(aca, str) and aca.lower() == 'true':
            findings['details'].append("Access-Control-Allow-Credentials is true — combined with '*' may allow credentialed cross-origin requests.")
    return findings
