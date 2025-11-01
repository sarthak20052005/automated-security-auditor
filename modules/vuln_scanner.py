# modules/vuln_scanner.py
import requests
from urllib.parse import urlparse, urlencode, parse_qsl

def check_basic_xss(url):
    """
    Non-destructive reflected XSS test: appends a unique test param and checks reflection.
    """
    payload = "<ScRipT>A_UNIQUE_TEST_STRING_12345</sCRiPt>"
    results = {'vulnerable': False, 'tested_url': '', 'error': None}

    try:
        parsed = urlparse(url)
        query_params = parse_qsl(parsed.query)
        query_params.append(('test_xss', payload))
        new_query = urlencode(query_params)
        test_url = parsed._replace(query=new_query).geturl()
        results['tested_url'] = test_url
        r = requests.get(test_url, headers={'User-Agent': 'AutomatedSecurityAuditor/1.0'}, timeout=8)
        if payload in r.text:
            results['vulnerable'] = True
    except requests.RequestException as e:
        results['error'] = str(e)

    return results

def check_clickjacking(url, headers):
    """
    Checks presence of X-Frame-Options or CSP frame-ancestors to reduce clickjacking risk.
    """
    findings = {'vulnerable': False, 'reasons': []}
    if not headers:
        headers = {}
    if 'X-Frame-Options' not in headers and 'Content-Security-Policy' not in headers:
        findings['vulnerable'] = True
        findings['reasons'].append('Missing X-Frame-Options and frame-ancestors CSP')
    else:
        # If CSP present, check for frame-ancestors directive
        csp = headers.get('Content-Security-Policy', '')
        if csp and 'frame-ancestors' not in csp.lower() and 'x-frame-options' not in {k.lower() for k in headers.keys()}:
            findings['vulnerable'] = True
            findings['reasons'].append('CSP present but missing frame-ancestors directive')
    return findings

def check_cors(headers):
    """
    Simple CORS check: if Access-Control-Allow-Origin: * present when sensitive auth headers are allowed.
    """
    findings = {'issue': False, 'details': []}
    if not headers:
        headers = {}
    aco = headers.get('Access-Control-Allow-Origin')
    aca = headers.get('Access-Control-Allow-Credentials')
    if aco == '*':
        findings['issue'] = True
        findings['details'].append("Access-Control-Allow-Origin is '*' (allow all)")
        if aca and aca.lower() == 'true':
            findings['details'].append("Access-Control-Allow-Credentials is true — combined with '*' may allow credentialed cross-origin requests.")
    return findings
