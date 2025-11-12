# modules/header_analyzer.py

RECOMMENDED_HEADERS = {
    'Content-Security-Policy': 'Provides strong protection against XSS and data injection.',
    'Strict-Transport-Security': 'Enforces secure (HTTPS) connections.',
    'X-Content-Type-Options': 'Prevents "MIME-sniffing" attacks.',
    'X-Frame-Options': 'Protects against clickjacking.',
    'Referrer-Policy': 'Controls how much referrer information is sent.'
}

FINGERPRINT_HEADERS = {
    'Server',
    'X-Powered-By',
    'X-AspNet-Version'
}

def analyze_headers(headers):
    """
    Analyzes HTTP response headers against security best practices and returns a
    structured result including presence, missing headers, CSP weaknesses and a score.
    """
    results = {
        'missing': [],
        'present': [],
        'recommendations': [],
        'fingerprinting': [],
        'csp_weaknesses': [],
        'score': 0
    }

    if headers is None:
        headers = {}

    header_keys = {k for k in headers.keys()}

    for header, description in RECOMMENDED_HEADERS.items():
        if header not in header_keys:
            results['missing'].append(header)
            results['recommendations'].append(f"Missing '{header}': {description}")
        else:
            results['present'].append(header)

    # CSP analysis
    if 'Content-Security-Policy' in header_keys:
        csp_value = headers.get('Content-Security-Policy', '')
        results['csp_weaknesses'] = analyze_csp(csp_value)

    # Fingerprinting headers
    for header in FINGERPRINT_HEADERS:
        if header in header_keys:
            results['fingerprinting'].append(
                f"Header '{header}: {headers.get(header)}' reveals server technology."
            )

    # Score: proportion of recommended headers present
    total = len(RECOMMENDED_HEADERS)
    present = len(results['present'])
    results['score'] = int((present / total) * 100)

    return results

def analyze_csp(csp_value):
    weaknesses = []
    if not csp_value:
        return weaknesses

    csp_value = csp_value.lower()

    if "'unsafe-inline'" in csp_value:
        weaknesses.append("'unsafe-inline' is present, allowing inline 'script' and 'style' tags.")
    if "'unsafe-eval'" in csp_value:
        weaknesses.append("'unsafe-eval' is present, allowing eval-like behaviors.")
    if "script-src" in csp_value and "http:" in csp_value:
        weaknesses.append("Policy allows scripts from insecure 'http:' sources.")

    return weaknesses

def analyze_cookies(cookies):
    """
    Analyzes cookies for Secure and HttpOnly attributes and returns a dict:
      - insecure_cookies: human-readable list of warnings
      - score: 0-100 (forgiving; missing Secure/HttpOnly reduce score but not to 0)
      - cookies: normalized list of cookie dicts for reporting
    Accepts a requests.cookies.RequestsCookieJar, list of cookie objects or dict.
    """
    results = {
        'insecure_cookies': [],
        'score': 100,
        'cookies': []
    }

    if not cookies:
        return results

    total = 0
    total_penalty = 0

    for cookie in cookies:
        total += 1
        # normalize cookie representation
        name = ''
        value = ''
        secure_flag = False
        httponly_flag = False
        samesite = ''

        try:
            if isinstance(cookie, dict):
                name = cookie.get('name') or cookie.get('Name') or list(cookie.keys())[0] if cookie else ''
                value = cookie.get('value') or cookie.get('Value') or ''
                secure_flag = bool(cookie.get('secure') or cookie.get('Secure'))
                httponly_flag = bool(cookie.get('httponly') or cookie.get('HttpOnly') or cookie.get('httpOnly'))
                samesite = cookie.get('samesite') or cookie.get('SameSite') or ''
            else:
                name = getattr(cookie, 'name', '') or getattr(cookie, 'key', '') or str(cookie)
                value = getattr(cookie, 'value', '') or getattr(cookie, 'val', '') or ''
                secure_flag = bool(getattr(cookie, 'secure', False))
                # HttpOnly often in _rest or rest dicts
                rest = getattr(cookie, '_rest', None) or getattr(cookie, 'rest', None) or {}
                has_httponly = False
                if isinstance(rest, dict):
                    for k in rest.keys():
                        if str(k).lower() == 'httponly':
                            has_httponly = True
                            break
                if not has_httponly and hasattr(cookie, 'has_nonstandard_attr'):
                    try:
                        has_httponly = bool(cookie.has_nonstandard_attr('httponly'))
                    except Exception:
                        pass
                httponly_flag = has_httponly
                samesite = rest.get('samesite') if isinstance(rest, dict) else ''

        except Exception:
            # best-effort fallback
            name = getattr(cookie, 'name', '') or str(cookie)
            value = ''
            secure_flag = False
            httponly_flag = False

        # build normalized cookie entry for templates
        normalized = {
            'name': name or '',
            'value': value or '',
            'secure': bool(secure_flag),
            'httponly': bool(httponly_flag),
            'samesite': samesite or ''
        }
        results['cookies'].append(normalized)

        # Determine penalties (forgiving): Secure missing -> -10, HttpOnly missing -> -8
        cookie_warnings = []
        penalty = 0
        if not normalized['secure']:
            cookie_warnings.append('Missing "Secure" flag')
            penalty += 10
        if not normalized['httponly']:
            cookie_warnings.append('Missing "HttpOnly" flag')
            penalty += 8

        if cookie_warnings:
            results['insecure_cookies'].append(f"Cookie '{normalized['name']}' warnings: {', '.join(cookie_warnings)}")
            total_penalty += penalty

    # Convert penalties to score; cap penalty to avoid 0 and ensure a minimum baseline (40%)
    total_penalty = min(total_penalty, 60)  # cap overall cookie penalty
    score = max(40, 100 - int(total_penalty))
    results['score'] = score

    return results
