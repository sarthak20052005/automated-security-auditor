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
    Analyzes cookies for Secure and HttpOnly attributes and returns a dict.
    Accepts a requests.cookies.RequestsCookieJar or list of cookies.
    """
    results = {
        'insecure_cookies': [],
        'score': 100
    }

    if not cookies:
        return results

    insecure_count = 0
    total = 0

    for cookie in cookies:
        total += 1
        is_insecure = False
        reasons = []
        # cookie is a requests.cookies.Cookie object typically
        try:
            if not getattr(cookie, "secure", False):
                is_insecure = True
                reasons.append('Missing "Secure" flag')
        except Exception:
            pass

        # HttpOnly can be stored in cookie._rest or cookie._rest.get('HttpOnly')
        try:
            rest = getattr(cookie, "_rest", {})
            has_httponly = False
            # keys may vary in case; check case-insensitively
            if isinstance(rest, dict):
                for k in rest.keys():
                    if str(k).lower() == "httponly":
                        has_httponly = True
                        break
            # if cookie object has attribute 'httponly' check that too
            if not has_httponly and hasattr(cookie, "has_nonstandard_attr"):
                try:
                    has_httponly = cookie.has_nonstandard_attr("httponly")
                except Exception:
                    pass

            if not has_httponly:
                is_insecure = True
                reasons.append('Missing "HttpOnly" flag')
        except Exception:
            # conservative approach: mark insecure if we cannot confirm
            is_insecure = True
            reasons.append('Missing "HttpOnly" flag (could not verify)')

        if is_insecure:
            insecure_count += 1
            results['insecure_cookies'].append(f"Cookie '{getattr(cookie, 'name', str(cookie))}' is insecure: {', '.join(reasons)}")

    # Score: percent of cookies that are secure
    if total > 0:
        results['score'] = int(((total - insecure_count) / total) * 100)

    return results
