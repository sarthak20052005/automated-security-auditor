# modules/core_scanner.py
import requests
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import socket
import json
from typing import Dict, Any

DEFAULT_HEADERS = {'User-Agent': 'AutomatedSecurityAuditor/1.0'}

def get_target_info(base_url: str) -> Dict[str, Any]:
    results = {
        'url': base_url,
        'headers': None,
        'content': None,
        'cookies': None,
        'robots_txt': None,
        'sitemap_xml': None,
        'server_tech': 'Unknown',
        'error': None
    }
    try:
        response = requests.get(base_url, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
        response.raise_for_status()
        results['headers'] = response.headers
        results['content'] = response.text
        results['cookies'] = response.cookies

        if 'Server' in response.headers:
            results['server_tech'] = response.headers['Server']

        # robots.txt
        try:
            r = requests.get(urljoin(base_url, '/robots.txt'), headers=DEFAULT_HEADERS, timeout=5)
            if r.status_code == 200:
                results['robots_txt'] = r.text
        except requests.RequestException:
            pass

        # sitemap.xml
        try:
            s = requests.get(urljoin(base_url, '/sitemap.xml'), headers=DEFAULT_HEADERS, timeout=5)
            if s.status_code == 200:
                results['sitemap_xml'] = s.text
        except requests.RequestException:
            pass

    except requests.RequestException as e:
        results['error'] = str(e)

    return results

def get_hostname(url: str) -> str:
    return urlparse(url).hostname

def parse_robots_txt(robots_content: str):
    if not robots_content:
        return []
    disallowed_paths = []
    parser = RobotFileParser()
    parser.parse(robots_content.splitlines())
    try:
        for entry in getattr(parser, "entries", []):
            for rule in getattr(entry, "rulelines", []):
                if not getattr(rule, "allowance", True):
                    disallowed_paths.append(getattr(rule, "path", ""))
    except Exception:
        pass
    return sorted(list(set(disallowed_paths)))

# -----------------------------
# Extras: WHOIS, DNS, port-scan
# -----------------------------
def _whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Try to import python-whois library. If not present, skip gracefully.
    """
    try:
        import whois
    except Exception:
        return {"error": "python-whois library not installed"}
    try:
        w = whois.whois(domain)
        # Convert to basic serializable dict
        return {k: str(v) for k, v in w.items() if v}
    except Exception as e:
        return {"error": str(e)}

def _dns_lookup(domain: str) -> Dict[str, Any]:
    """
    Basic DNS resolution and lookup of A, AAAA, MX records using socket and optionally dnspython.
    """
    out = {}
    try:
        out['resolved_ip'] = socket.gethostbyname(domain)
    except Exception as e:
        out['resolved_ip_error'] = str(e)

    # Try dnspython if present for richer info
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, 'MX')
        out['mx'] = [str(r.exchange).rstrip('.') for r in answers]
    except Exception:
        # ignore if dnspython missing or no MX
        pass
    return out

def _port_scan_top(domain: str, top_ports=None, timeout=0.8):
    if top_ports is None:
        # common top 10 web-related ports
        top_ports = [21,22,23,25,53,80,110,143,443,3306]
    results = []
    try:
        ip = socket.gethostbyname(domain)
    except Exception as e:
        return {"error": f"DNS error: {e}"}
    for p in top_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            rc = s.connect_ex((ip, p))
            s.close()
            results.append({"port": p, "open": rc == 0})
        except Exception:
            results.append({"port": p, "open": False})
    return results

def gather_extras(hostname: str) -> Dict[str, Any]:
    """
    Gather optional extras: whois, dns, top-port scan. Non-blocking best-effort.
    """
    domain = hostname or ''
    out = {}
    if not domain:
        return {"error": "No hostname provided"}
    out['dns'] = _dns_lookup(domain)
    out['ports'] = _port_scan_top(domain)
    out['whois'] = _whois_lookup(domain)
    return out
