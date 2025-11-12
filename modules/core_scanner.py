# modules/core_scanner.py
from typing import Dict, Any, List, Optional, Tuple
import requests
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import socket
import whois as whois_lib
import dns.resolver
import time
import gzip
from xml.etree import ElementTree as ET

# Use a mainstream browser UA to avoid simple blocks
DEFAULT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    # requests will handle gzip/deflate; avoid brotli here so we can handle .br optionally later
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}


def _fetch_text_resource(url: str, headers: Dict[str, str] = None, timeout: float = 8.0) -> Tuple[Optional[int], Optional[str]]:
    """
    Robust GET that follows redirects, sets a browser UA, and returns (status_code, text).
    On network errors/timeouts returns (None, "<error message>").
    Handles gzip-compressed bodies (including .gz sitemaps).
    """
    hdrs = headers or DEFAULT_HEADERS
    try:
        resp = requests.get(url, headers=hdrs, timeout=timeout, allow_redirects=True)
        status = resp.status_code

        # Grab raw bytes
        body_bytes = resp.content or b""

        # Headers that might indicate compression
        content_encoding = (resp.headers.get('Content-Encoding') or "").lower()
        content_type = (resp.headers.get('Content-Type') or "").lower()

        # Detect gzip by magic bytes OR header OR url suffix OR content-type
        looks_gzip = False
        try:
            if body_bytes.startswith(b'\x1f\x8b'):
                looks_gzip = True
        except Exception:
            looks_gzip = False

        if looks_gzip or 'gzip' in content_encoding or url.lower().endswith('.gz') or 'application/gzip' in content_type:
            try:
                decompressed = gzip.decompress(body_bytes)
                enc = resp.encoding or 'utf-8'
                text = decompressed.decode(enc, errors='replace')
                return status, text
            except Exception as ex:
                # If decompression fails, fallback to best-effort decode of raw bytes
                try:
                    enc = resp.encoding or 'utf-8'
                    text = body_bytes.decode(enc, errors='replace')
                    return status, text
                except Exception as ex2:
                    return status, f"Error decoding gzip content: {ex}; fallback failed: {ex2}"
        else:
            # Not gzip-like: prefer resp.text (requests will decode common encodings)
            try:
                return status, resp.text
            except Exception as ex:
                try:
                    enc = resp.encoding or 'utf-8'
                    return status, body_bytes.decode(enc, errors='replace')
                except Exception as ex2:
                    return status, f"Error decoding response body: {ex}; fallback failed: {ex2}"

    except requests.Timeout as e:
        return None, str(e)
    except requests.ConnectionError as e:
        return None, str(e)
    except requests.RequestException as e:
        return None, str(e)


def _fetch_sitemap_with_fallback(url: str, origin: Optional[str] = None, timeout: float = 8.0) -> Tuple[Optional[int], Optional[str]]:
    """
    Try to fetch sitemap URL. On 406/415 or empty non-404 responses, retry with permissive headers (Accept: */*),
    and without Referer. Returns (status, text_or_error).
    """
    # First try: prefer xml and send Referer (existing behaviour)
    headers = DEFAULT_HEADERS.copy()
    if origin:
        headers['Referer'] = origin

    status, text = _fetch_text_resource(url, headers=headers, timeout=timeout)

    # If server returned 406/415 or returned a non-404 non-empty status with empty body,
    # retry with permissive headers:
    need_retry = False
    if status in (406, 415):
        need_retry = True
    elif status is not None and status not in (200, 301, 302, 303, 307, 308, 404):
        # If we got a non-404, non-200/redirect-like status and no useful content, try fallback
        if not text or (isinstance(text, str) and not text.strip()):
            need_retry = True

    if need_retry:
        # Permissive headers for fallback: accept anything
        fallback_headers = DEFAULT_HEADERS.copy()
        fallback_headers['Accept'] = '*/*'
        # Include common encodings; note: requests may not decode 'br' without extra lib,
        # but asking for it sometimes changes server behavior (or returns gzip instead).
        fallback_headers['Accept-Encoding'] = 'gzip, deflate, br'
        # Do not send Referer on fallback; some sites or CDNs treat Referer specially
        fallback_headers.pop('Referer', None)

        print(f"[DEBUG] sitemap fetch received status={status} for {url}; retrying with permissive headers")
        f_status, f_text = _fetch_text_resource(url, headers=fallback_headers, timeout=timeout)
        # prefer fallback result if it looks better
        if f_status is not None and f_status != 404 and f_text and f_text.strip():
            return f_status, f_text
        # if fallback didn't fix it, return the fallback result if present else original
        return (f_status if f_status is not None else status), (f_text or text)

    return status, text


def get_target_info(base_url: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        'url': base_url,
        'headers': {},
        'content': None,
        'cookies': None,
        'robots_txt': None,
        'sitemap_xml': None,
        'server_tech': 'Unknown',
        'error': None
    }

    try:
        # Normalize base_url for initial fetch: ensure scheme present
        if not base_url.startswith(('http://', 'https://')):
            base_url = 'https://' + base_url  # prefer https by default

        # initial fetch (we'll use r.url to compute origin after redirects)
        r = requests.get(base_url, headers=DEFAULT_HEADERS, timeout=10, allow_redirects=True)
        r.raise_for_status()

        results['headers'] = dict(r.headers)
        results['content'] = r.text
        try:
            results['cookies'] = r.cookies
        except Exception:
            results['cookies'] = None

        if 'Server' in r.headers:
            results['server_tech'] = r.headers.get('Server')

        # compute final origin from r.url (handles redirects to www/https)
        final_url = r.url if hasattr(r, 'url') and r.url else base_url
        parsed_final = urlparse(final_url)
        origin = f"{parsed_final.scheme}://{parsed_final.netloc}/"

        # ----------------------
        # robots.txt (robust)
        # ----------------------
        try:
            robots_url = urljoin(origin, 'robots.txt')
            print(f"[DEBUG] Fetching robots.txt from: {robots_url}")
            status, text = _fetch_text_resource(robots_url, headers=DEFAULT_HEADERS, timeout=8.0)
            print(f"[DEBUG] robots.txt status={status}")

            if status is None:
                # network error/timeouts -> text contains error message if present
                if text:
                    results['robots_txt'] = f"Error: {text}"
                else:
                    results['robots_txt'] = "Error: Network failure (unknown)"
            elif status == 404:
                results['robots_txt'] = "Error: 404 Not Found"
            else:
                # got a non-404 response
                if text and text.strip():
                    results['robots_txt'] = text
                else:
                    results['robots_txt'] = "Error: 200 OK but content is empty"
        except Exception as e:
            results['robots_txt'] = f"Error: {e}"

        # ----------------------
        # sitemap.xml (try robots Sitemap: then fallback to /sitemap.xml)
        # ----------------------
        try:
            sitemap_content = None
            sitemap_source_url = None

            robots_txt_val = results.get('robots_txt')
            if isinstance(robots_txt_val, str) and robots_txt_val and not robots_txt_val.startswith("Error:"):
                for line in robots_txt_val.splitlines():
                    if not line:
                        continue
                    ln = line.lstrip()
                    if ln.lower().startswith('sitemap:'):
                        parts = ln.split(':', 1)
                        if len(parts) > 1:
                            candidate = parts[1].strip()
                            candidate_url = urljoin(origin, candidate)
                            print(f"[DEBUG] Found robots Sitemap: candidate={candidate_url}")
                            st_status, st_text = _fetch_sitemap_with_fallback(candidate_url, origin=origin, timeout=8.0)
                            print(f"[DEBUG] sitemap candidate status={st_status} for {candidate_url}")

                            if st_status is None:
                                # network failure for this candidate -> continue to next candidate
                                if st_text:
                                    # store error for visibility but continue searching
                                    sitemap_content = f"Error: {st_text}"
                                continue
                            if st_status == 404:
                                continue
                            if st_text and st_text.strip():
                                sitemap_content = st_text
                                sitemap_source_url = candidate_url
                                break
                            else:
                                sitemap_content = f"Error: {st_status} but content empty"
                                sitemap_source_url = candidate_url
                                break

            # fallback to /sitemap.xml on origin
            if sitemap_content is None:
                sitemap_url = urljoin(origin, 'sitemap.xml')
                print(f"[DEBUG] Fetching fallback sitemap: {sitemap_url}")
                s_status, s_text = _fetch_sitemap_with_fallback(sitemap_url, origin=origin, timeout=8.0)
                print(f"[DEBUG] fallback sitemap status={s_status} for {sitemap_url}")
                if s_status is None:
                    if s_text:
                        sitemap_content = f"Error: {s_text}"
                    else:
                        sitemap_content = "Error: Network failure (unknown)"
                    sitemap_source_url = sitemap_url
                elif s_status == 404:
                    sitemap_content = "Error: 404 Not Found"
                    sitemap_source_url = sitemap_url
                else:
                    if s_text and s_text.strip():
                        sitemap_content = s_text
                        sitemap_source_url = sitemap_url
                    else:
                        sitemap_content = f"Error: {s_status} but content empty"
                        sitemap_source_url = sitemap_url

            # If we have sitemap content and it looks like XML, detect sitemapindex and fetch child sitemaps
            if sitemap_content and isinstance(sitemap_content, str) and not sitemap_content.startswith("Error:"):
                try:
                    # Parse XML (ElementTree handles namespaces if we search with wildcard)
                    tree = ET.fromstring(sitemap_content.encode('utf-8'))
                    root_tag = tree.tag.lower()
                    if 'sitemapindex' in root_tag:
                        # It's a sitemap index — extract child <loc> elements (namespace-aware)
                        locs = [elem.text for elem in tree.findall('.//{*}loc') if elem.text]
                        child_contents: List[str] = []
                        # limit number of child sitemaps to fetch
                        for child_loc in locs[:5]:
                            child_url = urljoin(origin, child_loc)
                            print(f"[DEBUG] Fetching child sitemap: {child_url}")
                            ch_status, ch_text = _fetch_sitemap_with_fallback(child_url, origin=origin, timeout=8.0)
                            print(f"[DEBUG] child sitemap status={ch_status} for {child_url}")
                            if ch_status and ch_status != 404 and ch_text and ch_text.strip():
                                child_contents.append(ch_text)
                        if child_contents:
                            # concatenate child sitemaps for convenience
                            sitemap_content = "\n".join(child_contents)
                except ET.ParseError:
                    # Not XML or malformed; leave content as-is
                    pass
                except Exception as e:
                    # parsing/fetching child sitemaps failed — record error but keep original content
                    print(f"[DEBUG] sitemap index handling error: {e}")

            results['sitemap_xml'] = sitemap_content
        except Exception as e:
            results['sitemap_xml'] = f"Error: {e}"

    except requests.RequestException as e:
        # Surface main fetch error for visibility
        results['error'] = str(e)
        results['robots_txt'] = f"Error (main fetch): {e}"
        results['sitemap_xml'] = f"Error (main fetch): {e}"

    return results


def get_hostname(url: str) -> Optional[str]:
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def parse_robots_txt(robots_content: str) -> List[str]:
    """
    Return a list of disallowed paths parsed from a robots.txt content.
    If robots_content is falsy, returns empty list.
    """
    if not robots_content:
        return []
    disallowed_paths: List[str] = []
    parser = RobotFileParser()
    try:
        parser.parse(robots_content.splitlines())
        # RobotFileParser internals vary by Python version; attempt to read entries safely
        for entry in getattr(parser, "entries", []):
            for rule in getattr(entry, "rulelines", []):
                try:
                    allowance = getattr(rule, "allowance", None)
                    path = getattr(rule, "path", "")
                    # rule.allowance == False indicates disallow
                    if allowance is False and path:
                        disallowed_paths.append(path)
                except Exception:
                    continue
    except Exception:
        # parsing failed -> return empty
        pass
    return sorted(list(set(disallowed_paths)))


# -----------------------------
# Extras: WHOIS, DNS, port-scan
# -----------------------------
def _whois_lookup(domain: str) -> Dict[str, Any]:
    """
    Lightweight whois wrapper using python-whois. Returns a dict with common fields.
    """
    out: Dict[str, Any] = {}
    try:
        w = whois_lib.whois(domain)
        # pick interesting fields, convert to str for safe JSON
        for k in ('domain_name', 'registrar', 'creation_date', 'expiration_date', 'updated_date', 'name_servers', 'emails', 'org'):
            v = getattr(w, k, None) if hasattr(w, k) else w.get(k) if isinstance(w, dict) else None
            if v is not None:
                try:
                    # format dates and lists sensibly
                    if isinstance(v, (list, tuple)):
                        out[k] = [str(x) for x in v]
                    else:
                        out[k] = str(v)
                except Exception:
                    out[k] = str(v)
    except Exception as e:
        out['error'] = str(e)
    return out


def _dns_lookup(domain: str) -> Dict[str, Any]:
    """
    Resolve A and MX records using dnspython. Returns dict with:
      - 'a': list of A/AAAA answers
      - 'resolved_ip': first A/AAAA IP or None
      - 'mx': list of MX strings
      - 'error': optional error message
    """
    result: Dict[str, Any] = {'a': [], 'mx': [], 'resolved_ip': None}
    try:
        # Try A records first
        try:
            answers = dns.resolver.resolve(domain, 'A', lifetime=4)
            a_list = [r.to_text() for r in answers]
            result['a'] = a_list
        except Exception:
            # fallback to AAAA (IPv6)
            try:
                answers = dns.resolver.resolve(domain, 'AAAA', lifetime=4)
                a_list = [r.to_text() for r in answers]
                result['a'] = a_list
            except Exception:
                result['a'] = []

        # set resolved_ip to first A/AAAA if present
        if result['a']:
            result['resolved_ip'] = result['a'][0]

        # MX records
        try:
            mx_ans = dns.resolver.resolve(domain, 'MX', lifetime=4)
            mx_list: List[str] = []
            for r in mx_ans:
                try:
                    pref = getattr(r, 'preference', None)
                    exch = getattr(r, 'exchange', None)
                    if exch:
                        entry = f"{pref} {str(exch).rstrip('.')}"
                    else:
                        entry = str(r)
                    entry = entry.strip()
                    if entry and entry != ".":
                        mx_list.append(entry)
                except Exception:
                    continue
            result['mx'] = mx_list
        except Exception:
            result['mx'] = []

    except Exception as e:
        result['error'] = str(e)
    return result


def _port_scan_top(domain: str, top_ports: Optional[List[int]] = None, timeout: float = 0.6) -> List[Dict[str, Any]]:
    """
    Simple TCP connect-based scan for the provided top_ports.
    Returns list of dicts: {'port': n, 'open': bool}
    """
    if top_ports is None:
        top_ports = [80, 443, 22, 21, 25, 53, 3306, 8080, 8443]
    results: List[Dict[str, Any]] = []
    for p in top_ports:
        is_open = False
        try:
            with socket.create_connection((domain, int(p)), timeout=timeout):
                is_open = True
        except Exception:
            is_open = False
        results.append({'port': p, 'open': is_open})
    return results


def gather_extras(hostname: str) -> Dict[str, Any]:
    """
    Run whois, dns, and a lightweight port probe. Returns a dict with the findings.
    """
    out: Dict[str, Any] = {}
    if not hostname:
        return {'error': 'no hostname provided'}

    # DNS
    try:
        out['dns'] = _dns_lookup(hostname)
    except Exception as e:
        out['dns'] = {'error': str(e)}

    # Whois
    try:
        out['whois'] = _whois_lookup(hostname)
    except Exception as e:
        out['whois'] = {'error': str(e)}

    # Ports (use resolved IP if available otherwise hostname)
    try:
        target = hostname
        if out.get('dns') and out['dns'].get('a'):
            # use first resolved IP for port probing
            target = out['dns']['a'][0]
        out['ports'] = _port_scan_top(target)
    except Exception as e:
        out['ports'] = {'error': str(e)}

    return out
