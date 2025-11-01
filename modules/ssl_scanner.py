# modules/ssl_scanner.py
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import socket
import ssl
import datetime
from typing import Dict, Any, Optional

# sslyze imports
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ServerNetworkConfiguration,
    ServerScanStatusEnum
)

def _parse_peercert_dict(cert_dict):
    if not cert_dict:
        return {}
    subject = {}
    for tup in cert_dict.get("subject", ()):
        subject.update({k: v for k, v in tup})
    issuer = {}
    for tup in cert_dict.get("issuer", ()):
        issuer.update({k: v for k, v in tup})
    return {
        "subject": subject,
        "issuer": issuer,
        "not_valid_before": cert_dict.get("notBefore", ""),
        "not_valid_after": cert_dict.get("notAfter", "")
    }

def _fallback_tls_check(hostname: str, port: int = 443, timeout: int = 6):
    """
    Fallback TLS handshake using python ssl to determine negotiated TLS version
    and retrieve peer certificate if sslyze fails or is blocked.
    """
    results = {
        "tls_1_0": False,
        "tls_1_1": False,
        "tls_1_2": False,
        "tls_1_3": False,
        "certificate_details": {}
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                ver = ssock.version()
                cert = ssock.getpeercert()
                if ver:
                    if "1.0" in ver:
                        results["tls_1_0"] = True
                    if "1.1" in ver:
                        results["tls_1_1"] = True
                    if "1.2" in ver:
                        results["tls_1_2"] = True
                    if "1.3" in ver:
                        results["tls_1_3"] = True
                results["certificate_details"] = _parse_peercert_dict(cert)
    except Exception:
        # best-effort only
        pass

    return results

def scan_ssl(hostname: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {
        "supports_sslv2": False,
        "supports_sslv3": False,
        "supports_tls_1_0": False,
        "supports_tls_1_1": False,
        "supports_tls_1_2": False,
        "supports_tls_1_3": False,
        "heartbleed_vulnerable": False,
        "robot_vulnerable": False,
        "weak_ciphers_found": [],
        "certificate_details": {},
        "error": None,
    }

    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception as e:
        results["error"] = f"DNS resolution failed: {e}"
        return results

    print(f"[*] Scanning {hostname} -> {ip_address}:443 (SNI={hostname})")

    try:
        server_location = ServerNetworkLocation(ip_address, 443)
        network_config = ServerNetworkConfiguration(
            tls_server_name_indication=hostname,
            network_timeout=30,
        )

        # Request a broad set of commands
        scan_request = ServerScanRequest(
            server_location=server_location,
            network_configuration=network_config,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
            },
        )

        scanner = Scanner()
        scanner.queue_scans([scan_request])

        for result in scanner.get_results():
            if result.scan_status != ServerScanStatusEnum.COMPLETED:
                results["error"] = f"Scan incomplete: {getattr(result, 'error_reason', 'unknown')}"
                break

            # SSLv2 / SSLv3
            ssl2 = getattr(result, "ssl_2_0_cipher_suites", None)
            ssl3 = getattr(result, "ssl_3_0_cipher_suites", None)
            results["supports_sslv2"] = bool(ssl2 and getattr(ssl2, "accepted_cipher_suites", []))
            results["supports_sslv3"] = bool(ssl3 and getattr(ssl3, "accepted_cipher_suites", []))

            # TLS 1.x
            tls10 = getattr(result, "tls_1_0_cipher_suites", None)
            tls11 = getattr(result, "tls_1_1_cipher_suites", None)
            tls12 = getattr(result, "tls_1_2_cipher_suites", None)
            tls13 = getattr(result, "tls_1_3_cipher_suites", None)

            results["supports_tls_1_0"] = bool(tls10 and getattr(tls10, "accepted_cipher_suites", []))
            results["supports_tls_1_1"] = bool(tls11 and getattr(tls11, "accepted_cipher_suites", []))
            results["supports_tls_1_2"] = bool(tls12 and getattr(tls12, "accepted_cipher_suites", []))
            results["supports_tls_1_3"] = bool(tls13 and getattr(tls13, "accepted_cipher_suites", []))

            # weak ciphers
            try:
                if tls12 and getattr(tls12, "weak_cipher_suites", None):
                    results["weak_ciphers_found"] = [c.name for c in tls12.weak_cipher_suites]
            except Exception:
                pass

            # heartbleed
            heartbleed = getattr(result, "heartbleed", None)
            if heartbleed and getattr(heartbleed, "is_vulnerable_to_heartbleed", False):
                results["heartbleed_vulnerable"] = True

            # ROBOT
            robot = getattr(result, "robot", None)
            if robot:
                robot_name = getattr(getattr(robot, "robot_scan_result", None), "name", "")
                if robot_name and "NOT_VULNERABLE" not in robot_name:
                    results["robot_vulnerable"] = True

            # Certificate - prefer sslyze's parsed certificate if available
            certinfo = getattr(result, "certificate_info", None)
            if certinfo:
                try:
                    if getattr(certinfo, "certificate_deployment", None) and getattr(certinfo.certificate_deployment, "received_certificate_chain", None):
                        chain = certinfo.certificate_deployment.received_certificate_chain
                        if chain:
                            cert = chain[0]
                            results["certificate_details"] = {
                                "subject": cert.subject.rfc4514_string() if getattr(cert, "subject", None) else "",
                                "issuer": cert.issuer.rfc4514_string() if getattr(cert, "issuer", None) else "",
                                "not_valid_before": str(getattr(cert, "not_valid_before", "")),
                                "not_valid_after": str(getattr(cert, "not_valid_after", "")),
                            }
                except Exception:
                    pass

            break  # only one queued scan

        # fallback: if TLS not detected by sslyze, try python ssl handshake
        if not (results.get("supports_tls_1_2") or results.get("supports_tls_1_3")):
            fb = _fallback_tls_check(hostname)
            results["supports_tls_1_0"] = results["supports_tls_1_0"] or fb.get("tls_1_0", False)
            results["supports_tls_1_1"] = results["supports_tls_1_1"] or fb.get("tls_1_1", False)
            results["supports_tls_1_2"] = results["supports_tls_1_2"] or fb.get("tls_1_2", False)
            results["supports_tls_1_3"] = results["supports_tls_1_3"] or fb.get("tls_1_3", False)
            if not results["certificate_details"] and fb.get("certificate_details"):
                results["certificate_details"] = fb.get("certificate_details")

    except Exception as e:
        results["error"] = str(e)

    # Add certificate expiry flag if possible
    try:
        na = results.get("certificate_details", {}).get("not_valid_after")
        if na:
            try:
                dt = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
            except Exception:
                try:
                    dt = datetime.datetime.fromisoformat(na)
                except Exception:
                    dt = None
            if dt:
                results["certificate_details"]["is_expired"] = dt < datetime.datetime.utcnow()
    except Exception:
        pass

    return results

if __name__ == "__main__":
    import json
    print(json.dumps(scan_ssl("example.com"), indent=2))
