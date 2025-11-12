# modules/ssl_scanner.py
import warnings
# keep deprecation warnings muted only for this module's scope if necessary
warnings.filterwarnings("ignore", category=DeprecationWarning)

import socket
import ssl
import datetime
from typing import Dict, Any, Optional
import logging
from time import sleep

# sslyze imports
from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ScanCommand,
    ServerNetworkConfiguration,
    ServerScanStatusEnum
)

logger = logging.getLogger(__name__)

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
    Probe individual TLS versions explicitly to detect support reliably.
    Returns booleans for tls_1_0..tls_1_3 and best-effort certificate details.
    """
    results = {
        "tls_1_0": False,
        "tls_1_1": False,
        "tls_1_2": False,
        "tls_1_3": False,
        "certificate_details": {}
    }

    # If TLSVersion enum is available, probe per-version by restricting context
    try:
        TLSVersion = ssl.TLSVersion
        probes = [
            ("tls_1_0", TLSVersion.TLSv1),
            ("tls_1_1", TLSVersion.TLSv1_1),
            ("tls_1_2", TLSVersion.TLSv1_2),
        ]
        try:
            probes.append(("tls_1_3", TLSVersion.TLSv1_3))
        except Exception:
            pass

        for name, tv in probes:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # restrict to single version
                ctx.minimum_version = tv
                ctx.maximum_version = tv

                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        # handshake succeeded for this version
                        results[name] = True
                        if not results["certificate_details"]:
                            try:
                                cert = ssock.getpeercert()
                                results["certificate_details"] = _parse_peercert_dict(cert)
                            except Exception:
                                pass
            except Exception:
                # handshake failed for this version
                continue
        return results
    except Exception:
        # Fallback: do a default handshake and infer negotiated version
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ver = (ssock.version() or "").lower()
                    cert = ssock.getpeercert()
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
            pass
        return results

def scan_ssl(hostname: str, port: int = 443) -> Dict[str, Any]:
    """
    Scan SSL/TLS configuration using sslyze with a fallback handshake.
    port is configurable. Returns structured results and error messages.
    """
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

    # DNS resolution with a small retry/backoff
    ip_address = None
    for attempt in range(2):
        try:
            ip_address = socket.gethostbyname(hostname)
            break
        except Exception as e:
            logger.debug("DNS resolution attempt %d failed for %s: %s", attempt + 1, hostname, e)
            if attempt == 0:
                sleep(0.2)
            last_dns_err = e
    if not ip_address:
        results["error"] = f"DNS resolution failed: {last_dns_err}"
        return results

    logger.info("Scanning %s -> %s:%d (SNI=%s)", hostname, ip_address, port, hostname)

    try:
        server_location = ServerNetworkLocation(ip_address, port)
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
            fb = _fallback_tls_check(hostname, port=port)
            results["supports_tls_1_0"] = results["supports_tls_1_0"] or fb.get("tls_1_0", False)
            results["supports_tls_1_1"] = results["supports_tls_1_1"] or fb.get("tls_1_1", False)
            results["supports_tls_1_2"] = results["supports_tls_1_2"] or fb.get("tls_1_2", False)
            results["supports_tls_1_3"] = results["supports_tls_1_3"] or fb.get("tls_1_3", False)
            if not results["certificate_details"] and fb.get("certificate_details"):
                results["certificate_details"] = fb.get("certificate_details")

    except Exception as e:
        results["error"] = str(e)
        logger.exception("ssl scan failed for %s:%d", hostname, port)

    # Add certificate expiry flag if possible
    try:
        na = results.get("certificate_details", {}).get("not_valid_after")
        if na:
            dt = None
            # Try common formats
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.datetime.strptime(na, fmt)
                    break
                except Exception:
                    continue
            if not dt:
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
    # keep direct run minimal and use logging instead of print
    logging.basicConfig(level=logging.INFO)
    print(json.dumps(scan_ssl("example.com"), indent=2))
