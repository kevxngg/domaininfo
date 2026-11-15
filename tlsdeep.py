"""Inspección TLS a fondo con ssl de la biblioteca estándar.

- Certificado verificado o, si falla la verificación, el motivo y los datos del certificado.
- Versiones de TLS que acepta el servidor (1.0, 1.1, 1.2, 1.3).
- Nombres del certificado (SAN), emisor, si es autofirmado o comodín.
"""

from datetime import datetime, timezone
import os
import socket
import ssl
import tempfile
import time
import warnings

VERSIONS = (("TLSv1.0", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3"))


def _flatten(name):
    out = {}
    for rdn in name or ():
        for key, value in rdn:
            out[key] = value
    return out


def decode_der(der):
    """Decodifica un certificado DER sin librerías externas (usa el decodificador de CPython)."""
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        return {}
    handle, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(handle, "w", encoding="ascii") as stream:
            stream.write(ssl.DER_cert_to_PEM_cert(der))
        return decoder(path)
    except (OSError, ValueError, ssl.SSLError):
        return {}
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def describe(cert):
    subject, issuer = _flatten(cert.get("subject")), _flatten(cert.get("issuer"))
    san = [value for kind, value in cert.get("subjectAltName", ()) if kind in ("DNS", "IP Address")]
    info = {"subject": subject.get("commonName"), "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "issuer_cn": issuer.get("commonName"), "san": san, "serial": cert.get("serialNumber"),
            "not_before": cert.get("notBefore"), "self_signed": bool(subject) and subject == issuer,
            "wildcard": any(name.startswith("*.") for name in san)}
    if cert.get("notAfter"):
        expiry = ssl.cert_time_to_seconds(cert["notAfter"])
        info["expires"] = datetime.fromtimestamp(expiry, timezone.utc).date().isoformat()
        info["days_remaining"] = int((expiry - time.time()) // 86400)
    return info


def inspect(host, port, timeout, server_name=None):
    """Conexión verificada; si falla la verificación, repite sin verificar para explicar por qué."""
    sni = server_name or host
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=sni) as conn:
                cert = conn.getpeercert()
                return {"verified": True, "protocol": conn.version(), "cipher": conn.cipher(),
                        "certificate": cert, **describe(cert)}
    except ssl.SSLCertVerificationError as exc:
        reason = getattr(exc, "verify_message", None) or str(exc)
    loose = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    loose.check_hostname = False
    loose.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with loose.wrap_socket(raw, server_hostname=sni) as conn:
            der = conn.getpeercert(binary_form=True)
            cert = decode_der(der) if der else {}
            return {"verified": False, "verify_error": reason, "protocol": conn.version(),
                    "cipher": conn.cipher(), "certificate": cert, **describe(cert)}


def versions(host, port, timeout, server_name=None):
    """True si el servidor acepta esa versión, False si la rechaza, None si este equipo no puede probarla."""
    result = {}
    for label, attr in VERSIONS:
        version = getattr(ssl.TLSVersion, attr, None)
        if version is None:
            result[label] = None
            continue
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with warnings.catch_warnings():
                # Probar TLS 1.0/1.1 es justo el objetivo: se silencia el aviso de obsolescencia.
                warnings.simplefilter("ignore", DeprecationWarning)
                context.minimum_version = version
                context.maximum_version = version
            if label in ("TLSv1.0", "TLSv1.1"):
                context.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            result[label] = None
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=server_name or host) as conn:
                    # ssl informa "TLSv1" para la 1.0
                    result[label] = conn.version() in (label, label.replace(".0", ""))
        except ssl.SSLError as exc:
            # "no protocols available": la OpenSSL local no ofrece esa versión; no se puede concluir.
            result[label] = None if "no protocols available" in str(exc).lower() else False
        except OSError:
            result[label] = False
        except (NotImplementedError, TypeError, ValueError):
            result[label] = None
    return result
