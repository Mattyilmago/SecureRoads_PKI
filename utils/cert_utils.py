"""
Certificate utility functions for PKI operations.

Provides helper functions for certificate SKI extraction, identifier generation,
and temporal information handling.

NOTA IMPORTANTE - Gestione Datetime con cryptography:
-----------------------------------------------------
La libreria cryptography restituisce datetime NAIVE (senza timezone) dai certificati.
Tutte le funzioni di questa utility normalizzano automaticamente in UTC-aware.

- not_valid_before → datetime NAIVE
- not_valid_after → datetime NAIVE

Usa sempre get_cert_valid_from() e get_cert_valid_to() per ottenere datetime UTC-aware.
"""

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def get_certificate_ski(certificate: x509.Certificate) -> str:
    """
    Extracts Subject Key Identifier (SKI) from certificate in hex format.

    Returns SKI extension value if present, otherwise generates SHA-256 hash
    of the public key for legacy certificates.

    Args:
        certificate: X.509 certificate

    Returns:
        SKI as hex uppercase string
    """
    try:
        ski_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        # ski_ext.value.digest è bytes, converti in hex uppercase
        return ski_ext.value.digest.hex().upper()
    except x509.ExtensionNotFound:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend

        public_key_der = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(public_key_der)
        ski_hash = digest.finalize()

        return ski_hash.hex().upper()


def get_certificate_identifier(certificate: x509.Certificate) -> str:
    """
    Generates unique certificate identifier (Subject + SKI).

    Format: "CN=EntityName_SKI-{first12chars}"

    Args:
        certificate: X.509 certificate

    Returns:
        Human-readable unique identifier
    """
    try:
        subject = certificate.subject.rfc4514_string()
        ski = get_certificate_ski(certificate)
        ski_short = ski[:12]
        return f"{subject}_SKI-{ski_short}"
    except Exception as e:
        serial = certificate.serial_number
        subject = certificate.subject.rfc4514_string()
        return f"{subject}_SERIAL-{serial}"


def get_short_identifier(certificate: x509.Certificate) -> str:
    """
    Generates short certificate identifier (last 8 hex chars of SKI).

    Used for file naming and compact identifiers.

    Args:
        certificate: X.509 certificate

    Returns:
        8-character hex string uppercase
    """
    try:
        ski = get_certificate_ski(certificate)
        return ski[-8:]
    except ValueError:
        serial_hex = hex(certificate.serial_number)[2:].upper()
        return serial_hex[-8:].zfill(8)


def get_certificate_expiry_time(certificate: x509.Certificate) -> datetime:
    """
    Extracts certificate expiration timestamp (timezone-aware).

    Args:
        certificate: X.509 certificate

    Returns:
        Expiration datetime in UTC
    """
    # Use not_valid_after_utc (cryptography 39.0+) instead of deprecated not_valid_after
    return certificate.not_valid_after_utc


def get_certificate_not_before(certificate: x509.Certificate) -> datetime:
    """
    Extracts certificate validity start timestamp (timezone-aware).

    Args:
        certificate: X.509 certificate

    Returns:
        Start datetime in UTC
    """
    # Use not_valid_before_utc (cryptography 39.0+) instead of deprecated not_valid_before
    return certificate.not_valid_before_utc


def format_certificate_info(certificate: x509.Certificate) -> str:
    """
    Formats certificate information as human-readable string.

    Args:
        certificate: X.509 certificate

    Returns:
        Formatted string with certificate details
    """
    subject = certificate.subject.rfc4514_string()
    serial = certificate.serial_number
    not_before = get_certificate_not_before(certificate)
    not_after = get_certificate_expiry_time(certificate)

    try:
        ski = get_certificate_ski(certificate)
        ski_line = f"SKI: {ski[:16]}...\n"
    except ValueError:
        ski_line = "SKI: N/A\n"

    return (
        f"Subject: {subject}\n"
        f"Serial: {serial}\n"
        f"{ski_line}"
        f"Validity: {not_before.strftime('%Y-%m-%d %H:%M:%S')} to "
        f"{not_after.strftime('%Y-%m-%d %H:%M:%S')}"
    )


def is_certificate_expired(certificate: x509.Certificate) -> bool:
    """
    Checks if certificate is expired.

    Args:
        certificate: X.509 certificate

    Returns:
        True if expired, False otherwise
    """
    expiry = get_certificate_expiry_time(certificate)
    now = datetime.now(timezone.utc)
    return expiry < now


def is_certificate_valid_at(
    certificate: x509.Certificate, timestamp: Optional[datetime] = None
) -> bool:
    """
    Checks if certificate is valid at a given time.

    Args:
        certificate: X.509 certificate
        timestamp: Time to check (default: current UTC time)

    Returns:
        True if valid, False otherwise
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    not_before = get_certificate_not_before(certificate)
    not_after = get_certificate_expiry_time(certificate)

    return not_before <= timestamp <= not_after


def count_active_certificates(cert_dir: Path, crl_manager=None, timestamp: Optional[datetime] = None) -> int:
    """
    Conta i certificati attivi in una directory secondo ETSI TS 102 941.

    Un certificato è considerato attivo se:
    - È presente nella directory
    - È entro il periodo di validità (not_before <= timestamp <= not_valid_after)
    - Non è revocato (non presente nella lista CRL dell'autorità competente)

    ETSI TS 102 941 Section 6.4.1 - Certificate Validation
    ETSI TS 102 941 Section 7.1 - Certificate Revocation

    Args:
        cert_dir: Directory contenente i certificati PEM
        crl_manager: CRL manager per verificare le revoche (gestisce già Full + Delta CRL)
        timestamp: Momento temporale per validità (default: ora corrente UTC)

    Returns:
        Numero di certificati attivi
    """
    if not cert_dir.exists():
        return 0

    active_count = 0

    # Iterate through all PEM files in directory
    for cert_file in cert_dir.glob("*.pem"):
        try:
            with open(cert_file, 'rb') as f:
                cert_data = f.read()

            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

            if is_certificate_active(cert, crl_manager, timestamp):
                active_count += 1

        except Exception:
            # Skip invalid certificate files
            continue

    return active_count


def is_certificate_revoked(certificate: x509.Certificate, crl_manager=None) -> bool:
    """
    Checks if certificate is revoked according to CRL.

    Args:
        certificate: X.509 certificate
        crl_manager: CRL manager instance (optional)

    Returns:
        True if revoked, False otherwise
    """
    if crl_manager is None:
        return False

    # Check if certificate serial is in revoked list
    serial = certificate.serial_number

    # revoked_certificates contains dicts with 'serial_number' key
    for entry in crl_manager.revoked_certificates:
        if isinstance(entry, dict) and entry.get('serial_number') == serial:
            return True
        elif entry == serial:  # Fallback for direct serial numbers
            return True

    return False


def is_certificate_active(certificate: x509.Certificate, crl_manager=None, timestamp: Optional[datetime] = None) -> bool:
    """
    Checks if certificate is active (valid and not revoked).

    ETSI TS 102 941 Section 6.4.1 - Certificate Validation
    ETSI TS 102 941 Section 7.1 - Certificate Revocation

    Args:
        certificate: X.509 certificate
        crl_manager: CRL manager instance (optional)
        timestamp: Time to check validity (default: current UTC time)

    Returns:
        True if active, False otherwise
    """
    # Check temporal validity
    if not is_certificate_valid_at(certificate, timestamp):
        return False

    # Check revocation status
    if is_certificate_revoked(certificate, crl_manager):
        return False

    return True
