"""
Certificate utility functions for PKI operations.

Provides helper functions for certificate SKI extraction, identifier generation,
and temporal information handling.
"""

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from datetime import datetime, timezone
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
    expiry = certificate.not_valid_after
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry


def get_certificate_not_before(certificate: x509.Certificate) -> datetime:
    """
    Extracts certificate validity start timestamp (timezone-aware).

    Args:
        certificate: X.509 certificate

    Returns:
        Start datetime in UTC
    """
    not_before = certificate.not_valid_before
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    return not_before


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
