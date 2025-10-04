"""
Utility functions for certificate identification and management.

Questo modulo fornisce funzioni helper per identificare univocamente
i certificati usando Subject Key Identifier (SKI) invece del serial number.

Approccio: Subject + SKI
- Human-readable: il subject name identifica l'entità
- Univoco: SKI garantisce unicità anche con subject duplicati
- Conforme ETSI: usa standard X.509 (RFC 5280)
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import hashlib


def get_certificate_ski(certificate):
    """
    Estrae o genera il Subject Key Identifier (SKI) di un certificato.
    
    SKI è un identificatore univoco basato sulla chiave pubblica del certificato.
    Se presente come extension, lo estrae; altrimenti lo genera dal fingerprint.
    
    Args:
        certificate: Certificato X.509
        
    Returns:
        str: SKI in formato esadecimale (es: "A1B2C3D4...")
    """
    try:
        # Prova a estrarre SKI dall'extension (se presente)
        ski_ext = certificate.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        ski_bytes = ski_ext.value.digest
        return ski_bytes.hex().upper()
    except x509.ExtensionNotFound:
        # Se non c'è extension SKI, genera da fingerprint della chiave pubblica
        public_key_bytes = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        ski_hash = hashlib.sha256(public_key_bytes).digest()
        # Usa primi 20 byte (160 bit) come da RFC 5280
        return ski_hash[:20].hex().upper()


def get_certificate_identifier(certificate):
    """
    Genera un identificatore univoco per un certificato basato su Subject + SKI.
    
    Formato: "CN=EntityName_SKI-A1B2C3D4E5F6"
    
    Questo identificatore è:
    - Human-readable: contiene il Common Name
    - Univoco: SKI garantisce unicità
    - File-system safe: usa solo caratteri validi per nomi file
    - Compatto: troncato per praticità
    
    Args:
        certificate: Certificato X.509
        
    Returns:
        str: Identificatore univoco (es: "CN=RootCA_SKI-A1B2C3D4E5F6")
    """
    # Estrai Common Name dal subject
    try:
        cn = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        # Fallback: usa tutto il subject RFC4514
        cn = certificate.subject.rfc4514_string().replace(",", "_").replace("=", "-")
    
    # Estrai SKI
    ski = get_certificate_ski(certificate)
    
    # Trunca SKI a primi 12 caratteri per leggibilità (sufficientemente univoco)
    ski_short = ski[:12]
    
    # Sanitizza CN per file system (rimuovi caratteri non validi)
    cn_safe = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in cn)
    
    return f"CN={cn_safe}_SKI-{ski_short}"


def get_certificate_fingerprint(certificate):
    """
    Calcola SHA-256 fingerprint del certificato.
    
    Questo è l'hash dell'intero certificato in formato DER.
    Completamente univoco ma meno human-readable del SKI.
    
    Args:
        certificate: Certificato X.509
        
    Returns:
        str: Fingerprint SHA-256 in formato esadecimale
    """
    cert_der = certificate.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
    return fingerprint


def get_short_identifier(certificate, max_length=32):
    """
    Genera un identificatore corto per uso in nomi file.
    
    Formato: "EntityName_A1B2C3D4"
    
    Args:
        certificate: Certificato X.509
        max_length: Lunghezza massima dell'identificatore
        
    Returns:
        str: Identificatore corto
    """
    try:
        cn = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        cn = "Unknown"
    
    # Sanitizza CN
    cn_safe = "".join(c if c.isalnum() or c in ('-', '_') else '_' for c in cn)
    
    # Estrai SKI
    ski = get_certificate_ski(certificate)
    ski_short = ski[:8]  # Usa solo 8 caratteri
    
    identifier = f"{cn_safe}_{ski_short}"
    
    # Trunca se troppo lungo
    if len(identifier) > max_length:
        # Mantieni sempre almeno gli ultimi 8 caratteri (SKI)
        cn_max = max_length - 9  # -9 per "_" + 8 char SKI
        identifier = f"{cn_safe[:cn_max]}_{ski_short}"
    
    return identifier


def compare_certificates(cert1, cert2):
    """
    Confronta due certificati per verificare se sono identici.
    
    Usa SKI per il confronto (più efficiente del fingerprint completo).
    
    Args:
        cert1: Primo certificato X.509
        cert2: Secondo certificato X.509
        
    Returns:
        bool: True se i certificati sono identici
    """
    return get_certificate_ski(cert1) == get_certificate_ski(cert2)


def format_certificate_info(certificate):
    """
    Formatta informazioni leggibili su un certificato per logging.
    
    Args:
        certificate: Certificato X.509
        
    Returns:
        str: Stringa formattata con info certificato
    """
    try:
        cn = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        cn = "Unknown"
    
    ski = get_certificate_ski(certificate)
    serial = certificate.serial_number
    
    return f"{cn} (SKI: {ski[:16]}..., Serial: {serial})"
