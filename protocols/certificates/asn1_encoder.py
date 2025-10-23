"""
ASN.1 Certificate Encoder - Wrapper per asn1_compiler

Fornisce funzioni helper per generare certificati ETSI usando il compiler ASN.1.
Riutilizza il compiler già caricato da protocols.messages.encoder per evitare
duplicazione e garantire conformità ETSI TS 103097 / IEEE 1609.2.

Questo modulo può essere usato dagli encoder esistenti per passare gradualmente
dall'encoding manuale all'uso del compiler ASN.1.

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Standard

Author: SecureRoad PKI Project
Date: October 2025
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

# Riusa il compiler ASN.1 già caricato
from protocols.messages.encoder import asn1_compiler
from protocols.core.primitives import (
    compute_hashed_id8,
    encode_public_key_compressed,
    time32_encode,
)


def build_certificate_dict(
    certificate_type: str,
    issuer_hashed_id8: bytes,
    subject_public_key: EllipticCurvePublicKey,
    start_validity: datetime,
    duration_hours: int,
    subject_id: str,
    country: str = "IT",
    organization: str = "SecureRoad PKI",
    **kwargs
) -> Dict[str, Any]:
    """
    Costruisce un dizionario Python rappresentante un certificato ETSI,
    pronto per essere passato a asn1_compiler.encode().
    
    Args:
        certificate_type: Tipo certificato ("Root", "EA", "AA", "EC", "AT")
        issuer_hashed_id8: HashedId8 dell'issuer (8 bytes)
        subject_public_key: Chiave pubblica del subject
        start_validity: Data inizio validità
        duration_hours: Durata in ore
        subject_id: Identificativo subject (es: "EA_001", "Vehicle_001")
        country: Codice paese (2 char)
        organization: Nome organizzazione
        **kwargs: Parametri aggiuntivi specifici per tipo certificato
        
    Returns:
        Dict rappresentante il certificato in formato ASN.1
    """
    
    # Encode public key in compressed format (33 bytes)
    public_key_compressed = encode_public_key_compressed(subject_public_key)
    
    # Encode validity period
    start_time32 = time32_encode(start_validity)
    
    # Duration come CHOICE (hours)
    duration_choice = ('hours', duration_hours)
    
    # Build CertificateId (CHOICE - usa tupla)
    certificate_id = ('name', subject_id)  # ('name', Hostname)
    
    # Build IssuerIdentifier (CHOICE - usa tupla)
    if len(issuer_hashed_id8) == 8:
        issuer_identifier = ('sha256AndDigest', issuer_hashed_id8)
    else:
        # Self-signed (Root CA) - usa HashAlgorithm enum
        issuer_identifier = ('self', 'sha256')
    
    # Build ToBeSignedCertificate
    to_be_signed = {
        'id': certificate_id,
        'cracaId': b'\x00\x00\x00',  # 3 bytes - sempre 0 per ETSI
        'crlSeries': 0,
        'validityPeriod': {
            'start': start_time32,
            'duration': duration_choice
        },
        'verifyKeyIndicator': ('verificationKey', ('ecdsaNistP256', 
            ('compressed-y-0', public_key_compressed[1:]) if public_key_compressed[0] == 0x02 else ('compressed-y-1', public_key_compressed[1:])
        ))
    }
    
    # Aggiungi campi opzionali in base al tipo certificato
    
    # Region (opzionale)
    if 'region' in kwargs:
        to_be_signed['region'] = kwargs['region']
    
    # Assurance level (opzionale)
    if 'assuranceLevel' in kwargs:
        to_be_signed['assuranceLevel'] = kwargs['assuranceLevel']
    
    # App permissions (per AT)
    if 'appPermissions' in kwargs:
        to_be_signed['appPermissions'] = kwargs['appPermissions']
    
    # Cert issue permissions (per EA/AA)
    if 'certIssuePermissions' in kwargs:
        to_be_signed['certIssuePermissions'] = kwargs['certIssuePermissions']
    
    # Cert request permissions (per EC)
    if 'certRequestPermissions' in kwargs:
        to_be_signed['certRequestPermissions'] = kwargs['certRequestPermissions']
    
    # Encryption key (opzionale)
    if 'encryptionKey' in kwargs:
        to_be_signed['encryptionKey'] = kwargs['encryptionKey']
    
    # Build complete certificate structure
    certificate = {
        'version': 3,
        'type': determine_certificate_type(certificate_type),
        'issuer': issuer_identifier,
        'toBeSigned': to_be_signed,
        # signature verrà aggiunta dopo la firma
    }
    
    return certificate


def determine_certificate_type(cert_type_str: str) -> str:
    """
    Mappa il tipo certificato stringa al valore enum CertificateType.
    
    ETSI TS 103097 Section 6.4.1:
    - explicit: Root CA, EA, AA
    - implicit: Authorization Ticket (AT) 
    
    Note: enrollment type non esiste in IEEE 1609.2, è una constraint ETSI.
    """
    mapping = {
        'Root': 'explicit',
        'EA': 'explicit',
        'AA': 'explicit',
        'AT': 'implicit',
        'EC': 'explicit',  # EC usa explicit, non 'enrollment'
    }
    
    return mapping.get(cert_type_str, 'explicit')


def encode_certificate_with_asn1(
    certificate_dict: Dict[str, Any],
    signature_raw: bytes,
    certificate_type: str = "Certificate"
) -> bytes:
    """
    Codifica un certificato usando asn1_compiler.
    
    Args:
        certificate_dict: Dizionario rappresentante il certificato
        signature_raw: Firma ECDSA in formato raw (64 bytes: r||s)
        certificate_type: Tipo ASN.1 da usare per encoding
        
    Returns:
        bytes: Certificato codificato in formato ASN.1 OER
    """
    
    # Aggiungi signature al certificato
    r = int.from_bytes(signature_raw[:32], byteorder='big')
    s = int.from_bytes(signature_raw[32:64], byteorder='big')
    
    # Signature è un CHOICE - usa tupla
    certificate_dict['signature'] = ('ecdsaNistP256Signature', {
        'rSig': ('x-only', signature_raw[:32]),  # R component (CHOICE)
        'sSig': signature_raw[32:]  # S component (OCTET STRING)
    })
    
    # Encode usando asn1_compiler
    return asn1_compiler.encode(certificate_type, certificate_dict)


def decode_certificate_with_asn1(
    certificate_bytes: bytes,
    certificate_type: str = "Certificate"
) -> Dict[str, Any]:
    """
    Decodifica un certificato usando asn1_compiler.
    
    Args:
        certificate_bytes: Certificato codificato in ASN.1 OER
        certificate_type: Tipo ASN.1 da usare per decoding
        
    Returns:
        Dict rappresentante il certificato decodificato
    """
    return asn1_compiler.decode(certificate_type, certificate_bytes)


# ============================================================================
# HIGH-LEVEL HELPERS PER TIPI SPECIFICI DI CERTIFICATI
# ============================================================================


def generate_root_certificate(
    ca_name: str,
    private_key: EllipticCurvePrivateKey,
    duration_years: int = 10,
    country: str = "IT",
    organization: str = "SecureRoad PKI"
) -> bytes:
    """
    Genera Root CA Certificate self-signed usando ASN.1 compiler.
    
    Args:
        ca_name: Nome della CA (es: "RootCA")
        private_key: Chiave privata della Root CA
        duration_years: Durata validità in anni (max 7 anni per Uint16 hours limit)
        country: Codice paese
        organization: Nome organizzazione
        
    Returns:
        bytes: Root Certificate in formato ASN.1 OER
    """
    public_key = private_key.public_key()
    start_validity = datetime.now(timezone.utc)
    
    # Limita duration_hours a 65535 (max Uint16)
    # 65535 ore = ~7.5 anni, quindi per durate > 7 anni usiamo il max
    duration_hours = min(duration_years * 365 * 24, 65535)
    
    # Build certificate dict (self-signed, issuer = self)
    cert_dict = build_certificate_dict(
        certificate_type="Root",
        issuer_hashed_id8=b'',  # Empty = self-signed
        subject_public_key=public_key,
        start_validity=start_validity,
        duration_hours=duration_hours,
        subject_id=ca_name,
        country=country,
        organization=organization
    )
    
    # Encode TBS (To Be Signed)
    tbs_bytes = asn1_compiler.encode('ToBeSignedCertificate', cert_dict['toBeSigned'])
    
    # Self-sign
    signature_der = private_key.sign(tbs_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    
    # Encode complete certificate
    return encode_certificate_with_asn1(cert_dict, signature_raw, "Certificate")


def generate_subordinate_certificate(
    root_ca_cert_asn1: bytes,
    root_ca_private_key: EllipticCurvePrivateKey,
    authority_public_key: EllipticCurvePublicKey,
    authority_id: str,
    authority_type: str = "EA",
    duration_years: int = 5,
    country: str = "IT",
    organization: str = "SecureRoad PKI",
    encryption_key: Optional[EllipticCurvePublicKey] = None
) -> bytes:
    """
    Genera Subordinate Certificate (EA/AA) firmato da Root CA usando ASN.1.
    
    ETSI TS 102941 § 6.1.3.1: AA certificates MUST include an encryption key
    to allow ITS-S to encrypt authorization requests.
    
    Args:
        root_ca_cert_asn1: Certificato Root CA (per HashedId8)
        root_ca_private_key: Chiave privata Root CA (per firma)
        authority_public_key: Chiave pubblica EA/AA (verification key)
        authority_id: ID dell'authority (es: "EA_001", "AA_001")
        authority_type: "EA" o "AA"
        duration_years: Durata validità in anni (max 7 anni per Uint16 hours limit)
        country: Codice paese
        organization: Nome organizzazione
        encryption_key: Chiave pubblica per encryption (opzionale, generata auto se AA)
        
    Returns:
        bytes: Subordinate Certificate in formato ASN.1 OER
    """
    # Compute Root CA HashedId8
    root_ca_hashed_id8 = compute_hashed_id8(root_ca_cert_asn1)
    
    start_validity = datetime.now(timezone.utc)
    
    # Limita duration_hours a 65535 (max Uint16)
    duration_hours = min(duration_years * 365 * 24, 65535)
    
    # Per AA certificates, aggiungi encryptionKey (ETSI TS 102941 requirement)
    kwargs = {}
    if authority_type == "AA":
        # Se non fornita, usa la stessa chiave per verification e encryption
        # (In produzione, dovrebbero essere chiavi separate)
        enc_key = encryption_key if encryption_key else authority_public_key
        enc_key_compressed = encode_public_key_compressed(enc_key)
        
        # Build PublicEncryptionKey structure
        # PublicEncryptionKey ::= SEQUENCE {
        #     supportedSymmAlg    SymmAlgorithm,
        #     publicKey           BasePublicEncryptionKey
        # }
        kwargs['encryptionKey'] = {
            'supportedSymmAlg': 'aes128Ccm',  # ETSI default
            'publicKey': ('eciesNistP256', 
                ('compressed-y-0', enc_key_compressed[1:]) if enc_key_compressed[0] == 0x02 else ('compressed-y-1', enc_key_compressed[1:])
            )
        }
    
    # Build certificate dict
    cert_dict = build_certificate_dict(
        certificate_type=authority_type,  # "EA" or "AA"
        issuer_hashed_id8=root_ca_hashed_id8,
        subject_public_key=authority_public_key,
        start_validity=start_validity,
        duration_hours=duration_hours,
        subject_id=authority_id,
        country=country,
        organization=organization,
        # Add certIssuePermissions per EA/AA
        certIssuePermissions=[{
            'subjectPermissions': ('all', None),
            'minChainLength': 0,
            'chainLengthRange': 0,
            # EndEntityType is BIT STRING SIZE(8) - encode as (bytes, num_bits)
            # app(0) = bit 0 set = 0x80, enrol(1) = bit 1 set = 0x40
            'eeType': (b'\x80', 8) if authority_type == "AA" else (b'\x40', 8)
        }],
        **kwargs  # Include encryptionKey per AA
    )
    
    # Encode TBS
    tbs_bytes = asn1_compiler.encode('ToBeSignedCertificate', cert_dict['toBeSigned'])
    
    # Sign with Root CA
    signature_der = root_ca_private_key.sign(tbs_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    
    # Encode complete certificate
    return encode_certificate_with_asn1(cert_dict, signature_raw, "Certificate")


def generate_enrollment_certificate(
    ea_cert_asn1: bytes,
    ea_private_key: EllipticCurvePrivateKey,
    its_public_key: EllipticCurvePublicKey,
    its_id: str,
    duration_days: int = 365,
    country: str = "IT",
    organization: str = "SecureRoad PKI"
) -> bytes:
    """
    Genera Enrollment Certificate (EC) firmato da EA usando ASN.1.
    
    Args:
        ea_cert_asn1: Certificato EA (per HashedId8)
        ea_private_key: Chiave privata EA (per firma)
        its_public_key: Chiave pubblica ITS-S
        its_id: ID del veicolo (es: "Vehicle_001")
        duration_days: Durata validità in giorni (max ~2730 giorni per Uint16 hours)
        country: Codice paese
        organization: Nome organizzazione
        
    Returns:
        bytes: Enrollment Certificate in formato ASN.1 OER
    """
    # Compute EA HashedId8
    ea_hashed_id8 = compute_hashed_id8(ea_cert_asn1)
    
    start_validity = datetime.now(timezone.utc)
    
    # Limita duration_hours a 65535 (max Uint16)
    duration_hours = min(duration_days * 24, 65535)
    
    # Build certificate dict
    cert_dict = build_certificate_dict(
        certificate_type="EC",
        issuer_hashed_id8=ea_hashed_id8,
        subject_public_key=its_public_key,
        start_validity=start_validity,
        duration_hours=duration_hours,
        subject_id=its_id,
        country=country,
        organization=organization,
        # EC può richiedere AT
        certRequestPermissions=[{
            'subjectPermissions': ('all', None),
            'minChainLength': 0,
            'chainLengthRange': 0,
            # EndEntityType BIT STRING: app(0) = 0x80
            'eeType': (b'\x80', 8)
        }]
    )
    
    # Encode TBS
    tbs_bytes = asn1_compiler.encode('ToBeSignedCertificate', cert_dict['toBeSigned'])
    
    # Sign with EA
    signature_der = ea_private_key.sign(tbs_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    
    # Encode complete certificate
    return encode_certificate_with_asn1(cert_dict, signature_raw, "Certificate")


def generate_authorization_ticket(
    aa_cert_asn1: bytes,
    aa_private_key: EllipticCurvePrivateKey,
    its_public_key: EllipticCurvePublicKey,
    duration_hours: int = 24,
    app_permissions: Optional[list] = None
) -> bytes:
    """
    Genera Authorization Ticket (AT) firmato da AA usando ASN.1.
    
    Args:
        aa_cert_asn1: Certificato AA (per HashedId8)
        aa_private_key: Chiave privata AA (per firma)
        its_public_key: Chiave pubblica ITS-S (effimera)
        duration_hours: Durata validità in ore (default 24)
        app_permissions: Lista permessi applicazioni (CAM, DENM, etc)
        
    Returns:
        bytes: Authorization Ticket in formato ASN.1 OER
    """
    # Compute AA HashedId8
    aa_hashed_id8 = compute_hashed_id8(aa_cert_asn1)
    
    start_validity = datetime.now(timezone.utc)
    
    # Generate pseudonym ID (random)
    import secrets
    pseudonym_id = f"AT_{secrets.token_hex(4)}"
    
    # Build certificate dict
    cert_kwargs = {
        'certificate_type': "AT",
        'issuer_hashed_id8': aa_hashed_id8,
        'subject_public_key': its_public_key,
        'start_validity': start_validity,
        'duration_hours': duration_hours,
        'subject_id': pseudonym_id,
    }
    
    # Add app permissions se specificati
    if app_permissions:
        cert_kwargs['appPermissions'] = app_permissions
    
    cert_dict = build_certificate_dict(**cert_kwargs)
    
    # Encode TBS
    tbs_bytes = asn1_compiler.encode('ToBeSignedCertificate', cert_dict['toBeSigned'])
    
    # Sign with AA
    signature_der = aa_private_key.sign(tbs_bytes, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    
    # Encode complete certificate
    return encode_certificate_with_asn1(cert_dict, signature_raw, "Certificate")


# Export public API
__all__ = [
    'build_certificate_dict',
    'encode_certificate_with_asn1',
    'decode_certificate_with_asn1',
    'determine_certificate_type',
    'asn1_compiler',  # Re-export per uso diretto
    # High-level generators
    'generate_root_certificate',
    'generate_subordinate_certificate',
    'generate_enrollment_certificate',
    'generate_authorization_ticket',
]
