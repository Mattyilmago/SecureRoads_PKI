"""
ETSI Certificate Utilities - ASN.1 OER Certificate Helper Functions

This module provides centralized utility functions for working with ETSI TS 103097
certificates in ASN.1 OER format. These functions implement DRY principles by
providing reusable components for certificate validation, extraction, and verification.

Functions included:
- ValidityPeriod extraction and expiry checking
- Cryptographic signature verification
- Public key extraction and encoding/decoding
- HashedId8 computation

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Services

Design Principles:
- DRY (Don't Repeat Yourself): Centralized utility functions
- Single Responsibility: Each function has one clear purpose
- ETSI Compliance: Strict adherence to ETSI standards

Author: SecureRoad PKI Project
Date: October 2025
"""

import hashlib
import struct
from datetime import datetime, timedelta, timezone
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


# ============================================================================
# ETSI CONSTANTS
# ============================================================================

# ETSI Epoch: 2004-01-01 00:00:00 UTC (TAI - International Atomic Time)
ETSI_EPOCH = datetime(2004, 1, 1, tzinfo=timezone.utc)


# ============================================================================
# TIME ENCODING/DECODING
# ============================================================================


def time32_encode(dt: datetime) -> int:
    """
    Encode datetime to Time32 format.
    
    ETSI TS 103097 Section 4.2.15: Time32
    Represents seconds since ETSI epoch (2004-01-01 00:00:00 UTC).
    
    Args:
        dt: Datetime object to encode (must be UTC-aware)
        
    Returns:
        int: Seconds since ETSI epoch (32-bit unsigned)
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    delta = dt - ETSI_EPOCH
    return int(delta.total_seconds())


def time32_decode(time32: int) -> datetime:
    """
    Decode Time32 to datetime.
    
    ETSI TS 103097 Section 4.2.15: Time32
    
    Args:
        time32: Seconds since ETSI epoch
        
    Returns:
        datetime: Decoded datetime object (UTC-aware)
    """
    return ETSI_EPOCH + timedelta(seconds=time32)


# ============================================================================
# HASHED IDENTIFIER COMPUTATION
# ============================================================================


def compute_hashed_id8(certificate_bytes: bytes) -> bytes:
    """
    Compute HashedId8 from certificate bytes.
    
    ETSI TS 103097 Section 4.2.11: HashedId8
    HashedId8 = SHA-256(certificate)[-8:]  # Last 8 bytes
    
    This is the canonical identifier for ETSI certificates used in:
    - Certificate references in CTL
    - Issuer identification
    - Certificate chain validation
    
    Args:
        certificate_bytes: Complete certificate (ASN.1 OER or DER)
        
    Returns:
        bytes: Last 8 bytes of SHA-256 hash (HashedId8)
    """
    hash_value = hashlib.sha256(certificate_bytes).digest()
    return hash_value[-8:]  # Last 8 bytes (ETSI standard)


# ============================================================================
# VALIDITY PERIOD EXTRACTION
# ============================================================================


def extract_validity_period(cert_asn1_oer: bytes) -> Tuple[datetime, datetime, int]:
    """
    Estrae ValidityPeriod da un certificato ASN.1 OER generico.
    
    Funzione centralizzata DRY-compliant per estrarre periodo di validità
    da qualsiasi certificato ETSI TS 103097 V2.1.1 in formato ASN.1 OER.
    
    ETSI TS 103097 v2.1.1 Section 6.4.6:
    ValidityPeriod ::= SEQUENCE {
        start     Time32,    -- 4 bytes, seconds since ETSI epoch (2004-01-01)
        duration  Duration   -- 4 bytes, validity duration in seconds
    }
    
    Args:
        cert_asn1_oer: Certificato ASN.1 OER completo (bytes)
        
    Returns:
        tuple: (start_datetime, expiry_datetime, duration_seconds)
            - start_datetime: Data/ora inizio validità (datetime UTC)
            - expiry_datetime: Data/ora scadenza (datetime UTC)
            - duration_seconds: Durata in secondi (int)
            
    Raises:
        ValueError: Se il certificato è malformato o ValidityPeriod non trovato
    """
    try:
        # Struttura comune certificati ASN.1 OER:
        # [tbs_len(2) | version(1) | type(1) | issuer_type(1) | issuer_id(8) | 
        #  validity_period(8: start_time32(4) + duration(4)) | ...]
        
        # Offset tipico per ValidityPeriod: dopo version(1) + type(1) + issuer(1+8) = 11
        # Ma potrebbe variare, quindi proviamo offset comuni
        
        # Leggi TBS length (primi 2 bytes)
        if len(cert_asn1_oer) < 2:
            raise ValueError("Certificate too short to extract ValidityPeriod")
        
        tbs_len = struct.unpack('>H', cert_asn1_oer[0:2])[0]
        
        if len(cert_asn1_oer) < 2 + tbs_len:
            raise ValueError(f"Certificate truncated: expected {2 + tbs_len} bytes")
        
        tbs_data = cert_asn1_oer[2:2+tbs_len]
        
        # ValidityPeriod è tipicamente a offset 11 in TBS (dopo version + type + issuer)
        # Offset possibili: 11 (standard), 10, 12 (variazioni struttura)
        for validity_offset in [11, 10, 12, 13]:
            if len(tbs_data) < validity_offset + 8:
                continue
            
            try:
                # Estrai start Time32 (4 bytes) e duration (4 bytes)
                start_time32, duration_sec = struct.unpack(
                    '>II', 
                    tbs_data[validity_offset:validity_offset+8]
                )
                
                # Sanity check: start_time32 deve essere ragionevole
                # ETSI epoch: 2004-01-01, quindi start_time32 > 0 e < 2^31
                if start_time32 == 0 or start_time32 > 0x7FFFFFFF:
                    continue
                
                # Sanity check: duration deve essere ragionevole (max 10 anni)
                if duration_sec == 0 or duration_sec > (10 * 365 * 86400):
                    continue
                
                # Decodifica start time
                start_datetime = time32_decode(start_time32)
                
                # Calcola expiry
                expiry_datetime = start_datetime + timedelta(seconds=duration_sec)
                
                return (start_datetime, expiry_datetime, duration_sec)
                
            except Exception:
                # Prova prossimo offset
                continue
        
        raise ValueError("ValidityPeriod not found at expected offsets")
        
    except Exception as e:
        raise ValueError(f"Failed to extract ValidityPeriod: {e}")


# ============================================================================
# PUBLIC KEY ENCODING/DECODING
# ============================================================================


def encode_public_key_compressed(public_key: EllipticCurvePublicKey) -> bytes:
    """
    Encode ECDSA public key to compressed point format.
    
    ETSI TS 103097 Section 5.3.4:
    EccP256CurvePoint ::= CHOICE {
        compressed-y-0 OCTET STRING (SIZE(32)),  -- y = 0
        compressed-y-1 OCTET STRING (SIZE(32)),  -- y = 1
        uncompressedP256 SEQUENCE {
            x OCTET STRING (SIZE(32)),
            y OCTET STRING (SIZE(32))
        }
    }
    
    Args:
        public_key: EllipticCurvePublicKey object (NIST P-256)
        
    Returns:
        bytes: Compressed point (33 bytes: 0x02/0x03 + x-coordinate)
    """
    # Get uncompressed point format (0x04 + x + y)
    uncompressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    if len(uncompressed) != 65:  # 1 + 32 + 32 for P-256
        raise ValueError(f"Invalid public key size: {len(uncompressed)} bytes")
    
    # Extract coordinates
    x = uncompressed[1:33]
    y = uncompressed[33:65]
    
    # Determine compression prefix based on y parity
    y_int = int.from_bytes(y, byteorder='big')
    prefix = b'\x02' if y_int % 2 == 0 else b'\x03'
    
    # Return compressed format: prefix + x
    return prefix + x


def decode_public_key_compressed(compressed_key: bytes) -> EllipticCurvePublicKey:
    """
    Decode compressed ECDSA public key (ETSI TS 103097 format).
    
    Args:
        compressed_key: Compressed key (33 bytes: prefix + x-coordinate)
        
    Returns:
        EllipticCurvePublicKey: Decompressed public key
        
    Raises:
        ValueError: If key format is invalid
    """
    if len(compressed_key) != 33:
        raise ValueError(f"Invalid compressed key length: {len(compressed_key)} bytes (expected 33)")
    
    prefix = compressed_key[0]
    if prefix not in (0x02, 0x03):
        raise ValueError(f"Invalid compression prefix: 0x{prefix:02x}")
    
    # Extract x-coordinate
    x_bytes = compressed_key[1:33]
    x = int.from_bytes(x_bytes, byteorder='big')
    
    # NIST P-256 parameters
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = p - 3
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    
    # Compute y² = x³ + ax + b (mod p)
    y_squared = (pow(x, 3, p) + a * x + b) % p
    
    # Compute y using modular square root (Tonelli-Shanks or direct for P-256)
    # For P-256, p ≡ 3 (mod 4), so we can use: y = y²^((p+1)/4) mod p
    y = pow(y_squared, (p + 1) // 4, p)
    
    # Choose correct y based on prefix (even/odd)
    if (y % 2 == 0 and prefix == 0x03) or (y % 2 == 1 and prefix == 0x02):
        y = p - y
    
    # Construct uncompressed point: 0x04 + x + y
    x_bytes_padded = x.to_bytes(32, byteorder='big')
    y_bytes_padded = y.to_bytes(32, byteorder='big')
    uncompressed = b'\x04' + x_bytes_padded + y_bytes_padded
    
    # Create public key from uncompressed point
    return ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(),
        uncompressed
    )


# ============================================================================
# CERTIFICATE SIGNATURE VERIFICATION
# ============================================================================


def verify_asn1_certificate_signature(
    cert_asn1_oer: bytes,
    issuer_public_key: EllipticCurvePublicKey,
) -> bool:
    """
    Verifica la firma crittografica di un certificato ASN.1 OER generico.
    
    Funzione centralizzata DRY-compliant per verificare firme ECDSA-SHA256
    su certificati ETSI TS 103097 V2.1.1 in formato ASN.1 OER.
    
    ETSI TS 102941 v2.1.1 Section 6.1.3.2 - Certificate Signature Verification
    
    Supporta tutti i tipi di certificati ETSI:
    - Root CA Certificates (self-signed)
    - Authority Certificates (EA, AA)
    - Enrollment Certificates
    - Authorization Tickets
    - Link Certificates
    
    Args:
        cert_asn1_oer: Certificato ASN.1 OER completo (bytes)
        issuer_public_key: Chiave pubblica dell'issuer (EllipticCurvePublicKey)
        
    Returns:
        bool: True se la firma è valida, False altrimenti
        
    Raises:
        ValueError: Se il certificato è malformato
    """
    try:
        # Struttura certificato ASN.1 OER generica:
        # [headers_vari | tbs_len(2) | tbs_data | sig_type(1) | signature(64)]
        
        if len(cert_asn1_oer) < 67:  # Minimo teorico
            raise ValueError("Certificate too short for signature verification")
        
        # Prova offset comuni per TBS length (dipende dal tipo certificato)
        # Offset possibili: 11-13 per la maggior parte dei certificati ETSI
        for tbs_offset in [11, 12, 13, 10, 14]:
            if len(cert_asn1_oer) < tbs_offset + 2:
                continue
                
            try:
                # Leggi TBS length (2 bytes big-endian)
                tbs_len = struct.unpack('>H', cert_asn1_oer[tbs_offset:tbs_offset+2])[0]
                
                # Verifica lunghezza ragionevole
                if tbs_len < 10 or tbs_len > 10000:  # Sanity check
                    continue
                
                # Estrai TBS data
                tbs_start = tbs_offset + 2
                tbs_end = tbs_start + tbs_len
                
                if tbs_end + 65 > len(cert_asn1_oer):  # Deve esserci spazio per sig
                    continue
                
                tbs_data = cert_asn1_oer[tbs_start:tbs_end]
                
                # Estrai signature type (1 byte)
                sig_type = cert_asn1_oer[tbs_end]
                if sig_type != 0x00:  # Solo ECDSA-SHA256 supportato
                    continue
                
                # Estrai signature (64 bytes: R 32 + S 32)
                signature_raw = cert_asn1_oer[tbs_end+1:tbs_end+1+64]
                if len(signature_raw) != 64:
                    continue
                
                # Converti da formato raw (r||s) a DER per cryptography
                r_int = int.from_bytes(signature_raw[:32], byteorder='big')
                s_int = int.from_bytes(signature_raw[32:64], byteorder='big')
                
                # Skip invalid signatures (all zeros or malformed)
                if r_int == 0 or s_int == 0:
                    continue
                
                der_signature = encode_dss_signature(r_int, s_int)
                
                # Verifica firma ECDSA-SHA256
                issuer_public_key.verify(
                    der_signature,
                    tbs_data,
                    ec.ECDSA(hashes.SHA256())
                )
                
                # Firma verificata con successo
                return True
                
            except Exception:
                # Prova prossimo offset
                continue
        
        # Nessun offset ha prodotto una firma valida
        return False
        
    except Exception as e:
        raise ValueError(f"Certificate signature verification failed: {e}")


# ============================================================================
# PUBLIC KEY EXTRACTION FROM CERTIFICATES
# ============================================================================


def extract_public_key_from_asn1_certificate(cert_asn1_oer: bytes, key_type: str = "verification") -> EllipticCurvePublicKey:
    """
    Estrae la chiave pubblica da un certificato ASN.1 OER generico.
    
    Questa funzione decodifica il certificato ASN.1 OER usando il decoder ufficiale
    e estrae la chiave pubblica dal campo verifyKeyIndicator o encryptionKey, supportando:
    - Root CA certificates
    - Authority certificates (EA, AA)
    - Enrollment certificates
    - Authorization Tickets
    
    ETSI TS 103097 v2.1.1 Section 6.4.11: VerificationKeyIndicator
    ETSI TS 103097 v2.1.1 Section 6.4.26: PublicEncryptionKey
    
    Args:
        cert_asn1_oer: Certificato ASN.1 OER completo (bytes)
        key_type: Tipo di chiave da estrarre:
                  - "verification": chiave di verifica firma (default)
                  - "encryption": chiave di cifratura (per AA/EA certificates)
        
    Returns:
        EllipticCurvePublicKey: Chiave pubblica estratta
        
    Raises:
        ValueError: Se la chiave pubblica non può essere estratta
    """
    try:
        # Import asn1_compiler qui per evitare import circolari
        from protocols.certificates.asn1_encoder import decode_certificate_with_asn1
        
        # Decodifica certificato usando ASN.1 decoder ufficiale
        cert_dict = decode_certificate_with_asn1(cert_asn1_oer, "EtsiTs103097Certificate")
        
        # Naviga nella struttura decodificata per trovare la chiave richiesta
        # Struttura: certificate -> toBeSigned -> verifyKeyIndicator / encryptionKey
        if 'toBeSigned' not in cert_dict:
            raise ValueError("toBeSigned field not found in certificate")
        
        to_be_signed = cert_dict['toBeSigned']
        
        # Se richiesta chiave di encryption, cerca nel campo encryptionKey
        if key_type == "encryption":
            if 'encryptionKey' not in to_be_signed:
                raise ValueError("encryptionKey field not found in certificate")
            
            encryption_key = to_be_signed['encryptionKey']
            
            # encryptionKey è PublicEncryptionKey
            # PublicEncryptionKey ::= SEQUENCE {
            #     supportedSymmAlg    SymmAlgorithm,
            #     publicKey           BasePublicEncryptionKey
            # }
            # BasePublicEncryptionKey ::= CHOICE {
            #     eciesNistP256       EccP256CurvePoint,
            #     eciesBrainpoolP256r1 EccP256CurvePoint,
            #     ...
            # }
            
            if not isinstance(encryption_key, dict):
                raise ValueError("Invalid encryptionKey format")
            
            if 'publicKey' not in encryption_key:
                raise ValueError("publicKey field not found in encryptionKey")
            
            public_key = encryption_key['publicKey']
            
            # publicKey è un CHOICE (BasePublicEncryptionKey)
            if not isinstance(public_key, tuple) or len(public_key) != 2:
                raise ValueError("Invalid BasePublicEncryptionKey format")
            
            alg_tag, key_data = public_key
            
            # Supporta eciesNistP256
            if alg_tag not in ('eciesNistP256', 'eciesBrainpoolP256r1'):
                raise ValueError(f"Unsupported encryption algorithm: {alg_tag}")
            
            # key_data è EccP256CurvePoint (CHOICE)
            return _extract_ecc_point(key_data)
        
        # Altrimenti, estrai la chiave di verifica (default)
        if 'verifyKeyIndicator' not in to_be_signed:
            raise ValueError("verifyKeyIndicator field not found in toBeSigned")
        
        verify_key_indicator = to_be_signed['verifyKeyIndicator']
        
        # verifyKeyIndicator è un CHOICE, può essere:
        # - ('verificationKey', PublicVerificationKey)
        # - ('reconstructionValue', EccP256CurvePoint)
        
        if not isinstance(verify_key_indicator, tuple) or len(verify_key_indicator) != 2:
            raise ValueError("Invalid verifyKeyIndicator format")
        
        choice_tag, choice_value = verify_key_indicator
        
        if choice_tag == 'verificationKey':
            # PublicVerificationKey è anche un CHOICE
            if not isinstance(choice_value, tuple) or len(choice_value) != 2:
                raise ValueError("Invalid PublicVerificationKey format")
            
            alg_tag, key_data = choice_value
            
            # Supporta solo ecdsaNistP256 per ora
            if alg_tag != 'ecdsaNistP256':
                raise ValueError(f"Unsupported algorithm: {alg_tag}")
            
            # key_data è EccP256CurvePoint (CHOICE)
            return _extract_ecc_point(key_data)
            
        elif choice_tag == 'reconstructionValue':
            # Per ora non supportato - usato per certificate compression
            raise ValueError("reconstructionValue not supported yet")
        
        else:
            raise ValueError(f"Unknown verifyKeyIndicator choice: {choice_tag}")
        
    except Exception as e:
        raise ValueError(f"Failed to extract public key ({key_type}): {e}")


def _extract_ecc_point(key_data) -> EllipticCurvePublicKey:
    """
    Helper function per estrarre una chiave ECC da un EccP256CurvePoint.
    
    Args:
        key_data: EccP256CurvePoint (CHOICE format)
        
    Returns:
        EllipticCurvePublicKey: Chiave pubblica estratta
        
    Raises:
        ValueError: Se il formato non è valido
    """
    # key_data è EccP256CurvePoint (CHOICE)
    if not isinstance(key_data, tuple) or len(key_data) != 2:
        raise ValueError("Invalid EccP256CurvePoint format")
    
    point_type, point_data = key_data
    
    # Ricostruisci chiave compressa da compressed-y-0 o compressed-y-1
    if point_type == 'compressed-y-0':
        compressed_key = b'\x02' + point_data  # point_data è 32 bytes (x-coordinate)
    elif point_type == 'compressed-y-1':
        compressed_key = b'\x03' + point_data
    elif point_type == 'uncompressedP256':
        # point_data è un dict {'x': bytes, 'y': bytes}
        x = point_data['x']
        y = point_data['y']
        uncompressed = b'\x04' + x + y
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            uncompressed
        )
    else:
        raise ValueError(f"Unsupported point format: {point_type}")
    
    # Decodifica chiave compressa
    return decode_public_key_compressed(compressed_key)
