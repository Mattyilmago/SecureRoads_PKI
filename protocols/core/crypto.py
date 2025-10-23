"""
ETSI Cryptographic Operations

Provides core cryptographic operations for ETSI ITS PKI:
- ECDSA signature generation and verification
- ECDH shared secret computation
- HKDF key derivation

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- NIST SP 800-56A Rev. 3 - ECDH
- RFC 5869 - HKDF

Author: SecureRoad PKI Project
Date: October 2025
"""

from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature


# ============================================================================
# ECDSA SIGNATURE OPERATIONS (ETSI TS 103097 Section 5.3.1)
# ============================================================================


def sign_data_ecdsa_sha256(data: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
    """
    Sign data using ECDSA with SHA-256.
    
    ETSI TS 103097 Section 5.3.1: Signature
    Returns raw signature format (r || s, 64 bytes total).
    
    Args:
        data: Data to sign (typically ToBeSignedCertificate or message hash)
        private_key: ECDSA private key (NIST P-256)
        
    Returns:
        bytes: Raw ECDSA signature (64 bytes: r || s)
        
    Raises:
        ValueError: If signature generation fails
    """
    if not data:
        raise ValueError("Data to sign cannot be empty")
    
    try:
        # Sign with ECDSA-SHA256
        der_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        
        # Convert DER signature to raw format (r || s)
        # DER format: 0x30 [total_len] 0x02 [r_len] [r] 0x02 [s_len] [s]
        # We need to extract r and s and concatenate them
        
        # Parse DER signature
        if der_signature[0] != 0x30:
            raise ValueError("Invalid DER signature format")
        
        # Skip sequence header (0x30 + length)
        offset = 2
        
        # Parse r
        if der_signature[offset] != 0x02:
            raise ValueError("Invalid DER signature: r not found")
        offset += 1
        r_len = der_signature[offset]
        offset += 1
        r_bytes = der_signature[offset:offset + r_len]
        offset += r_len
        
        # Parse s
        if der_signature[offset] != 0x02:
            raise ValueError("Invalid DER signature: s not found")
        offset += 1
        s_len = der_signature[offset]
        offset += 1
        s_bytes = der_signature[offset:offset + s_len]
        
        # Remove leading zero bytes if present (DER encoding)
        r_bytes = r_bytes.lstrip(b'\x00')
        s_bytes = s_bytes.lstrip(b'\x00')
        
        # Pad to 32 bytes (P-256 coordinate size)
        r_bytes = r_bytes.rjust(32, b'\x00')
        s_bytes = s_bytes.rjust(32, b'\x00')
        
        # Return raw format: r || s
        return r_bytes + s_bytes
        
    except Exception as e:
        raise ValueError(f"Failed to sign data: {e}")


def verify_signature_ecdsa_sha256(
    data: bytes,
    signature: bytes,
    public_key: EllipticCurvePublicKey
) -> bool:
    """
    Verify ECDSA-SHA256 signature.
    
    ETSI TS 103097 Section 5.3.1: Signature verification
    Accepts raw signature format (r || s, 64 bytes).
    
    Args:
        data: Original data that was signed
        signature: Raw ECDSA signature (64 bytes: r || s)
        public_key: ECDSA public key (NIST P-256)
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    if not data:
        return False
    
    if len(signature) != 64:
        return False
    
    try:
        # Extract r and s from raw format
        r_bytes = signature[:32]
        s_bytes = signature[32:64]
        
        # Convert to integers
        r = int.from_bytes(r_bytes, byteorder='big')
        s = int.from_bytes(s_bytes, byteorder='big')
        
        # Convert to DER format for cryptography library
        # DER: 0x30 [total_len] 0x02 [r_len] [r] 0x02 [s_len] [s]
        
        # Remove leading zeros but keep at least one byte
        r_bytes_minimal = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big') or b'\x00'
        s_bytes_minimal = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big') or b'\x00'
        
        # Add leading zero if high bit is set (DER encoding rule)
        if r_bytes_minimal[0] & 0x80:
            r_bytes_minimal = b'\x00' + r_bytes_minimal
        if s_bytes_minimal[0] & 0x80:
            s_bytes_minimal = b'\x00' + s_bytes_minimal
        
        # Build DER signature
        r_part = b'\x02' + bytes([len(r_bytes_minimal)]) + r_bytes_minimal
        s_part = b'\x02' + bytes([len(s_bytes_minimal)]) + s_bytes_minimal
        total_len = len(r_part) + len(s_part)
        der_signature = b'\x30' + bytes([total_len]) + r_part + s_part
        
        # Verify signature
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
        
    except InvalidSignature:
        return False
    except Exception:
        return False


# ============================================================================
# ECDH OPERATIONS (NIST SP 800-56A)
# ============================================================================


def compute_ecdh_shared_secret(
    private_key: EllipticCurvePrivateKey,
    public_key: EllipticCurvePublicKey
) -> bytes:
    """
    Compute ECDH shared secret.
    
    Used in ECIES encryption and butterfly key expansion.
    
    NIST SP 800-56A Rev. 3: Elliptic Curve Diffie-Hellman
    
    Args:
        private_key: Local ECDSA private key
        public_key: Remote ECDSA public key
        
    Returns:
        bytes: Shared secret (32 bytes for P-256)
        
    Raises:
        ValueError: If shared secret computation fails
    """
    try:
        shared_secret = private_key.exchange(ec.ECDH(), public_key)
        return shared_secret
    except Exception as e:
        raise ValueError(f"Failed to compute ECDH shared secret: {e}")


# ============================================================================
# HKDF KEY DERIVATION (RFC 5869)
# ============================================================================


def derive_key_hkdf(
    input_key_material: bytes,
    length: int,
    info: bytes,
    salt: Optional[bytes] = None
) -> bytes:
    """
    Derive key using HKDF-SHA256.
    
    RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function
    Used in butterfly key expansion and ECIES.
    
    Args:
        input_key_material: Input keying material (e.g., ECDH shared secret)
        length: Desired output key length in bytes
        info: Context-specific information (application/purpose identifier)
        salt: Optional salt value (None = zero-length salt)
        
    Returns:
        bytes: Derived key material
        
    Raises:
        ValueError: If derivation fails or parameters are invalid
    """
    if not input_key_material:
        raise ValueError("Input key material cannot be empty")
    
    if length < 1 or length > 255 * 32:  # HKDF-SHA256 limit
        raise ValueError(f"Invalid output length: {length} (must be 1-8160)")
    
    try:
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return kdf.derive(input_key_material)
    except Exception as e:
        raise ValueError(f"Failed to derive key: {e}")


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
    import struct
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    
    try:
        # Struttura certificato ASN.1 OER generica:
        # [headers_vari | tbs_len(2) | tbs_data | sig_type(1) | signature(64)]
        
        if len(cert_asn1_oer) < 67:  # Minimo teorico
            raise ValueError("Certificate too short for signature verification")
        
        # Prova offset comuni per TBS length (dipende dal tipo certificato)
        # Offset possibili: 
        # - Enrollment Certificates: offset 0 (TBS length at start!)
        # - Authority Certificates: offset 11 (version + type + issuer choice + HashedId8)
        # - Root Certificates: offset 11-13
        for tbs_offset in [0, 11, 12, 13, 10, 14, 3]:
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
