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
    
    🔄 REFACTORED: Usa ASN.1 decoder invece di offset fissi (DRY-compliant)
    =====================================================================
    Questa funzione ora decodifica il certificato con asn1_compiler per estrarre
    esattamente lo stesso TBS usato durante la firma, garantendo correttezza.
    
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
    import logging
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    
    logger = logging.getLogger("TLM_MAIN")  # Usa logger TLM per vedere i log
    
    try:
        # Import ASN.1 compiler (evita import circolari)
        from protocols.certificates.asn1_encoder import decode_certificate_with_asn1, asn1_compiler
        
        logger.info("🔍 [DEBUG] Starting ASN.1-based signature verification")
        
        # 1. Decodifica certificato con ASN.1 decoder ufficiale
        cert_dict = decode_certificate_with_asn1(cert_asn1_oer, "EtsiTs103097Certificate")
        logger.info(f"🔍 [DEBUG] Certificate decoded, keys: {cert_dict.keys()}")
        
        # 2. Estrai TBS usando lo stesso encoder usato durante la firma
        if 'toBeSigned' not in cert_dict:
            raise ValueError("toBeSigned field not found in decoded certificate")
        
        tbs_bytes = asn1_compiler.encode('ToBeSignedCertificate', cert_dict['toBeSigned'])
        logger.info(f"🔍 [DEBUG] TBS extracted: {len(tbs_bytes)} bytes")
        
        # 3. Estrai signature dal certificato decodificato
        if 'signature' not in cert_dict:
            raise ValueError("signature field not found in decoded certificate")
        
        signature = cert_dict['signature']
        
        # DEBUG: Log signature structure
        logger.info(f"🔍 [DEBUG] Signature structure: type={type(signature)}")
        logger.info(f"🔍 [DEBUG] Signature content: {signature}")
        
        # signature è un CHOICE: (tag, value)
        # Esempio: ('ecdsaNistP256Signature', EcdsaP256Signature)
        if not isinstance(signature, tuple) or len(signature) != 2:
            raise ValueError(f"Invalid signature format: {type(signature)}")
        
        sig_alg, sig_value = signature
        logger.info(f"🔍 sig_alg={sig_alg}, sig_value type={type(sig_value)}")
        
        # Supporta solo ECDSA-SHA256 per ora
        if sig_alg != 'ecdsaNistP256Signature':
            raise ValueError(f"Unsupported signature algorithm: {sig_alg}")
        
        # sig_value è un dict con 'rSig' e 'sSig':
        # {
        #     'rSig': ('x-only', r_bytes),  # CHOICE with 32 bytes
        #     'sSig': s_bytes  # OCTET STRING with 32 bytes
        # }
        
        if not isinstance(sig_value, dict):
            raise ValueError(f"Expected dict for signature, got: {type(sig_value)}")
        
        logger.info(f"🔍 sig_value keys: {list(sig_value.keys())}")
        
        if 'rSig' not in sig_value or 'sSig' not in sig_value:
            raise ValueError(f"Missing rSig or sSig in signature: {list(sig_value.keys())}")
        
        # rSig è un CHOICE, tipicamente ('x-only', r_bytes)
        r_sig = sig_value['rSig']
        s_sig = sig_value['sSig']
        
        # Estrai r_bytes
        if isinstance(r_sig, tuple) and len(r_sig) == 2:
            # CHOICE format: (tag, value)
            _, r_bytes = r_sig
        else:
            # Fallback: assume sia già raw bytes
            r_bytes = r_sig
        
        # s_sig dovrebbe essere già bytes
        s_bytes = s_sig
        
        # Concatena r||s
        signature_raw = r_bytes + s_bytes
        
        if len(signature_raw) != 64:
            raise ValueError(f"Invalid signature length: {len(signature_raw)} (expected 64)")
        
        # 4. Converti da formato raw (r||s) a DER per cryptography
        r_int = int.from_bytes(signature_raw[:32], byteorder='big')
        s_int = int.from_bytes(signature_raw[32:64], byteorder='big')
        
        # Skip invalid signatures (all zeros)
        if r_int == 0 or s_int == 0:
            raise ValueError("Invalid signature: r or s is zero")
        
        der_signature = encode_dss_signature(r_int, s_int)
        
        # 5. Verifica firma ECDSA-SHA256 su TBS
        issuer_public_key.verify(
            der_signature,
            tbs_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        logger.info("✅ Signature verified successfully using ASN.1 decoder")
        return True
        
    except Exception as e:
        logger.error(f"❌ Signature verification failed: {e}")
        return False
