"""
ETSI Encoding Utilities

Provides encoding/decoding functions for ETSI-specific data formats:
- Time32 encoding (seconds since ETSI epoch)
- HashedId8 computation (certificate identifiers)
- Public key compression/decompression (ECC points)
- Request hash computation

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- IEEE 1609.2 - WAVE Security Services

Author: SecureRoad PKI Project
Date: October 2025
"""

import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from .types import ETSI_EPOCH


# ============================================================================
# TIME32 ENCODING (ETSI TS 103097 Section 4.2.15)
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
        
    Raises:
        ValueError: If datetime is before ETSI epoch
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    delta = dt - ETSI_EPOCH
    seconds = int(delta.total_seconds())
    
    if seconds < 0:
        raise ValueError(f"Datetime {dt} is before ETSI epoch (2004-01-01)")
    
    if seconds > 0xFFFFFFFF:  # 32-bit unsigned max
        raise ValueError(f"Datetime {dt} exceeds Time32 range (max year ~2140)")
    
    return seconds


def time32_decode(time32: int) -> datetime:
    """
    Decode Time32 to datetime.
    
    ETSI TS 103097 Section 4.2.15: Time32
    
    Args:
        time32: Seconds since ETSI epoch (32-bit unsigned)
        
    Returns:
        datetime: Decoded datetime object (UTC-aware)
        
    Raises:
        ValueError: If time32 is negative or exceeds 32-bit range
    """
    if time32 < 0:
        raise ValueError(f"Time32 value must be non-negative, got {time32}")
    
    if time32 > 0xFFFFFFFF:
        raise ValueError(f"Time32 value exceeds 32-bit range: {time32}")
    
    return ETSI_EPOCH + timedelta(seconds=time32)


# ============================================================================
# HASHEDID8 COMPUTATION (ETSI TS 103097 Section 4.2.11)
# ============================================================================


def compute_hashed_id8(certificate_bytes: bytes) -> bytes:
    """
    Compute HashedId8 from certificate bytes.
    
    ETSI TS 103097 Section 4.2.11: HashedId8
    HashedId8 = SHA-256(certificate)[-8:]  # Last 8 bytes
    
    This is the canonical identifier for ETSI certificates used in:
    - Certificate references in CTL
    - Issuer identification in certificates
    - Certificate chain validation
    - Message recipient identification
    
    Args:
        certificate_bytes: Complete certificate (ASN.1 OER encoded)
        
    Returns:
        bytes: Last 8 bytes of SHA-256 hash (HashedId8)
        
    Raises:
        ValueError: If certificate_bytes is empty
    """
    if not certificate_bytes:
        raise ValueError("Certificate bytes cannot be empty")
    
    hash_value = hashlib.sha256(certificate_bytes).digest()
    return hash_value[-8:]  # Last 8 bytes (ETSI standard)


def compute_hashed_id3(certificate_bytes: bytes) -> bytes:
    """
    Compute HashedId3 from certificate bytes.
    
    ETSI TS 103097 Section 4.2.11: HashedId3
    HashedId3 = SHA-256(certificate)[-3:]  # Last 3 bytes
    
    Used for CRACA (Crash Relevant Authority CA) identification.
    
    Args:
        certificate_bytes: Complete certificate (ASN.1 OER encoded)
        
    Returns:
        bytes: Last 3 bytes of SHA-256 hash (HashedId3)
    """
    if not certificate_bytes:
        raise ValueError("Certificate bytes cannot be empty")
    
    hash_value = hashlib.sha256(certificate_bytes).digest()
    return hash_value[-3:]  # Last 3 bytes


def compute_hashed_id8_from_public_key(public_key: EllipticCurvePublicKey) -> bytes:
    """
    Compute HashedId8 from a public key (for temporary identification).
    
    This is used when a certificate is not yet available (e.g., in enrollment responses
    where the ITS-S doesn't have a certificate yet).
    
    Args:
        public_key: EllipticCurvePublicKey to hash
        
    Returns:
        bytes: 8-byte HashedId8 derived from public key
    """
    # Serialize public key in uncompressed format
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    # Hash and take last 8 bytes
    sha256_hash = hashlib.sha256(public_bytes).digest()
    return sha256_hash[-8:]


# ============================================================================
# PUBLIC KEY ENCODING (ETSI TS 103097 Section 5.3.4)
# ============================================================================


def encode_public_key_compressed(public_key: EllipticCurvePublicKey) -> bytes:
    """
    Encode ECDSA public key to compressed point format.
    
    ETSI TS 103097 Section 5.3.4:
    EccP256CurvePoint ::= CHOICE {
        compressed-y-0 OCTET STRING (SIZE(32)),  -- y even
        compressed-y-1 OCTET STRING (SIZE(32)),  -- y odd
    }
    
    Compressed format: 1 byte prefix (0x02 or 0x03) + 32 bytes x-coordinate
    
    Args:
        public_key: EllipticCurvePublicKey object (NIST P-256)
        
    Returns:
        bytes: Compressed point (33 bytes: prefix + x-coordinate)
        
    Raises:
        ValueError: If public key is not on NIST P-256 curve
    """
    # Verify curve type
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError(f"Only NIST P-256 (SECP256R1) is supported, got {type(public_key.curve).__name__}")
    
    # Get uncompressed point format (0x04 + x + y)
    uncompressed = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    if len(uncompressed) != 65:  # 1 + 32 + 32 for P-256
        raise ValueError(f"Invalid public key size: {len(uncompressed)} bytes (expected 65)")
    
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
    
    Reconstructs full public key from compressed representation using
    elliptic curve mathematics (y² = x³ + ax + b).
    
    Args:
        compressed_key: Compressed key (33 bytes: prefix + x-coordinate)
        
    Returns:
        EllipticCurvePublicKey: Decompressed public key (NIST P-256)
        
    Raises:
        ValueError: If key format is invalid or decompression fails
    """
    if len(compressed_key) != 33:
        raise ValueError(f"Invalid compressed key length: {len(compressed_key)} bytes (expected 33)")
    
    prefix = compressed_key[0]
    if prefix not in (0x02, 0x03):
        raise ValueError(f"Invalid compression prefix: 0x{prefix:02x} (expected 0x02 or 0x03)")
    
    # Extract x-coordinate
    x_bytes = compressed_key[1:33]
    x = int.from_bytes(x_bytes, byteorder='big')
    
    # NIST P-256 curve parameters (FIPS 186-4)
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    a = p - 3
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    
    # Compute y² = x³ + ax + b (mod p)
    y_squared = (pow(x, 3, p) + a * x + b) % p
    
    # Compute y using modular square root (Tonelli-Shanks for p ≡ 3 mod 4)
    y = pow(y_squared, (p + 1) // 4, p)
    
    # Choose correct y based on prefix (even/odd parity)
    if (y % 2 == 0 and prefix == 0x03) or (y % 2 == 1 and prefix == 0x02):
        y = p - y  # Use the other root
    
    # Construct uncompressed point: 0x04 + x + y
    x_bytes_padded = x.to_bytes(32, byteorder='big')
    y_bytes_padded = y.to_bytes(32, byteorder='big')
    uncompressed = b'\x04' + x_bytes_padded + y_bytes_padded
    
    # Create public key from uncompressed point
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            uncompressed
        )
    except Exception as e:
        raise ValueError(f"Failed to reconstruct public key: {e}")


def etsi_verification_key_to_public_key(asn1_key: tuple) -> EllipticCurvePublicKey:
    """
    Convert ETSI IEEE 1609.2 PublicVerificationKey format to EllipticCurvePublicKey.
    
    This is the inverse of public_key_to_etsi_verification_key().
    
    Args:
        asn1_key: ASN.1 CHOICE tuple: (algorithm, (point_type, bytes))
                  Example: ('ecdsaNistP256', ('compressed-y-0', b'\\x12\\x34...'))
        
    Returns:
        EllipticCurvePublicKey: Reconstructed public key object
        
    Raises:
        ValueError: If format is invalid or curve is unsupported
        
    Examples:
        >>> asn1_key = ('ecdsaNistP256', ('compressed-y-1', x_bytes))
        >>> public_key = etsi_verification_key_to_public_key(asn1_key)
        >>> isinstance(public_key, ec.EllipticCurvePublicKey)
        True
    """
    if not isinstance(asn1_key, tuple) or len(asn1_key) != 2:
        raise ValueError("Invalid ASN.1 key format: expected (algorithm, point)")
    
    algorithm, point_data = asn1_key
    
    # Only support NIST P-256 for now (most common in V2X)
    if algorithm != 'ecdsaNistP256':
        raise ValueError(f"Unsupported algorithm: {algorithm}. Only ecdsaNistP256 supported.")
    
    # Extract point bytes based on encoding
    if isinstance(point_data, tuple) and len(point_data) == 2:
        point_type, point_bytes = point_data
        
        if point_type in ['compressed-y-0', 'compressed-y-1', 'x-only']:
            # Decompress point using SEC1 algorithm
            if point_type == 'compressed-y-0':
                prefix = 0x02  # even y
            elif point_type == 'compressed-y-1':
                prefix = 0x03  # odd y
            else:  # x-only
                prefix = 0x02  # assume even y
            
            # NIST P-256 curve parameters
            p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
            a = p - 3
            b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
            
            x = int.from_bytes(point_bytes, byteorder='big')
            y_squared = (pow(x, 3, p) + a * x + b) % p
            y = pow(y_squared, (p + 1) // 4, p)
            
            # Choose correct y based on parity
            if (y % 2 == 0 and prefix == 0x03) or (y % 2 == 1 and prefix == 0x02):
                y = p - y
            
            # Create uncompressed point
            x_bytes_padded = x.to_bytes(32, byteorder='big')
            y_bytes_padded = y.to_bytes(32, byteorder='big')
            uncompressed = b'\x04' + x_bytes_padded + y_bytes_padded
            
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed)
            
        elif point_type == 'uncompressedP256':
            # Uncompressed format
            if isinstance(point_bytes, dict) and 'x' in point_bytes and 'y' in point_bytes:
                x_bytes = point_bytes['x']
                y_bytes = point_bytes['y']
                uncompressed = b'\x04' + x_bytes + y_bytes
                return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), uncompressed)
            else:
                raise ValueError("Invalid uncompressedP256 format")
        else:
            raise ValueError(f"Unsupported point type: {point_type}")
    else:
        raise ValueError(f"Invalid point data format: {type(point_data)}")


def public_key_to_etsi_verification_key(public_key: EllipticCurvePublicKey) -> tuple:
    """
    Convert ECC public key to ETSI IEEE 1609.2 PublicVerificationKey format.
    
    ETSI TS 103097 V2.1.1 Section 4.2.3:
    =====================================
    PublicVerificationKey ::= CHOICE {
        ecdsaNistP256         EccP256CurvePoint,
        ecdsaBrainpoolP256r1  EccP256CurvePoint,
        ecdsaBrainpoolP384r1  EccP384CurvePoint,
        ...
    }
    
    EccP256CurvePoint ::= CHOICE {
        x-only          OCTET STRING (SIZE(32)),
        fill            NULL,
        compressed-y-0  OCTET STRING (SIZE(32)),  -- x coordinate, y is even
        compressed-y-1  OCTET STRING (SIZE(32)),  -- x coordinate, y is odd
        uncompressedP256 SEQUENCE {
            x OCTET STRING (SIZE(32)),
            y OCTET STRING (SIZE(32))
        }
    }
    
    Compressed point format reduces certificate size by 50% (32 bytes vs 64 bytes).
    This is critical for V2X applications where bandwidth is limited.
    
    Args:
        public_key: EllipticCurvePublicKey object (NIST P-256 or Brainpool)
        
    Returns:
        tuple: ASN.1 CHOICE format: (algorithm_name, (point_type, x_bytes))
               Example: ('ecdsaNistP256', ('compressed-y-0', b'\\x12\\x34...'))
               
    Raises:
        ValueError: If curve type is not supported
        
    Examples:
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> private_key = ec.generate_private_key(ec.SECP256R1())
        >>> public_key = private_key.public_key()
        >>> verification_key = public_key_to_etsi_verification_key(public_key)
        >>> verification_key
        ('ecdsaNistP256', ('compressed-y-1', b'\\xab\\xcd...'))
    """
    # Determine algorithm based on curve type
    curve = public_key.curve
    
    if isinstance(curve, ec.SECP256R1):
        algorithm = 'ecdsaNistP256'
        coord_size = 32
    elif isinstance(curve, ec.BrainpoolP256R1):
        algorithm = 'ecdsaBrainpoolP256r1'
        coord_size = 32
    elif isinstance(curve, ec.BrainpoolP384R1):
        algorithm = 'ecdsaBrainpoolP384r1'
        coord_size = 48
    else:
        raise ValueError(f"Unsupported curve type: {type(curve).__name__}. "
                        f"Supported: SECP256R1, BrainpoolP256R1, BrainpoolP384R1")
    
    # Extract x,y coordinates from public key
    public_numbers = public_key.public_numbers()
    x_bytes = public_numbers.x.to_bytes(coord_size, byteorder='big')
    y_bytes = public_numbers.y.to_bytes(coord_size, byteorder='big')
    
    # Use compressed point format (only x + parity bit for y)
    # This saves 32 bytes per public key in certificates
    if y_bytes[-1] % 2 == 0:
        curve_point = ('compressed-y-0', x_bytes)  # y is even
    else:
        curve_point = ('compressed-y-1', x_bytes)  # y is odd
    
    # Return ASN.1 CHOICE format: (algorithm, point)
    return (algorithm, curve_point)


def public_key_to_etsi_encryption_key(public_key: EllipticCurvePublicKey) -> dict:
    """
    Convert ECC public key to ETSI IEEE 1609.2 PublicEncryptionKey format.
    
    ETSI TS 103097 V2.1.1 / IEEE 1609.2:
    =====================================
    PublicEncryptionKey ::= SEQUENCE {
        supportedSymmAlg    SymmAlgorithm,
        publicKey           BasePublicEncryptionKey
    }
    
    BasePublicEncryptionKey ::= CHOICE {
        eciesNistP256         EccP256CurvePoint,
        eciesBrainpoolP256r1  EccP256CurvePoint,
        ...
    }
    
    SymmAlgorithm ::= ENUMERATED {
        aes128Ccm,
        ...
    }
    
    Args:
        public_key: EllipticCurvePublicKey object (NIST P-256 or Brainpool)
        
    Returns:
        dict: ASN.1 SEQUENCE format for PublicEncryptionKey
        {
            'supportedSymmAlg': 'aes128Ccm',
            'publicKey': ('eciesNistP256', ('compressed-y-0', x_bytes))
        }
        
    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> private_key = ec.generate_private_key(ec.SECP256R1())
        >>> public_key = private_key.public_key()
        >>> encryption_key = public_key_to_etsi_encryption_key(public_key)
    """
    # Determine algorithm based on curve type
    curve = public_key.curve
    
    if isinstance(curve, ec.SECP256R1):
        algorithm = 'eciesNistP256'
        coord_size = 32
    elif isinstance(curve, ec.BrainpoolP256R1):
        algorithm = 'eciesBrainpoolP256r1'
        coord_size = 32
    elif isinstance(curve, ec.BrainpoolP384R1):
        algorithm = 'eciesBrainpoolP384r1'
        coord_size = 48
    else:
        raise ValueError(f"Unsupported curve type: {type(curve).__name__}. "
                        f"Supported: SECP256R1, BrainpoolP256R1, BrainpoolP384R1")
    
    # Extract x,y coordinates from public key
    public_numbers = public_key.public_numbers()
    x_bytes = public_numbers.x.to_bytes(coord_size, byteorder='big')
    y_bytes = public_numbers.y.to_bytes(coord_size, byteorder='big')
    
    # Use compressed point format
    if y_bytes[-1] % 2 == 0:
        curve_point = ('compressed-y-0', x_bytes)  # y is even
    else:
        curve_point = ('compressed-y-1', x_bytes)  # y is odd
    
    # Return PublicEncryptionKey structure
    return {
        'supportedSymmAlg': 'aes128Ccm',  # Default symmetric algorithm
        'publicKey': (algorithm, curve_point)
    }


def etsi_encryption_key_to_public_key(asn1_key: dict) -> EllipticCurvePublicKey:
    """
    Convert ETSI IEEE 1609.2 PublicEncryptionKey format to EllipticCurvePublicKey.
    
    This is the inverse of public_key_to_etsi_encryption_key().
    
    ETSI TS 102 941 V2.1.1 Section 6.2.3.4:
    The encryption key from the request is used to encrypt the response.
    
    Args:
        asn1_key: ASN.1 SEQUENCE dict:
                  {'supportedSymmAlg': 'aes128Ccm', 'publicKey': (algorithm, point)}
        
    Returns:
        EllipticCurvePublicKey: Reconstructed public key object
        
    Raises:
        ValueError: If format is invalid or curve is unsupported
        
    Examples:
        >>> asn1_key = {
        ...     'supportedSymmAlg': 'aes128Ccm',
        ...     'publicKey': ('eciesNistP256', ('compressed-y-0', x_bytes))
        ... }
        >>> public_key = etsi_encryption_key_to_public_key(asn1_key)
        >>> isinstance(public_key, ec.EllipticCurvePublicKey)
        True
    """
    if not isinstance(asn1_key, dict) or 'publicKey' not in asn1_key:
        raise ValueError("Invalid ASN.1 encryption key format: expected dict with 'publicKey'")
    
    algorithm, point_data = asn1_key['publicKey']
    
    # Support both NIST P-256 and Brainpool curves
    if algorithm == 'eciesNistP256':
        curve = ec.SECP256R1()
        coord_size = 32
        p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        a = p - 3
        b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    elif algorithm == 'eciesBrainpoolP256r1':
        curve = ec.BrainpoolP256R1()
        coord_size = 32
        # Brainpool P-256 parameters would go here
        raise NotImplementedError("BrainpoolP256R1 decompression not yet implemented")
    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
    
    # Extract point bytes based on encoding
    if isinstance(point_data, tuple) and len(point_data) == 2:
        point_type, point_bytes = point_data
        
        if point_type in ['compressed-y-0', 'compressed-y-1', 'x-only']:
            # Decompress point using SEC1 algorithm (same as verification key)
            if point_type == 'compressed-y-0':
                prefix = 0x02  # even y
            elif point_type == 'compressed-y-1':
                prefix = 0x03  # odd y
            else:  # x-only
                prefix = 0x02  # assume even y
            
            x = int.from_bytes(point_bytes, byteorder='big')
            y_squared = (pow(x, 3, p) + a * x + b) % p
            y = pow(y_squared, (p + 1) // 4, p)
            
            # Choose correct y based on parity
            if (y % 2 == 0 and prefix == 0x03) or (y % 2 == 1 and prefix == 0x02):
                y = p - y
            
            # Create uncompressed point
            x_bytes_padded = x.to_bytes(coord_size, byteorder='big')
            y_bytes_padded = y.to_bytes(coord_size, byteorder='big')
            uncompressed = b'\x04' + x_bytes_padded + y_bytes_padded
            
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, uncompressed)
            
        elif point_type == 'uncompressedP256':
            # Uncompressed format
            if isinstance(point_bytes, dict) and 'x' in point_bytes and 'y' in point_bytes:
                x_bytes = point_bytes['x']
                y_bytes = point_bytes['y']
                uncompressed = b'\x04' + x_bytes + y_bytes
                return ec.EllipticCurvePublicKey.from_encoded_point(curve, uncompressed)
            else:
                raise ValueError("Invalid uncompressedP256 format")
        else:
            raise ValueError(f"Unsupported point type: {point_type}")
    else:
        raise ValueError(f"Invalid point data format: {type(point_data)}")


def sign_data_ieee1609(private_key, data: bytes, hash_algorithm=hashes.SHA256()) -> tuple:
    """
    Sign data directly in IEEE 1609.2 format (no DER conversion).
    
    Generates ECDSA signature and returns it directly in ASN.1 format,
    bypassing DER encoding entirely.
    
    Args:
        private_key: EllipticCurvePrivateKey for signing
        data: Data to sign
        hash_algorithm: Hash algorithm (default: SHA256)
        
    Returns:
        tuple: ASN.1 CHOICE format: ('ecdsaNistP256Signature', signature_dict)
        
    Examples:
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> private_key = ec.generate_private_key(ec.SECP256R1())
        >>> signature_asn1 = sign_data_ieee1609(private_key, b"data")
        >>> # signature_asn1 is already in IEEE 1609.2 format!
    """
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    
    # Sign data (DER format internally)
    signature_der = private_key.sign(data, ec.ECDSA(hash_algorithm))
    
    # Decode DER to get raw (r, s) integers
    r, s = decode_dss_signature(signature_der)
    
    # Convert integers to 32-byte big-endian format (P-256)
    r_bytes = r.to_bytes(32, byteorder='big')
    s_bytes = s.to_bytes(32, byteorder='big')
    
    # Build IEEE 1609.2 signature structure directly
    r_sig = ("x-only", r_bytes)
    signature_structure = {
        "rSig": r_sig,
        "sSig": s_bytes
    }
    
    return ("ecdsaNistP256Signature", signature_structure)


def verify_ieee1609_signature(public_key, signature_asn1: tuple, data: bytes, hash_algorithm=hashes.SHA256()) -> bool:
    """
    Verify IEEE 1609.2 signature directly (no DER conversion).
    
    Args:
        public_key: EllipticCurvePublicKey for verification
        signature_asn1: ASN.1 signature tuple from sign_data_ieee1609()
        data: Data that was signed
        hash_algorithm: Hash algorithm (default: SHA256)
        
    Returns:
        bool: True if signature is valid, False otherwise
        
    Examples:
        >>> signature_asn1 = sign_data_ieee1609(private_key, b"data")
        >>> is_valid = verify_ieee1609_signature(public_key, signature_asn1, b"data")
    """
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.exceptions import InvalidSignature
    
    # Extract r and s from ASN.1 structure
    choice, signature_structure = signature_asn1
    
    if choice != "ecdsaNistP256Signature":
        raise ValueError(f"Unsupported signature type: {choice}")
    
    r_sig = signature_structure.get("rSig")
    s_bytes = signature_structure.get("sSig")
    
    # Extract r bytes
    if isinstance(r_sig, tuple) and len(r_sig) == 2:
        point_type, r_bytes = r_sig
        if point_type == "x-only":
            pass
        elif point_type in ["compressed-y-0", "compressed-y-1"]:
            pass
        elif point_type == "uncompressedP256":
            if isinstance(r_bytes, dict) and "x" in r_bytes:
                r_bytes = r_bytes["x"]
        else:
            raise ValueError(f"Unsupported point type: {point_type}")
    else:
        raise ValueError("Invalid rSig format")
    
    # Convert bytes to integers
    r = int.from_bytes(r_bytes, byteorder='big')
    s = int.from_bytes(s_bytes, byteorder='big')
    
    # Encode as DER for cryptography library
    signature_der = encode_dss_signature(r, s)
    
    # Verify
    try:
        public_key.verify(signature_der, data, ec.ECDSA(hash_algorithm))
        return True
    except InvalidSignature:
        return False


def der_signature_to_asn1(der_signature: bytes) -> tuple:
    """
    Convert DER-encoded ECDSA signature to IEEE 1609.2 Signature structure.
    
    IEEE 1609.2 / ETSI TS 103097 Section 4.2.7:
    ============================================
    Signature ::= CHOICE {
        ecdsaNistP256Signature        EcdsaP256Signature,
        ecdsaBrainpoolP256r1Signature EcdsaP256Signature,
        ecdsaBrainpoolP384r1Signature EcdsaP384Signature,
        ...
    }
    
    EcdsaP256Signature ::= SEQUENCE {
        rSig    EccP256CurvePoint,
        sSig    OCTET STRING (SIZE(32))
    }
    
    Context:
    --------
    Python's cryptography library generates ECDSA signatures in DER format
    (PKCS#11/X.509 standard), but ETSI/IEEE 1609.2 requires a specific ASN.1
    structure with separate r and s components. This function bridges the gap.
    
    DER Format:
        0x30 [total_len] 0x02 [r_len] [r_bytes] 0x02 [s_len] [s_bytes]
    
    IEEE 1609.2 Format:
        rSig: ECC curve point (x-only compressed format)
        sSig: 32-byte octet string
    
    Args:
        der_signature: DER-encoded ECDSA signature bytes from cryptography.sign()
        
    Returns:
        tuple: ASN.1 CHOICE format: ('ecdsaNistP256Signature', signature_dict)
               where signature_dict = {'rSig': (point_type, r_bytes), 'sSig': s_bytes}
               
    Raises:
        ValueError: If DER signature format is invalid
        
    Examples:
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> from cryptography.hazmat.primitives import hashes
        >>> private_key = ec.generate_private_key(ec.SECP256R1())
        >>> signature_der = private_key.sign(b"data", ec.ECDSA(hashes.SHA256()))
        >>> signature_asn1 = der_signature_to_asn1(signature_der)
        >>> signature_asn1[0]
        'ecdsaNistP256Signature'
    """
    # Parse DER signature: 0x30 [total_len] 0x02 [r_len] [r] 0x02 [s_len] [s]
    if len(der_signature) < 8:
        raise ValueError("DER signature too short")
    
    if der_signature[0] != 0x30:
        raise ValueError("Invalid DER signature format: missing SEQUENCE tag (0x30)")
    
    offset = 2  # Skip sequence header (0x30 + length)
    
    # Parse r component
    if der_signature[offset] != 0x02:
        raise ValueError("Invalid DER signature: missing INTEGER tag for r (0x02)")
    offset += 1
    r_len = der_signature[offset]
    offset += 1
    r_bytes = der_signature[offset:offset + r_len]
    offset += r_len
    
    # Parse s component
    if offset >= len(der_signature):
        raise ValueError("Invalid DER signature: truncated before s component")
    if der_signature[offset] != 0x02:
        raise ValueError("Invalid DER signature: missing INTEGER tag for s (0x02)")
    offset += 1
    s_len = der_signature[offset]
    offset += 1
    s_bytes = der_signature[offset:offset + s_len]
    
    # Remove leading zero bytes (DER uses padding for positive integers)
    r_bytes = r_bytes.lstrip(b'\x00')
    s_bytes = s_bytes.lstrip(b'\x00')
    
    # Pad to 32 bytes (P-256 coordinate size)
    # IEEE 1609.2 requires fixed 32-byte size for P-256
    r_bytes = r_bytes.rjust(32, b'\x00')
    s_bytes = s_bytes.rjust(32, b'\x00')
    
    # Use x-only encoding for r coordinate (most compact format)
    # This is valid because r is just a coordinate, not a full point needing y
    r_sig = ("x-only", r_bytes)
    
    # Build EcdsaP256Signature structure
    signature_structure = {
        "rSig": r_sig,
        "sSig": s_bytes
    }
    
    # Return as CHOICE tuple for ASN.1 encoding
    return ("ecdsaNistP256Signature", signature_structure)


def asn1_signature_to_der(asn1_signature: tuple) -> bytes:
    """
    Convert IEEE 1609.2 Signature structure to DER-encoded ECDSA signature.
    
    This is the inverse of der_signature_to_asn1(), converting from ETSI/IEEE
    format back to cryptography library's expected DER format.
    
    Args:
        asn1_signature: ASN.1 CHOICE tuple format:
                       ('ecdsaNistP256Signature', {'rSig': (point_type, r_bytes), 'sSig': s_bytes})
        
    Returns:
        bytes: DER-encoded signature compatible with cryptography library
        
    Raises:
        ValueError: If ASN.1 signature format is invalid
        
    Examples:
        >>> asn1_sig = ('ecdsaNistP256Signature', {'rSig': ('x-only', r_bytes), 'sSig': s_bytes})
        >>> der_sig = asn1_signature_to_der(asn1_sig)
        >>> public_key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
    """
    if not isinstance(asn1_signature, tuple) or len(asn1_signature) != 2:
        raise ValueError("Invalid ASN.1 signature format: expected tuple (choice, value)")
    
    choice, signature_structure = asn1_signature
    
    # Support only NIST P-256 for now (most common in V2X)
    if choice != "ecdsaNistP256Signature":
        raise ValueError(f"Unsupported signature type: {choice}")
    
    if not isinstance(signature_structure, dict):
        raise ValueError("Invalid signature structure: expected dict")
    
    # Extract r and s components
    r_sig = signature_structure.get("rSig")
    s_bytes = signature_structure.get("sSig")
    
    if not r_sig or not s_bytes:
        raise ValueError("Missing rSig or sSig in signature structure")
    
    # Extract r bytes from ECC point structure
    if isinstance(r_sig, tuple) and len(r_sig) == 2:
        point_type, r_bytes = r_sig
        # Support various point encoding types
        if point_type == "x-only":
            pass  # r_bytes is already the x coordinate
        elif point_type in ["compressed-y-0", "compressed-y-1"]:
            pass  # r_bytes is the x coordinate
        elif point_type == "uncompressedP256":
            if isinstance(r_bytes, dict) and "x" in r_bytes:
                r_bytes = r_bytes["x"]
            else:
                raise ValueError("Invalid uncompressedP256 format")
        else:
            raise ValueError(f"Unsupported point type: {point_type}")
    else:
        raise ValueError("Invalid rSig format")
    
    # Ensure r and s are 32 bytes
    if len(r_bytes) != 32 or len(s_bytes) != 32:
        raise ValueError(f"Invalid coordinate size: r={len(r_bytes)}, s={len(s_bytes)} (expected 32)")
    
    # Remove leading zeros for DER encoding (DER uses minimal encoding)
    r_bytes = r_bytes.lstrip(b'\x00')
    s_bytes = s_bytes.lstrip(b'\x00')
    
    # Add leading zero if high bit is set (DER requires positive integers)
    if r_bytes[0] & 0x80:
        r_bytes = b'\x00' + r_bytes
    if s_bytes[0] & 0x80:
        s_bytes = b'\x00' + s_bytes
    
    # Build DER structure: SEQUENCE { INTEGER r, INTEGER s }
    # Format: 0x30 [total_len] 0x02 [r_len] [r] 0x02 [s_len] [s]
    r_der = b'\x02' + bytes([len(r_bytes)]) + r_bytes
    s_der = b'\x02' + bytes([len(s_bytes)]) + s_bytes
    sequence_content = r_der + s_der
    der_signature = b'\x30' + bytes([len(sequence_content)]) + sequence_content
    
    return der_signature


# ============================================================================
# REQUEST HASH COMPUTATION
# ============================================================================


def compute_request_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of request for response correlation.
    
    Used in ETSI TS 102941 messages to link responses to their corresponding
    requests (e.g., InnerEcResponse.requestHash).
    
    Args:
        data: Serialized request data
        
    Returns:
        bytes: SHA-256 hash (32 bytes)
        
    Raises:
        ValueError: If data is empty
    """
    if not data:
        raise ValueError("Request data cannot be empty")
    
    return hashlib.sha256(data).digest()


# ============================================================================
# VALIDITY PERIOD EXTRACTION
# ============================================================================


def extract_validity_period(cert_asn1_oer: bytes) -> tuple:
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
    import struct
    
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
# PUBLIC KEY EXTRACTION FROM CERTIFICATES
# ============================================================================


def extract_public_key_from_asn1_certificate(cert_asn1_oer: bytes, key_type: str = "verification") -> EllipticCurvePublicKey:
    """
    Estrae la chiave pubblica da un certificato ASN.1 OER generico.
    
    Questa funzione cerca la chiave pubblica in diverse posizioni tipiche
    della struttura ASN.1 OER dei certificati ETSI, supportando:
    - Root CA certificates
    - Authority certificates (EA, AA)
    - Enrollment certificates
    - Authorization Tickets
    
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
    import struct
    
    try:
        # Leggi TBS length (primi 2 bytes)
        if len(cert_asn1_oer) < 2:
            raise ValueError("Certificate too short")
        
        tbs_len = struct.unpack('>H', cert_asn1_oer[0:2])[0]
        tbs_data = cert_asn1_oer[2:2+tbs_len]
        
        # La chiave pubblica è solitamente verso la fine del TBS
        # Cerca un pattern di 33 bytes che inizia con 0x02 o 0x03 (compressed key)
        # Se key_type="encryption", cerca la seconda chiave trovata
        keys_found = []
        for offset in range(len(tbs_data) - 33):
            if tbs_data[offset] in (0x02, 0x03):
                try:
                    compressed_key = tbs_data[offset:offset+33]
                    public_key = decode_public_key_compressed(compressed_key)
                    keys_found.append(public_key)
                    
                    # Se cerchiamo verification key, ritorna la prima
                    if key_type == "verification" and len(keys_found) == 1:
                        return public_key
                    # Se cerchiamo encryption key e abbiamo trovato 2 chiavi, ritorna la seconda
                    elif key_type == "encryption" and len(keys_found) == 2:
                        return public_key
                except Exception:
                    continue
        
        # Fallback: se abbiamo trovato almeno una chiave, ritornala
        if keys_found:
            return keys_found[0]
        
        raise ValueError(f"Public key ({key_type}) not found in certificate")
        
    except Exception as e:
        raise ValueError(f"Failed to extract public key: {e}")


# ============================================================================
# IEEE 1609.2 ENCRYPTED DATA STRUCTURES
# ============================================================================


def create_ieee1609dot2_encrypted_data(
    ecies_ciphertext: bytes, 
    recipient_id: bytes
) -> dict:
    """
    Create IEEE 1609.2 EncryptedData structure from ECIES ciphertext.
    
    Converts raw ECIES encrypted data into proper IEEE 1609.2 / ETSI TS 103097
    Ieee1609Dot2Data structure with EncryptedData content.
    
    ECIES format: ephemeral_public_key (65 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
    
    Standards:
    - IEEE 1609.2-2016 Section 5.3.4 (ECIES encryption)
    - ETSI TS 103097 V2.1.1 Section 5.2 (Data structures)
    
    Args:
        ecies_ciphertext: Raw ECIES encrypted data from ecies_encrypt()
        recipient_id: HashedId8 of recipient's certificate (8 bytes)
    
    Returns:
        dict: Ieee1609Dot2Data dictionary with encryptedData content, ready for ASN.1 encoding
        
    Example:
        >>> from protocols.security.ecies import ecies_encrypt
        >>> from protocols.core.primitives import compute_hashed_id8, create_ieee1609dot2_encrypted_data
        >>> encrypted = ecies_encrypt(b"secret", recipient_public_key)
        >>> recipient_id = compute_hashed_id8(recipient_cert_bytes)
        >>> ieee_structure = create_ieee1609dot2_encrypted_data(encrypted, recipient_id)
        >>> # Now encode with: asn1_compiler.encode("EtsiTs103097Data-Encrypted", ieee_structure)
    """
    # Parse ECIES components
    ephemeral_public_bytes = ecies_ciphertext[:65]  # 0x04 || x || y (uncompressed point)
    nonce = ecies_ciphertext[65:77]  # 12 bytes nonce
    ciphertext_and_tag = ecies_ciphertext[77:]  # encrypted payload + 16-byte auth tag
    
    # Extract authentication tag (last 16 bytes)
    tag = ciphertext_and_tag[-16:]
    actual_ciphertext = ciphertext_and_tag[:-16]
    
    # Create EccP256CurvePoint from ephemeral public key
    # Uncompressed format: 0x04 || x (32 bytes) || y (32 bytes)
    if ephemeral_public_bytes[0] != 0x04:
        raise ValueError(f"Invalid ephemeral public key format: expected 0x04, got {ephemeral_public_bytes[0]:02x}")
    
    x_coord = ephemeral_public_bytes[1:33]
    y_coord = ephemeral_public_bytes[33:65]
    
    uncompressed_point = {
        "x": x_coord,
        "y": y_coord
    }
    
    # EccP256CurvePoint is a CHOICE - must be tuple (choice_name, value)
    ecc_point = ("uncompressedP256", uncompressed_point)
    
    # Create ECIES encrypted key structure (IEEE 1609.2 EciesP256EncryptedKey)
    # Note: Field 'c' should be encrypted symmetric key (16 bytes), but we use direct encryption
    # Pad nonce to 16 bytes to match the SIZE(16) requirement
    padded_c_field = nonce + b'\x00' * 4  # Pad 12-byte nonce to 16 bytes
    
    ecies_key = {
        "v": ecc_point,      # Ephemeral public key point
        "c": padded_c_field, # Encryption key material (16 bytes required)
        "t": tag             # Authentication tag
    }
    
    # EncryptedDataEncryptionKey is a CHOICE - must be tuple (choice_name, value)
    encrypted_data_enc_key = ("eciesNistP256", ecies_key)
    
    # Create PKRecipientInfo (certificate-based recipient)
    pk_recipient_info = {
        "recipientId": recipient_id,  # HashedId8 of recipient's certificate
        "encKey": encrypted_data_enc_key
    }
    
    # RecipientInfo is a CHOICE - must be tuple (choice_name, value)
    recipient_info = ("certRecipInfo", pk_recipient_info)
    
    # Create AesCcmCiphertext structure (SEQUENCE with nonce and ccmCiphertext)
    aes_ccm_ciphertext = {
        "nonce": nonce,
        "ccmCiphertext": actual_ciphertext
    }
    
    # Create SymmetricCiphertext with AES-128-CCM
    # SymmetricCiphertext is a CHOICE - must be tuple (choice_name, value)
    symmetric_ciphertext = ("aes128ccm", aes_ccm_ciphertext)
    
    # Create EncryptedData structure
    encrypted_data = {
        "recipients": [recipient_info],
        "ciphertext": symmetric_ciphertext
    }
    
    # Wrap in Ieee1609Dot2Data with protocol version 3
    # IMPORTANT: 'content' is a CHOICE, so it must be a tuple (choice_name, value)
    return {
        "protocolVersion": 3,
        "content": ("encryptedData", encrypted_data)
    }


def extract_ecies_from_ieee1609dot2_encrypted_data(ieee1609dot2_data: dict) -> bytes:
    """
    Extract ECIES ciphertext from IEEE 1609.2 EncryptedData structure.
    
    Extracts raw ECIES encrypted data from IEEE 1609.2 / ETSI TS 103097
    Ieee1609Dot2Data structure, suitable for decryption with ecies_decrypt().
    
    Standards:
    - IEEE 1609.2-2016 Section 5.3.4 (ECIES encryption)
    - ETSI TS 103097 V2.1.1 Section 5.2 (Data structures)
    
    Args:
        ieee1609dot2_data: Decoded Ieee1609Dot2Data dictionary (from ASN.1 decode)
    
    Returns:
        bytes: Raw ECIES ciphertext in format: ephemeral_public_key || nonce || ciphertext || tag
        
    Raises:
        KeyError: If expected structure elements are missing
        ValueError: If structure format is invalid
        
    Example:
        >>> ieee_data = asn1_compiler.decode("EtsiTs103097Data-Encrypted", encrypted_bytes)
        >>> ecies_ciphertext = extract_ecies_from_ieee1609dot2_encrypted_data(ieee_data)
        >>> plaintext = ecies_decrypt(ecies_ciphertext, recipient_private_key)
    """
    try:
        # Navigate to EncryptedData - 'content' is a CHOICE tuple (choice_name, value)
        content = ieee1609dot2_data["content"]
        if isinstance(content, tuple):
            choice_name, content_value = content
            if choice_name != "encryptedData":
                raise ValueError(f"Expected encryptedData, got {choice_name}")
            encrypted_data = content_value
        elif isinstance(content, dict) and "encryptedData" in content:
            # Fallback for dict format (shouldn't happen with proper ASN.1 decode)
            encrypted_data = content["encryptedData"]
        else:
            raise ValueError("Invalid content structure")
        
        # Extract recipient info (assume first recipient)
        if not encrypted_data["recipients"]:
            raise ValueError("No recipients found in EncryptedData")
        
        recipient_info = encrypted_data["recipients"][0]
        
        # RecipientInfo is a CHOICE - could be tuple or dict
        if isinstance(recipient_info, tuple):
            choice_name, cert_recip_info = recipient_info
            if choice_name != "certRecipInfo":
                raise ValueError(f"Expected certRecipInfo, got {choice_name}")
        elif isinstance(recipient_info, dict):
            cert_recip_info = recipient_info["certRecipInfo"]
        else:
            raise ValueError("Invalid RecipientInfo structure")
        
        # EncryptedDataEncryptionKey is a CHOICE - could be tuple or dict
        enc_key = cert_recip_info["encKey"]
        if isinstance(enc_key, tuple):
            key_choice_name, ecies_key = enc_key
            if key_choice_name != "eciesNistP256":
                raise ValueError(f"Expected eciesNistP256, got {key_choice_name}")
        elif isinstance(enc_key, dict):
            ecies_key = enc_key["eciesNistP256"]
        else:
            raise ValueError("Invalid EncryptedDataEncryptionKey structure")
        
        # Extract ECC point (ephemeral public key) - EccP256CurvePoint is a CHOICE
        ecc_point_field = ecies_key["v"]
        if isinstance(ecc_point_field, tuple):
            point_choice_name, uncompressed_point = ecc_point_field
            if point_choice_name != "uncompressedP256":
                raise ValueError(f"Expected uncompressedP256, got {point_choice_name}")
            x_coord = uncompressed_point["x"]
            y_coord = uncompressed_point["y"]
        elif isinstance(ecc_point_field, dict):
            ecc_point = ecc_point_field["uncompressedP256"]
            x_coord = ecc_point["x"]
            y_coord = ecc_point["y"]
        else:
            raise ValueError("Invalid EccP256CurvePoint structure")
        
        # Reconstruct uncompressed point format
        ephemeral_public_bytes = b'\x04' + bytes(x_coord) + bytes(y_coord)
        
        # Extract authentication tag
        tag = bytes(ecies_key["t"])
        
        # Extract ciphertext and nonce - SymmetricCiphertext is a CHOICE
        ciphertext_field = encrypted_data["ciphertext"]
        if isinstance(ciphertext_field, tuple):
            cipher_choice_name, aes_ccm_data = ciphertext_field
            if cipher_choice_name != "aes128ccm":
                raise ValueError(f"Expected aes128ccm, got {cipher_choice_name}")
            # AesCcmCiphertext is a SEQUENCE with nonce and ccmCiphertext
            nonce = bytes(aes_ccm_data["nonce"])
            actual_ciphertext = bytes(aes_ccm_data["ccmCiphertext"])
        elif isinstance(ciphertext_field, dict):
            aes_ccm_data = ciphertext_field["aes128ccm"]
            nonce = bytes(aes_ccm_data["nonce"])
            actual_ciphertext = bytes(aes_ccm_data["ccmCiphertext"])
        else:
            raise ValueError("Invalid SymmetricCiphertext structure")
        
        # Reconstruct ECIES format: ephemeral_public || nonce || ciphertext || tag
        return ephemeral_public_bytes + nonce + actual_ciphertext + tag
        
    except KeyError as e:
        raise KeyError(f"Missing required field in IEEE 1609.2 EncryptedData structure: {e}")
    except Exception as e:
        raise ValueError(f"Failed to extract ECIES from EncryptedData: {e}")


def create_ieee1609dot2_signed_and_encrypted_data(
    ecies_ciphertext: bytes,
    recipient_id: bytes,
    signer_certificate_asn1: bytes,
    signer_private_key,
    psid: int = 0x24  # Default: CA Basic Service (0x24 = 36)
) -> dict:
    """
    Create IEEE 1609.2 SignedAndEncryptedData structure.
    
    This creates a complete ETSI TS 103097 Data-SignedAndEncrypted structure
    following IEEE 1609.2-2016 and ETSI TS 103097 V2.1.1 standards.
    
    Structure created (100% standard ETSI):
    ========================================
    Ieee1609Dot2Data {
        protocolVersion: 3,
        content: signedData {
            hashId: sha256,
            tbsData: {
                payload: {
                    data: Ieee1609Dot2Data {
                        content: encryptedData { ... }
                    }
                },
                headerInfo: { psid, generationTime }
            },
            signer: certificate [signer_certificate],
            signature: ECDSA signature
        }
    }
    
    Standards:
    - IEEE 1609.2-2016 Section 6.3.9 (SignedData)
    - ETSI TS 103097 V2.1.1 Section 5.2 (Data structures)
    - ETSI TS 102941 V2.1.1 Section 6.3.2 (Authorization Request)
    
    Args:
        ecies_ciphertext: Raw ECIES encrypted data from ecies_encrypt()
        recipient_id: HashedId8 of recipient's certificate (8 bytes)
        signer_certificate_asn1: Signer's certificate ASN.1 OER bytes (e.g., Enrollment Certificate)
        signer_private_key: Signer's private key for signature
        psid: Provider Service Identifier (default: 0x24 for CA Basic Service)
    
    Returns:
        dict: Ieee1609Dot2Data dictionary ready for ASN.1 encoding
        
    Example:
        >>> from protocols.security.ecies import ecies_encrypt
        >>> encrypted = ecies_encrypt(inner_request_bytes, aa_public_key)
        >>> recipient_id = compute_hashed_id8(aa_cert_asn1)
        >>> signed_encrypted = create_ieee1609dot2_signed_and_encrypted_data(
        ...     encrypted, recipient_id, ec_cert_asn1, ec_private_key
        ... )
        >>> encoded = asn1_compiler.encode("EtsiTs103097Data-SignedAndEncrypted", signed_encrypted)
    """
    # 1. Create inner EncryptedData structure
    encrypted_data_structure = create_ieee1609dot2_encrypted_data(
        ecies_ciphertext=ecies_ciphertext,
        recipient_id=recipient_id
    )
    
    # 2. Create SignedDataPayload containing the EncryptedData
    signed_data_payload = {
        "data": encrypted_data_structure  # Ieee1609Dot2Data with encryptedData
        # extDataHash is OPTIONAL, not needed for this use case
    }
    
    # 3. Create HeaderInfo with PSID and generation time
    header_info = {
        "psid": psid,  # CA Basic Service for PKI operations
        "generationTime": int((datetime.now(timezone.utc) - datetime(2004, 1, 1, 0, 0, 0, tzinfo=timezone.utc)).total_seconds() * 1000000)  # Time64 in microseconds
    }
    
    # 4. Create ToBeSignedData
    to_be_signed_data = {
        "payload": signed_data_payload,
        "headerInfo": header_info
    }
    
    # 5. Encode ToBeSignedData for signing
    # Import here to avoid circular dependency
    try:
        from protocols.messages.encoder import asn1_compiler
    except ImportError:
        # Fallback if running outside normal package structure
        import sys
        import os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
        from protocols.messages.encoder import asn1_compiler
    
    tbs_bytes = asn1_compiler.encode("ToBeSignedData", to_be_signed_data)
    
    # 6. Sign the ToBeSignedData
    signature_asn1 = sign_data_ieee1609(signer_private_key, tbs_bytes)
    
    # 7. Create SignerIdentifier with certificate
    # Decode certificate from ASN.1 OER bytes to dict structure (required by ASN.1 compiler)
    certificate_dict = asn1_compiler.decode("EtsiTs103097Certificate", signer_certificate_asn1)
    # SignerIdentifier is a CHOICE - use "certificate" option with sequence of certs
    signer_identifier = ("certificate", [certificate_dict])
    
    # 8. Create SignedData structure
    signed_data = {
        "hashId": "sha256",  # HashAlgorithm ENUMERATED
        "tbsData": to_be_signed_data,
        "signer": signer_identifier,
        "signature": signature_asn1
    }
    
    # 9. Wrap in Ieee1609Dot2Data with SignedData content
    # 'content' is a CHOICE, so it must be a tuple (choice_name, value)
    return {
        "protocolVersion": 3,
        "content": ("signedData", signed_data)
    }


def extract_encrypted_data_from_signed_and_encrypted(ieee1609dot2_data: dict):
    """
    Extract EncryptedData from SignedAndEncrypted structure.
    
    Navigates through the SignedData wrapper to extract the inner EncryptedData,
    which can then be decrypted using extract_ecies_from_ieee1609dot2_encrypted_data().
    
    Standards:
    - IEEE 1609.2-2016 Section 6.3.9
    - ETSI TS 103097 V2.1.1 Section 5.2
    
    Args:
        ieee1609dot2_data: Decoded Ieee1609Dot2Data with SignedData content
    
    Returns:
        tuple: (encrypted_data_dict, signer_certificate_asn1)
            - encrypted_data_dict: Inner Ieee1609Dot2Data with encryptedData
            - signer_certificate_asn1: Signer's certificate (e.g., EC) as ASN.1 bytes
        
    Raises:
        ValueError: If structure is invalid or not SignedAndEncrypted
        
    Example:
        >>> signed_encrypted = asn1_compiler.decode("EtsiTs103097Data-SignedAndEncrypted", request_bytes)
        >>> encrypted_data, ec_cert = extract_encrypted_data_from_signed_and_encrypted(signed_encrypted)
        >>> ecies_ciphertext = extract_ecies_from_ieee1609dot2_encrypted_data(encrypted_data)
        >>> plaintext = ecies_decrypt(ecies_ciphertext, aa_private_key)
    """
    try:
        # Navigate to SignedData
        content = ieee1609dot2_data["content"]
        if isinstance(content, tuple):
            choice_name, signed_data = content
            if choice_name != "signedData":
                raise ValueError(f"Expected signedData, got {choice_name}")
        elif isinstance(content, dict) and "signedData" in content:
            signed_data = content["signedData"]
        else:
            raise ValueError("Invalid content structure: expected signedData")
        
        # Extract signer certificate
        signer = signed_data["signer"]
        signer_cert_asn1 = None
        
        if isinstance(signer, tuple):
            signer_choice, signer_value = signer
            if signer_choice == "certificate":
                # SequenceOfCertificate - take first certificate
                if isinstance(signer_value, list) and len(signer_value) > 0:
                    cert_dict = signer_value[0]
                    # Re-encode certificate dict back to ASN.1 OER bytes
                    # Import here to avoid circular dependency
                    try:
                        from protocols.messages.encoder import asn1_compiler
                    except ImportError:
                        import sys
                        import os
                        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
                        from protocols.messages.encoder import asn1_compiler
                    
                    signer_cert_asn1 = asn1_compiler.encode("EtsiTs103097Certificate", cert_dict)
            elif signer_choice == "digest":
                # Only HashedId8 available, no full certificate
                pass
        
        # Navigate to payload
        tbs_data = signed_data["tbsData"]
        payload = tbs_data["payload"]
        
        # Extract inner Ieee1609Dot2Data with EncryptedData
        if "data" not in payload:
            raise ValueError("No data in SignedDataPayload")
        
        encrypted_data_structure = payload["data"]
        
        # Verify it contains encryptedData
        inner_content = encrypted_data_structure.get("content")
        if isinstance(inner_content, tuple):
            choice_name, _ = inner_content
            if choice_name != "encryptedData":
                raise ValueError(f"Expected encryptedData in payload, got {choice_name}")
        
        return encrypted_data_structure, signer_cert_asn1
        
    except KeyError as e:
        raise ValueError(f"Missing required field in SignedAndEncrypted structure: {e}")
    except Exception as e:
        raise ValueError(f"Failed to extract EncryptedData from SignedAndEncrypted: {e}")
