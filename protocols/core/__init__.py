"""
ETSI Core Types and Utilities

This module provides the foundational types, constants, and utility functions
for ETSI ITS PKI protocol implementation.

Submodules:
- types: Enumerations, constants, and basic type definitions
- primitives: Time32, HashedId8, and public key encoding/decoding
- crypto: Cryptographic operations (signatures, ECDH, HKDF)

Standards Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats

Author: SecureRoad PKI Project
Date: October 2025
"""

# Re-export all core functionality for convenience
from .types import (
    # Constants
    ETSI_EPOCH,
    CERT_TYPE_EXPLICIT,
    CERT_TYPE_AUTHORIZATION,
    CERT_TYPE_ENROLLMENT,
    
    # Enums
    ETSIMessageType,
    ResponseCode,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
)

from .primitives import (
    time32_encode,
    time32_decode,
    compute_hashed_id8,
    compute_hashed_id3,
    encode_public_key_compressed,
    decode_public_key_compressed,
    public_key_to_etsi_verification_key,
    etsi_verification_key_to_public_key,
    public_key_to_etsi_encryption_key,
    etsi_encryption_key_to_public_key,
    der_signature_to_asn1,
    compute_request_hash,
    extract_validity_period,
    extract_public_key_from_asn1_certificate,
)

from .crypto import (
    sign_data_ecdsa_sha256,
    verify_signature_ecdsa_sha256,
    compute_ecdh_shared_secret,
    derive_key_hkdf,
    verify_asn1_certificate_signature,
)

__all__ = [
    # Constants
    "ETSI_EPOCH",
    "CERT_TYPE_EXPLICIT",
    "CERT_TYPE_AUTHORIZATION",
    "CERT_TYPE_ENROLLMENT",
    
    # Enums
    "ETSIMessageType",
    "ResponseCode",
    "PublicKeyAlgorithm",
    "SymmetricAlgorithm",
    
    # Encoding
    "time32_encode",
    "time32_decode",
    "compute_hashed_id8",
    "compute_hashed_id3",
    "encode_public_key_compressed",
    "decode_public_key_compressed",
    "public_key_to_etsi_verification_key",
    "etsi_verification_key_to_public_key",
    "public_key_to_etsi_encryption_key",
    "etsi_encryption_key_to_public_key",
    "der_signature_to_asn1",
    "compute_request_hash",
    "extract_validity_period",
    "extract_public_key_from_asn1_certificate",
    
    # Crypto
    "sign_data_ecdsa_sha256",
    "verify_signature_ecdsa_sha256",
    "compute_ecdh_shared_secret",
    "derive_key_hkdf",
    "verify_asn1_certificate_signature",
]
