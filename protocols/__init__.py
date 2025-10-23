"""
ETSI ITS PKI Protocol Implementations

Implements the core cryptographic protocols and message types for V2X PKI
according to ETSI TS 102 941 and related standards.

Module Structure (Refactored):
- core/: Core types, encoding, and cryptographic operations
- certificates/: Certificate encoders for all certificate types
- messages/: Protocol message dataclasses
- security/: Security operations (butterfly, ECIES, PoP)

Standards Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats

Author: SecureRoad PKI Project
Date: October 2025
"""

__version__ = "2.0.0"  # Version 2.0.0 with modular architecture

# ============================================================================
# NEW MODULAR IMPORTS (Refactored Architecture)
# ============================================================================

# Core types and utilities
from .core import (
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
    
    # Encoding utilities
    time32_encode,
    time32_decode,
    compute_hashed_id8,
    encode_public_key_compressed,
    decode_public_key_compressed,
    compute_request_hash,
    
    # Cryptographic operations
    sign_data_ecdsa_sha256,
    verify_signature_ecdsa_sha256,
    compute_ecdh_shared_secret,
    derive_key_hkdf,
)

# Certificate encoders (new modular structure)
from .certificates import (
    BaseCertificate,
    RootCertificate,
    SubordinateCertificate,  # Replaces "AuthorityCertificate" (EA/AA)
    EnrollmentCertificate,
    AuthorizationTicket,
    LinkCertificate,
    extract_validity_period,
    verify_asn1_certificate_signature,
    extract_public_key_from_asn1_certificate,
)

# Protocol messages
from .messages import (
    # Enrollment
    InnerEcRequest,
    InnerEcRequestSignedForPop,
    EnrollmentRequest,
    InnerEcResponse,
    EnrollmentResponse,
    
    # Authorization
    SharedAtRequest,
    InnerAtRequest,
    AuthorizationRequest,
    ButterflyAuthorizationRequest,
    InnerAtResponse,
    AuthorizationResponse,
    
    # Validation
    AuthorizationValidationRequest,
    AuthorizationValidationResponse,
    
    # Trust List
    CtlRequest,
    CtlResponse,
    
    # Revocation
    CrlRequest,
    CrlResponse,
    
    # CA Certificate
    CaCertificateRequest,
    CaCertificateResponse,
)

# Security operations
from .security import (
    ButterflyExpansion,
    ecies_encrypt,
    ecies_decrypt,
    generate_pop_signature,
    verify_pop_signature,
)

# ============================================================================
# BACKWARD COMPATIBILITY IMPORTS (Legacy Architecture)
# ============================================================================

# Keep old imports for backward compatibility during migration
from .messages.types import (
    InnerEcRequest as _InnerEcRequest,
    InnerEcResponse as _InnerEcResponse,
    InnerAtRequest as _InnerAtRequest,
    InnerAtResponse as _InnerAtResponse,
    SharedAtRequest as _SharedAtRequest,
)

# Legacy certificate imports - NOW USING NEW MODULAR STRUCTURE
from .certificates import (
    RootCertificate as ETSIRootCertificateEncoder,
    SubordinateCertificate as ETSIAuthorityCertificateEncoder,
    EnrollmentCertificate as ETSIEnrollmentCertificateEncoder,
    AuthorizationTicket as ETSIAuthorizationTicketEncoder,
    LinkCertificate as ETSILinkCertificateEncoder,
    TrustListEncoder as ETSITrustListEncoder,
)

# Legacy utilities - NOW USING NEW MODULAR STRUCTURE
from .certificates.utils import (
    extract_validity_period as _extract_validity_period,
    verify_asn1_certificate_signature,
    extract_public_key_from_asn1_certificate,
)

# Legacy butterfly imports - NOW USING NEW MODULAR STRUCTURE
from .security.butterfly import (
    ButterflyExpansion,
)
# Create function aliases for backward compatibility
_butterfly = ButterflyExpansion()
derive_at_keys = lambda *args, **kwargs: _butterfly.derive_at_keys(*args, **kwargs)
generate_key_tag = lambda *args, **kwargs: _butterfly.generate_key_tag(*args, **kwargs)
derive_ecc_key_pair_from_seed = lambda seed: _butterfly.derive_ecc_key_pair_from_seed(seed)
compute_shared_secret_ecdh = lambda priv, pub: _butterfly.compute_shared_secret_ecdh(priv, pub)
validate_butterfly_keys = lambda *args: _butterfly.validate_butterfly_keys(*args)
compute_key_fingerprint = lambda key: _butterfly.compute_key_fingerprint(key)
derive_ticket_hmac = lambda *args: _butterfly.derive_ticket_hmac(*args)

# ============================================================================
# PUBLIC API EXPORTS
# ============================================================================

__all__ = [
    # Version
    "__version__",
    
    # Core constants
    "ETSI_EPOCH",
    "CERT_TYPE_EXPLICIT",
    "CERT_TYPE_AUTHORIZATION",
    "CERT_TYPE_ENROLLMENT",
    
    # Core enums
    "ETSIMessageType",
    "ResponseCode",
    "PublicKeyAlgorithm",
    "SymmetricAlgorithm",
    
    # Core encoding
    "time32_encode",
    "time32_decode",
    "compute_hashed_id8",
    "encode_public_key_compressed",
    "decode_public_key_compressed",
    "compute_request_hash",
    
    # Core crypto
    "sign_data_ecdsa_sha256",
    "verify_signature_ecdsa_sha256",
    "compute_ecdh_shared_secret",
    "derive_key_hkdf",
    
    # Certificates (new API)
    "BaseCertificate",
    "RootCertificate",
    "SubordinateCertificate",
    "EnrollmentCertificate",
    "AuthorizationTicket",
    "LinkCertificate",
    "extract_validity_period",
    "verify_asn1_certificate_signature",
    "extract_public_key_from_asn1_certificate",
    
    # Certificates (legacy API - backward compatibility)
    "ETSIRootCertificateEncoder",
    "ETSIAuthorityCertificateEncoder",
    "ETSIEnrollmentCertificateEncoder",
    "ETSIAuthorizationTicketEncoder",
    "ETSILinkCertificateEncoder",
    "ETSITrustListEncoder",
    
    # Messages
    "InnerEcRequest",
    "InnerEcRequestSignedForPop",
    "EnrollmentRequest",
    "InnerEcResponse",
    "EnrollmentResponse",
    "SharedAtRequest",
    "InnerAtRequest",
    "AuthorizationRequest",
    "ButterflyAuthorizationRequest",
    "InnerAtResponse",
    "AuthorizationResponse",
    "AuthorizationValidationRequest",
    "AuthorizationValidationResponse",
    "CtlRequest",
    "CtlResponse",
    "CrlRequest",
    "CrlResponse",
    "CaCertificateRequest",
    "CaCertificateResponse",
    
    # Security
    "ButterflyExpansion",
    "ecies_encrypt",
    "ecies_decrypt",
    "generate_pop_signature",
    "verify_pop_signature",
    
    # Legacy butterfly (backward compatibility)
    "derive_at_keys",
    "generate_key_tag",
    "derive_ecc_key_pair_from_seed",
    "compute_shared_secret_ecdh",
    "validate_butterfly_keys",
    "compute_key_fingerprint",
    "derive_ticket_hmac",
]
