"""
ETSI Protocol Messages

This module provides protocol message dataclasses for ETSI ITS PKI communication.

Message categories:
- Enrollment: EnrollmentRequest/Response
- Authorization: AuthorizationRequest/Response  
- Validation: AuthorizationValidationRequest/Response
- Trust List: CtlRequest/Response
- Revocation: CrlRequest/Response
- CA Certificate: CaCertificateRequest/Response

Standards Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management

Author: SecureRoad PKI Project
Date: October 2025
"""

# Re-export all message types from types module
from .types import (
    # Enrollment messages
    InnerEcRequest,
    InnerEcRequestSignedForPop,
    EnrollmentRequest,
    InnerEcResponse,
    EnrollmentResponse,
    
    # Authorization messages
    SharedAtRequest,
    InnerAtRequest,
    AuthorizationRequest,
    ButterflyAuthorizationRequest,
    InnerAtResponse,
    AuthorizationResponse,
    
    # Validation messages
    AuthorizationValidationRequest,
    AuthorizationValidationResponse,
    
    # Trust list messages
    CtlRequest,
    CtlResponse,
    
    # Revocation messages
    CrlRequest,
    CrlResponse,
    
    # CA certificate messages
    CaCertificateRequest,
    CaCertificateResponse,
    
    # Registry
    MESSAGE_TYPE_REGISTRY,
)

__all__ = [
    # Enrollment
    "InnerEcRequest",
    "InnerEcRequestSignedForPop",
    "EnrollmentRequest",
    "InnerEcResponse",
    "EnrollmentResponse",
    
    # Authorization
    "SharedAtRequest",
    "InnerAtRequest",
    "AuthorizationRequest",
    "ButterflyAuthorizationRequest",
    "InnerAtResponse",
    "AuthorizationResponse",
    
    # Validation
    "AuthorizationValidationRequest",
    "AuthorizationValidationResponse",
    
    # Trust list
    "CtlRequest",
    "CtlResponse",
    
    # Revocation
    "CrlRequest",
    "CrlResponse",
    
    # CA certificate
    "CaCertificateRequest",
    "CaCertificateResponse",
    
    # Registry
    "MESSAGE_TYPE_REGISTRY",
]

