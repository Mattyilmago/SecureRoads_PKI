"""
ETSI Certificate Encoders

This module provides certificate encoding/decoding for all ETSI ITS PKI
certificate types according to ETSI TS 103097 V2.1.1.

Certificate Types:
- Root Certificate: Self-signed trust anchor (Root CA)
- Subordinate Certificate: Intermediate certificates (EA/AA)
- Enrollment Certificate: Long-lived ITS-S certificates
- Authorization Ticket: Short-lived pseudonymous certificates
- Link Certificate: Certificate renewal linkage

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management

Author: SecureRoad PKI Project
Date: October 2025
"""

from .base import BaseCertificate
from .root import RootCertificate
from .subordinate import SubordinateCertificate
from .enrollment import EnrollmentCertificate
from .authorization import AuthorizationTicket
from .link import LinkCertificate
from .trust_list import TrustListEncoder
from .utils import (
    extract_validity_period,
    verify_asn1_certificate_signature,
    extract_public_key_from_asn1_certificate,
)
from .asn1_encoder import (
    build_certificate_dict,
    encode_certificate_with_asn1,
    decode_certificate_with_asn1,
    asn1_compiler,
    generate_root_certificate,
    generate_subordinate_certificate,
    generate_enrollment_certificate,
    generate_authorization_ticket,
)

__all__ = [
    # Base class
    "BaseCertificate",
    
    # Certificate types
    "RootCertificate",
    "SubordinateCertificate",
    "EnrollmentCertificate",
    "AuthorizationTicket",
    "LinkCertificate",
    "TrustListEncoder",
    
    # Utilities
    "extract_validity_period",
    "verify_asn1_certificate_signature",
    "extract_public_key_from_asn1_certificate",
    
    # ASN.1 helpers
    "build_certificate_dict",
    "encode_certificate_with_asn1",
    "decode_certificate_with_asn1",
    "asn1_compiler",
    "generate_root_certificate",
    "generate_subordinate_certificate",
    "generate_enrollment_certificate",
    "generate_authorization_ticket",
]
