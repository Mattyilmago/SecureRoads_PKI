"""
ETSI Core Types and Constants

Defines fundamental enumerations, constants, and type definitions used throughout
the ETSI ITS PKI protocol implementation.

Standards Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats

Author: SecureRoad PKI Project
Date: October 2025
"""

from datetime import datetime, timezone
from enum import Enum


# ============================================================================
# ETSI CONSTANTS (ETSI TS 103097 Section 4)
# ============================================================================

# ETSI Epoch: 2004-01-01 00:00:00 UTC (TAI - International Atomic Time)
# Used as reference for Time32 encoding
ETSI_EPOCH = datetime(2004, 1, 1, tzinfo=timezone.utc)

# Certificate Types (ETSI TS 103097 Section 6.4.1)
CERT_TYPE_EXPLICIT = 0  # Root CA and Subordinate Certificates (EA/AA)
CERT_TYPE_AUTHORIZATION = 1  # Authorization Ticket
CERT_TYPE_ENROLLMENT = 2  # Enrollment Certificate


# ============================================================================
# ENUMERATIONS
# ============================================================================


class ETSIMessageType(Enum):
    """
    ETSI Message Type Identifiers
    
    Defines all message types supported by ETSI TS 102941 protocol.
    """

    ENROLLMENT_REQUEST = "EnrollmentRequest"
    ENROLLMENT_RESPONSE = "EnrollmentResponse"
    AUTHORIZATION_REQUEST = "AuthorizationRequest"
    AUTHORIZATION_RESPONSE = "AuthorizationResponse"
    AUTHORIZATION_VALIDATION_REQUEST = "AuthorizationValidationRequest"
    AUTHORIZATION_VALIDATION_RESPONSE = "AuthorizationValidationResponse"
    CA_CERTIFICATE_REQUEST = "CaCertificateRequest"
    CA_CERTIFICATE_RESPONSE = "CaCertificateResponse"
    CTL_REQUEST = "CtlRequest"
    CTL_RESPONSE = "CtlResponse"
    CRL_REQUEST = "CrlRequest"
    CRL_RESPONSE = "CrlResponse"


class ResponseCode(Enum):
    """
    Response codes for ETSI messages
    
    ETSI TS 102941 Section 6.1.2
    """

    OK = 0
    CANONICAL_ENCODING_ERROR = 1
    BAD_CONTENT_TYPE = 2
    IMPLICIT_CERTIFICATE_VERIFICATION_FAILED = 3
    DECRYPTION_FAILED = 4
    UNKNOWN_ITS_ID = 5
    INVALID_SIGNATURE = 6
    INVALID_ENCRYPTION_KEY = 7
    BAD_REQUEST = 8
    UNAUTHORIZED = 9
    INTERNAL_SERVER_ERROR = 10
    UNSUPPORTED_VERSION = 11
    WRONG_EA = 12
    WRONG_AA = 13
    DENM_INVALID_PERMISSIONS = 14
    CAM_INVALID_PERMISSIONS = 15
    UNKNOWN_EA = 16


class PublicKeyAlgorithm(Enum):
    """
    Public key algorithms supported
    
    ETSI TS 103097 Section 5.3
    """

    ECDSA_NISTP256_WITH_SHA256 = "ecdsa-nistp256-with-sha256"
    ECDSA_BRAINPOOLP256R1_WITH_SHA256 = "ecdsa-brainpoolp256r1-with-sha256"
    ECDSA_BRAINPOOLP384R1_WITH_SHA384 = "ecdsa-brainpoolp384r1-with-sha384"


class SymmetricAlgorithm(Enum):
    """
    Symmetric encryption algorithms
    
    ETSI TS 103097 Section 5.2
    """

    AES_128_CCM = "aes128-ccm"


class CertificateType(Enum):
    """
    Certificate type enumeration with semantic names
    
    Maps to ETSI TS 103097 CertificateType values.
    """
    
    EXPLICIT = 0  # Root CA and Subordinate (EA/AA)
    AUTHORIZATION = 1  # Authorization Ticket
    ENROLLMENT = 2  # Enrollment Certificate


# ============================================================================
# ITS APPLICATION IDENTIFIERS (ETSI TS 102965)
# ============================================================================

# ITS Application IDs (PSIDs) for V2X communication
ITS_APP_IDS = {
    'CAM': 36,   # Cooperative Awareness Message (ETSI EN 302 637-2)
    'DENM': 37,  # Decentralized Environmental Notification Message (ETSI EN 302 637-3)
}


def convert_app_permissions_to_psid_ssp(app_names: list) -> list:
    """
    Convert list of ITS-AID strings to ETSI PsidSsp sequence.
    
    According to IEEE 1609.2 and ETSI TS 102941:
    PsidSsp ::= SEQUENCE {
        psid    Psid,
        ssp     ServiceSpecificPermissions OPTIONAL
    }
    
    Args:
        app_names: List of ITS-AID names (e.g., ["CAM", "DENM"]) or numeric PSIDs
        
    Returns:
        List of PsidSsp dictionaries: [{"psid": 36}, {"psid": 37}]
        
    Example:
        >>> convert_app_permissions_to_psid_ssp(["CAM", "DENM"])
        [{'psid': 36}, {'psid': 37}]
    """
    psid_ssp_list = []
    for app_name in app_names:
        if isinstance(app_name, str):
            # Look up string name in ITS_APP_IDS
            psid = ITS_APP_IDS.get(app_name)
            if psid is None:
                # Try to parse as numeric string
                try:
                    psid = int(app_name)
                except (ValueError, TypeError):
                    raise ValueError(f"Unknown ITS-AID: {app_name}. Known AIDs: {list(ITS_APP_IDS.keys())}")
        elif isinstance(app_name, int):
            psid = app_name
        else:
            raise TypeError(f"Invalid ITS-AID type: {type(app_name)}. Expected str or int.")
        
        # Create PsidSsp with psid only (no SSP - Service Specific Permissions)
        psid_ssp_list.append({"psid": psid})
    
    return psid_ssp_list


# ============================================================================
# SIGNATURE ALGORITHM IDENTIFIERS
# ============================================================================

SIGNATURE_ALGORITHM_ECDSA_SHA256 = 0
SIGNATURE_ALGORITHM_ECDSA_SHA384 = 1
