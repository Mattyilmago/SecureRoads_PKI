"""
ETSI TS 102941 Message Types

This module implements the message type structures defined in ETSI TS 102941
for V2X PKI communication. These messages are used for enrollment, authorization,
and certificate management in the ETSI ITS PKI infrastructure.

Standards Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats

Author: SecureRoad PKI Project
Date: October 2025
"""

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# ============================================================================
# ENUMERATIONS
# ============================================================================


class ETSIMessageType(Enum):
    """ETSI Message Type Identifiers"""

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
    """Response codes for ETSI messages"""

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


class PublicKeyAlgorithm(Enum):
    """Public key algorithms supported"""

    ECDSA_NISTP256_WITH_SHA256 = "ecdsa-nistp256-with-sha256"
    ECDSA_BRAINPOOLP256R1_WITH_SHA256 = "ecdsa-brainpoolp256r1-with-sha256"
    ECDSA_BRAINPOOLP384R1_WITH_SHA384 = "ecdsa-brainpoolp384r1-with-sha384"


class SymmetricAlgorithm(Enum):
    """Symmetric encryption algorithms"""

    AES_128_CCM = "aes128-ccm"


# ============================================================================
# ENROLLMENT MESSAGES (ITS-S → EA)
# ============================================================================


@dataclass
class InnerEcRequest:
    """
    Inner Enrollment Certificate Request (unencrypted content)

    This is the actual enrollment request data before encryption.
    Contains ITS-S identity and public key for which certificate is requested.

    ETSI TS 102941 Section 6.2.3.1

    Conformità ETSI:
    - itsId: Identificativo canonico (es: "Vehicle_001", MAC address, etc.)
    - certificateFormat: 1 = ETSI TS 103097 V2X certificates
    - publicKeys: {"verification": public_key_bytes, "encryption": public_key_bytes}
    - requestedSubjectAttributes: Può includere:
        * "country": Codice ISO paese (es: "IT", "DE")
        * "organization": Nome organizzazione
        * "geographicRegion": Regione geografica operativa (ETSI TS 103097)
        * "assuranceLevel": Livello di sicurezza (0-7)
        * "validityPeriod": Periodo validità richiesto (giorni)
    """

    itsId: str  # Canonical ITS-S identifier
    certificateFormat: int = 1  # 1 = ETSI TS 103097 format
    publicKeys: Dict[str, bytes] = field(default_factory=dict)  # Key purpose → public key bytes
    requestedSubjectAttributes: Optional[Dict[str, Any]] = (
        None  # Subject DN attributes (see docstring)
    )

    def __post_init__(self):
        """Validate required fields"""
        if not self.itsId:
            raise ValueError("itsId is required")
        if not self.publicKeys:
            raise ValueError("At least one public key is required")


@dataclass
class InnerEcRequestSignedForPop:
    """
    Inner EC Request with Proof of Possession (PoP)

    Wraps InnerEcRequest with a signature proving possession of private key.

    ETSI TS 102941 Section 6.2.3.2
    """

    ecRequest: InnerEcRequest
    tbsData: bytes  # To-be-signed data (serialized InnerEcRequest)
    signature: bytes  # ECDSA signature over tbsData

    def verify_pop(self, public_key) -> bool:
        """
        Verify Proof of Possession signature

        Args:
            public_key: Public key (EllipticCurvePublicKey) to verify signature against

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Verify ECDSA signature over tbsData using provided public key
            public_key.verify(self.signature, self.tbsData, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False


@dataclass
class EnrollmentRequest:
    """
    Complete Enrollment Request Message (encrypted)

    This is the top-level message sent from ITS-S to EA.
    The InnerEcRequest is encrypted with EA's public key.

    ETSI TS 102941 Section 6.2.3

    Message Flow:
        ITS-S → EA: EnrollmentRequest
        EA → ITS-S: EnrollmentResponse (with EC)
    """

    version: str = "1.3.1"  # ETSI TS 102941 version
    encryptedData: bytes = b""  # Encrypted InnerEcRequestSignedForPop
    recipientId: Optional[str] = None  # HashedId8 of EA certificate
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.ENROLLMENT_REQUEST


@dataclass
class InnerEcResponse:
    """
    Inner Enrollment Certificate Response

    Contains the issued enrollment certificate or error information.

    ETSI TS 102941 Section 6.2.4.1
    """

    requestHash: bytes  # Hash of original InnerEcRequest
    responseCode: ResponseCode
    certificate: Optional[bytes] = None  # DER-encoded X.509 certificate

    def is_success(self) -> bool:
        """Check if enrollment was successful"""
        return self.responseCode == ResponseCode.OK


@dataclass
class EnrollmentResponse:
    """
    Complete Enrollment Response Message

    Response from EA to ITS-S with enrollment certificate or error.

    ETSI TS 102941 Section 6.2.4
    """

    version: str = "1.3.1"
    encryptedData: bytes = b""  # Encrypted InnerEcResponse
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.ENROLLMENT_RESPONSE


# ============================================================================
# AUTHORIZATION MESSAGES (ITS-S → AA)
# ============================================================================


@dataclass
class SharedAtRequest:
    """
    Shared Authorization Ticket Request

    Used in butterfly key expansion for batch AT requests.
    Contains parameters shared across all ATs in a batch.

    ETSI TS 102941 Section 6.3.3.1
    """

    eaId: bytes  # HashedId8 of EA that issued enrollment certificate
    keyTag: bytes  # Random value linking request to encryption key
    certificateFormat: int = 1
    requestedSubjectAttributes: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Validate shared request"""
        if not self.eaId:
            raise ValueError("eaId is required")
        if not self.keyTag:
            raise ValueError("keyTag is required")


@dataclass
class InnerAtRequest:
    """
    Inner Authorization Ticket Request (standard mode)

    Request for a single authorization ticket.

    ETSI TS 102941 Section 6.3.2.1

    Conformità ETSI:
    - publicKeys: Chiavi pubbliche per AT (diversa da EC per unlinkability!)
    - hmacKey: Chiave HMAC 32 bytes per crittare risposta → PRIVACY ETSI
        * Impedisce all'AA di correlare richieste dello stesso veicolo
        * Critica per unlinkability dei veicoli
    - sharedAtRequest: Parametri condivisi per butterfly expansion (batch AT)
    - requestedSubjectAttributes: Permessi richiesti:
        * "appPermissions": Lista servizi ITS (CAM, DENM, SPATEM, etc.)
        * "validityPeriod": Durata AT in ore (tipicamente 1-168h)
        * "geographicRegion": Regione operativa
        * "priority": Priorità traffico (emergenza, trasporto pubblico, etc.)
    """

    publicKeys: Dict[str, bytes]  # Verification key → public key bytes (MUST be different from EC!)
    hmacKey: bytes  # HMAC key for unlinkability (32 bytes recommended)
    sharedAtRequest: Optional[SharedAtRequest] = None  # For butterfly expansion
    ecSignature: Optional[bytes] = None  # EC signature (if butterfly mode)
    requestedSubjectAttributes: Optional[Dict[str, Any]] = (
        None  # ITS app permissions (see docstring)
    )

    def __post_init__(self):
        """Validate request"""
        if not self.publicKeys:
            raise ValueError("At least one public key is required")
        if not self.hmacKey:
            raise ValueError("hmacKey is required")


@dataclass
class AuthorizationRequest:
    """
    Complete Authorization Request Message

    Top-level message from ITS-S to AA requesting authorization tickets.

    ETSI TS 102941 Section 6.3.2

    Message Flow:
        ITS-S → AA: AuthorizationRequest (with EC)
        AA → EA: AuthorizationValidationRequest (check EC status)
        EA → AA: AuthorizationValidationResponse
        AA → ITS-S: AuthorizationResponse (with AT batch)
    """

    version: str = "1.3.1"
    encryptedData: bytes = b""  # Encrypted InnerAtRequest
    enrollmentCertificate: bytes = b""  # DER-encoded EC for authentication
    recipientId: Optional[str] = None  # HashedId8 of AA certificate
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.AUTHORIZATION_REQUEST


@dataclass
class ButterflyAuthorizationRequest:
    """
    Butterfly Authorization Request (batch mode)

    Enhanced request for multiple authorization tickets using butterfly
    key expansion. More efficient than multiple individual requests.

    ETSI TS 102941 Section 6.3.3

    Butterfly Key Expansion:
        1. ITS-S generates shared parameters (SharedAtRequest)
        2. ITS-S generates N individual InnerAtRequest (one per AT)
        3. AA expands keys using butterfly expansion
        4. AA issues N authorization tickets in one batch
    """

    sharedAtRequest: SharedAtRequest
    innerAtRequests: List[InnerAtRequest]  # Batch of AT requests
    batchSize: int
    version: str = "1.3.1"
    enrollmentCertificate: bytes = b""
    recipientId: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        """Validate butterfly request"""
        if self.batchSize != len(self.innerAtRequests):
            raise ValueError(
                f"Batch size mismatch: expected {self.batchSize}, got {len(self.innerAtRequests)}"
            )
        if self.batchSize < 1 or self.batchSize > 100:
            raise ValueError("Batch size must be between 1 and 100")

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.AUTHORIZATION_REQUEST


@dataclass
class InnerAtResponse:
    """
    Inner Authorization Ticket Response

    Contains issued AT or error information.

    ETSI TS 102941 Section 6.3.4.1
    """

    requestHash: bytes  # Hash of original InnerAtRequest
    responseCode: ResponseCode
    certificate: Optional[bytes] = None  # DER-encoded AT certificate

    def is_success(self) -> bool:
        """Check if authorization was successful"""
        return self.responseCode == ResponseCode.OK


@dataclass
class AuthorizationResponse:
    """
    Complete Authorization Response Message

    Response from AA to ITS-S with authorization tickets.

    ETSI TS 102941 Section 6.3.4
    """

    version: str = "1.3.1"
    encryptedData: bytes = b""  # Encrypted InnerAtResponse or batch
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.AUTHORIZATION_RESPONSE


# ============================================================================
# AUTHORIZATION VALIDATION MESSAGES (AA → EA)
# ============================================================================


@dataclass
class AuthorizationValidationRequest:
    """
    Authorization Validation Request (AA → EA)

    AA asks EA to validate that enrollment certificate is still valid
    and has not been revoked before issuing authorization tickets.

    ETSI TS 102941 Section 6.4.1

    Message Flow:
        AA → EA: AuthorizationValidationRequest
        EA → AA: AuthorizationValidationResponse (OK or REVOKED)
    """

    sharedAtRequest: SharedAtRequest
    enrollmentCertificate: bytes  # EC to validate
    version: str = "1.3.1"
    recipientId: Optional[str] = None  # HashedId8 of EA certificate
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.AUTHORIZATION_VALIDATION_REQUEST


@dataclass
class AuthorizationValidationResponse:
    """
    Authorization Validation Response (EA → AA)

    EA responds with validation status of enrollment certificate.

    ETSI TS 102941 Section 6.4.2
    """

    requestHash: bytes  # Hash of AuthorizationValidationRequest
    responseCode: ResponseCode
    version: str = "1.3.1"
    confirmedSubjectAttributes: Optional[Dict[str, Any]] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_valid(self) -> bool:
        """Check if certificate is valid"""
        return self.responseCode == ResponseCode.OK

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.AUTHORIZATION_VALIDATION_RESPONSE


# ============================================================================
# CERTIFICATE TRUST LIST MESSAGES (ITS-S → TLM)
# ============================================================================


@dataclass
class CtlRequest:
    """
    Certificate Trust List Request

    ITS-S requests the latest CTL from Trust List Manager.

    ETSI TS 102941 Section 6.5.1
    """

    version: str = "1.3.1"
    requestType: str = "full"  # "full" or "delta"
    lastKnownCtlSequence: Optional[int] = None  # For delta requests
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.CTL_REQUEST


@dataclass
class CtlResponse:
    """
    Certificate Trust List Response

    TLM responds with full or delta CTL.

    ETSI TS 102941 Section 6.5.2
    """

    responseCode: ResponseCode
    ctlSequence: int  # CTL sequence number
    isFullCtl: bool  # True if full CTL, False if delta
    version: str = "1.3.1"
    ctlData: Optional[bytes] = None  # Serialized CTL
    nextUpdate: Optional[datetime] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_success(self) -> bool:
        """Check if CTL retrieval was successful"""
        return self.responseCode == ResponseCode.OK

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.CTL_RESPONSE


# ============================================================================
# CRL MESSAGES (ITS-S → CA)
# ============================================================================


@dataclass
class CrlRequest:
    """
    Certificate Revocation List Request

    ITS-S requests latest CRL from CA.

    ETSI TS 102941 Section 6.6.1
    """

    issuerId: bytes  # HashedId8 of CA
    version: str = "1.3.1"
    lastKnownCrlSequence: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.CRL_REQUEST


@dataclass
class CrlResponse:
    """
    Certificate Revocation List Response

    CA responds with latest CRL.

    ETSI TS 102941 Section 6.6.2
    """

    responseCode: ResponseCode
    version: str = "1.3.1"
    crlData: Optional[bytes] = None  # DER-encoded X.509 CRL
    nextUpdate: Optional[datetime] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_success(self) -> bool:
        """Check if CRL retrieval was successful"""
        return self.responseCode == ResponseCode.OK

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.CRL_RESPONSE


# ============================================================================
# CA CERTIFICATE MESSAGES
# ============================================================================


@dataclass
class CaCertificateRequest:
    """
    CA Certificate Request

    Request for CA certificate (Root CA, EA, AA).

    ETSI TS 102941 Section 6.7.1
    """

    version: str = "1.3.1"
    caId: Optional[bytes] = None  # HashedId8, None = Root CA
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.CA_CERTIFICATE_REQUEST


@dataclass
class CaCertificateResponse:
    """
    CA Certificate Response

    Response with requested CA certificate.

    ETSI TS 102941 Section 6.7.2
    """

    responseCode: ResponseCode
    version: str = "1.3.1"
    certificate: Optional[bytes] = None  # DER-encoded certificate
    certificateChain: Optional[List[bytes]] = None  # Full chain to root
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_success(self) -> bool:
        """Check if certificate retrieval was successful"""
        return self.responseCode == ResponseCode.OK

    def get_message_type(self) -> ETSIMessageType:
        """Returns the message type identifier"""
        return ETSIMessageType.CA_CERTIFICATE_RESPONSE


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def compute_request_hash(data: bytes) -> bytes:
    """
    Compute SHA-256 hash of request for response correlation.

    Args:
        data: Serialized request data

    Returns:
        SHA-256 hash (32 bytes)
    """
    return hashlib.sha256(data).digest()


def compute_hashed_id8(certificate_bytes: bytes) -> bytes:
    """
    Compute HashedId8 (8-byte identifier) from certificate.

    Used for recipient identification in encrypted messages.

    Args:
        certificate_bytes: DER-encoded certificate

    Returns:
        Last 8 bytes of SHA-256 hash
    """
    full_hash = hashlib.sha256(certificate_bytes).digest()
    return full_hash[-8:]  # Last 8 bytes


def verify_message_version(version: str) -> bool:
    """
    Verify that message version is supported.

    Args:
        version: ETSI TS 102941 version string

    Returns:
        True if version is supported
    """
    supported_versions = ["1.3.1", "1.4.1", "2.1.1"]
    return version in supported_versions


# ============================================================================
# MESSAGE TYPE REGISTRY
# ============================================================================

MESSAGE_TYPE_REGISTRY = {
    ETSIMessageType.ENROLLMENT_REQUEST: EnrollmentRequest,
    ETSIMessageType.ENROLLMENT_RESPONSE: EnrollmentResponse,
    ETSIMessageType.AUTHORIZATION_REQUEST: AuthorizationRequest,
    ETSIMessageType.AUTHORIZATION_RESPONSE: AuthorizationResponse,
    ETSIMessageType.AUTHORIZATION_VALIDATION_REQUEST: AuthorizationValidationRequest,
    ETSIMessageType.AUTHORIZATION_VALIDATION_RESPONSE: AuthorizationValidationResponse,
    ETSIMessageType.CTL_REQUEST: CtlRequest,
    ETSIMessageType.CTL_RESPONSE: CtlResponse,
    ETSIMessageType.CRL_REQUEST: CrlRequest,
    ETSIMessageType.CRL_RESPONSE: CrlResponse,
    ETSIMessageType.CA_CERTIFICATE_REQUEST: CaCertificateRequest,
    ETSIMessageType.CA_CERTIFICATE_RESPONSE: CaCertificateResponse,
}
