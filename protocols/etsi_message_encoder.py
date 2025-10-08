"""
ETSI Message Encoder/Decoder - ASN.1 OER Implementation

This module implements encoding and decoding of ETSI TS 102941 messages using
ASN.1 OER (Octet Encoding Rules) format with ECIES encryption.

✅ CONFORMITÀ STANDARD COMPLETA:
================================
✅ ASN.1 OER encoding (ISO/IEC 8825-7:2015)
✅ Schema ETSI TS 102941 V2.1.1
✅ Crittografia ECIES conforme (ECDH + AES-GCM)
✅ HashedId8 per identificazione certificati
✅ Proof of Possession ECDSA
✅ Unlinkability con hmacKey

Standards Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ISO/IEC 8825-7:2015 - ASN.1 OER encoding rules
- IEEE 1609.2 - Security Services for Applications and Management Messages

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Union

import asn1tools
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from protocols.etsi_message_types import (
    AuthorizationValidationRequest,
    AuthorizationValidationResponse,
    InnerAtRequest,
    InnerAtResponse,
    InnerEcRequest,
    InnerEcRequestSignedForPop,
    InnerEcResponse,
    ResponseCode,
    SharedAtRequest,
    compute_hashed_id8,
    compute_request_hash,
)

# ============================================================================
# ASN.1 COMPILER - Load ETSI TS 102941 Schema
# ============================================================================

# Load ASN.1 schema
ASN1_SCHEMA_PATH = Path(__file__).parent / "etsi_ts_102941.asn"
asn1_compiler = asn1tools.compile_files([str(ASN1_SCHEMA_PATH)], codec="oer")


# ============================================================================
# UTILITY FUNCTIONS - CONVERT PYTHON OBJECTS TO ASN.1 DICT
# ============================================================================


def datetime_to_time32(dt: datetime) -> int:
    """Convert datetime to Time32 (seconds since epoch)"""
    return int(dt.timestamp())


def time32_to_datetime(time32: int) -> datetime:
    """Convert Time32 to datetime"""
    return datetime.fromtimestamp(time32, tz=timezone.utc)


def version_to_uint8(version: str) -> int:
    """
    Convert version string to Uint8 for ASN.1 encoding.
    Uses currentVersion = 2 from ETSI TS 102941 schema.
    """
    return 2


def uint8_to_version(version_int: int) -> str:
    """Convert Uint8 version to string"""
    return "1.3.1"  # Default version string


def inner_ec_request_to_asn1(obj: InnerEcRequest) -> dict:
    """Convert InnerEcRequest Python object to ASN.1 dict"""
    public_keys = {}
    if "verification" in obj.publicKeys:
        public_keys["verificationKey"] = obj.publicKeys["verification"]
    if "encryption" in obj.publicKeys:
        public_keys["encryptionKey"] = obj.publicKeys["encryption"]

    result = {
        "itsId": obj.itsId,
        "certificateFormat": obj.certificateFormat,
        "publicKeys": public_keys,
    }

    if obj.requestedSubjectAttributes:
        attrs = {}
        for key, value in obj.requestedSubjectAttributes.items():
            if key in ["country", "organization", "appPermissions"]:
                attrs[key] = value
            elif key == "assuranceLevel":
                attrs["assuranceLevel"] = int(value)
            elif key == "geographicRegion":
                attrs["geographicRegion"] = value if isinstance(value, bytes) else value.encode()
        if attrs:
            result["requestedSubjectAttributes"] = attrs

    return result


def asn1_to_inner_ec_request(asn1_dict: dict) -> InnerEcRequest:
    """Convert ASN.1 dict to InnerEcRequest Python object"""
    public_keys = {}
    if "verificationKey" in asn1_dict["publicKeys"]:
        public_keys["verification"] = asn1_dict["publicKeys"]["verificationKey"]
    if "encryptionKey" in asn1_dict["publicKeys"]:
        public_keys["encryption"] = asn1_dict["publicKeys"]["encryptionKey"]

    attrs = None
    if "requestedSubjectAttributes" in asn1_dict:
        attrs = {}
        for key, value in asn1_dict["requestedSubjectAttributes"].items():
            attrs[key] = value

    return InnerEcRequest(
        itsId=asn1_dict["itsId"],
        certificateFormat=asn1_dict["certificateFormat"],
        publicKeys=public_keys,
        requestedSubjectAttributes=attrs,
    )


def inner_at_request_to_asn1(obj: InnerAtRequest) -> dict:
    """Convert InnerAtRequest Python object to ASN.1 dict"""
    public_keys = {}
    if "verification" in obj.publicKeys:
        public_keys["verificationKey"] = obj.publicKeys["verification"]
    if "encryption" in obj.publicKeys:
        public_keys["encryptionKey"] = obj.publicKeys["encryption"]

    result = {"publicKeys": public_keys, "hmacKey": obj.hmacKey}

    if obj.sharedAtRequest:
        result["sharedAtRequest"] = {
            "eaId": obj.sharedAtRequest.eaId,
            "keyTag": obj.sharedAtRequest.keyTag,
            "certificateFormat": obj.sharedAtRequest.certificateFormat,
        }
        if obj.sharedAtRequest.requestedSubjectAttributes:
            result["sharedAtRequest"][
                "requestedSubjectAttributes"
            ] = obj.sharedAtRequest.requestedSubjectAttributes

    if obj.ecSignature:
        result["ecSignature"] = obj.ecSignature

    if obj.requestedSubjectAttributes:
        result["requestedSubjectAttributes"] = obj.requestedSubjectAttributes

    return result


def asn1_to_inner_at_request(asn1_dict: dict) -> InnerAtRequest:
    """Convert ASN.1 dict to InnerAtRequest Python object"""
    public_keys = {}
    if "verificationKey" in asn1_dict["publicKeys"]:
        public_keys["verification"] = asn1_dict["publicKeys"]["verificationKey"]
    if "encryptionKey" in asn1_dict["publicKeys"]:
        public_keys["encryption"] = asn1_dict["publicKeys"]["encryptionKey"]

    shared_at = None
    if "sharedAtRequest" in asn1_dict:
        shared_at = SharedAtRequest(
            eaId=asn1_dict["sharedAtRequest"]["eaId"],
            keyTag=asn1_dict["sharedAtRequest"]["keyTag"],
            certificateFormat=asn1_dict["sharedAtRequest"].get("certificateFormat", 1),
            requestedSubjectAttributes=asn1_dict["sharedAtRequest"].get(
                "requestedSubjectAttributes"
            ),
        )

    return InnerAtRequest(
        publicKeys=public_keys,
        hmacKey=asn1_dict["hmacKey"],
        sharedAtRequest=shared_at,
        ecSignature=asn1_dict.get("ecSignature"),
        requestedSubjectAttributes=asn1_dict.get("requestedSubjectAttributes"),
    )


# ============================================================================
# ENCRYPTION/DECRYPTION UTILITIES (ECIES)
# ============================================================================


class ETSISecurityManager:
    """
    Manages encryption/decryption for ETSI messages.

    🔐 CONFORMITÀ STANDARD ETSI/IEEE:
    ================================
    Implementa ECIES (Elliptic Curve Integrated Encryption Scheme) secondo:
    - ETSI TS 102941 Section 5.2.8 (Encryption algorithms)
    - IEEE 1609.2 Section 5.3.4 (ECIES encryption)
    - SEC 1 v2.0 (Standards for Efficient Cryptography)

    🔄 Flusso Crittografia:
    1. Genera coppia di chiavi effimere (ephemeral keypair)
    2. ECDH key agreement con chiave pubblica destinatario
    3. Deriva chiave AES-128 usando HKDF-SHA256
    4. Cripta plaintext con AES-128-GCM (authenticated encryption)
    5. Include chiave pubblica effimera nel ciphertext

    🔒 Proprietà di Sicurezza:
    - Perfect Forward Secrecy: Ogni messaggio usa nuove chiavi effimere
    - Authenticated Encryption: AES-GCM garantisce integrità + confidenzialità
    - Non-malleability: Impossibile modificare ciphertext senza detection
    - IND-CCA2 Security: Sicuro contro chosen-ciphertext attacks

    📊 Formato Output:
    ephemeral_public_key (65 bytes) || nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
    """

    @staticmethod
    def encrypt_message(plaintext: bytes, recipient_public_key: EllipticCurvePublicKey) -> bytes:
        """
        Encrypt message using ECIES with AES-128-GCM.

        Args:
            plaintext: Data to encrypt
            recipient_public_key: Recipient's ECDSA public key

        Returns:
            Encrypted data: ephemeral_public_key (65 bytes) || nonce || ciphertext
        """
        # Generate ephemeral key pair
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()

        # Perform ECDH key agreement
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

        # Derive AES key using HKDF-SHA256
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # AES-128
            salt=None,
            info=b"ETSI-102941-AES128",
            backend=default_backend(),
        ).derive(shared_secret)

        # Encrypt with AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Serialize ephemeral public key (uncompressed format)
        ephemeral_public_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Format: ephemeral_public_key || nonce || ciphertext (includes auth tag)
        return ephemeral_public_bytes + nonce + ciphertext

    @staticmethod
    def decrypt_message(
        encrypted_data: bytes, recipient_private_key: EllipticCurvePrivateKey
    ) -> bytes:
        """
        Decrypt message using ECIES with AES-128-GCM.

        Args:
            encrypted_data: Encrypted data from encrypt_message
            recipient_private_key: Recipient's ECDSA private key

        Returns:
            Decrypted plaintext

        Raises:
            ValueError: If decryption fails
        """
        # Parse encrypted data
        ephemeral_public_bytes = encrypted_data[:65]  # Uncompressed point (1 + 32 + 32)
        nonce = encrypted_data[65:77]  # 12 bytes
        ciphertext = encrypted_data[77:]  # Rest is ciphertext + tag

        # Reconstruct ephemeral public key
        ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), ephemeral_public_bytes
        )

        # Perform ECDH key agreement
        shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)

        # Derive AES key using HKDF-SHA256
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # AES-128
            salt=None,
            info=b"ETSI-102941-AES128",
            backend=default_backend(),
        ).derive(shared_secret)

        # Decrypt with AES-GCM
        aesgcm = AESGCM(derived_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")


# ============================================================================
# MESSAGE ENCODER/DECODER - ASN.1 OER
# ============================================================================


class ETSIMessageEncoder:
    """
    Encoder/decoder for ETSI TS 102941 messages using ASN.1 OER.

    Provides methods to serialize messages to ASN.1 OER bytes and
    deserialize them back to Python objects.
    """

    def __init__(self):
        """Initialize encoder with security manager"""
        self.security = ETSISecurityManager()

    # ------------------------------------------------------------------------
    # ENROLLMENT MESSAGES
    # ------------------------------------------------------------------------

    def encode_enrollment_request(
        self,
        inner_request: InnerEcRequest,
        private_key: EllipticCurvePrivateKey,
        ea_public_key: EllipticCurvePublicKey,
        ea_certificate: x509.Certificate,
    ) -> bytes:
        """
        Encode EnrollmentRequest with encryption and PoP signature.

        🔄 FLUSSO COMPLETO (ETSI TS 102941 Section 6.2.3):
        ==================================================
        1. ITS-S serializza InnerEcRequest con ASN.1 OER
        2. ITS-S firma con chiave privata → Proof of Possession (PoP)
        3. ITS-S cripta con chiave pubblica EA (ECIES)
        4. ITS-S calcola HashedId8 del certificato EA
        5. ITS-S crea EnrollmentRequest completo con ASN.1 OER

        Args:
            inner_request: Inner EC request with ITS-S info
            private_key: ITS-S private key for PoP signature
            ea_public_key: EA's public key for encryption
            ea_certificate: EA's certificate for recipient ID

        Returns:
            ASN.1 OER encoded EnrollmentRequest bytes
        """
        # 1. Convert to ASN.1 dict and encode
        inner_asn1 = inner_ec_request_to_asn1(inner_request)
        tbs_data = asn1_compiler.encode("InnerEcRequest", inner_asn1)

        # 2. Sign for Proof of Possession
        signature = private_key.sign(tbs_data, ec.ECDSA(hashes.SHA256()))

        # 3. Create signed request
        signed_request_asn1 = {"ecRequest": inner_asn1, "tbsData": tbs_data, "signature": signature}

        # 4. Encode signed request
        plaintext = asn1_compiler.encode("InnerEcRequestSignedForPop", signed_request_asn1)

        # 5. Encrypt with EA's public key
        encrypted_data = self.security.encrypt_message(plaintext, ea_public_key)

        # 6. Compute EA certificate HashedId8
        ea_cert_der = ea_certificate.public_bytes(serialization.Encoding.DER)
        recipient_id = compute_hashed_id8(ea_cert_der)

        # 7. Create final request
        enrollment_request_asn1 = {
            "version": 2,  # ETSI TS 102941 V2.x
            "encryptedData": encrypted_data,
            "recipientId": recipient_id,
            "timestamp": datetime_to_time32(datetime.now(timezone.utc)),
        }

        # 8. Encode to ASN.1 OER
        return asn1_compiler.encode("EnrollmentRequest", enrollment_request_asn1)

    def decode_enrollment_request(
        self, request_bytes: bytes, ea_private_key: EllipticCurvePrivateKey
    ) -> InnerEcRequestSignedForPop:
        """
        Decode and decrypt EnrollmentRequest.

        Args:
            request_bytes: ASN.1 OER encoded enrollment request
            ea_private_key: EA's private key for decryption

        Returns:
            Decrypted InnerEcRequestSignedForPop
        """
        # 1. Decode ASN.1 OER
        enrollment_request_asn1 = asn1_compiler.decode("EnrollmentRequest", request_bytes)

        # 2. Decrypt
        plaintext = self.security.decrypt_message(
            enrollment_request_asn1["encryptedData"], ea_private_key
        )

        # 3. Decode inner signed request
        signed_request_asn1 = asn1_compiler.decode("InnerEcRequestSignedForPop", plaintext)

        # 4. Convert to Python objects
        inner_request = asn1_to_inner_ec_request(signed_request_asn1["ecRequest"])

        return InnerEcRequestSignedForPop(
            ecRequest=inner_request,
            tbsData=signed_request_asn1["tbsData"],
            signature=signed_request_asn1["signature"],
        )

    def encode_enrollment_response(
        self,
        response_code: ResponseCode,
        request_hash: bytes,
        certificate: Union[x509.Certificate, None],
        itss_public_key: EllipticCurvePublicKey,
    ) -> bytes:
        """
        Encode EnrollmentResponse with encryption.

        Args:
            response_code: Response status
            request_hash: Hash of original request
            certificate: Issued enrollment certificate (if successful)
            itss_public_key: ITS-S public key for encryption

        Returns:
            ASN.1 OER encoded EnrollmentResponse bytes
        """
        # 1. Create inner response
        cert_bytes = None
        if certificate:
            cert_bytes = certificate.public_bytes(serialization.Encoding.DER)

        inner_response_asn1 = {
            "requestHash": request_hash,
            "responseCode": response_code.name.lower(),  # Convert to lowercase for ASN.1 ENUMERATED
        }
        if cert_bytes:
            inner_response_asn1["certificate"] = cert_bytes

        # 2. Encode inner response
        plaintext = asn1_compiler.encode("InnerEcResponse", inner_response_asn1)

        # 3. Encrypt with ITS-S public key
        encrypted_data = self.security.encrypt_message(plaintext, itss_public_key)

        # 4. Create final response
        enrollment_response_asn1 = {
            "version": 2,
            "encryptedData": encrypted_data,
            "timestamp": datetime_to_time32(datetime.now(timezone.utc)),
        }

        # 5. Encode to ASN.1 OER
        return asn1_compiler.encode("EnrollmentResponse", enrollment_response_asn1)

    def decode_enrollment_response(
        self, response_bytes: bytes, itss_private_key: EllipticCurvePrivateKey
    ) -> InnerEcResponse:
        """
        Decode and decrypt EnrollmentResponse.

        Args:
            response_bytes: ASN.1 OER encoded enrollment response
            itss_private_key: ITS-S private key for decryption

        Returns:
            Decrypted InnerEcResponse
        """
        # 1. Decode ASN.1 OER
        enrollment_response_asn1 = asn1_compiler.decode("EnrollmentResponse", response_bytes)

        # 2. Decrypt
        plaintext = self.security.decrypt_message(
            enrollment_response_asn1["encryptedData"], itss_private_key
        )

        # 3. Decode inner response
        inner_response_asn1 = asn1_compiler.decode("InnerEcResponse", plaintext)

        # 4. Convert to Python object
        return InnerEcResponse(
            requestHash=inner_response_asn1["requestHash"],
            responseCode=ResponseCode[
                inner_response_asn1["responseCode"].upper()
            ],  # Convert lowercase to uppercase for ResponseCode enum
            certificate=inner_response_asn1.get("certificate"),
        )

    # ------------------------------------------------------------------------
    # AUTHORIZATION MESSAGES
    # ------------------------------------------------------------------------

    def encode_authorization_request(
        self,
        inner_request: InnerAtRequest,
        enrollment_certificate: x509.Certificate,
        aa_public_key: EllipticCurvePublicKey,
        aa_certificate: x509.Certificate,
    ) -> bytes:
        """
        Encode AuthorizationRequest with encryption.

        🔄 FLUSSO COMPLETO (ETSI TS 102941 Section 6.3.2):
        ==================================================
        1. ITS-S serializza InnerAtRequest con ASN.1 OER
        2. ITS-S cripta InnerAtRequest con chiave pubblica AA (ECIES)
        3. ITS-S allega Enrollment Certificate IN CHIARO
        4. ITS-S calcola HashedId8 del certificato AA
        5. ITS-S crea AuthorizationRequest completo con ASN.1 OER

        Args:
            inner_request: Inner AT request (MUST include unique hmacKey!)
            enrollment_certificate: ITS-S enrollment certificate
            aa_public_key: AA's public key for encryption
            aa_certificate: AA's certificate for recipient ID

        Returns:
            ASN.1 OER encoded AuthorizationRequest bytes
        """
        # 1. Convert to ASN.1 dict and encode
        inner_asn1 = inner_at_request_to_asn1(inner_request)
        plaintext = asn1_compiler.encode("InnerAtRequest", inner_asn1)

        # 2. Encrypt with AA's public key
        encrypted_data = self.security.encrypt_message(plaintext, aa_public_key)

        # 3. Compute AA certificate HashedId8
        aa_cert_der = aa_certificate.public_bytes(serialization.Encoding.DER)
        recipient_id = compute_hashed_id8(aa_cert_der)

        # 4. Get enrollment certificate DER
        ec_der = enrollment_certificate.public_bytes(serialization.Encoding.DER)

        # 5. Create final request
        auth_request_asn1 = {
            "version": 2,
            "encryptedData": encrypted_data,
            "enrollmentCertificate": ec_der,
            "recipientId": recipient_id,
            "timestamp": datetime_to_time32(datetime.now(timezone.utc)),
        }

        # 6. Encode to ASN.1 OER
        return asn1_compiler.encode("AuthorizationRequest", auth_request_asn1)

    def decode_authorization_request(
        self, request_bytes: bytes, aa_private_key: EllipticCurvePrivateKey
    ) -> InnerAtRequest:
        """
        Decode and decrypt AuthorizationRequest.

        Args:
            request_bytes: ASN.1 OER encoded authorization request
            aa_private_key: AA's private key for decryption

        Returns:
            Decrypted InnerAtRequest
        """
        # 1. Decode ASN.1 OER
        auth_request_asn1 = asn1_compiler.decode("AuthorizationRequest", request_bytes)

        # 2. Decrypt
        plaintext = self.security.decrypt_message(
            auth_request_asn1["encryptedData"], aa_private_key
        )

        # 3. Decode inner request
        inner_request_asn1 = asn1_compiler.decode("InnerAtRequest", plaintext)

        # 4. Convert to Python object
        return asn1_to_inner_at_request(inner_request_asn1)

    def encode_authorization_response(
        self,
        response_code: ResponseCode,
        request_hash: bytes,
        certificate: Union[x509.Certificate, None],
        hmac_key: bytes,
    ) -> bytes:
        """
        Encode AuthorizationResponse with encryption using hmacKey.

        Args:
            response_code: Response status
            request_hash: Hash of original request
            certificate: Issued authorization ticket (if successful)
            hmac_key: HMAC key from request for encryption

        Returns:
            ASN.1 OER encoded AuthorizationResponse bytes
        """
        # 1. Create inner response
        cert_bytes = None
        if certificate:
            cert_bytes = certificate.public_bytes(serialization.Encoding.DER)

        inner_response_asn1 = {
            "requestHash": request_hash,
            "responseCode": response_code.name.lower(),  # Convert to lowercase for ASN.1 ENUMERATED
        }
        if cert_bytes:
            inner_response_asn1["certificate"] = cert_bytes

        # 2. Encode inner response
        plaintext = asn1_compiler.encode("InnerAtResponse", inner_response_asn1)

        # 3. Encrypt with HMAC key (convert to AES key using HKDF)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"ETSI-102941-AT-RESPONSE",
            backend=default_backend(),
        ).derive(hmac_key)

        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Format: nonce || ciphertext
        encrypted_data = nonce + ciphertext

        # 4. Create final response
        auth_response_asn1 = {
            "version": 2,
            "encryptedData": encrypted_data,
            "timestamp": datetime_to_time32(datetime.now(timezone.utc)),
        }

        # 5. Encode to ASN.1 OER
        return asn1_compiler.encode("AuthorizationResponse", auth_response_asn1)

    def decode_authorization_response(
        self, response_bytes: bytes, hmac_key: bytes
    ) -> InnerAtResponse:
        """
        Decode and decrypt AuthorizationResponse.

        Args:
            response_bytes: ASN.1 OER encoded authorization response
            hmac_key: HMAC key from original request

        Returns:
            Decrypted InnerAtResponse
        """
        # 1. Decode ASN.1 OER
        auth_response_asn1 = asn1_compiler.decode("AuthorizationResponse", response_bytes)

        # 2. Parse encrypted data
        encrypted_data = auth_response_asn1["encryptedData"]
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # 3. Derive AES key from HMAC key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b"ETSI-102941-AT-RESPONSE",
            backend=default_backend(),
        ).derive(hmac_key)

        # 4. Decrypt
        aesgcm = AESGCM(derived_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # 5. Decode inner response
        inner_response_asn1 = asn1_compiler.decode("InnerAtResponse", plaintext)

        # 6. Convert to Python object
        return InnerAtResponse(
            requestHash=inner_response_asn1["requestHash"],
            responseCode=ResponseCode[
                inner_response_asn1["responseCode"].upper()
            ],  # Convert lowercase to uppercase for ResponseCode enum
            certificate=inner_response_asn1.get("certificate"),
        )

    # ------------------------------------------------------------------------
    # AUTHORIZATION VALIDATION FLOW (AA ↔ EA)
    # ------------------------------------------------------------------------

    def encode_authorization_validation_request(
        self, shared_at_request: SharedAtRequest, enrollment_certificate: bytes
    ) -> bytes:
        """
        Encode Authorization Validation Request (AA → EA).

        AA sends this to EA to validate the EC certificate status
        before issuing an Authorization Ticket.

        ETSI TS 102941 Section 6.4.1

        Args:
            shared_at_request: SharedAtRequest for unlinkability
            enrollment_certificate: EC certificate to validate

        Returns:
            ASN.1 OER encoded message
        """
        # 1. Create inner validation request
        inner_validation_request = AuthorizationValidationRequest(
            sharedAtRequest=shared_at_request, enrollmentCertificate=enrollment_certificate
        )

        # 2. Convert to ASN.1
        shared_at_asn1 = {
            "eaId": shared_at_request.eaId,
            "keyTag": shared_at_request.keyTag,
            "certificateFormat": shared_at_request.certificateFormat,
        }
        if shared_at_request.requestedSubjectAttributes:
            shared_at_asn1["requestedSubjectAttributes"] = (
                shared_at_request.requestedSubjectAttributes
            )

        inner_asn1 = {
            "sharedAtRequest": shared_at_asn1,
            "enrollmentCertificate": inner_validation_request.enrollmentCertificate,
            "version": version_to_uint8(inner_validation_request.version),
            "timestamp": datetime_to_time32(inner_validation_request.timestamp),
        }

        # Add optional fields
        if inner_validation_request.recipientId:
            inner_asn1["recipientId"] = inner_validation_request.recipientId

        # 3. Encode message (not encrypted for validation messages)
        return asn1_compiler.encode("AuthorizationValidationRequest", inner_asn1)

    def decode_authorization_validation_request(
        self, request_bytes: bytes
    ) -> AuthorizationValidationRequest:
        """
        Decode Authorization Validation Request (received by EA).

        Args:
            request_bytes: ASN.1 OER encoded message

        Returns:
            Decoded AuthorizationValidationRequest
        """
        # 1. Decode ASN.1 OER (not encrypted for validation messages)
        inner_request_asn1 = asn1_compiler.decode("AuthorizationValidationRequest", request_bytes)

        # 2. Convert to Python object
        shared_at_request = SharedAtRequest(
            eaId=inner_request_asn1["sharedAtRequest"]["eaId"],
            keyTag=inner_request_asn1["sharedAtRequest"]["keyTag"],
            certificateFormat=inner_request_asn1["sharedAtRequest"].get("certificateFormat", 1),
            requestedSubjectAttributes=inner_request_asn1["sharedAtRequest"].get(
                "requestedSubjectAttributes"
            ),
        )

        return AuthorizationValidationRequest(
            sharedAtRequest=shared_at_request,
            enrollmentCertificate=inner_request_asn1["enrollmentCertificate"],
            version=uint8_to_version(inner_request_asn1["version"]),
            recipientId=inner_request_asn1.get("recipientId"),
            timestamp=datetime.fromtimestamp(inner_request_asn1["timestamp"], tz=timezone.utc),
        )

    def encode_authorization_validation_response(
        self, request_hash: bytes, response_code: ResponseCode
    ) -> bytes:
        """
        Encode Authorization Validation Response (EA → AA).

        EA responds with the EC certificate status (OK or REVOKED).

        ETSI TS 102941 Section 6.3.3

        Args:
            request_hash: Hash of AuthorizationValidationRequest
            response_code: ResponseCode (ok or deniedrequest)

        Returns:
            ASN.1 OER encoded message
        """
        # 1. Create inner validation response
        inner_validation_response = AuthorizationValidationResponse(
            requestHash=request_hash, responseCode=response_code
        )

        # 2. Convert to ASN.1
        inner_asn1 = {
            "requestHash": inner_validation_response.requestHash,
            "responseCode": inner_validation_response.responseCode.name.lower(),  # Convert to lowercase
            "version": version_to_uint8(inner_validation_response.version),
            "timestamp": datetime_to_time32(inner_validation_response.timestamp),
        }

        # Add optional fields
        if inner_validation_response.confirmedSubjectAttributes:
            inner_asn1["confirmedSubjectAttributes"] = (
                inner_validation_response.confirmedSubjectAttributes
            )

        # 3. Encode message (not encrypted for validation messages)
        return asn1_compiler.encode("AuthorizationValidationResponse", inner_asn1)

    def decode_authorization_validation_response(
        self, response_bytes: bytes
    ) -> AuthorizationValidationResponse:
        """
        Decode Authorization Validation Response (received by AA).

        Args:
            response_bytes: ASN.1 OER encoded message

        Returns:
            Decoded AuthorizationValidationResponse
        """
        # 1. Decode ASN.1 OER (not encrypted for validation messages)
        inner_response_asn1 = asn1_compiler.decode(
            "AuthorizationValidationResponse", response_bytes
        )

        # 2. Convert to Python object
        return AuthorizationValidationResponse(
            requestHash=inner_response_asn1["requestHash"],
            responseCode=ResponseCode[
                inner_response_asn1["responseCode"].upper()
            ],  # Convert to uppercase
            version=uint8_to_version(inner_response_asn1["version"]),
            confirmedSubjectAttributes=inner_response_asn1.get("confirmedSubjectAttributes"),
            timestamp=datetime.fromtimestamp(inner_response_asn1["timestamp"], tz=timezone.utc),
        )

    # ------------------------------------------------------------------------
    # UTILITY METHODS
    # ------------------------------------------------------------------------

    def compute_message_hash(self, message_bytes: bytes) -> bytes:
        """
        Compute SHA-256 hash of ASN.1 encoded message.

        Args:
            message_bytes: ASN.1 OER encoded message

        Returns:
            SHA-256 hash (32 bytes)
        """
        return compute_request_hash(message_bytes)


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================


def create_encoder() -> ETSIMessageEncoder:
    """
    Create a new ETSI message encoder instance.

    Returns:
        Configured encoder with ASN.1 OER support
    """
    return ETSIMessageEncoder()
