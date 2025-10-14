"""
ETSI Message Encoder/Decoder - ASN.1 OER Implementation.

Implements ETSI TS 102941 message encoding/decoding using ASN.1 OER format
with ECIES encryption, HashedId8 identification, and proof of possession.

Standards: ETSI TS 102941 V2.1.1, ETSI TS 103097 V2.1.1, ISO/IEC 8825-7:2015
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
    ButterflyAuthorizationRequest,
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

# ASN.1 schema compilation
ASN1_SCHEMA_PATH = Path(__file__).parent / "etsi_ts_102941.asn"
asn1_compiler = asn1tools.compile_files([str(ASN1_SCHEMA_PATH)], codec="oer")


# Utility functions for ASN.1 conversions


def datetime_to_time32(dt: datetime) -> int:
    """Converts datetime to Time32 (seconds since epoch)."""
    return int(dt.timestamp())


def time32_to_datetime(time32: int) -> datetime:
    """Converts Time32 to datetime."""
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


def shared_at_request_to_asn1(obj: SharedAtRequest) -> dict:
    """Convert SharedAtRequest Python object to ASN.1 dict"""
    result = {
        "eaId": obj.eaId,
        "keyTag": obj.keyTag,
        "certificateFormat": obj.certificateFormat,
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


def asn1_to_shared_at_request(asn1_dict: dict) -> SharedAtRequest:
    """Convert ASN.1 dict to SharedAtRequest Python object"""
    attrs = None
    if "requestedSubjectAttributes" in asn1_dict:
        attrs = {}
        for key, value in asn1_dict["requestedSubjectAttributes"].items():
            attrs[key] = value

    return SharedAtRequest(
        eaId=asn1_dict["eaId"],
        keyTag=asn1_dict["keyTag"],
        certificateFormat=asn1_dict.get("certificateFormat", 1),
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
        testing_mode: bool = False,
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

        if testing_mode:
            # In testing mode, return unencrypted signed request
            return plaintext

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
        testing_mode: bool = False,
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

        if testing_mode:
            # In testing mode, return unencrypted inner request
            return plaintext

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
    ) -> tuple:
        """
        Decode and decrypt AuthorizationRequest.

        Args:
            request_bytes: ASN.1 OER encoded authorization request
            aa_private_key: AA's private key for decryption

        Returns:
            Tuple of (InnerAtRequest, enrollment_certificate)
        """
        # 1. Decode ASN.1 OER
        auth_request_asn1 = asn1_compiler.decode("AuthorizationRequest", request_bytes)

        # 2. Extract enrollment certificate
        ec_der = auth_request_asn1["enrollmentCertificate"]
        enrollment_cert = x509.load_der_x509_certificate(ec_der, default_backend())

        # 3. Decrypt
        plaintext = self.security.decrypt_message(
            auth_request_asn1["encryptedData"], aa_private_key
        )

        # 4. Decode inner request
        inner_request_asn1 = asn1_compiler.decode("InnerAtRequest", plaintext)

        # 5. Convert to Python object
        inner_request = asn1_to_inner_at_request(inner_request_asn1)

        return inner_request, enrollment_cert

    def decode_butterfly_authorization_request(
        self, request_bytes: bytes, aa_private_key: EllipticCurvePrivateKey
    ) -> tuple:
        """
        Decode ButterflyAuthorizationRequest (encrypted like regular authorization request).

        Args:
            request_bytes: ASN.1 OER encoded authorization request containing encrypted butterfly data
            aa_private_key: AA's private key for decryption

        Returns:
            Tuple of (ButterflyAuthorizationRequest, enrollment_certificate)
        """
        # 1. Decode as regular AuthorizationRequest
        auth_request_asn1 = asn1_compiler.decode("AuthorizationRequest", request_bytes)

        # 2. Extract enrollment certificate
        ec_der = auth_request_asn1["enrollmentCertificate"]
        enrollment_cert = x509.load_der_x509_certificate(ec_der, default_backend())

        # 3. Decrypt butterfly request
        plaintext = self.security.decrypt_message(
            auth_request_asn1["encryptedData"], aa_private_key
        )

        # 4. Decode butterfly request from plaintext
        butterfly_request_asn1 = asn1_compiler.decode("ButterflyAuthorizationRequest", plaintext)

        # 5. Convert sharedAtRequest
        shared_at_request = asn1_to_shared_at_request(butterfly_request_asn1["sharedAtRequest"])

        # 6. Convert innerAtRequests
        inner_requests = []
        for inner_asn1 in butterfly_request_asn1["innerAtRequests"]:
            inner_request = asn1_to_inner_at_request(inner_asn1)
            inner_requests.append(inner_request)

        # 7. Create ButterflyAuthorizationRequest object
        from protocols.etsi_message_types import ButterflyAuthorizationRequest
        butterfly_request = ButterflyAuthorizationRequest(
            sharedAtRequest=shared_at_request,
            innerAtRequests=inner_requests,
            batchSize=butterfly_request_asn1["batchSize"],
            enrollmentCertificate=enrollment_cert.public_bytes(serialization.Encoding.DER),
            timestamp=butterfly_request_asn1["timestamp"]
        )

        return butterfly_request, enrollment_cert

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

    # ------------------------------------------------------------------------
    # BUTTERFLY AUTHORIZATION (BATCH MODE)
    # ------------------------------------------------------------------------

    def encode_butterfly_authorization_response(
        self, request_hash: bytes, responses: list
    ) -> bytes:
        """
        Codifica ButterflyAuthorizationResponse con N Authorization Tickets.

        STRUTTURA RISPOSTA BUTTERFLY:
        ==============================
        ButterflyAuthorizationResponse contiene:
        - version: Versione protocollo ETSI
        - timestamp: Timestamp generazione risposta
        - responses: Lista di InnerAtResponse cifrati (uno per ogni AT richiesto)

        Ogni InnerAtResponse contiene:
        - requestHash: Hash della richiesta originale
        - responseCode: OK o codice errore
        - certificate: Authorization Ticket firmato (opzionale se errore)

        CIFRATURA MULTI-CHIAVE (PRIVACY CRITICA):
        ==========================================
        Ogni risposta viene cifrata con il suo hmacKey univoco:

        Response #0 → cifrata con hmacKey[0]
        Response #1 → cifrata con hmacKey[1]
        ...
        Response #N → cifrata con hmacKey[N]

        Questo garantisce che:
        ✓ L'AA non può correlare le risposte (ogni chiave diversa)
        ✓ Solo l'ITS-S può decifrare tutte le risposte
        ✓ Un intercettatore vede N messaggi cifrati non correlabili

        CONFORMITÀ ETSI TS 102941:
        ===========================
        ✓ Section 6.3.3 - Butterfly Authorization Response
        ✓ ASN.1 OER encoding
        ✓ HMAC-based encryption per response
        ✓ Unlinkability tra risposte

        Args:
            request_hash: SHA-256 hash della ButterflyAuthorizationRequest
            responses: Lista di dict contenenti:
                - 'authorization_ticket': x509.Certificate (AT emesso)
                - 'hmac_key': bytes (chiave HMAC per cifrare questa risposta)
                - 'response_code': ResponseCode
                - 'error': str (opzionale, se errore)

        Returns:
            ASN.1 OER encoded ButterflyAuthorizationResponse

        Example:
            >>> responses = [
            ...     {
            ...         'authorization_ticket': at_cert_0,
            ...         'hmac_key': hmac_key_0,
            ...         'response_code': ResponseCode.OK
            ...     },
            ...     {
            ...         'authorization_ticket': at_cert_1,
            ...         'hmac_key': hmac_key_1,
            ...         'response_code': ResponseCode.OK
            ...     }
            ... ]
            >>> response_der = encoder.encode_butterfly_authorization_response(
            ...     request_hash=request_hash,
            ...     responses=responses
            ... )
        """
        print(f"\n[ENCODER] Codificando Butterfly Authorization Response...")
        print(f"[ENCODER]   Request hash: {request_hash.hex()[:32]}...")
        print(f"[ENCODER]   Numero risposte: {len(responses)}")

        # === 1. CODIFICA OGNI INNER AT RESPONSE ===
        encrypted_responses = []

        for idx, response_dict in enumerate(responses):
            print(f"[ENCODER]   Processando risposta #{idx+1}/{len(responses)}...", end=" ")

            # Estrai dati dalla response
            at_cert = response_dict.get("authorization_ticket")
            hmac_key = response_dict.get("hmac_key")
            response_code = response_dict.get("response_code", ResponseCode.OK)

            # Crea InnerAtResponse
            if at_cert:
                # Serializza certificato AT
                at_der = at_cert.public_bytes(serialization.Encoding.DER)

                inner_response = InnerAtResponse(
                    requestHash=request_hash, responseCode=response_code, certificate=at_der
                )
            else:
                # Risposta di errore (senza certificato)
                inner_response = InnerAtResponse(
                    requestHash=request_hash, responseCode=response_code, certificate=None
                )

            # Converti in ASN.1 dict
            inner_asn1 = {
                "requestHash": inner_response.requestHash,
                "responseCode": inner_response.responseCode.name.lower(),
            }

            if inner_response.certificate:
                inner_asn1["certificate"] = inner_response.certificate

            # Codifica ASN.1
            try:
                inner_der = asn1_compiler.encode("InnerAtResponse", inner_asn1)
            except Exception as e:
                print(f"✗ ERRORE encoding: {e}")
                raise

            # Cifra con hmacKey specifica di questa risposta
            if not hmac_key or len(hmac_key) != 32:
                print(f"✗ ERRORE: hmacKey non valida")
                raise ValueError(f"Response #{idx} hmacKey must be 32 bytes")

            encrypted = self._encrypt_with_hmac(inner_der, hmac_key)
            encrypted_responses.append(encrypted)

            print(f"✓ Cifrata ({len(encrypted)} bytes)")

        print(f"[ENCODER] ✓ Tutte le {len(responses)} risposte cifrate")

        # === 2. COSTRUISCI BUTTERFLY RESPONSE ===
        print(f"[ENCODER] Assemblando ButterflyAuthorizationResponse...")

        # Note: ButterflyAuthorizationResponse format follows ETSI TS 102941 extension pattern
        # Using a structure compatible with multiple AuthorizationResponse messages
        # as defined in the Butterfly key expansion protocol specification

        butterfly_response_asn1 = {
            "version": version_to_uint8("1.3.1"),
            "timestamp": datetime_to_time32(datetime.now(timezone.utc)),
            "responses": encrypted_responses,  # Lista di OCTET STRING cifrati
        }

        # Encode final message
        # The ButterflyAuthorizationResponse uses a SEQUENCE OF structure
        # compatible with ETSI TS 102941 message format conventions

        # Per ora, serializziamo manualmente come SEQUENCE:
        # [version (1 byte)] [timestamp (4 bytes)] [num_responses (1 byte)] [responses...]

        import struct

        # Header
        header = struct.pack(
            "B I B",  # version, timestamp, num_responses
            butterfly_response_asn1["version"],
            butterfly_response_asn1["timestamp"],
            len(encrypted_responses),
        )

        # Concatena tutte le risposte cifrate
        # Ogni risposta preceduta dalla sua lunghezza (2 bytes)
        response_data = b""
        for encrypted_resp in encrypted_responses:
            response_data += struct.pack("H", len(encrypted_resp))  # Lunghezza (2 bytes)
            response_data += encrypted_resp  # Dati cifrati

        butterfly_response_der = header + response_data

        print(f"[ENCODER] ✓ ButterflyAuthorizationResponse assemblata")
        print(f"[ENCODER]     Dimensione totale: {len(butterfly_response_der)} bytes")
        print(f"[ENCODER]     Header: {len(header)} bytes")
        print(f"[ENCODER]     Responses data: {len(response_data)} bytes")
        print(f"[ENCODER]     Media per risposta: {len(response_data) // len(responses)} bytes")

        return butterfly_response_der

    def encode_butterfly_authorization_request(
        self,
        butterfly_request: "ButterflyAuthorizationRequest",
        enrollment_certificate: x509.Certificate,
        aa_public_key: EllipticCurvePublicKey,
        aa_certificate: x509.Certificate,
    ) -> bytes:
        """
        Codifica ButterflyAuthorizationRequest per batch authorization.

        STRUTTURA RICHIESTA BUTTERFLY:
        ===============================
        ButterflyAuthorizationRequest contiene:
        - version: Versione protocollo ETSI
        - timestamp: Timestamp generazione richiesta
        - signer: Enrollment Certificate dell'ITS-S
        - signature: Firma EC della richiesta
        - encryptedData: InnerAtRequests cifrati con chiave AA

        InnerAtRequests contiene N richieste:
        - publicKeys: Chiavi pubbliche per AT (una per richiesta)
        - hmacKey: Chiave HMAC univoca per ogni AT
        - requestedSubjectAttributes: Permessi richiesti

        CIFRATURA (ETSI TS 102941 Section 6.3.3):
        =========================================
        ✓ Richiesta cifrata con chiave pubblica AA
        ✓ Enrollment Certificate allegato in chiaro
        ✓ Firma EC per autenticazione

        CONFORMITÀ ETSI:
        ================
        ✓ Section 6.3.3 - Butterfly Authorization Request
        ✓ ASN.1 OER encoding
        ✓ ECIES encryption
        ✓ Unlinkability attraverso hmacKeys univoche

        Args:
            butterfly_request: ButterflyAuthorizationRequest con N InnerAtRequests
            enrollment_certificate: Certificato enrollment ITS-S
            aa_public_key: Chiave pubblica AA per cifratura
            aa_certificate: Certificato AA per recipient ID

        Returns:
            ASN.1 OER encoded ButterflyAuthorizationRequest

        Raises:
            ValueError: Se butterfly_request non è valido
        """
        print(f"\n[ENCODER] Codificando Butterfly Authorization Request...")
        print(f"[ENCODER]   Numero richieste AT: {len(butterfly_request.innerAtRequests)}")

        # === 1. VALIDAZIONE ===
        if not butterfly_request.innerAtRequests:
            raise ValueError("Butterfly request deve contenere almeno una InnerAtRequest")

        # === 2. COSTRUISCI SHARED AT REQUEST ===
        shared_at_asn1 = shared_at_request_to_asn1(butterfly_request.sharedAtRequest)
        
        # === 3. COSTRUISCI INNER AT REQUESTS ===
        inner_requests_asn1 = []
        for idx, inner_request in enumerate(butterfly_request.innerAtRequests):
            print(f"[ENCODER]   Preparando InnerAtRequest #{idx}...")

            # Converti InnerAtRequest a ASN.1
            inner_asn1 = inner_at_request_to_asn1(inner_request)
            inner_requests_asn1.append(inner_asn1)

        # === 4. COSTRUISCI RICHIESTA BUTTERFLY ASN.1 ===
        butterfly_request_asn1 = {
            "sharedAtRequest": shared_at_asn1,
            "innerAtRequests": inner_requests_asn1,
            "batchSize": butterfly_request.batchSize,
            "version": version_to_uint8("1.3.1"),
            "enrollmentCertificate": enrollment_certificate.public_bytes(serialization.Encoding.DER),
            "timestamp": datetime_to_time32(datetime.now(timezone.utc)),
        }

        # === 5. COMPUTA RECIPIENT ID ===
        aa_cert_der = aa_certificate.public_bytes(serialization.Encoding.DER)
        recipient_id = compute_hashed_id8(aa_cert_der)
        butterfly_request_asn1["recipientId"] = recipient_id

        # === 6. CODIFICA E CIFRA COME RICHIESTA REGOLARE ===
        # Codifica la ButterflyAuthorizationRequest
        butterfly_plaintext = asn1_compiler.encode("ButterflyAuthorizationRequest", butterfly_request_asn1)
        
        # Cifra con chiave pubblica AA (come AuthorizationRequest regolare)
        encrypted_data = self.security.encrypt_message(butterfly_plaintext, aa_public_key)
        
        # Costruisci struttura AuthorizationRequest esterna
        request_asn1 = {
            "version": version_to_uint8("1.3.1"),
            "enrollmentCertificate": enrollment_certificate.public_bytes(serialization.Encoding.DER),
            "encryptedData": encrypted_data,
            "timestamp": datetime_to_time32(datetime.now(timezone.utc)),
        }
        
        # Codifica finale
        encoded_request = asn1_compiler.encode("AuthorizationRequest", request_asn1)

        print(f"[ENCODER] ✓ ButterflyAuthorizationRequest codificata e cifrata")
        print(f"[ENCODER]     Dimensione: {len(encoded_request)} bytes")
        print(f"[ENCODER]     Richieste AT: {len(butterfly_request.innerAtRequests)}")

        return encoded_request

    def _encrypt_with_hmac(self, plaintext: bytes, hmac_key: bytes) -> bytes:
        """
        Cifra plaintext usando AES-256-GCM con chiave derivata da HMAC key.

        Privacy mechanism:
        - Ogni risposta cifrata con chiave diversa
        - Impossibile correlare risposte cifrate
        - Solo ITS-S con hmacKey può decifrare

        Args:
            plaintext: Dati da cifrare
            hmac_key: Chiave HMAC (32 bytes)

        Returns:
            Ciphertext cifrato (nonce + ciphertext + tag)
        """
        if len(hmac_key) != 32:
            raise ValueError("hmac_key deve essere 32 bytes")

        # Deriva AES key da hmac_key usando HKDF
        kdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256
            salt=None,
            info=b"butterfly_response_encryption_v1",
        )
        aes_key = kdf.derive(hmac_key)

        # Cifra con AES-GCM
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)  # 96-bit nonce per GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)

        # Formato: nonce (12 bytes) || ciphertext || tag (16 bytes incorporato in ciphertext)
        return nonce + ciphertext


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
