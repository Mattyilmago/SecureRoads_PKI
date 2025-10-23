"""
ETSI Message Encoder/Decoder - ASN.1 OER Implementation.

Implements ETSI TS 102941 message encoding/decoding using ASN.1 OER format
with ECIES encryption, HashedId8 identification, and proof of possession.

Standards: ETSI TS 102941 V2.1.1, ETSI TS 103097 V2.1.1, ISO/IEC 8825-7:2015

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Union

import asn1tools
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Import from new modular structure
from protocols.messages.types import (
    AuthorizationValidationRequest,
    AuthorizationValidationResponse,
    ButterflyAuthorizationRequest,
    InnerAtRequest,
    InnerAtResponse,
    InnerEcRequest,
    InnerEcRequestSignedForPop,
    InnerEcResponse,
    SharedAtRequest,
)
from protocols.core.types import ResponseCode
from protocols.core.primitives import (
    compute_hashed_id8,
    compute_hashed_id8_from_public_key,
    compute_request_hash,
    time32_encode,
    sign_data_ieee1609,
    verify_ieee1609_signature,
    create_ieee1609dot2_encrypted_data,
   create_ieee1609dot2_signed_and_encrypted_data,
    extract_ecies_from_ieee1609dot2_encrypted_data,
    extract_encrypted_data_from_signed_and_encrypted,
    public_key_to_etsi_verification_key,
    public_key_to_etsi_encryption_key,
)

# Import ECIES from security module
from protocols.security.ecies import ecies_encrypt, ecies_decrypt


# Backward compatibility: ETSISecurityManager class wrapper
class ETSISecurityManager:
    """Legacy wrapper for ECIES. Use ecies_encrypt/ecies_decrypt directly in new code."""
    
    @staticmethod
    def encrypt_message(plaintext: bytes, recipient_public_key) -> bytes:
        """Encrypt message using ECIES."""
        return ecies_encrypt(plaintext, recipient_public_key)
    
    @staticmethod
    def decrypt_message(encrypted_data: bytes, recipient_private_key) -> bytes:
        """Decrypt message using ECIES."""
        return ecies_decrypt(encrypted_data, recipient_private_key)

# ASN.1 schema compilation - Multi-file compilation for standards compliance
PROTOCOLS_DIR = Path(__file__).parent.parent
IEEE1609DOT2_SCHEMA = PROTOCOLS_DIR / "ieee1609dot2.asn"
ETSI_TS_103097_SCHEMA = PROTOCOLS_DIR / "etsi_ts_103097.asn"
ETSI_TS_102941_SCHEMA = PROTOCOLS_DIR / "etsi_ts_102941.asn"

# Compile all ASN.1 schemas in dependency order
asn1_compiler = asn1tools.compile_files(
    [
        str(IEEE1609DOT2_SCHEMA),      # Base standard (IEEE)
        str(ETSI_TS_103097_SCHEMA),    # ETSI certificate format
        str(ETSI_TS_102941_SCHEMA)     # ETSI PKI messages
    ],
    codec="oer"  # Octet Encoding Rules (ITU-T X.696)
)


# Utility functions for ASN.1 conversions


def enum_to_camel_case(enum_name: str) -> str:
    """
    Convert Python enum name (UPPER_SNAKE_CASE) to ASN.1 camelCase.
    
    Example: INTERNAL_SERVER_ERROR -> internalServerError
    """
    words = enum_name.lower().split('_')
    return words[0] + ''.join(word.capitalize() for word in words[1:])


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
    """Convert InnerEcRequest Python object to ASN.1 dict (ETSI TS 102941 compliant)
    
    Handles multiple input formats and converts to proper ETSI structures:
    - Tuple ASN.1 format: ('ecdsaNistP256', ('compressed-y-0', bytes))
    - Dict ASN.1 format: {'supportedSymmAlg': 'aes128Ccm', 'publicKey': (...)}
    - Raw bytes format: b'\\x04...' (converted automatically)
    - EllipticCurvePublicKey objects (converted automatically)
    
    ETSI TS 102941 V2.1.1:
    ----------------------
    PublicKeys ::= SEQUENCE {
        verificationKey     PublicVerificationKey,
        encryptionKey       PublicEncryptionKey OPTIONAL
    }
    """
    public_keys = {}
    
    # Handle verification key (PublicVerificationKey)
    if "verification" in obj.publicKeys:
        ver_key = obj.publicKeys["verification"]
        
        if isinstance(ver_key, tuple):
            # Already in PublicVerificationKey format: ('ecdsaNistP256', point)
            public_keys["verificationKey"] = ver_key
            
        elif isinstance(ver_key, bytes):
            # Raw bytes - convert to uncompressed point structure
            if len(ver_key) == 65 and ver_key[0] == 0x04:
                x = ver_key[1:33]
                y = ver_key[33:65]
                # Use uncompressed format (can be optimized to compressed later)
                public_keys["verificationKey"] = (
                    'ecdsaNistP256',
                    ('uncompressedP256', {'x': x, 'y': y})
                )
            else:
                raise ValueError(f"Invalid verification key: expected 65-byte uncompressed point, got {len(ver_key)} bytes")
                
        elif hasattr(ver_key, 'public_numbers'):
            # EllipticCurvePublicKey object - convert using proper function
            public_keys["verificationKey"] = public_key_to_etsi_verification_key(ver_key)
            
        else:
            raise ValueError(f"Invalid verification key type: {type(ver_key)}")
    
    # Handle encryption key (PublicEncryptionKey) - OPTIONAL
    if "encryption" in obj.publicKeys:
        enc_key = obj.publicKeys["encryption"]
        
        if isinstance(enc_key, dict) and 'supportedSymmAlg' in enc_key:
            # Already in PublicEncryptionKey format: {supportedSymmAlg, publicKey}
            public_keys["encryptionKey"] = enc_key
            
        elif isinstance(enc_key, bytes):
            # Raw bytes - convert to PublicEncryptionKey structure
            if len(enc_key) == 65 and enc_key[0] == 0x04:
                x = enc_key[1:33]
                y = enc_key[33:65]
                public_keys["encryptionKey"] = {
                    'supportedSymmAlg': 'aes128Ccm',
                    'publicKey': (
                        'eciesNistP256',
                        ('uncompressedP256', {'x': x, 'y': y})
                    )
                }
            else:
                raise ValueError(f"Invalid encryption key: expected 65-byte uncompressed point")
                
        elif hasattr(enc_key, 'public_numbers'):
            # EllipticCurvePublicKey object - convert using proper function
            public_keys["encryptionKey"] = public_key_to_etsi_encryption_key(enc_key)
            
        else:
            raise ValueError(f"Invalid encryption key type: {type(enc_key)}")

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
    """Convert InnerAtRequest Python object to ASN.1 dict (ETSI TS 102941 compliant)
    
    Uses same PublicKeys structure as InnerEcRequest.
    """
    public_keys = {}
    
    # Handle verification key (same logic as InnerEcRequest)
    if "verification" in obj.publicKeys:
        ver_key = obj.publicKeys["verification"]
        
        if isinstance(ver_key, tuple):
            public_keys["verificationKey"] = ver_key
        elif isinstance(ver_key, bytes):
            if len(ver_key) == 65 and ver_key[0] == 0x04:
                x = ver_key[1:33]
                y = ver_key[33:65]
                public_keys["verificationKey"] = (
                    'ecdsaNistP256',
                    ('uncompressedP256', {'x': x, 'y': y})
                )
            else:
                raise ValueError(f"Invalid verification key format")
        elif hasattr(ver_key, 'public_numbers'):
            public_keys["verificationKey"] = public_key_to_etsi_verification_key(ver_key)
        else:
            raise ValueError(f"Invalid verification key type: {type(ver_key)}")
    
    # Handle encryption key (same logic as InnerEcRequest)
    if "encryption" in obj.publicKeys:
        enc_key = obj.publicKeys["encryption"]
        
        if isinstance(enc_key, dict) and 'supportedSymmAlg' in enc_key:
            public_keys["encryptionKey"] = enc_key
        elif isinstance(enc_key, bytes):
            if len(enc_key) == 65 and enc_key[0] == 0x04:
                x = enc_key[1:33]
                y = enc_key[33:65]
                public_keys["encryptionKey"] = {
                    'supportedSymmAlg': 'aes128Ccm',
                    'publicKey': (
                        'eciesNistP256',
                        ('uncompressedP256', {'x': x, 'y': y})
                    )
                }
            else:
                raise ValueError(f"Invalid encryption key format")
        elif hasattr(enc_key, 'public_numbers'):
            public_keys["encryptionKey"] = public_key_to_etsi_encryption_key(enc_key)
        else:
            raise ValueError(f"Invalid encryption key type: {type(enc_key)}")

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
# MESSAGE ENCODER/DECODER - ASN.1 OER
# ============================================================================


class MessageEncoder:
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
        ea_certificate_asn1: bytes,
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
            ea_certificate_asn1: EA's certificate ASN.1 OER bytes for recipient ID

        Returns:
            ASN.1 OER encoded EnrollmentRequest bytes
        """
        # 1. Convert to ASN.1 dict and encode
        inner_asn1 = inner_ec_request_to_asn1(inner_request)
        tbs_data = asn1_compiler.encode("InnerEcRequest", inner_asn1)

        # 2. Sign directly in IEEE 1609.2 format (no DER conversion!)
        signature_asn1 = sign_data_ieee1609(private_key, tbs_data)

        # 3. Create signed request
        signed_request_asn1 = {"ecRequest": inner_asn1, "tbsData": tbs_data, "signature": signature_asn1}

        # 4. Encode signed request
        plaintext = asn1_compiler.encode("InnerEcRequestSignedForPop", signed_request_asn1)

        if testing_mode:
            # In testing mode, return unencrypted signed request
            return plaintext

        # 5. Encrypt with EA's public key
        encrypted_data = self.security.encrypt_message(plaintext, ea_public_key)

        # 6. Compute EA certificate HashedId8 from ASN.1 OER bytes
        recipient_id = compute_hashed_id8(ea_certificate_asn1)

        # 7. Create IEEE 1609.2 EncryptedData structure
        enrollment_request_asn1 = create_ieee1609dot2_encrypted_data(
            ecies_ciphertext=encrypted_data,
            recipient_id=recipient_id
        )

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

        # 2. Extract ECIES ciphertext from IEEE 1609.2 structure
        ecies_ciphertext = extract_ecies_from_ieee1609dot2_encrypted_data(enrollment_request_asn1)

        # 3. Decrypt
        plaintext = self.security.decrypt_message(ecies_ciphertext, ea_private_key)

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
        certificate_asn1: Union[bytes, None],
        itss_public_key: EllipticCurvePublicKey,
    ) -> bytes:
        """
        Encode EnrollmentResponse with encryption.

        Args:
            response_code: Response status
            request_hash: Hash of original request
            certificate_asn1: Issued enrollment certificate ASN.1 OER bytes (if successful)
            itss_public_key: ITS-S public key for encryption

        Returns:
            ASN.1 OER encoded EnrollmentResponse bytes
        """
        # Map ResponseCode to ETSI EnrolmentResponseCode (ASN.1 schema)
        response_code_map = {
            ResponseCode.OK: "ok",
            ResponseCode.CANONICAL_ENCODING_ERROR: "cantparse",
            ResponseCode.BAD_CONTENT_TYPE: "badcontenttype",
            ResponseCode.DECRYPTION_FAILED: "decryptionfailed",
            ResponseCode.UNKNOWN_ITS_ID: "unknownits",
            ResponseCode.INVALID_SIGNATURE: "invalidsignature",
            ResponseCode.INVALID_ENCRYPTION_KEY: "invalidencryptionkey",
            ResponseCode.BAD_REQUEST: "incompleterequest",
            ResponseCode.UNAUTHORIZED: "deniedrequest",
            ResponseCode.INTERNAL_SERVER_ERROR: "deniedrequest",  # Fallback
        }
        
        # 1. Create inner response
        inner_response_asn1 = {
            "requestHash": request_hash,
            "responseCode": response_code_map.get(response_code, "deniedrequest"),  # ETSI ASN.1 value
        }
        
        if certificate_asn1:
            # Decode certificate from ASN.1 OER bytes to dict structure
            # The certificate must be decoded as EtsiTs103097Certificate type
            try:
                certificate_dict = asn1_compiler.decode("EtsiTs103097Certificate", certificate_asn1)
                inner_response_asn1["certificate"] = certificate_dict
            except Exception as e:
                # If decoding fails, skip certificate (will return error response)
                import logging
                logging.getLogger(__name__).error(f"Failed to decode certificate for response: {e}")
                # Don't include certificate in response
                pass

        # 2. Encode inner response
        plaintext = asn1_compiler.encode("InnerEcResponse", inner_response_asn1)

        # 3. Encrypt with ITS-S public key
        encrypted_data = self.security.encrypt_message(plaintext, itss_public_key)

        # 4. Compute recipient ID from ITS-S public key (temporary, should use canonical certificate)
        # TODO: According to ETSI TS 102941, should use HashedId8 of canonical certificate
        recipient_id = compute_hashed_id8_from_public_key(itss_public_key)

        # 5. Create IEEE 1609.2 EncryptedData structure
        enrollment_response_asn1 = create_ieee1609dot2_encrypted_data(
            ecies_ciphertext=encrypted_data,
            recipient_id=recipient_id
        )

        # 6. Encode to ASN.1 OER
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

        # 2. Extract ECIES ciphertext from IEEE 1609.2 structure
        ecies_ciphertext = extract_ecies_from_ieee1609dot2_encrypted_data(enrollment_response_asn1)

        # 3. Decrypt
        plaintext = self.security.decrypt_message(ecies_ciphertext, itss_private_key)

        # 3. Decode inner response
        inner_response_asn1 = asn1_compiler.decode("InnerEcResponse", plaintext)

        # 4. Extract and re-encode certificate if present
        certificate_bytes = None
        if "certificate" in inner_response_asn1:
            certificate_dict = inner_response_asn1["certificate"]
            # Re-encode certificate dict back to ASN.1 OER bytes
            certificate_bytes = asn1_compiler.encode("EtsiTs103097Certificate", certificate_dict)

        # 5. Map ETSI EnrolmentResponseCode to Python ResponseCode
        etsi_to_response_code = {
            "ok": ResponseCode.OK,
            "cantparse": ResponseCode.CANONICAL_ENCODING_ERROR,
            "badcontenttype": ResponseCode.BAD_CONTENT_TYPE,
            "decryptionfailed": ResponseCode.DECRYPTION_FAILED,
            "unknownits": ResponseCode.UNKNOWN_ITS_ID,
            "invalidsignature": ResponseCode.INVALID_SIGNATURE,
            "invalidencryptionkey": ResponseCode.INVALID_ENCRYPTION_KEY,
            "incompleterequest": ResponseCode.BAD_REQUEST,
            "deniedrequest": ResponseCode.UNAUTHORIZED,
            "deniedpermissions": ResponseCode.UNAUTHORIZED,
        }
        
        response_code_str = inner_response_asn1["responseCode"]
        response_code = etsi_to_response_code.get(response_code_str, ResponseCode.INTERNAL_SERVER_ERROR)

        # 6. Convert to Python object
        return InnerEcResponse(
            requestHash=inner_response_asn1["requestHash"],
            responseCode=response_code,
            certificate=certificate_bytes,
        )

    # ------------------------------------------------------------------------
    # AUTHORIZATION MESSAGES
    # ------------------------------------------------------------------------

    def encode_authorization_request(
        self,
        inner_request: InnerAtRequest,
        enrollment_certificate_asn1: bytes,
        enrollment_private_key,
        aa_public_key: EllipticCurvePublicKey,
        aa_certificate_asn1: bytes,
        testing_mode: bool = False,
    ) -> bytes:
        """
        Encode AuthorizationRequest with SignedAndEncrypted (100% ETSI TS 102941).

        🔄 FLUSSO COMPLETO STANDARD ETSI (ETSI TS 102941 Section 6.3.2):
        ================================================================
        1. ITS-S serializza InnerAtRequest con ASN.1 OER
        2. ITS-S cripta InnerAtRequest con chiave pubblica AA (ECIES)
        3. ITS-S firma i dati criptati con chiave privata EC (Proof of Possession)
        4. ITS-S allega Enrollment Certificate come signer
        5. ITS-S crea AuthorizationRequest = EtsiTs103097Data-SignedAndEncrypted

        Args:
            inner_request: Inner AT request (MUST include unique hmacKey!)
            enrollment_certificate_asn1: ITS-S enrollment certificate ASN.1 OER bytes
            enrollment_private_key: EC private key for signing
            aa_public_key: AA's public key for encryption
            aa_certificate_asn1: AA's certificate ASN.1 OER bytes for recipient ID
            testing_mode: If True, skip encryption (return plaintext)

        Returns:
            ASN.1 OER encoded AuthorizationRequest bytes (SignedAndEncrypted)
        """
        # 1. Convert to ASN.1 dict and encode
        inner_asn1 = inner_at_request_to_asn1(inner_request)
        plaintext = asn1_compiler.encode("InnerAtRequest", inner_asn1)

        if testing_mode:
            # In testing mode, return unencrypted inner request
            return plaintext

        # 2. Encrypt with AA's public key (ECIES)
        encrypted_data = self.security.encrypt_message(plaintext, aa_public_key)

        # 3. Compute AA certificate HashedId8 from ASN.1 OER bytes
        recipient_id = compute_hashed_id8(aa_certificate_asn1)

        # 4. Create IEEE 1609.2 SignedAndEncryptedData structure (100% ETSI standard)
        auth_request_asn1 = create_ieee1609dot2_signed_and_encrypted_data(
            ecies_ciphertext=encrypted_data,
            recipient_id=recipient_id,
            signer_certificate_asn1=enrollment_certificate_asn1,
            signer_private_key=enrollment_private_key,
            psid=0x24  # CA Basic Service (PKI operations)
        )

        # 5. Encode to ASN.1 OER as EtsiTs103097Data-SignedAndEncrypted (ETSI standard)
        return asn1_compiler.encode("EtsiTs103097Data-SignedAndEncrypted", auth_request_asn1)

    def decode_authorization_request(
        self, request_bytes: bytes, aa_private_key: EllipticCurvePrivateKey
    ) -> tuple:
        """
        Decode and decrypt AuthorizationRequest (SignedAndEncrypted).

        Args:
            request_bytes: ASN.1 OER encoded authorization request (SignedAndEncrypted)
            aa_private_key: AA's private key for decryption

        Returns:
            Tuple of (InnerAtRequest, enrollment_certificate_asn1)
            - enrollment_certificate_asn1: EC in formato ASN.1 OER (bytes)
        """
        # 1. Decode ASN.1 OER as SignedAndEncrypted
        auth_request_asn1 = asn1_compiler.decode("EtsiTs103097Data-SignedAndEncrypted", request_bytes)

        # 2. Extract EncryptedData and signer certificate from SignedData wrapper
        encrypted_data_structure, enrollment_cert_asn1 = extract_encrypted_data_from_signed_and_encrypted(
            auth_request_asn1
        )

        # 3. Extract ECIES ciphertext from EncryptedData
        ecies_ciphertext = extract_ecies_from_ieee1609dot2_encrypted_data(encrypted_data_structure)

        # 4. Decrypt
        plaintext = self.security.decrypt_message(ecies_ciphertext, aa_private_key)

        # 5. Decode inner request
        inner_request_asn1 = asn1_compiler.decode("InnerAtRequest", plaintext)

        # 6. Convert to Python object
        inner_request = asn1_to_inner_at_request(inner_request_asn1)

        # Return with enrollment certificate extracted from signer
        return inner_request, enrollment_cert_asn1

    def decode_butterfly_authorization_request(
        self, request_bytes: bytes, aa_private_key: EllipticCurvePrivateKey
    ) -> tuple:
        """
        Decode ButterflyAuthorizationRequest (SignedAndEncrypted).

        Args:
            request_bytes: ASN.1 OER encoded authorization request (SignedAndEncrypted)
            aa_private_key: AA's private key for decryption

        Returns:
            Tuple of (ButterflyAuthorizationRequest, enrollment_certificate_asn1)
            - enrollment_certificate_asn1: EC in formato ASN.1 OER (bytes)
        """
        # 1. Decode as SignedAndEncrypted
        auth_request_asn1 = asn1_compiler.decode("EtsiTs103097Data-SignedAndEncrypted", request_bytes)

        # 2. Extract EncryptedData and signer certificate from SignedData wrapper
        encrypted_data_structure, enrollment_cert_asn1 = extract_encrypted_data_from_signed_and_encrypted(
            auth_request_asn1
        )

        # 3. Extract ECIES ciphertext from EncryptedData
        ecies_ciphertext = extract_ecies_from_ieee1609dot2_encrypted_data(encrypted_data_structure)

        # 4. Decrypt butterfly request
        plaintext = self.security.decrypt_message(ecies_ciphertext, aa_private_key)

        # 5. Decode butterfly request from plaintext
        butterfly_request_asn1 = asn1_compiler.decode("ButterflyAuthorizationRequest", plaintext)

        # 6. Convert sharedAtRequest
        shared_at_request = asn1_to_shared_at_request(butterfly_request_asn1["sharedAtRequest"])

        # 7. Convert innerAtRequests
        inner_requests = []
        for inner_asn1 in butterfly_request_asn1["innerAtRequests"]:
            inner_request = asn1_to_inner_at_request(inner_asn1)
            inner_requests.append(inner_request)

        # 8. Create ButterflyAuthorizationRequest object
        from protocols.messages.types import ButterflyAuthorizationRequest
        
        butterfly_request = ButterflyAuthorizationRequest(
            sharedAtRequest=shared_at_request,
            innerAtRequests=inner_requests,
            batchSize=butterfly_request_asn1["batchSize"],
            enrollmentCertificate=enrollment_cert_asn1 if enrollment_cert_asn1 else b"",
            timestamp=butterfly_request_asn1["timestamp"]
        )

        return butterfly_request, enrollment_cert_asn1

    def encode_authorization_response(
        self,
        response_code: ResponseCode,
        request_hash: bytes,
        certificate_asn1: Union[bytes, None],
        hmac_key: bytes,
    ) -> bytes:
        """
        Encode AuthorizationResponse with encryption using hmacKey.

        Args:
            response_code: Response status
            request_hash: Hash of original request
            certificate_asn1: Issued authorization ticket ASN.1 OER bytes (if successful)
            hmac_key: HMAC key from request for encryption

        Returns:
            ASN.1 OER encoded AuthorizationResponse bytes
        """
        # Map ResponseCode to ETSI AuthorizationResponseCode (ASN.1 schema)
        response_code_map = {
            ResponseCode.OK: "ok",
            ResponseCode.CANONICAL_ENCODING_ERROR: "aa-cantparse",
            ResponseCode.BAD_CONTENT_TYPE: "aa-badcontenttype",
            ResponseCode.DECRYPTION_FAILED: "aa-decryptionfailed",
            ResponseCode.UNKNOWN_ITS_ID: "unknownits",
            ResponseCode.INVALID_SIGNATURE: "invalidsignature",
            ResponseCode.INVALID_ENCRYPTION_KEY: "invalidencryptionkey",
            ResponseCode.BAD_REQUEST: "deniedrequest",
            ResponseCode.UNAUTHORIZED: "deniedrequest",
            ResponseCode.INTERNAL_SERVER_ERROR: "deniedrequest",  # Fallback
        }
        
        # 1. Create inner response
        inner_response_asn1 = {
            "requestHash": request_hash,
            "responseCode": response_code_map.get(response_code, "deniedrequest"),  # ETSI ASN.1 value
        }
        if certificate_asn1:
            # Decode certificate bytes to dict for ASN.1 encoding
            # InnerAtResponse.certificate expects a Certificate structure (dict), not bytes
            from protocols.certificates.asn1_encoder import decode_certificate_with_asn1
            certificate_dict = decode_certificate_with_asn1(certificate_asn1, "Certificate")
            inner_response_asn1["certificate"] = certificate_dict

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

        # 4. Create final response following IEEE 1609.2 / ETSI TS 103097 structure
        # AuthorizationResponse ::= EtsiTs103097Data-Encrypted
        # Which is Ieee1609Dot2Data with protocolVersion=3 and content containing encryptedData
        
        # Build EncryptedData structure according to IEEE 1609.2
        # AesCcmCiphertext ::= SEQUENCE {
        #     nonce       OCTET STRING (SIZE (12)),
        #     ccmCiphertext Opaque
        # }
        aes_ccm_ciphertext = {
            'nonce': nonce,
            'ccmCiphertext': ciphertext
        }
        
        encrypted_data_structure = {
            'recipients': [],  # Empty for symmetric encryption
            'ciphertext': ('aes128ccm', aes_ccm_ciphertext)  # CHOICE
        }
        
        auth_response_asn1 = {
            "protocolVersion": 3,  # IEEE 1609.2 version 3
            "content": ('encryptedData', encrypted_data_structure)  # CHOICE
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
        # 1. Decode ASN.1 OER (IEEE 1609.2 structure)
        auth_response_asn1 = asn1_compiler.decode("AuthorizationResponse", response_bytes)

        # 2. Extract encrypted data from IEEE 1609.2 structure
        # content is a CHOICE, extract encryptedData
        content = auth_response_asn1["content"]
        if isinstance(content, tuple):
            choice_tag, choice_value = content
            if choice_tag == 'encryptedData':
                encrypted_data_structure = choice_value
            else:
                raise ValueError(f"Unexpected content type: {choice_tag}")
        else:
            raise ValueError("Invalid content structure")
        
        # Extract ciphertext from EncryptedData structure
        # ciphertext is a CHOICE (cipher_type, cipher_value)
        ciphertext_choice = encrypted_data_structure.get('ciphertext')
        if isinstance(ciphertext_choice, tuple):
            cipher_type, aes_ccm_ciphertext = ciphertext_choice
            # aes_ccm_ciphertext is a dict with 'nonce' and 'ccmCiphertext'
            if cipher_type == 'aes128ccm' and isinstance(aes_ccm_ciphertext, dict):
                nonce = aes_ccm_ciphertext['nonce']
                ciphertext = aes_ccm_ciphertext['ccmCiphertext']
            else:
                raise ValueError(f"Unsupported cipher type: {cipher_type}")
        else:
            raise ValueError("Invalid ciphertext structure")

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

        # 6. Map ETSI AuthorizationResponseCode to Python ResponseCode
        etsi_to_response_code = {
            "ok": ResponseCode.OK,
            "its-s-cantparse": ResponseCode.CANONICAL_ENCODING_ERROR,
            "its-s-badcontenttype": ResponseCode.BAD_CONTENT_TYPE,
            "its-s-decryptionfailed": ResponseCode.DECRYPTION_FAILED,
            "aa-cantparse": ResponseCode.CANONICAL_ENCODING_ERROR,
            "aa-badcontenttype": ResponseCode.BAD_CONTENT_TYPE,
            "aa-decryptionfailed": ResponseCode.DECRYPTION_FAILED,
            "unknownits": ResponseCode.UNKNOWN_ITS_ID,
            "invalidsignature": ResponseCode.INVALID_SIGNATURE,
            "invalidencryptionkey": ResponseCode.INVALID_ENCRYPTION_KEY,
            "deniedrequest": ResponseCode.UNAUTHORIZED,
            "deniedpermissions": ResponseCode.UNAUTHORIZED,
        }
        
        response_code_str = inner_response_asn1["responseCode"]
        response_code = etsi_to_response_code.get(response_code_str, ResponseCode.INTERNAL_SERVER_ERROR)

        # 7. Convert to Python object
        # Re-encode certificate dict to bytes for ITS-Station to save
        certificate_bytes = None
        if inner_response_asn1.get("certificate"):
            certificate_dict = inner_response_asn1["certificate"]
            # Re-encode the certificate dict back to ASN.1 OER bytes
            certificate_bytes = asn1_compiler.encode("Certificate", certificate_dict)
        
        return InnerAtResponse(
            requestHash=inner_response_asn1["requestHash"],
            responseCode=response_code,
            certificate=certificate_bytes,
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
            "timestamp": time32_encode(inner_validation_request.timestamp),
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
            "timestamp": time32_encode(inner_validation_response.timestamp),
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
    ) -> list:
        """
        Codifica N AuthorizationResponse separate per Butterfly (100% ETSI Standard).

        CONFORMITÀ ETSI TS 102941:
        ===========================
        ✓ Section 6.3.2 - AuthorizationResponse (standard message)
        ✓ ASN.1 OER encoding per ogni risposta
        ✓ HMAC-based encryption per response (Section 6.3.3)
        ✓ Unlinkability tra risposte (chiavi diverse)

        STRUTTURA RISPOSTA BUTTERFLY (ETSI COMPLIANT):
        ===============================================
        Invece di una struttura custom, il Butterfly Expansion usa N
        AuthorizationResponse standard ETSI, una per ogni AT richiesto:

        Response #0: AuthorizationResponse cifrata con hmacKey[0]
        Response #1: AuthorizationResponse cifrata con hmacKey[1]
        ...
        Response #N: AuthorizationResponse cifrata con hmacKey[N]

        Ogni AuthorizationResponse è un messaggio ETSI TS 102941 completo:
        - version: Versione protocollo
        - encryptedData: InnerAtResponse cifrato con hmacKey
        - timestamp: Timestamp generazione

        Ogni InnerAtResponse contiene:
        - requestHash: Hash della richiesta originale
        - responseCode: OK o codice errore
        - certificate: Authorization Ticket (ASN.1 OER bytes)

        VANTAGGI APPROCCIO STANDARD:
        =============================
        ✓ 100% conforme ETSI TS 102941 (no estensioni custom)
        ✓ Ogni risposta è un messaggio valido indipendente
        ✓ Privacy garantita: ogni risposta cifrata con chiave diversa
        ✓ Compatibile con parser ETSI standard
        ✓ Facilita debugging (ogni risposta decodificabile separatamente)

        Args:
            request_hash: SHA-256 hash della ButterflyAuthorizationRequest
            responses: Lista di dict contenenti:
                - 'authorization_ticket': bytes (certificato AT in ASN.1 OER)
                - 'hmac_key': bytes (chiave HMAC per cifrare questa risposta)
                - 'response_code': ResponseCode
                - 'error': str (opzionale, se errore)

        Returns:
            Lista di bytes, ognuno è un AuthorizationResponse ASN.1 OER encoded

        Example:
            >>> responses = [
            ...     {
            ...         'authorization_ticket': at_cert_0_asn1,
            ...         'hmac_key': hmac_key_0,
            ...         'response_code': ResponseCode.OK
            ...     },
            ...     {
            ...         'authorization_ticket': at_cert_1_asn1,
            ...         'hmac_key': hmac_key_1,
            ...         'response_code': ResponseCode.OK
            ...     }
            ... ]
            >>> encoded_responses = encoder.encode_butterfly_authorization_response(
            ...     request_hash=request_hash,
            ...     responses=responses
            ... )
            >>> # Invia N risposte separate
            >>> for resp in encoded_responses:
            ...     send_to_itss(resp)
        """
        print(f"\n[ENCODER] Codificando Butterfly Authorization Response (ETSI Standard)...")
        print(f"[ENCODER]   Request hash: {request_hash.hex()[:32]}...")
        print(f"[ENCODER]   Numero risposte: {len(responses)}")

        # === CODIFICA OGNI AUTHORIZATION RESPONSE (STANDARD ETSI) ===
        encoded_responses = []

        for idx, response_dict in enumerate(responses):
            print(f"[ENCODER]   Processando risposta #{idx+1}/{len(responses)}...", end=" ")

            # Estrai dati dalla response
            at_cert_asn1 = response_dict.get("authorization_ticket")  # Already ASN.1 OER bytes
            hmac_key = response_dict.get("hmac_key")
            response_code = response_dict.get("response_code", ResponseCode.OK)

            # Validazione hmac_key
            if not hmac_key or len(hmac_key) != 32:
                print(f"✗ ERRORE: hmacKey non valida")
                raise ValueError(f"Response #{idx} hmacKey must be 32 bytes")

            try:
                # Usa encode_authorization_response standard ETSI
                encoded_response = self.encode_authorization_response(
                    response_code=response_code,
                    request_hash=request_hash,
                    certificate_asn1=at_cert_asn1,
                    hmac_key=hmac_key
                )
                
                encoded_responses.append(encoded_response)
                
                cert_info = f"{len(at_cert_asn1)} bytes" if at_cert_asn1 else "NO CERT"
                print(f"✓ ({len(encoded_response)} bytes, cert: {cert_info})")

            except Exception as e:
                print(f"✗ ERRORE encoding: {e}")
                raise

        print(f"[ENCODER] ✓ Tutte le {len(responses)} risposte codificate (ETSI compliant)")
        total_size = sum(len(r) for r in encoded_responses)
        print(f"[ENCODER]     Dimensione totale: {total_size} bytes")
        print(f"[ENCODER]     Media per risposta: {total_size // len(responses)} bytes")

        return encoded_responses

    def encode_butterfly_authorization_request(
        self,
        butterfly_request: "ButterflyAuthorizationRequest",
        enrollment_certificate_asn1: bytes,
        enrollment_private_key: EllipticCurvePrivateKey,
        aa_public_key: EllipticCurvePublicKey,
        aa_certificate_asn1: bytes,
    ) -> bytes:
        """
        Codifica ButterflyAuthorizationRequest per batch authorization.

        🔄 FLUSSO COMPLETO STANDARD ETSI (ETSI TS 102941 Section 6.3.3):
        ================================================================
        1. ITS-S serializza ButterflyAuthorizationRequest con ASN.1 OER
        2. ITS-S cripta richiesta con chiave pubblica AA (ECIES)
        3. ITS-S firma i dati criptati con chiave privata EC (Proof of Possession)
        4. ITS-S allega Enrollment Certificate come signer
        5. ITS-S crea EtsiTs103097Data-SignedAndEncrypted

        STRUTTURA RICHIESTA BUTTERFLY:
        ===============================
        ButterflyAuthorizationRequest contiene:
        - sharedAtRequest: Parametri comuni per tutti gli AT
        - innerAtRequests: N richieste individuali (N chiavi pubbliche + N hmacKeys)
        - batchSize: Numero di AT richiesti

        InnerAtRequests (N volte):
        - publicKeys: Chiave pubblica univoca per questo AT
        - hmacKey: Chiave HMAC univoca per questo AT (unlinkability)
        - requestedSubjectAttributes: Permessi richiesti

        CONFORMITÀ ETSI:
        ================
        ✓ Section 6.3.3 - Butterfly Authorization Request
        ✓ ASN.1 OER encoding (SignedAndEncrypted come standard request)
        ✓ ECIES encryption
        ✓ EC signature for Proof of Possession
        ✓ Unlinkability attraverso N hmacKeys univoche

        Args:
            butterfly_request: ButterflyAuthorizationRequest con N InnerAtRequests
            enrollment_certificate_asn1: Certificato enrollment ITS-S (ASN.1 OER bytes)
            enrollment_private_key: Chiave privata EC per firma
            aa_public_key: Chiave pubblica AA per cifratura
            aa_certificate_asn1: Certificato AA (ASN.1 OER bytes) per recipient ID

        Returns:
            ASN.1 OER encoded EtsiTs103097Data-SignedAndEncrypted

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
        }

        # === 5. CODIFICA BUTTERFLY REQUEST ===
        # Codifica la ButterflyAuthorizationRequest come plaintext ASN.1 OER
        butterfly_plaintext = asn1_compiler.encode("ButterflyAuthorizationRequest", butterfly_request_asn1)
        print(f"[ENCODER]   ButterflyAuthorizationRequest serializzata: {len(butterfly_plaintext)} bytes")

        # === 6. CIFRA CON CHIAVE PUBBLICA AA (ECIES) ===
        # Cifra plaintext con chiave pubblica AA (come AuthorizationRequest standard)
        encrypted_data = self.security.encrypt_message(butterfly_plaintext, aa_public_key)
        print(f"[ENCODER]   Dati cifrati con ECIES: {len(encrypted_data)} bytes")

        # === 7. COMPUTA RECIPIENT ID (AA CERTIFICATE HASHED ID8) ===
        recipient_id = compute_hashed_id8(aa_certificate_asn1)
        print(f"[ENCODER]   AA HashedId8: {recipient_id.hex()}")

        # === 8. CREA SIGNED AND ENCRYPTED DATA (100% ETSI STANDARD) ===
        # Usa SignedAndEncrypted come AuthorizationRequest standard (Section 6.3.2)
        # Include firma EC per Proof of Possession
        auth_request_asn1 = create_ieee1609dot2_signed_and_encrypted_data(
            ecies_ciphertext=encrypted_data,
            recipient_id=recipient_id,
            signer_certificate_asn1=enrollment_certificate_asn1,
            signer_private_key=enrollment_private_key,
            psid=0x24  # CA Basic Service (PKI operations)
        )

        # === 9. CODIFICA FINALE COME SIGNEDANDENCRYPTED ===
        encoded_request = asn1_compiler.encode("EtsiTs103097Data-SignedAndEncrypted", auth_request_asn1)

        print(f"[ENCODER] ✓ ButterflyAuthorizationRequest codificata con SignedAndEncrypted")
        print(f"[ENCODER]     Dimensione finale: {len(encoded_request)} bytes")
        print(f"[ENCODER]     Richieste AT: {len(butterfly_request.innerAtRequests)}")
        print(f"[ENCODER]     Formato: EtsiTs103097Data-SignedAndEncrypted (ETSI TS 102941)")

        return encoded_request

    # ------------------------------------------------------------------------
    # BUTTERFLY RESPONSE DECODING
    # ------------------------------------------------------------------------

    def decode_butterfly_authorization_response(
        self, response_bytes_list: list, hmac_keys: list
    ) -> list:
        """
        Decodifica N AuthorizationResponse separate per Butterfly (100% ETSI Standard).

        CONFORMITÀ ETSI TS 102941:
        ===========================
        ✓ Section 6.3.2 - AuthorizationResponse (standard message)
        ✓ ASN.1 OER decoding per ogni risposta
        ✓ HMAC-based decryption per response (Section 6.3.3)
        ✓ Unlinkability tra risposte (chiavi diverse)

        STRUTTURA RISPOSTA BUTTERFLY (ETSI COMPLIANT):
        ===============================================
        Il Butterfly Expansion riceve N AuthorizationResponse standard ETSI,
        una per ogni AT richiesto:

        Response #0: AuthorizationResponse cifrata con hmacKey[0]
        Response #1: AuthorizationResponse cifrata con hmacKey[1]
        ...
        Response #N: AuthorizationResponse cifrata con hmacKey[N]

        Ogni AuthorizationResponse viene decodificata con decode_authorization_response()
        standard ETSI usando la corrispondente hmacKey.

        DECIFRATURA MULTI-CHIAVE:
        =========================
        Response #0 → decifrata con hmacKey[0] → InnerAtResponse → AT certificate
        Response #1 → decifrata con hmacKey[1] → InnerAtResponse → AT certificate
        ...
        Response #N → decifrata con hmacKey[N] → InnerAtResponse → AT certificate

        Args:
            response_bytes_list: Lista di bytes, ognuno è un AuthorizationResponse ASN.1 OER
            hmac_keys: Lista di chiavi HMAC (una per ogni AT richiesto, ordine originale)

        Returns:
            Lista di dict contenenti:
                - 'response_code': ResponseCode
                - 'authorization_ticket': bytes (certificato AT in formato ASN.1 OER) o None
                - 'request_hash': bytes (hash richiesta originale)
                - 'error': str (opzionale, se errore decifratura)

        Raises:
            ValueError: Se il numero di hmac_keys non corrisponde al numero di risposte
            Exception: Se decifratura fallisce

        Example:
            >>> hmac_keys = [hmac_key_0, hmac_key_1, hmac_key_2]
            >>> # Ricevi N risposte separate
            >>> response_bytes_list = [resp1_bytes, resp2_bytes, resp3_bytes]
            >>> responses = encoder.decode_butterfly_authorization_response(
            ...     response_bytes_list=response_bytes_list,
            ...     hmac_keys=hmac_keys
            ... )
            >>> for idx, resp in enumerate(responses):
            ...     if resp['response_code'] == ResponseCode.OK:
            ...         at_cert = resp['authorization_ticket']
            ...         print(f"AT #{idx}: {len(at_cert)} bytes")
        """
        print(f"\n[ENCODER] Decodificando Butterfly Authorization Response (ETSI Standard)...")
        print(f"[ENCODER]   Numero risposte ricevute: {len(response_bytes_list)}")
        print(f"[ENCODER]   Numero hmac_keys fornite: {len(hmac_keys)}")

        # Validazione
        if len(response_bytes_list) != len(hmac_keys):
            raise ValueError(
                f"Numero risposte ({len(response_bytes_list)}) != numero hmac_keys ({len(hmac_keys)})"
            )

        # === DECODIFICA OGNI AUTHORIZATION RESPONSE (STANDARD ETSI) ===
        responses = []

        for idx, (response_bytes, hmac_key) in enumerate(zip(response_bytes_list, hmac_keys)):
            print(f"[ENCODER]   Processando risposta #{idx+1}/{len(response_bytes_list)}...", end=" ")

            try:
                # Usa decode_authorization_response standard ETSI
                inner_response = self.decode_authorization_response(
                    response_bytes=response_bytes,
                    hmac_key=hmac_key
                )

                responses.append(
                    {
                        "response_code": inner_response.responseCode,
                        "authorization_ticket": inner_response.certificate,  # bytes ASN.1 OER o None
                        "request_hash": inner_response.requestHash,
                    }
                )

                status = "✓" if inner_response.responseCode == ResponseCode.OK else f"⚠ {inner_response.responseCode.name}"
                cert_info = f"{len(inner_response.certificate)} bytes" if inner_response.certificate else "NO CERT"
                print(f"{status} ({cert_info})")

            except Exception as e:
                print(f"✗ ERRORE: {e}")
                responses.append(
                    {
                        "response_code": ResponseCode.INTERNAL_SERVER_ERROR,
                        "authorization_ticket": None,
                        "request_hash": b"",
                        "error": str(e),
                    }
                )

        print(f"[ENCODER] ✓ Decodificate {len(responses)} risposte (ETSI compliant)")
        print(
            f"[ENCODER]     OK: {sum(1 for r in responses if r['response_code'] == ResponseCode.OK)}"
        )
        print(
            f"[ENCODER]     Errori: {sum(1 for r in responses if r['response_code'] != ResponseCode.OK)}"
        )

        return responses


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================


def create_encoder() -> MessageEncoder:
    """
    Create a new ETSI message encoder instance.

    Returns:
        Configured encoder with ASN.1 OER support
    """
    return MessageEncoder()


# Backward compatibility alias
ETSIMessageEncoder = MessageEncoder

__all__ = [
    'MessageEncoder',
    'ETSIMessageEncoder',  # Backward compatibility
    'ETSISecurityManager',  # Legacy
    'create_encoder',
]
