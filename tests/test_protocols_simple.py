"""
Test suite semplificata per Protocols (ETSI Message Types)

Focus su:
- Strutture dati ETSI Message Types  
- Enum values
- Dataclass creation e validation
"""

import pytest
from datetime import datetime, timezone

from protocols.etsi_message_types import (
    ETSIMessageType,
    ResponseCode,
    InnerEcRequest,
    InnerEcResponse,
    InnerAtRequest,
    InnerAtResponse,
    SharedAtRequest,
)


class TestETSIMessageTypes:
    """Test per ETSI Message Types"""

    def test_message_type_enum(self):
        """Test enumerazione tipi messaggio"""
        assert ETSIMessageType.ENROLLMENT_REQUEST.value == "EnrollmentRequest"
        assert ETSIMessageType.AUTHORIZATION_REQUEST.value == "AuthorizationRequest"
        assert ETSIMessageType.ENROLLMENT_RESPONSE.value == "EnrollmentResponse"
        assert ETSIMessageType.AUTHORIZATION_RESPONSE.value == "AuthorizationResponse"

    def test_response_code_enum(self):
        """Test enumerazione response codes"""
        assert ResponseCode.OK.value == 0
        assert hasattr(ResponseCode, "BAD_REQUEST")
        assert hasattr(ResponseCode, "UNAUTHORIZED")
        assert hasattr(ResponseCode, "INVALID_SIGNATURE")
        assert ResponseCode.BAD_REQUEST.value == 8
        assert ResponseCode.UNAUTHORIZED.value == 9

    def test_inner_ec_request_creation(self):
        """Test creazione InnerEcRequest"""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        # Genera chiave
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Crea request
        request = InnerEcRequest(
            itsId="TestVehicle",
            certificateFormat=1,
            publicKeys={"verification": public_key_bytes},
            requestedSubjectAttributes={"country": "IT"},
        )

        assert request.itsId == "TestVehicle"
        assert request.certificateFormat == 1
        assert "verification" in request.publicKeys
        assert request.publicKeys["verification"] == public_key_bytes
        assert request.requestedSubjectAttributes["country"] == "IT"

    def test_inner_ec_request_validation(self):
        """Test validazione InnerEcRequest - manca itsId"""
        with pytest.raises(ValueError, match="itsId is required"):
            InnerEcRequest(
                itsId="",  # vuoto -> invalido
                certificateFormat=1,
                publicKeys={"verification": b"test_key"},
            )

    def test_inner_ec_request_validation_no_keys(self):
        """Test validazione InnerEcRequest - mancano public keys"""
        with pytest.raises(ValueError, match="At least one public key is required"):
            InnerEcRequest(
                itsId="TestVehicle",
                certificateFormat=1,
                publicKeys={},  # vuoto -> invalido
            )

    def test_inner_ec_response_creation(self):
        """Test creazione InnerEcResponse"""
        response = InnerEcResponse(
            requestHash=b"test_hash_12345678",
            responseCode=ResponseCode.OK,
            certificate=b"test_certificate_data",
        )

        assert response.requestHash == b"test_hash_12345678"
        assert response.responseCode == ResponseCode.OK
        assert response.certificate == b"test_certificate_data"

    def test_inner_at_request_creation(self):
        """Test creazione InnerAtRequest"""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        # Genera chiave
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Crea request
        request = InnerAtRequest(
            publicKeys={"verification": public_key_bytes},
            hmacKey=b"test_hmac_key_32_bytes_length!!",
            sharedAtRequest=None,
            ecSignature=b"test_signature",
        )

        assert "verification" in request.publicKeys
        assert request.publicKeys["verification"] == public_key_bytes
        assert request.hmacKey == b"test_hmac_key_32_bytes_length!!"
        assert request.ecSignature == b"test_signature"
        assert request.sharedAtRequest is None

    def test_inner_at_response_creation(self):
        """Test creazione InnerAtResponse"""
        response = InnerAtResponse(
            requestHash=b"test_hash_12345678",
            responseCode=ResponseCode.OK,
            certificate=b"test_at_certificate",
        )

        assert response.requestHash == b"test_hash_12345678"
        assert response.responseCode == ResponseCode.OK
        assert response.certificate == b"test_at_certificate"

    def test_shared_at_request_creation(self):
        """Test creazione SharedAtRequest"""
        shared_request = SharedAtRequest(
            eaId="EA_001",
            keyTag=b"key_tag_bytes",
            certificateFormat=1,
            requestedSubjectAttributes={"psid": "36"},
        )

        assert shared_request.eaId == "EA_001"
        assert shared_request.keyTag == b"key_tag_bytes"
        assert shared_request.certificateFormat == 1
        assert shared_request.requestedSubjectAttributes["psid"] == "36"

    def test_response_code_values(self):
        """Test valori specifici ResponseCode"""
        assert ResponseCode.OK.value == 0
        assert ResponseCode.CANONICAL_ENCODING_ERROR.value == 1
        assert ResponseCode.BAD_CONTENT_TYPE.value == 2
        assert ResponseCode.DECRYPTION_FAILED.value == 4
        assert ResponseCode.UNKNOWN_ITS_ID.value == 5
        assert ResponseCode.INVALID_SIGNATURE.value == 6
        assert ResponseCode.INTERNAL_SERVER_ERROR.value == 10

    def test_message_type_values(self):
        """Test tutti i valori ETSIMessageType"""
        assert len(list(ETSIMessageType)) >= 8  # Almeno 8 tipi definiti
        
        # Verifica tipi principali
        types = [t.value for t in ETSIMessageType]
        assert "EnrollmentRequest" in types
        assert "EnrollmentResponse" in types
        assert "AuthorizationRequest" in types
        assert "AuthorizationResponse" in types
        assert "CrlRequest" in types
        assert "CrlResponse" in types


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
