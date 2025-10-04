"""
Test suite per Protocols (ETSI Message Types, Encoder/Decoder)

Testa le funzionalità principali di:
- ETSI Message Types (strutture dati)
- ETSI Message Encoder/Decoder (ASN.1 OER)
- Crittografia ECIES
- Serializzazione/deserializzazione messaggi
"""

import pytest
import os
from datetime import datetime, timezone

from protocols.etsi_message_types import (
    ETSIMessageType,
    ResponseCode,
    InnerEcRequest,
    InnerEcResponse,
    InnerAtRequest,
    InnerAtResponse,
)
from protocols.etsi_message_encoder import ETSIMessageEncoder


@pytest.fixture
def message_encoder():
    """Fixture per creare un Message Encoder"""
    encoder = ETSIMessageEncoder()
    return encoder


@pytest.fixture
def test_key_pair():
    """Fixture per creare una coppia di chiavi di test"""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


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
            certificateFormat=0,
            publicKeys={"verification": public_key_bytes},
            requestedSubjectAttributes={"country": "IT"},
        )

        assert request.itsId == "TestVehicle"
        assert request.publicKeys["verification"] == public_key_bytes
        assert request.requestedSubjectAttributes["country"] == "IT"

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

        assert request.publicKeys["verification"] == public_key_bytes
        assert request.hmacKey == b"test_hmac_key_32_bytes_length!!"
        assert request.ecSignature == b"test_signature"

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


class TestETSIMessageEncoder:
    """Test per ETSI Message Encoder/Decoder"""

    def test_encoder_initialization(self, message_encoder):
        """Test inizializzazione encoder"""
        assert message_encoder is not None
        assert message_encoder.asn1_compiler is not None

    def test_encode_decode_enrollment_request(self, message_encoder, test_key_pair):
        """Test encoding/decoding EnrollmentRequest"""
        private_key, public_key = test_key_pair

        from cryptography.hazmat.primitives import serialization

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Crea request
        inner_request = InnerEcRequest(
            itsId="TestVehicle",
            certificateFormat=0,
            publicKeys={"verification": public_key_bytes},
            requestedSubjectAttributes={"country": "IT", "organization": "Test"},
        )

        # Encode con crittografia
        encoded_request = message_encoder.encode_enrollment_request(
            inner_request=inner_request,
            recipient_public_key=public_key,
        )

        assert encoded_request is not None
        assert len(encoded_request) > 0

        # Decode
        decoded_request = message_encoder.decode_enrollment_request(
            encrypted_request=encoded_request, recipient_private_key=private_key
        )

        assert decoded_request is not None
        assert decoded_request.itsId == "TestVehicle"
        assert decoded_request.requestedSubjectAttributes["country"] == "IT"

    def test_encode_decode_enrollment_response(self, message_encoder, test_key_pair):
        """Test encoding/decoding EnrollmentResponse"""
        private_key, public_key = test_key_pair

        # Crea response
        inner_response = InnerEcResponse(
            requestHash=b"test_hash_value_",
            responseCode=ResponseCode.OK,
            certificate=b"test_certificate_pem_data",
        )

        # Encode con crittografia
        encoded_response = message_encoder.encode_enrollment_response(
            inner_response=inner_response,
            recipient_public_key=public_key,
        )

        assert encoded_response is not None
        assert len(encoded_response) > 0

        # Decode
        decoded_response = message_encoder.decode_enrollment_response(
            encrypted_response=encoded_response, recipient_private_key=private_key
        )

        assert decoded_response is not None
        assert decoded_response.responseCode == ResponseCode.OK
        assert decoded_response.certificate == b"test_certificate_pem_data"

    def test_encode_decode_authorization_request(self, message_encoder, test_key_pair):
        """Test encoding/decoding AuthorizationRequest"""
        private_key, public_key = test_key_pair

        from cryptography.hazmat.primitives import serialization

        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Crea request
        inner_request = InnerAtRequest(
            publicKeys={"verification": public_key_bytes},
            hmacKey=b"a" * 32,  # 32 bytes HMAC key
            sharedAtRequest=None,
            ecSignature=b"test_signature_data",
        )

        # Encode con crittografia
        encoded_request = message_encoder.encode_authorization_request(
            inner_request=inner_request,
            recipient_public_key=public_key,
        )

        assert encoded_request is not None
        assert len(encoded_request) > 0

        # Decode
        decoded_request = message_encoder.decode_authorization_request(
            encrypted_request=encoded_request, recipient_private_key=private_key
        )

        assert decoded_request is not None
        assert len(decoded_request.hmacKey) == 32
        assert decoded_request.ecSignature == b"test_signature_data"

    def test_encode_decode_authorization_response(self, message_encoder):
        """Test encoding/decoding AuthorizationResponse"""
        # Crea response
        inner_response = InnerAtResponse(
            requestHash=b"test_hash_value_",
            responseCode=ResponseCode.OK,
            certificate=b"test_at_certificate_data",
        )

        # HMAC key per unlinkability
        hmac_key = b"b" * 32

        # Encode con HMAC encryption
        encoded_response = message_encoder.encode_authorization_response(
            inner_response=inner_response,
            hmac_key=hmac_key,
        )

        assert encoded_response is not None
        assert len(encoded_response) > 0

        # Decode
        decoded_response = message_encoder.decode_authorization_response(
            encrypted_response=encoded_response, hmac_key=hmac_key
        )

        assert decoded_response is not None
        assert decoded_response.responseCode == ResponseCode.OK
        assert decoded_response.certificate == b"test_at_certificate_data"

    def test_ecies_encryption_decryption(self, message_encoder, test_key_pair):
        """Test crittografia/decrittografia ECIES"""
        private_key, public_key = test_key_pair

        plaintext = b"Test plaintext message for ECIES"

        # Encrypt
        ciphertext = message_encoder.ecies_encrypt(plaintext, public_key)

        assert ciphertext is not None
        assert len(ciphertext) > len(plaintext)  # Ciphertext è più lungo

        # Decrypt
        decrypted = message_encoder.ecies_decrypt(ciphertext, private_key)

        assert decrypted == plaintext

    def test_hmac_encryption_decryption(self, message_encoder):
        """Test crittografia/decrittografia HMAC-based"""
        hmac_key = b"c" * 32
        plaintext = b"Test plaintext message for HMAC encryption"

        # Encrypt
        ciphertext = message_encoder.hmac_encrypt(plaintext, hmac_key)

        assert ciphertext is not None
        assert len(ciphertext) > len(plaintext)

        # Decrypt
        decrypted = message_encoder.hmac_decrypt(ciphertext, hmac_key)

        assert decrypted == plaintext

    def test_calculate_hashed_id8(self, message_encoder):
        """Test calcolo HashedId8"""
        test_data = b"Test certificate data for hashing"

        hashed_id = message_encoder.calculate_hashed_id8(test_data)

        assert hashed_id is not None
        assert len(hashed_id) == 8  # HashedId8 è 8 bytes

    def test_invalid_decryption_fails(self, message_encoder, test_key_pair):
        """Test che decryption con chiave sbagliata fallisce"""
        private_key1, public_key1 = test_key_pair

        # Genera seconda coppia di chiavi
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend

        private_key2 = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key2 = private_key2.public_key()

        plaintext = b"Secret message"

        # Encrypt con public_key1
        ciphertext = message_encoder.ecies_encrypt(plaintext, public_key1)

        # Try to decrypt con private_key2 (chiave sbagliata)
        with pytest.raises(Exception):
            message_encoder.ecies_decrypt(ciphertext, private_key2)


class TestETSIMessageIntegration:
    """Test di integrazione per messaggi ETSI completi"""

    def test_full_enrollment_message_flow(self, message_encoder):
        """Test flusso completo messaggio enrollment"""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        # ITS-S genera chiave
        itss_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        itss_public = itss_private.public_key()

        # EA ha chiave
        ea_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ea_public = ea_private.public_key()

        itss_public_bytes = itss_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # 1. ITS-S crea e invia EnrollmentRequest
        request = InnerEcRequest(
            itsId="TestVehicle_Integration",
            certificateFormat=0,
            publicKeys={"verification": itss_public_bytes},
            requestedSubjectAttributes={"country": "IT"},
        )

        encrypted_request = message_encoder.encode_enrollment_request(request, ea_public)

        # 2. EA riceve e decripta
        decrypted_request = message_encoder.decode_enrollment_request(
            encrypted_request, ea_private
        )

        assert decrypted_request.itsId == "TestVehicle_Integration"

        # 3. EA crea e invia EnrollmentResponse
        response = InnerEcResponse(
            requestHash=b"hash_of_request_",
            responseCode=ResponseCode.OK,
            certificate=b"enrollment_certificate_pem",
        )

        encrypted_response = message_encoder.encode_enrollment_response(response, itss_public)

        # 4. ITS-S riceve e decripta
        decrypted_response = message_encoder.decode_enrollment_response(
            encrypted_response, itss_private
        )

        assert decrypted_response.responseCode == ResponseCode.OK
        assert decrypted_response.certificate == b"enrollment_certificate_pem"

    def test_full_authorization_message_flow(self, message_encoder):
        """Test flusso completo messaggio authorization"""
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization

        # ITS-S genera chiave per AT
        at_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        at_public = at_private.public_key()

        # AA ha chiave
        aa_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        aa_public = aa_private.public_key()

        at_public_bytes = at_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # HMAC key per unlinkability
        hmac_key = b"d" * 32

        # 1. ITS-S crea e invia AuthorizationRequest
        request = InnerAtRequest(
            publicKeys={"verification": at_public_bytes},
            hmacKey=hmac_key,
            sharedAtRequest=None,
            ecSignature=b"signature_from_ec",
        )

        encrypted_request = message_encoder.encode_authorization_request(request, aa_public)

        # 2. AA riceve e decripta
        decrypted_request = message_encoder.decode_authorization_request(
            encrypted_request, aa_private
        )

        assert len(decrypted_request.hmacKey) == 32

        # 3. AA crea e invia AuthorizationResponse (con HMAC)
        response = InnerAtResponse(
            requestHash=b"hash_of_at_req__",
            responseCode=ResponseCode.OK,
            certificate=b"authorization_ticket_pem",
        )

        encrypted_response = message_encoder.encode_authorization_response(response, hmac_key)

        # 4. ITS-S riceve e decripta
        decrypted_response = message_encoder.decode_authorization_response(
            encrypted_response, hmac_key
        )

        assert decrypted_response.responseCode == ResponseCode.OK
        assert decrypted_response.certificate == b"authorization_ticket_pem"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
