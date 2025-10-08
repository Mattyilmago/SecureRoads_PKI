"""
Test Suite: ETSI Message Types

Tests ETSI TS 102941 message types and enums:
- MessageType enum values
- ResponseCode enum values  
- InnerEcRequest/Response creation
- InnerAtRequest/Response creation
- Message validation

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from protocols.etsi_message_types import (
    ETSIMessageType,
    InnerAtRequest,
    InnerAtResponse,
    InnerEcRequest,
    InnerEcResponse,
    ResponseCode,
    SharedAtRequest,
)


class TestETSIEnums:
    """Test ETSI enum types"""

    def test_message_type_enum(self):
        """Test ETSIMessageType enum"""
        assert ETSIMessageType.ENROLLMENT_REQUEST.value == "EnrollmentRequest"
        assert ETSIMessageType.ENROLLMENT_RESPONSE.value == "EnrollmentResponse"
        assert ETSIMessageType.AUTHORIZATION_REQUEST.value == "AuthorizationRequest"
        assert ETSIMessageType.AUTHORIZATION_RESPONSE.value == "AuthorizationResponse"

    def test_response_code_enum(self):
        """Test ResponseCode enum"""
        assert ResponseCode.OK.value == 0
        assert ResponseCode.CANONICAL_ENCODING_ERROR.value == 1
        assert ResponseCode.BAD_CONTENT_TYPE.value == 2
        assert ResponseCode.BAD_REQUEST.value == 8

    def test_message_type_values(self):
        """Test all ETSIMessageType values exist"""
        types = [
            ETSIMessageType.ENROLLMENT_REQUEST,
            ETSIMessageType.ENROLLMENT_RESPONSE,
            ETSIMessageType.AUTHORIZATION_REQUEST,
            ETSIMessageType.AUTHORIZATION_RESPONSE,
        ]
        assert len(types) == 4

    def test_response_code_values(self):
        """Test ResponseCode values"""
        codes = [
            ResponseCode.OK,
            ResponseCode.CANONICAL_ENCODING_ERROR,
            ResponseCode.BAD_CONTENT_TYPE,
        ]
        assert len(codes) >= 3


class TestInnerEcMessages:
    """Test InnerEc message types"""

    def test_inner_ec_request_creation(self):
        """Test creating InnerEcRequest"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        request = InnerEcRequest(
            itsId="TEST_ITS",
            certificateFormat=1,
            publicKeys={"verification": public_key},
            requestedSubjectAttributes={},
        )

        assert request.itsId == "TEST_ITS"
        assert request.certificateFormat == 1
        assert "verification" in request.publicKeys

    def test_inner_ec_request_validation(self):
        """Test InnerEcRequest validates required fields"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        request = InnerEcRequest(
            itsId="TEST",
            certificateFormat=1,
            publicKeys={"verification": public_key},
            requestedSubjectAttributes={},
        )
        assert request is not None

    def test_inner_ec_request_validation_no_keys(self):
        """Test InnerEcRequest requires at least one key"""
        with pytest.raises(ValueError, match="At least one public key is required"):
            InnerEcRequest(
                itsId="TEST", certificateFormat=1, publicKeys={}, requestedSubjectAttributes={}
            )

    def test_inner_ec_response_creation(self):
        """Test creating InnerEcResponse"""
        response = InnerEcResponse(
            requestHash=b"\x00" * 16,
            responseCode=ResponseCode.OK,
            certificate=b"mock_cert",
        )

        assert response.requestHash == b"\x00" * 16
        assert response.responseCode == ResponseCode.OK


class TestInnerAtMessages:
    """Test InnerAt message types"""

    def test_inner_at_request_creation(self):
        """Test creating InnerAtRequest"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        request = InnerAtRequest(
            publicKeys={"verification": public_key},
            hmacKey=b"\x00" * 32,
            sharedAtRequest=SharedAtRequest(
                eaId=b"EA_001",
                keyTag=b"\x01" * 16,
                certificateFormat=1,
                requestedSubjectAttributes={"psid": [36]},
            ),
            ecSignature=b"mock_signature",
        )

        assert request.hmacKey == b"\x00" * 32
        assert request.sharedAtRequest.eaId == b"EA_001"

    def test_inner_at_response_creation(self):
        """Test creating InnerAtResponse"""
        response = InnerAtResponse(
            requestHash=b"\x00" * 16,
            responseCode=ResponseCode.OK,
            certificate=b"mock_at_cert",
        )

        assert response.requestHash == b"\x00" * 16
        assert response.responseCode == ResponseCode.OK

    def test_shared_at_request_creation(self):
        """Test creating SharedAtRequest"""
        request = SharedAtRequest(
            eaId=b"EA_TEST",
            keyTag=b"\x02" * 16,
            certificateFormat=1,
            requestedSubjectAttributes={"psid": [36, 37]},
        )

        assert request.eaId == b"EA_TEST"
        assert request.certificateFormat == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
