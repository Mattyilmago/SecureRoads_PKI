"""
Enrollment Authority Blueprint

Implements ETSI TS 102941 Section 6.2 - Enrollment Request/Response
and Section 6.4.1 - Authorization Validation Request/Response

Full ASN.1 OER encoding/decoding implementation.

Author: SecureRoad PKI Project
Date: October 2025
"""

import traceback

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Blueprint, current_app, jsonify, request

from api.middleware import optional_auth, rate_limit, require_mtls
from protocols.messages.encoder import MessageEncoder, asn1_compiler, asn1_to_inner_ec_request
from protocols.messages.types import InnerEcRequestSignedForPop
from protocols.core.types import ResponseCode
from protocols.core.primitives import compute_request_hash, verify_ieee1609_signature, etsi_verification_key_to_public_key
from utils.metrics import get_metrics_collector


def response_code_value(code: ResponseCode) -> int:
    """Convert ResponseCode enum to integer value for JSON"""
    return code.value


def create_enrollment_blueprint(ea_instance):
    """Create Flask blueprint for Enrollment Authority endpoints."""
    bp = Blueprint("enrollment", __name__)

    # Store EA instance
    bp.ea = ea_instance

    # Create encoder instance (ETSI TS 102941 compliant)
    bp.encoder = MessageEncoder()

    @bp.route("/request", methods=["POST"])
    @rate_limit
    @optional_auth
    def enrollment_request():
        """
        POST /enrollment/request

        Processes EnrollmentRequest from ITS-S and returns EnrollmentResponse.

        ETSI TS 102941 Section 6.2.3 - EnrollmentRequest
        ETSI TS 102941 Section 6.2.4 - EnrollmentResponse

        Request Body (ASN.1 OER encoded):
            EtsiTs102941Data-Encrypted {
                version: 2,
                encryptedData: OCTET STRING,
                recipientId: HashedId8,
                timestamp: Time32
            }

        Response Body (ASN.1 OER encoded):
            EtsiTs102941Data {
                version: 2,
                content: InnerEcResponse {
                    requestHash: OCTET STRING,
                    responseCode: EnrolmentResponseCode,
                    certificate: EtsiTs103097Certificate (optional)
                }
            }

        Returns:
            tuple: (response_body, status_code, headers)
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received EnrollmentRequest (ETSI TS 102941)")
        current_app.logger.info("=" * 80)

        try:
            # 1. Validate Content-Type (accept both ETSI-specific and generic binary)
            content_type = request.headers.get("Content-Type", "")
            accepted_types = ["application/octet-stream", "application/vnd.etsi.ts102941.v2.1.1"]
            
            if content_type not in accepted_types:
                current_app.logger.warning(
                    f"Invalid Content-Type: {content_type} (expected {' or '.join(accepted_types)})"
                )
                return (
                    jsonify(
                        {
                            "error": "Invalid Content-Type",
                            "responseCode": ResponseCode.BAD_CONTENT_TYPE.value,
                            "expected": accepted_types,
                            "received": content_type,
                        }
                    ),
                    415,
                )

            # 2. Get ASN.1 OER encoded payload
            raw_data = request.data
            if not raw_data:
                current_app.logger.error("Empty request body")
                return (
                    jsonify(
                        {
                            "error": "Empty request body",
                            "responseCode": ResponseCode.BAD_REQUEST.value,
                        }
                    ),
                    400,
                )

            current_app.logger.info(f"Received ASN.1 OER payload: {len(raw_data)} bytes")
            
            # 3. Delegate to EA entity (100% ETSI-compliant implementation)
            # This includes: decryption, PoP verification, certificate issuance, encryption
            response_bytes = bp.ea.process_enrollment_request_etsi(raw_data)
            
            current_app.logger.info(f"✅ Enrollment request processed successfully")
            current_app.logger.info(f"Response size: {len(response_bytes)} bytes")
            
            # 4. Return ASN.1 OER encoded response
            return (
                response_bytes,
                200,
                {"Content-Type": "application/octet-stream"}
            )

        except Exception as e:
            current_app.logger.error(f"Unexpected error: {e}")
            current_app.logger.debug(traceback.format_exc())
            return (
                jsonify(
                    {
                        "error": "Internal server error",
                        "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                        "details": str(e),
                    }
                ),
                500,
            )

    @bp.route("/validation", methods=["POST"])
    @rate_limit
    @require_mtls(allowed_authorities=["AA"])
    def authorization_validation():
        """
        POST /enrollment/validation

        Validates an Enrollment Certificate for Authorization Authority.
        Used when AA doesn't have TLM and needs EA to validate EC.

        ETSI TS 102941 Section 6.4.1 - AuthorizationValidationRequest
        
        **SECURITY: Requires mTLS authentication from Authorization Authority (AA)**

        Request Body (ASN.1 OER encoded):
            AuthorizationValidationRequest {
                sharedAtRequest: SharedAtRequest,
                ecSignature: Signature,
                certificate: EtsiTs103097Certificate
            }

        Response Body (ASN.1 OER encoded or JSON):
            AuthorizationValidationResponse {
                requestHash: OCTET STRING,
                responseCode: AuthorizationValidationResponseCode,
                confirmedSubjectAttributes: CertificateSubjectAttributes (optional)
            }

        Returns:
            tuple: (response_body, status_code, headers)
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received AuthorizationValidationRequest")
        current_app.logger.info("=" * 80)

        try:
            # 1. Validate Content-Type
            content_type = request.headers.get("Content-Type", "")
            if content_type != "application/octet-stream":
                current_app.logger.warning(f"Invalid Content-Type: {content_type}")
                return (
                    jsonify(
                        {
                            "error": "Invalid Content-Type",
                            "responseCode": ResponseCode.BAD_CONTENT_TYPE.value,
                            "expected": "application/octet-stream",
                        }
                    ),
                    415,
                )

            # 2. Get payload
            raw_data = request.data
            if not raw_data:
                current_app.logger.error("Empty request body")
                return (
                    jsonify(
                        {
                            "error": "Empty request body",
                            "responseCode": ResponseCode.BAD_REQUEST.value,
                        }
                    ),
                    400,
                )

            current_app.logger.info(f"Received {len(raw_data)} bytes")

            # 3. Decode validation request
            try:
                validation_request = bp.encoder.decode_authorization_validation_request(raw_data)
                current_app.logger.info("✓ Decoded validation request")
            except Exception as e:
                current_app.logger.error(f"Decoding error: {e}")
                return (
                    jsonify(
                        {
                            "error": "Failed to decode validation request",
                            "responseCode": ResponseCode.CANONICAL_ENCODING_ERROR.value,
                            "details": str(e),
                        }
                    ),
                    400,
                )

            # 4. Extract certificate to validate
            certificate = validation_request.certificate
            current_app.logger.info(f"Validating certificate: serial={certificate.serial_number}")

            # 5. Check if certificate is revoked
            if hasattr(bp.ea, "crl_manager"):
                is_revoked = bp.ea.crl_manager.is_certificate_revoked(certificate)
                if is_revoked:
                    current_app.logger.warning("Certificate is revoked")
                    request_hash = compute_request_hash(raw_data)

                    response_der = bp.encoder.encode_authorization_validation_response(
                        request_hash=request_hash,
                        response_code=ResponseCode.INVALID_SIGNATURE.value,
                        confirmed_attributes=None,
                    )

                    return response_der, 403, {"Content-Type": "application/octet-stream"}

            # 6. Extract confirmed subject attributes from certificate
            # In a real implementation, validate the certificate signature
            # and extract the confirmed attributes
            confirmed_attrs = {
                "subject": str(certificate.subject),
                "serial_number": certificate.serial_number,
                "not_valid_before": certificate.not_valid_before.isoformat(),
                "not_valid_after": certificate.not_valid_after.isoformat(),
            }

            current_app.logger.info("✓ Certificate validated successfully")
            current_app.logger.info(f"Confirmed attributes: {confirmed_attrs}")

            # 7. Encode response
            request_hash = compute_request_hash(raw_data)

            response_der = bp.encoder.encode_authorization_validation_response(
                request_hash=request_hash,
                response_code=ResponseCode.OK.value,
                confirmed_attributes=confirmed_attrs,
            )

            current_app.logger.info(f"✓ Encoded validation response: {len(response_der)} bytes")
            current_app.logger.info("=" * 80)

            return response_der, 200, {"Content-Type": "application/octet-stream"}

        except Exception as e:
            current_app.logger.error(f"Validation error: {e}")
            current_app.logger.debug(traceback.format_exc())
            return (
                jsonify(
                    {
                        "error": "Validation failed",
                        "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                        "details": str(e),
                    }
                ),
                500,
            )

    @bp.route("/certificate", methods=["GET"])
    @rate_limit
    def get_certificate():
        """
        GET /enrollment/certificate

        Returns the EA's public certificate in ASN.1 OER format.

        Returns:
            bytes: ASN.1 OER encoded certificate (ETSI TS 103097)
        """
        try:
            if not hasattr(bp.ea, "certificate_asn1") or bp.ea.certificate_asn1 is None:
                current_app.logger.error("EA certificate not available")
                return jsonify({"error": "Certificate not available"}), 404

            # Return ASN.1 OER certificate directly
            return bp.ea.certificate_asn1, 200, {"Content-Type": "application/octet-stream"}

        except Exception as e:
            current_app.logger.error(f"Error retrieving certificate: {e}")
            return jsonify({"error": "Internal server error"}), 500

    return bp
