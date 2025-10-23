"""
Authorization Authority Blueprint

Implements ETSI TS 102941 Section 6.3 - Authorization Request/Response

Full ASN.1 OER encoding/decoding implementation.

Author: SecureRoad PKI Project
Date: October 2025
"""

import traceback

from flask import Blueprint, current_app, jsonify, request

from api.middleware import optional_auth, rate_limit
from protocols.messages.encoder import MessageEncoder
from protocols.core.types import ResponseCode
from utils.metrics import get_metrics_collector


def response_code_value(code: ResponseCode) -> int:
    """Convert ResponseCode enum to integer value for JSON"""
    return code.value


def create_authorization_blueprint(aa_instance):
    """Create Flask blueprint for Authorization Authority endpoints."""
    bp = Blueprint("authorization", __name__)

    # Store AA instance
    bp.aa = aa_instance

    # Create encoder instance (ETSI TS 102941 compliant)
    bp.encoder = MessageEncoder()

    @bp.route("/request", methods=["POST"])
    @rate_limit
    @optional_auth
    def authorization_request():
        """
        POST /authorization/request

        Processes AuthorizationRequest from ITS-S and returns AuthorizationResponse.

        ETSI TS 102941 Section 6.3.1 - AuthorizationRequest
        ETSI TS 102941 Section 6.3.2 - AuthorizationResponse

        Request Body (ASN.1 OER encoded):
            EtsiTs102941Data-SignedEncrypted

        Response Body (ASN.1 OER encoded):
            EtsiTs102941Data-Encrypted

        Returns:
            tuple: (response_body, status_code, headers)
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received AuthorizationRequest (ETSI TS 102941)")
        current_app.logger.info("=" * 80)

        try:
            # Collect metrics
            metrics = get_metrics_collector()
            metrics.increment_counter("authorization_requests_total")

            # Validate Content-Type (accept both ETSI-specific and generic binary)
            content_type = request.headers.get("Content-Type", "")
            current_app.logger.info(f"Content-Type: {content_type}")
            
            accepted_types = ["application/octet-stream", "application/vnd.etsi.ts102941.v2.1.1"]
            if content_type not in accepted_types:
                current_app.logger.error(f"Invalid Content-Type: {content_type}")
                metrics.increment_counter("authorization_requests_failed")
                return (
                    jsonify({
                        "error": "Invalid Content-Type",
                        "expected": accepted_types,
                        "received": content_type,
                        "responseCode": ResponseCode.BAD_REQUEST.value,
                    }),
                    415,
                    {"Content-Type": "application/json"},
                )

            # Read request body
            request_bytes = request.get_data()
            current_app.logger.info(f"Request size: {len(request_bytes)} bytes")

            if len(request_bytes) == 0:
                current_app.logger.error("Empty request body")
                metrics.increment_counter("authorization_requests_failed")
                return (
                    jsonify({
                        "error": "Empty request body",
                        "responseCode": ResponseCode.BAD_REQUEST.value,
                    }),
                    400,
                    {"Content-Type": "application/json"},
                )

            # Delegate processing to AA entity (ETSI TS 102941 compliant)
            current_app.logger.info("Delegating to AA.process_authorization_request_etsi()...")
            response_bytes = bp.aa.process_authorization_request_etsi(request_bytes)

            current_app.logger.info(f"✅ AuthorizationResponse created: {len(response_bytes)} bytes")
            metrics.increment_counter("authorization_requests_success")

            # Return ASN.1 OER encoded response
            return (
                response_bytes,
                200,
                {
                    "Content-Type": "application/vnd.etsi.ts102941.v2.1.1",
                    "Content-Length": str(len(response_bytes)),
                },
            )

        except ValueError as e:
            current_app.logger.error(f"Validation error: {e}")
            metrics.increment_counter("authorization_requests_failed")
            return (
                jsonify({
                    "error": str(e),
                    "responseCode": ResponseCode.BAD_REQUEST.value,
                }),
                400,
                {"Content-Type": "application/json"},
            )

        except Exception as e:
            current_app.logger.error(f"Internal error: {e}")
            current_app.logger.error(traceback.format_exc())
            metrics.increment_counter("authorization_requests_failed")
            return (
                jsonify({
                    "error": "Internal server error",
                    "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                }),
                500,
                {"Content-Type": "application/json"},
            )

    @bp.route("/request/butterfly", methods=["POST"])
    @rate_limit
    @optional_auth
    def butterfly_authorization_request():
        """
        POST /authorization/request/butterfly

        Processes ButterflyAuthorizationRequest from ITS-S and returns ButterflyAuthorizationResponse.

        ETSI TS 102941 Section 6.3.3 - Butterfly Authorization
        Butterfly mode allows requesting N Authorization Tickets in a single request.

        Request Body (ASN.1 OER encoded):
            EtsiTs103097Data-SignedAndEncrypted {
                SignedData {
                    signer: Enrollment Certificate
                    signature: EC signature (Proof of Possession)
                    payload: EncryptedData {
                        ciphertext: ButterflyAuthorizationRequest {
                            sharedAtRequest: SharedAtRequest,
                            innerAtRequests: SEQUENCE OF InnerAtRequest
                        }
                    }
                }
            }

        Response Body (ASN.1 OER encoded):
            EtsiTs102941Data-Encrypted (ButterflyAuthorizationResponse)

        Returns:
            tuple: (response_body, status_code, headers)
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("🦋 Received ButterflyAuthorizationRequest (ETSI TS 102941)")
        current_app.logger.info("=" * 80)

        try:
            # Collect metrics
            metrics = get_metrics_collector()
            metrics.increment_counter("butterfly_authorization_requests_total")

            # Validate Content-Type (accept both ETSI-specific and generic binary)
            content_type = request.headers.get("Content-Type", "")
            current_app.logger.info(f"Content-Type: {content_type}")
            
            accepted_types = ["application/octet-stream", "application/vnd.etsi.ts102941.v2.1.1"]
            if content_type not in accepted_types:
                current_app.logger.error(f"Invalid Content-Type: {content_type}")
                metrics.increment_counter("butterfly_authorization_requests_failed", {"reason": "invalid_content_type"})
                return (
                    jsonify({
                        "error": "Invalid Content-Type",
                        "expected": accepted_types,
                        "received": content_type,
                        "responseCode": ResponseCode.BAD_REQUEST.value,
                    }),
                    415,
                    {"Content-Type": "application/json"},
                )

            # Read request body
            request_bytes = request.get_data()
            current_app.logger.info(f"Request size: {len(request_bytes)} bytes")

            if len(request_bytes) == 0:
                current_app.logger.error("Empty request body")
                metrics.increment_counter("butterfly_authorization_requests_failed", {"reason": "empty_body"})
                return (
                    jsonify({
                        "error": "Empty request body",
                        "responseCode": ResponseCode.BAD_REQUEST.value,
                    }),
                    400,
                    {"Content-Type": "application/json"},
                )

            # Delegate processing to AA entity (ETSI TS 102941 compliant)
            current_app.logger.info("Delegating to AA.process_butterfly_authorization_request_etsi()...")
            response_bytes = bp.aa.process_butterfly_authorization_request_etsi(request_bytes)

            current_app.logger.info(f"✅ ButterflyAuthorizationResponse created: {len(response_bytes)} bytes")
            metrics.increment_counter("butterfly_authorization_requests_success")

            # Return ASN.1 OER encoded response
            return (
                response_bytes,
                200,
                {
                    "Content-Type": "application/vnd.etsi.ts102941.v2.1.1",
                    "Content-Length": str(len(response_bytes)),
                },
            )

        except ValueError as e:
            current_app.logger.error(f"Validation error: {e}")
            metrics.increment_counter("butterfly_authorization_requests_failed", {"reason": "validation_error"})
            return (
                jsonify({
                    "error": str(e),
                    "responseCode": ResponseCode.BAD_REQUEST.value,
                }),
                400,
                {"Content-Type": "application/json"},
            )

        except Exception as e:
            current_app.logger.error(f"Internal error: {e}")
            current_app.logger.error(traceback.format_exc())
            metrics.increment_counter("butterfly_authorization_requests_failed", {"reason": "internal_error"})
            return (
                jsonify({
                    "error": "Internal server error",
                    "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                }),
                500,
                {"Content-Type": "application/json"},
            )

    @bp.route("/certificate", methods=["GET"])
    def get_aa_certificate():
        """
        GET /authorization/certificate

        Returns AA certificate in ASN.1 OER format.

        Returns:
            ASN.1 OER encoded AA certificate (binary)
        """
        try:
            current_app.logger.info("Received request for AA certificate")
            
            # Get AA certificate in ASN.1 OER format
            aa_cert_asn1 = bp.aa.certificate_asn1
            
            if not aa_cert_asn1:
                current_app.logger.error("AA certificate not available")
                return jsonify({"error": "AA certificate not available"}), 500
            
            current_app.logger.info(f"Returning AA certificate: {len(aa_cert_asn1)} bytes")
            
            return (
                aa_cert_asn1,
                200,
                {
                    "Content-Type": "application/octet-stream",
                    "Content-Disposition": f'attachment; filename="aa_{bp.aa.aa_id}_certificate.oer"'
                }
            )

        except Exception as e:
            current_app.logger.error(f"Error getting AA certificate: {e}")
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500

    @bp.route("/status", methods=["GET"])
    @optional_auth
    def status():
        """
        GET /authorization/status

        Returns AA status and statistics.

        Returns:
            JSON response with AA status
        """
        try:
            return jsonify({
                "status": "operational",
                "aa_id": bp.aa.aa_id,
                "issued_at_count": len(bp.aa.issued_ats),
                "revoked_at_count": len(bp.aa.revoked_ats),
                "uptime": "running"
            }), 200

        except Exception as e:
            current_app.logger.error(f"Error getting status: {e}")
            return jsonify({"error": str(e)}), 500

    return bp
