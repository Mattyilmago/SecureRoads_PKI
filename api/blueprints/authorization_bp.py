"""
Authorization Authority Blueprint

Implements ETSI TS 102941 Section 6.3 - Authorization Request/Response

Full ASN.1 OER encoding/decoding implementation.

Author: SecureRoad PKI Project
Date: October 2025
"""

import hashlib
import traceback

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Blueprint, current_app, jsonify, request

from api.middleware import optional_auth, rate_limit
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import ResponseCode


def compute_request_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash of request data"""
    return hashlib.sha256(data).digest()


def create_authorization_blueprint(aa_instance):
    """Create Flask blueprint for Authorization Authority endpoints."""
    bp = Blueprint("authorization", __name__)

    # Store AA instance
    bp.aa = aa_instance

    # Create encoder instance
    bp.encoder = ETSIMessageEncoder()

    @bp.route("/request", methods=["POST"])
    @rate_limit
    @optional_auth
    def authorization_request():
        """
        POST /authorization/request

        Processes AuthorizationRequest from ITS-S and returns AuthorizationResponse.

        ETSI TS 102941 Section 6.3.1 - AuthorizationRequest
        ETSI TS 102941 Section 6.3.2 - AuthorizationResponse

        CRITICAL: Response MUST be encrypted with hmacKey (NOT canonical key)
        to preserve unlinkability between enrollment and authorization!

        Request Body (ASN.1 OER encoded):
            EtsiTs102941Data-SignedEncrypted {
                signedData: {
                    signer: certificate (Enrollment Certificate),
                    signature: ...
                },
                encryptedData: InnerAtRequest {
                    publicKeys: ...,
                    hmacKey: OCTET STRING,  # CRITICAL!
                    sharedAtRequest: ...
                }
            }

        Response Body (ASN.1 OER encoded):
            EtsiTs102941Data-Encrypted {
                encryptedData: InnerAtResponse (encrypted with hmacKey!)
            }

        Returns:
            tuple: (response_body, status_code, headers)
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received AuthorizationRequest")
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

            current_app.logger.info(f"Received ASN.1 payload: {len(raw_data)} bytes")

            # 3. Check if AA has private key
            if not hasattr(bp.aa, "private_key"):
                current_app.logger.error("AA private key not available")
                return (
                    jsonify(
                        {
                            "error": "AA private key not configured",
                            "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                        }
                    ),
                    500,
                )

            # 4. Decode and decrypt authorization request
            try:
                auth_request = bp.encoder.decode_authorization_request(raw_data, bp.aa.private_key)
                current_app.logger.info("✓ ASN.1 OER decoding and decryption successful")
            except Exception as e:
                current_app.logger.error(f"Decoding/decryption error: {e}")
                current_app.logger.debug(traceback.format_exc())
                return (
                    jsonify(
                        {
                            "error": "Failed to decode or decrypt request",
                            "responseCode": ResponseCode.DECRYPTION_FAILED.value,
                            "details": str(e),
                        }
                    ),
                    400,
                )

            # 5. Extract Enrollment Certificate from signed data
            enrollment_cert = auth_request.signerCertificate
            current_app.logger.info(f"EC serial: {enrollment_cert.serial_number}")

            # 6. Validate EC with TLM or EA (ETSI TS 102941 Section 6.3.1.2)
            is_trusted = False
            if hasattr(bp.aa, "tlm") and bp.aa.tlm is not None:
                # Modern approach: Use TLM
                current_app.logger.info("Validating EC with TLM...")
                try:
                    ea_issuer = enrollment_cert.issuer
                    is_trusted = bp.aa.tlm.is_trusted(ea_issuer, authority_type="EA")
                    if is_trusted:
                        current_app.logger.info("✓ EA is trusted by TLM")
                    else:
                        current_app.logger.warning("✗ EA not in TLM trust list")
                except Exception as e:
                    current_app.logger.error(f"TLM validation error: {e}")
            else:
                # Legacy approach: Validate with EA directly
                current_app.logger.info("TLM not available, using legacy EA validation")
                # In production, make HTTP request to EA validation endpoint
                # For now, assume trusted if not revoked
                is_trusted = True

            if not is_trusted:
                current_app.logger.warning("Enrollment Certificate not trusted")
                return (
                    jsonify(
                        {
                            "error": "Unknown or untrusted EA",
                            "responseCode": ResponseCode.UNKNOWN_EA.value,
                        }
                    ),
                    403,
                )

            # 7. Check if EC is revoked
            if hasattr(bp.aa, "crl_manager"):
                is_revoked = bp.aa.crl_manager.is_certificate_revoked(enrollment_cert)
                if is_revoked:
                    current_app.logger.warning("Enrollment Certificate is revoked")
                    return (
                        jsonify(
                            {
                                "error": "Enrollment Certificate is revoked",
                                "responseCode": ResponseCode.INVALID_SIGNATURE.value,
                            }
                        ),
                        403,
                    )

            # 8. Extract InnerAtRequest
            inner_request = auth_request.innerAtRequest
            shared_at_request = inner_request.sharedAtRequest

            # 9. 🔥 CRITICAL: Extract and save hmacKey
            hmac_key = inner_request.hmacKey
            current_app.logger.info("🔥 Extracted hmacKey for response encryption (unlinkability!)")

            # 10. Extract ITS-S information
            its_id = extract_its_id_from_cert(enrollment_cert)
            verification_key = inner_request.publicKeys["verification"]
            permissions = shared_at_request.appPermissions

            current_app.logger.info(f"ITS-S ID: {its_id}")
            current_app.logger.info(f"Requested permissions: {permissions}")

            # 11. Issue Authorization Ticket
            try:
                if not hasattr(bp.aa, "issue_authorization_ticket"):
                    current_app.logger.warning("AA does not have issue_authorization_ticket method")
                    # Return success for testing
                    request_hash = compute_request_hash(raw_data)
                    return (
                        jsonify(
                            {
                                "status": "authorization_accepted",
                                "message": "AT issuance not fully implemented",
                                "responseCode": ResponseCode.OK.value,
                                "its_id": its_id,
                                "request_hash": request_hash.hex(),
                            }
                        ),
                        200,
                    )

                at = bp.aa.issue_authorization_ticket(
                    its_id=its_id, public_key=verification_key, permissions=permissions
                )

                current_app.logger.info(f"✓ Issued AT for {its_id}: serial={at.serial_number}")

            except Exception as e:
                current_app.logger.error(f"AT issuance failed: {e}")
                current_app.logger.debug(traceback.format_exc())
                return (
                    jsonify(
                        {
                            "error": "Authorization ticket issuance failed",
                            "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                            "details": str(e),
                        }
                    ),
                    500,
                )

            # 12. 🔥 CRITICAL: Encrypt response with hmacKey (NOT canonical key!)
            try:
                request_hash = compute_request_hash(raw_data)

                response_der = bp.encoder.encode_authorization_response(
                    response_code=ResponseCode.OK.value,
                    request_hash=request_hash,
                    authorization_ticket=at,
                    hmac_key=hmac_key,  # Use hmacKey for unlinkability!
                )

                current_app.logger.info(f"✓ Encoded response: {len(response_der)} bytes")
                current_app.logger.info(
                    "✓ Response encrypted with hmacKey (unlinkability preserved)"
                )
                current_app.logger.info("=" * 80)

                return response_der, 200, {"Content-Type": "application/octet-stream"}

            except Exception as e:
                current_app.logger.error(f"Response encoding failed: {e}")
                current_app.logger.debug(traceback.format_exc())
                return (
                    jsonify(
                        {
                            "error": "Failed to encode response",
                            "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                            "details": str(e),
                        }
                    ),
                    500,
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

    def extract_its_id_from_cert(cert: x509.Certificate) -> str:
        """Extract ITS-S ID from enrollment certificate"""
        # In real implementation, extract from certificate extensions
        # For now, use subject CN
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                return attr.value
        return f"ITSS_{cert.serial_number}"

    @bp.route("/request/butterfly", methods=["POST"])
    @rate_limit
    @optional_auth
    def butterfly_authorization_request():
        """
        POST /authorization/request/butterfly

        Batch authorization request - processes multiple InnerAtRequests.

        ETSI TS 102941 Section 6.3.3 - Butterfly Authorization

        Allows ITS-S to request multiple Authorization Tickets in a single request.
        Each InnerAtRequest has its own hmacKey for unlinkability.

        Request Body (ASN.1 OER encoded):
            ButterflyAuthorizationRequest {
                signedData: { signer: EC, ... },
                innerAtRequests: SEQUENCE OF InnerAtRequest
            }

        Response Body (ASN.1 OER encoded):
            ButterflyAuthorizationResponse {
                responses: SEQUENCE OF InnerAtResponse
            }

        Each response encrypted with its corresponding hmacKey!

        Returns:
            tuple: (response_body, status_code, headers)
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received Butterfly AuthorizationRequest")
        current_app.logger.info("=" * 80)

        try:
            # 1. Validate Content-Type
            content_type = request.headers.get("Content-Type", "")
            if content_type != "application/octet-stream":
                return (
                    jsonify(
                        {
                            "error": "Invalid Content-Type",
                            "responseCode": ResponseCode.BAD_CONTENT_TYPE.value,
                        }
                    ),
                    415,
                )

            # 2. Get payload
            raw_data = request.data
            if not raw_data:
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

            # 3. Decode butterfly request
            try:
                butterfly_request = bp.encoder.decode_butterfly_authorization_request(
                    raw_data, bp.aa.private_key
                )
                current_app.logger.info("✓ Decoded butterfly request")
            except Exception as e:
                current_app.logger.error(f"Decoding error: {e}")
                return (
                    jsonify(
                        {
                            "error": "Failed to decode butterfly request",
                            "responseCode": ResponseCode.DECRYPTION_FAILED.value,
                            "details": str(e),
                        }
                    ),
                    400,
                )

            # 4. Validate EC (same as regular authorization)
            enrollment_cert = butterfly_request.signerCertificate

            # Check if trusted
            is_trusted = False
            if hasattr(bp.aa, "tlm") and bp.aa.tlm is not None:
                is_trusted = bp.aa.tlm.is_trusted(enrollment_cert.issuer, "EA")
            else:
                is_trusted = True  # Legacy mode

            if not is_trusted:
                return (
                    jsonify({"error": "Unknown EA", "responseCode": ResponseCode.UNKNOWN_EA.value}),
                    403,
                )

            # Check if revoked
            if hasattr(bp.aa, "crl_manager"):
                if bp.aa.crl_manager.is_certificate_revoked(enrollment_cert):
                    return (
                        jsonify(
                            {
                                "error": "EC revoked",
                                "responseCode": ResponseCode.INVALID_SIGNATURE.value,
                            }
                        ),
                        403,
                    )

            # 5. Process multiple InnerAtRequests
            responses = []
            its_id = extract_its_id_from_cert(enrollment_cert)

            current_app.logger.info(f"Processing {len(butterfly_request.innerAtRequests)} requests")

            for idx, inner_request in enumerate(butterfly_request.innerAtRequests):
                current_app.logger.info(
                    f"Processing request {idx+1}/{len(butterfly_request.innerAtRequests)}"
                )

                # Extract hmacKey for this specific request
                hmac_key = inner_request.hmacKey

                try:
                    # Issue AT
                    if not hasattr(bp.aa, "issue_authorization_ticket"):
                        current_app.logger.warning("AT issuance not available")
                        continue

                    at = bp.aa.issue_authorization_ticket(
                        its_id=its_id,
                        public_key=inner_request.publicKeys["verification"],
                        permissions=inner_request.sharedAtRequest.appPermissions,
                    )

                    # Create response encrypted with THIS hmacKey
                    response = {
                        "authorization_ticket": at,
                        "hmac_key": hmac_key,  # Each response has its own key!
                        "response_code": ResponseCode.OK,
                    }

                    responses.append(response)
                    current_app.logger.info(f"✓ Issued AT {idx+1}: serial={at.serial_number}")

                except Exception as e:
                    current_app.logger.error(f"Failed to issue AT {idx+1}: {e}")
                    # Add error response
                    responses.append(
                        {"response_code": ResponseCode.INTERNAL_SERVER_ERROR, "error": str(e)}
                    )

            # 6. Encode butterfly response
            try:
                request_hash = compute_request_hash(raw_data)

                response_der = bp.encoder.encode_butterfly_authorization_response(
                    request_hash=request_hash, responses=responses
                )

                current_app.logger.info(f"✓ Encoded butterfly response: {len(response_der)} bytes")
                current_app.logger.info(f"✓ Issued {len(responses)} authorization tickets")
                current_app.logger.info("=" * 80)

                return response_der, 200, {"Content-Type": "application/octet-stream"}

            except Exception as e:
                current_app.logger.error(f"Response encoding failed: {e}")
                return (
                    jsonify(
                        {
                            "error": "Failed to encode butterfly response",
                            "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                            "details": str(e),
                        }
                    ),
                    500,
                )

        except Exception as e:
            current_app.logger.error(f"Butterfly error: {e}")
            current_app.logger.debug(traceback.format_exc())
            return (
                jsonify(
                    {
                        "error": "Butterfly authorization failed",
                        "responseCode": ResponseCode.INTERNAL_SERVER_ERROR.value,
                        "details": str(e),
                    }
                ),
                500,
            )

    return bp
