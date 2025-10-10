"""
Simplified Enrollment Blueprint (JSON API for testing)

⚠️  WARNING: FOR DEVELOPMENT/TESTING ONLY! ⚠️

This blueprint provides JSON-based endpoints as an alternative to the
standard ETSI TS 102941 ASN.1 OER encoded endpoints. Use this for:
- Manual testing with Swagger UI
- Development and debugging
- Integration testing

For production, use the standard ASN.1 OER endpoints in enrollment_bp.py

Author: SecureRoad PKI Project
Date: October 2025
"""

from flask import Blueprint, current_app, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from api.middleware import optional_auth, rate_limit


def create_simple_enrollment_blueprint(ea_instance):
    """
    Create Flask blueprint for simplified JSON-based Enrollment endpoints.
    
    ⚠️ FOR TESTING ONLY - NOT ETSI COMPLIANT ⚠️
    """
    bp = Blueprint("enrollment_simple", __name__)
    bp.ea = ea_instance

    # OPTIONS handler for CORS preflight
    @bp.route("/request/simple", methods=["OPTIONS"])
    def simple_enrollment_request_options():
        """Handle CORS preflight for enrollment request"""
        return "", 204

    @bp.route("/request/simple", methods=["POST"])
    @rate_limit
    @optional_auth
    def simple_enrollment_request():
        """
        POST /enrollment/request/simple
        
        ⚠️ TESTING ONLY - Simplified JSON-based enrollment request.
        
        This is NOT the standard ETSI TS 102941 endpoint!
        For production, use POST /api/enrollment/request (ASN.1 OER).
        
        Request Body (JSON):
            {
                "its_id": "VEHICLE_001",
                "public_key": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
                "requested_attributes": {
                    "country": "IT",
                    "organization": "SecureRoad",
                    "validity_days": 365
                }
            }
        
        Response Body (JSON):
            {
                "success": true,
                "certificate": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
                "serial_number": "123456789...",
                "valid_from": "2025-10-09T15:30:00Z",
                "valid_until": "2026-10-09T15:30:00Z"
            }
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received SIMPLE EnrollmentRequest (JSON)")
        current_app.logger.info("⚠️  FOR TESTING ONLY - NOT ETSI COMPLIANT")
        current_app.logger.info("=" * 80)
        
        try:
            # 1. Parse JSON request
            if not request.is_json:
                return jsonify({
                    "error": "Invalid Content-Type",
                    "message": "Expected application/json",
                    "received": request.headers.get("Content-Type", "")
                }), 415
            
            data = request.get_json()
            current_app.logger.info(f"Request data: {data}")
            
            # 2. Validate required fields
            required_fields = ["its_id", "public_key"]
            missing = [f for f in required_fields if f not in data]
            if missing:
                return jsonify({
                    "error": "Missing required fields",
                    "missing": missing
                }), 400
            
            its_id = data["its_id"]
            public_key_pem = data["public_key"]
            attributes = data.get("requested_attributes", {})
            
            current_app.logger.info(f"ITS ID: {its_id}")
            current_app.logger.info(f"Requested attributes: {attributes}")
            
            # 3. Parse public key
            try:
                public_key = serialization.load_pem_public_key(
                    public_key_pem.encode('utf-8'),
                    backend=default_backend()
                )
                current_app.logger.info("✅ Public key parsed successfully")
            except Exception as e:
                current_app.logger.error(f"Failed to parse public key: {e}")
                return jsonify({
                    "error": "Invalid public key",
                    "message": str(e)
                }), 400
            
            # 4. Extract attributes (for logging only, EA uses hardcoded values)
            country = attributes.get("country", "IT")
            organization = attributes.get("organization", "ITS-S")
            validity_days = attributes.get("validity_days", 365)
            
            current_app.logger.info(f"Requested attributes: country={country}, org={organization}, validity={validity_days} days")
            current_app.logger.info("⚠️  Note: EA currently uses hardcoded values (Country=IT, Org=ITS-S, validity=365 days)")
            
            # 5. Issue Enrollment Certificate
            current_app.logger.info(f"Issuing EC for ITS-S: {its_id}")
            
            try:
                # Call EA method with correct signature
                certificate = bp.ea.issue_enrollment_certificate(
                    its_id=its_id,
                    public_key=public_key,
                    attributes=attributes  # Pass as dict, currently unused by EA
                )
                
                # 6. Serialize certificate to PEM
                cert_pem = certificate.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode('utf-8')
                
                # 7. Extract certificate info
                serial = certificate.serial_number
                not_before = certificate.not_valid_before_utc.isoformat()
                not_after = certificate.not_valid_after_utc.isoformat()
                
                current_app.logger.info(f"✅ EC issued successfully!")
                current_app.logger.info(f"Serial: {serial}")
                current_app.logger.info(f"Valid: {not_before} to {not_after}")
                
                # Increment metrics counter for issued certificates
                from utils.metrics import get_metrics_collector
                metrics = get_metrics_collector()
                metrics.increment_counter('enrollment_certificates_issued')
                
                # 8. Return response
                return jsonify({
                    "success": True,
                    "message": "Enrollment Certificate issued successfully",
                    "certificate": cert_pem,
                    "certificate_info": {
                        "serial_number": str(serial),
                        "subject": {
                            "country": country,
                            "organization": organization,
                            "common_name": its_id
                        },
                        "validity": {
                            "not_before": not_before,
                            "not_after": not_after,
                            "days": validity_days
                        },
                        "issuer": bp.ea.ea_id  # ea_id già contiene il prefisso "EA_"
                    }
                }), 200
                
            except Exception as e:
                current_app.logger.error(f"Failed to issue EC: {e}")
                import traceback
                current_app.logger.error(traceback.format_exc())
                return jsonify({
                    "error": "Failed to issue certificate",
                    "message": str(e)
                }), 500
        
        except Exception as e:
            current_app.logger.error(f"Unexpected error: {e}")
            import traceback
            current_app.logger.error(traceback.format_exc())
            return jsonify({
                "error": "Internal server error",
                "message": str(e)
            }), 500

    @bp.route("/publish-crl", methods=["POST"])
    def publish_crl():
        """
        POST /enrollment/publish-crl
        
        Force publication of CRL (for testing purposes).
        
        Request Body (JSON):
            {
                "validity_days": 30  # Optional, default 30
            }
        
        Response Body (JSON):
            {
                "success": true,
                "message": "CRL published successfully",
                "crl_path": "/path/to/crl/file",
                "next_update": "2025-11-09T..."
            }
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Force CRL Publication")
        current_app.logger.info("=" * 80)
        
        try:
            data = request.get_json() if request.is_json else {}
            validity_days = data.get("validity_days", 30)
            
            # Check if EA has CRL manager
            if not hasattr(bp.ea, 'crl_manager'):
                return jsonify({
                    "error": "CRL manager not available",
                    "message": "EA does not have CRL manager configured"
                }), 500
            
            # Publish CRL
            crl_path = bp.ea.publish_crl(validity_days=validity_days)
            
            current_app.logger.info(f"✅ CRL published: {crl_path}")
            
            from datetime import datetime, timedelta
            next_update = datetime.utcnow() + timedelta(days=validity_days)
            
            return jsonify({
                "success": True,
                "message": "CRL published successfully",
                "crl_path": str(crl_path),
                "next_update": next_update.isoformat(),
                "validity_days": validity_days
            }), 200
            
        except Exception as e:
            current_app.logger.error(f"Failed to publish CRL: {e}")
            import traceback
            current_app.logger.error(traceback.format_exc())
            return jsonify({
                "error": "Failed to publish CRL",
                "message": str(e)
            }), 500

    return bp
