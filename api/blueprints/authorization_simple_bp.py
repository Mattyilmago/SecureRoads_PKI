"""
Simplified Authorization Blueprint (JSON API for testing)

⚠️  WARNING: FOR DEVELOPMENT/TESTING ONLY! ⚠️

This blueprint provides JSON-based endpoints as an alternative to the
standard ETSI TS 102941 ASN.1 OER encoded endpoints. Use this for:
- Manual testing from dashboard
- Development and debugging
- Integration testing

For production, use the standard ASN.1 OER endpoints in authorization_bp.py

Author: SecureRoad PKI Project
Date: October 2025
"""

from flask import Blueprint, current_app, jsonify, request
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import secrets

from api.middleware import optional_auth, rate_limit


def create_simple_authorization_blueprint(aa_instance):
    """
    Create Flask blueprint for simplified JSON-based Authorization endpoints.
    
    ⚠️ FOR TESTING ONLY - NOT ETSI COMPLIANT ⚠️
    """
    bp = Blueprint("authorization_simple", __name__)
    bp.aa = aa_instance

    # OPTIONS handler for CORS preflight
    @bp.route("/request/simple", methods=["OPTIONS"])
    def simple_authorization_request_options():
        """Handle CORS preflight for authorization request"""
        return "", 204

    @bp.route("/request/simple", methods=["POST"])
    @rate_limit
    @optional_auth
    def simple_authorization_request():
        """
        POST /authorization/request/simple
        
        ⚠️ TESTING ONLY - Simplified JSON-based authorization request.
        
        This is NOT the standard ETSI TS 102941 endpoint!
        For production, use POST /api/authorization/request (ASN.1 OER).
        
        Request Body (JSON):
            {
                "its_id": "VEHICLE_001",
                "enrollment_certificate": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
                "public_key": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
                "requested_permissions": ["cam", "denm"],
                "validity_days": 7
            }
        
        Response Body (JSON):
            {
                "success": true,
                "authorization_ticket": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
                "serial_number": "123456789...",
                "valid_from": "2025-10-10T15:30:00Z",
                "valid_until": "2025-10-17T15:30:00Z",
                "permissions": ["cam", "denm"]
            }
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received SIMPLE AuthorizationRequest (JSON)")
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
            current_app.logger.info(f"Request data keys: {list(data.keys())}")
            
            # 2. Validate required fields
            required_fields = ["its_id", "enrollment_certificate", "public_key"]
            missing = [f for f in required_fields if f not in data]
            if missing:
                return jsonify({
                    "error": "Missing required fields",
                    "missing": missing,
                    "hint": "Required: its_id, enrollment_certificate, public_key"
                }), 400
            
            its_id = data["its_id"]
            ec_pem = data["enrollment_certificate"]
            public_key_pem = data["public_key"]
            permissions = data.get("requested_permissions", ["cam", "denm"])
            validity_days = data.get("validity_days", 7)
            
            current_app.logger.info(f"ITS ID: {its_id}")
            current_app.logger.info(f"Requested permissions: {permissions}")
            current_app.logger.info(f"Validity: {validity_days} days")
            
            # 3. Parse Enrollment Certificate
            try:
                from cryptography import x509
                ec_cert = x509.load_pem_x509_certificate(
                    ec_pem.encode('utf-8'),
                    backend=default_backend()
                )
                current_app.logger.info("✅ EC parsed successfully")
                
                # Verify EC is valid (use timezone-aware datetime)
                now = datetime.now(timezone.utc)
                if ec_cert.not_valid_after_utc < now:
                    return jsonify({
                        "error": "Enrollment Certificate expired",
                        "expired_on": ec_cert.not_valid_after_utc.isoformat()
                    }), 400
                    
                if ec_cert.not_valid_before_utc > now:
                    return jsonify({
                        "error": "Enrollment Certificate not yet valid",
                        "valid_from": ec_cert.not_valid_before_utc.isoformat()
                    }), 400
                    
            except Exception as e:
                current_app.logger.error(f"Failed to parse EC: {e}")
                return jsonify({
                    "error": "Invalid enrollment certificate",
                    "message": str(e)
                }), 400
            
            # 4. Parse public key
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
            
            # 5. Generate HMAC key for unlinkability (simplified)
            hmac_key = secrets.token_bytes(32)
            current_app.logger.info(f"Generated HMAC key: {hmac_key.hex()[:16]}...")
            
            # 6. Issue Authorization Ticket
            current_app.logger.info(f"Issuing AT for ITS-S: {its_id}")
            
            try:
                # Prepare attributes for the AT
                # Note: The AA method uses a different signature, so we pass permissions via attributes
                attributes = {
                    'permissions': permissions,
                    'hmac_key': hmac_key
                }
                
                # Call AA method
                at_certificate = bp.aa.issue_authorization_ticket(
                    its_id=its_id,
                    public_key=public_key,
                    attributes=attributes
                )
                
                # 7. Serialize certificate to PEM
                at_pem = at_certificate.public_bytes(
                    encoding=serialization.Encoding.PEM
                ).decode('utf-8')
                
                # 8. Extract certificate info
                serial = at_certificate.serial_number
                not_before = at_certificate.not_valid_before_utc.isoformat()
                not_after = at_certificate.not_valid_after_utc.isoformat()
                
                current_app.logger.info(f"✅ AT issued successfully!")
                current_app.logger.info(f"Serial: {serial}")
                current_app.logger.info(f"Valid: {not_before} to {not_after}")
                
                # Increment metrics counter for issued authorization tickets
                from utils.metrics import get_metrics_collector
                metrics = get_metrics_collector()
                metrics.increment_counter('authorization_tickets_issued')
                
                # 9. Return response
                return jsonify({
                    "success": True,
                    "message": "Authorization Ticket issued successfully",
                    "authorization_ticket": at_pem,
                    "certificate_info": {
                        "serial_number": str(serial),
                        "subject": {
                            "common_name": its_id
                        },
                        "validity": {
                            "not_before": not_before,
                            "not_after": not_after,
                            "days": validity_days
                        },
                        "issuer": bp.aa.aa_id,
                        "permissions": permissions
                    },
                    "hmac_key": hmac_key.hex(),
                    "warning": "⚠️ In production, HMAC key must be derived securely and kept secret"
                }), 200
                
            except Exception as e:
                current_app.logger.error(f"Failed to issue AT: {e}")
                import traceback
                current_app.logger.error(traceback.format_exc())
                return jsonify({
                    "error": "Failed to issue authorization ticket",
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

    # OPTIONS handler for CORS preflight
    @bp.route("/butterfly-request/simple", methods=["OPTIONS"])
    def simple_butterfly_request_options():
        """Handle CORS preflight for butterfly request"""
        return "", 204

    @bp.route("/butterfly-request/simple", methods=["POST"])
    @rate_limit
    @optional_auth
    def simple_butterfly_request():
        """
        POST /authorization/butterfly-request/simple
        
        ⚠️ TESTING ONLY - Simplified JSON-based Butterfly Key Expansion.
        
        Request Body (JSON):
            {
                "its_id": "VEHICLE_001",
                "enrollment_certificate": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
                "public_keys": ["-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n", ...],
                "master_hmac_key": "hex_string_64_chars",
                "num_tickets": 20,
                "validity_days": 7
            }
        
        Response Body (JSON):
            {
                "success": true,
                "authorization_tickets": ["cert1_pem", "cert2_pem", ...],
                "count": 20,
                "hmac_keys": ["key1_hex", "key2_hex", ...],
                "validity": {...}
            }
        """
        current_app.logger.info("=" * 80)
        current_app.logger.info("Received SIMPLE Butterfly Request (JSON)")
        current_app.logger.info("⚠️  FOR TESTING ONLY - NOT ETSI COMPLIANT")
        current_app.logger.info("=" * 80)
        
        try:
            # 1. Parse JSON request
            if not request.is_json:
                return jsonify({
                    "error": "Invalid Content-Type",
                    "message": "Expected application/json"
                }), 415
            
            data = request.get_json()
            
            # 2. Validate required fields
            required_fields = ["its_id", "enrollment_certificate", "public_keys"]
            missing = [f for f in required_fields if f not in data]
            if missing:
                return jsonify({
                    "error": "Missing required fields",
                    "missing": missing
                }), 400
            
            its_id = data["its_id"]
            ec_pem = data["enrollment_certificate"]
            public_keys_pem = data["public_keys"]
            master_hmac = data.get("master_hmac_key")
            num_tickets = data.get("num_tickets", 20)
            validity_days = data.get("validity_days", 7)
            
            current_app.logger.info(f"ITS ID: {its_id}")
            current_app.logger.info(f"Public keys count: {len(public_keys_pem)}")
            current_app.logger.info(f"Requested tickets: {num_tickets}")
            
            # 3. Parse EC
            try:
                from cryptography import x509
                ec_cert = x509.load_pem_x509_certificate(
                    ec_pem.encode('utf-8'),
                    backend=default_backend()
                )
                current_app.logger.info("✅ EC parsed successfully")
            except Exception as e:
                return jsonify({
                    "error": "Invalid enrollment certificate",
                    "message": str(e)
                }), 400
            
            # 4. Parse public keys
            public_keys = []
            for idx, pk_pem in enumerate(public_keys_pem):
                try:
                    pk = serialization.load_pem_public_key(
                        pk_pem.encode('utf-8'),
                        backend=default_backend()
                    )
                    public_keys.append(pk)
                except Exception as e:
                    return jsonify({
                        "error": f"Invalid public key at index {idx}",
                        "message": str(e)
                    }), 400
            
            current_app.logger.info(f"✅ Parsed {len(public_keys)} public keys")
            
            # 5. Generate or parse master HMAC
            if master_hmac:
                try:
                    master_hmac_bytes = bytes.fromhex(master_hmac)
                except:
                    return jsonify({
                        "error": "Invalid master_hmac_key format",
                        "message": "Must be hex string"
                    }), 400
            else:
                master_hmac_bytes = secrets.token_bytes(32)
                current_app.logger.info(f"Generated master HMAC: {master_hmac_bytes.hex()[:16]}...")
            
            # 6. Issue batch ATs using Butterfly
            current_app.logger.info(f"Issuing {num_tickets} ATs via Butterfly expansion...")
            
            try:
                # Use issue_authorization_ticket_batch (not issue_butterfly_authorization_tickets)
                at_certificates = bp.aa.issue_authorization_ticket_batch(
                    its_id=its_id,
                    public_keys=public_keys[:num_tickets],
                    attributes={
                        "validity_days": validity_days,
                        "permissions": ["cam", "denm"],
                    }
                )
                
                # 7. Serialize certificates
                at_pems = []
                hmac_keys = []
                
                for idx, at_cert in enumerate(at_certificates):
                    at_pem = at_cert.public_bytes(
                        encoding=serialization.Encoding.PEM
                    ).decode('utf-8')
                    at_pems.append(at_pem)
                    
                    # Derive HMAC key for this ticket (simplified)
                    from protocols.butterfly_key_expansion import derive_ticket_hmac
                    ticket_hmac = derive_ticket_hmac(master_hmac_bytes, idx)
                    hmac_keys.append(ticket_hmac.hex())
                
                current_app.logger.info(f"✅ Issued {len(at_certificates)} ATs successfully!")
                
                # 8. Return response
                return jsonify({
                    "success": True,
                    "message": f"Issued {len(at_certificates)} Authorization Tickets via Butterfly",
                    "authorization_tickets": at_pems,
                    "count": len(at_certificates),
                    "hmac_keys": hmac_keys,
                    "master_hmac_key": master_hmac_bytes.hex(),
                    "certificate_info": {
                        "issuer": bp.aa.aa_id,
                        "validity_days": validity_days,
                        "first_serial": str(at_certificates[0].serial_number),
                        "last_serial": str(at_certificates[-1].serial_number)
                    },
                    "warning": "⚠️ Keep HMAC keys secret! Each ticket uses a derived key for unlinkability"
                }), 200
                
            except Exception as e:
                current_app.logger.error(f"Failed to issue Butterfly ATs: {e}")
                import traceback
                current_app.logger.error(traceback.format_exc())
                return jsonify({
                    "error": "Failed to issue butterfly tickets",
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

    return bp
