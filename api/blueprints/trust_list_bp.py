"""
Trust List Manager Blueprint

ETSI TS 102941 compliant CTL (Certificate Trust List) distribution endpoint.
Provides REST API for ITS-S to retrieve and verify trust anchors.
"""

from datetime import datetime

from flask import Blueprint, current_app, jsonify, request

# Optional helpers for certificate parsing
try:
    from utils.cert_utils import get_certificate_ski, get_certificate_expiry_time, get_certificate_identifier
except Exception:
    # If utils are not importable for some reason, define fallbacks
    def get_certificate_ski(cert):
        return getattr(cert, 'ski', None) or ''
    def get_certificate_expiry_time(cert):
        return None
    def get_certificate_identifier(cert):
        return getattr(cert, 'cert_id', None) or ''


def create_trust_list_blueprint(tlm_instance):
    """Create Flask blueprint for Trust List Manager endpoints."""
    bp = Blueprint("trust_list", __name__)

    # Store TLM instance
    bp.tlm = tlm_instance

    @bp.route("/full", methods=["GET"])
    def get_full_ctl():
        """
        GET /ctl/full
        Returns full Certificate Trust List
        """
        current_app.logger.info("Request for full CTL")

        try:
            # Build CTL response
            ctl_data = {
                "version": getattr(bp.tlm, "version", 1),
                "timestamp": datetime.now().isoformat(),
                "tlm_id": getattr(bp.tlm, "tlm_id", "unknown"),
                "trust_anchors": [],
            }

            # Add trust anchors if available. Provide richer metadata when certificate objects are stored.
            if hasattr(bp.tlm, "trust_anchors"):
                for ta in bp.tlm.trust_anchors:
                    # ta may be a dict with a 'certificate' object or a minimal serialized entry
                    try:
                        cert = ta.get('certificate') if isinstance(ta, dict) else getattr(ta, 'certificate', None)
                    except Exception:
                        cert = None

                    entry = {
                        "authority_type": ta.get('authority_type', getattr(ta, 'authority_type', 'unknown')) if isinstance(ta, dict) else getattr(ta, 'authority_type', 'unknown'),
                        "authority_id": ta.get('authority_id', getattr(ta, 'authority_id', 'unknown')) if isinstance(ta, dict) else getattr(ta, 'authority_id', 'unknown'),
                        "added": (
                            (ta.get('added_date') if isinstance(ta, dict) else getattr(ta, 'added_date', None))
                            or (ta.get('added_at') if isinstance(ta, dict) else getattr(ta, 'added_at', None))
                            or datetime.now()
                        ).isoformat() if not isinstance(((ta.get('added_date') if isinstance(ta, dict) else getattr(ta, 'added_date', None)) or (ta.get('added_at') if isinstance(ta, dict) else getattr(ta, 'added_at', None)) or None), str) else ((ta.get('added_date') if isinstance(ta, dict) else getattr(ta, 'added_date', None)) or (ta.get('added_at') if isinstance(ta, dict) else getattr(ta, 'added_at', None)) or datetime.now()).isoformat(),
                    }

                    # If certificate object available, include subject, ski, expiry, cert_id
                    if cert is not None:
                        try:
                            entry['subject'] = getattr(cert, 'subject', None).rfc4514_string() if hasattr(cert, 'subject') else None
                        except Exception:
                            entry['subject'] = None
                        try:
                            entry['ski'] = get_certificate_ski(cert)
                        except Exception:
                            entry['ski'] = None
                        try:
                            expiry = get_certificate_expiry_time(cert)
                            entry['expiry'] = expiry.isoformat() if expiry is not None else None
                        except Exception:
                            entry['expiry'] = None
                        try:
                            entry['cert_id'] = get_certificate_identifier(cert)
                        except Exception:
                            entry['cert_id'] = None
                    else:
                        # Fallback to any serialized fields present
                        if isinstance(ta, dict):
                            entry['subject'] = ta.get('subject_name') or ta.get('subject')
                            entry['ski'] = ta.get('ski')
                            entry['expiry'] = ta.get('expiry_date') or ta.get('expiry')
                            entry['cert_id'] = ta.get('cert_id')

                    ctl_data["trust_anchors"].append(entry)

            current_app.logger.info(
                f"Returning CTL with {len(ctl_data['trust_anchors'])} trust anchors"
            )

            return jsonify(ctl_data), 200

        except Exception as e:
            current_app.logger.error(f"Error getting CTL: {e}")
            return (
                jsonify({"error": "Failed to retrieve CTL", "message": str(e), "responseCode": 13}),
                500,
            )

    @bp.route("/delta", methods=["GET"])
    def get_delta_ctl():
        """
        GET /ctl/delta?since=<timestamp>
        Returns delta CTL since timestamp
        """
        current_app.logger.info("Request for delta CTL")

        since = request.args.get("since")

        # Delta CTL not fully implemented yet
        return (
            jsonify(
                {
                    "info": "Delta CTL not available",
                    "message": "Delta CTL functionality not yet implemented",
                    "since_parameter": since,
                    "responseCode": 8,
                }
            ),
            404,
        )

    return bp
