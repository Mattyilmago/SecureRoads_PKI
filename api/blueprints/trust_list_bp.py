"""
Trust List Manager Blueprint

Simplified implementation for testing.
"""

from datetime import datetime

from flask import Blueprint, current_app, jsonify, request


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

            # Add trust anchors if available
            if hasattr(bp.tlm, "trust_anchors"):
                for ta in bp.tlm.trust_anchors:
                    ctl_data["trust_anchors"].append(
                        {
                            "authority_type": getattr(ta, "authority_type", "unknown"),
                            "authority_id": getattr(ta, "authority_id", "unknown"),
                            "added": (
                                getattr(ta, "added_at", datetime.now()).isoformat()
                                if hasattr(ta, "added_at")
                                else datetime.now().isoformat()
                            ),
                        }
                    )

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
