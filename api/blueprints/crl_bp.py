"""
CRL Distribution Blueprint

Simplified implementation for testing.
"""

from flask import Blueprint, current_app, jsonify, request


def create_crl_blueprint(ca_instance):
    """Create Flask blueprint for CRL distribution endpoints."""
    bp = Blueprint("crl", __name__)

    # Store CA instance (can be EA, AA, or RootCA)
    bp.ca = ca_instance

    @bp.route("/full", methods=["GET"])
    def get_full_crl():
        """
        GET /crl/full
        Returns full CRL
        """
        current_app.logger.info("Request for full CRL")

        # Check if CA has crl_manager
        if not hasattr(bp.ca, "crl_manager"):
            return jsonify({"error": "CRL manager not available", "responseCode": 8}), 404

        # Try to get CRL
        try:
            # Check if CRL file exists
            crl_manager = bp.ca.crl_manager
            crl_path = crl_manager.full_crl_path

            import os

            if not os.path.exists(crl_path):
                return (
                    jsonify(
                        {
                            "info": "No CRL published yet",
                            "message": "CRL file does not exist",
                            "responseCode": 8,
                        }
                    ),
                    404,
                )

            # Read CRL file
            with open(crl_path, "rb") as f:
                crl_der = f.read()

            current_app.logger.info(f"Returning CRL: {len(crl_der)} bytes")

            return (
                crl_der,
                200,
                {
                    "Content-Type": "application/pkix-crl",
                    "Content-Disposition": 'attachment; filename="full.crl"',
                },
            )

        except Exception as e:
            current_app.logger.error(f"Error getting CRL: {e}")
            return (
                jsonify({"error": "Failed to retrieve CRL", "message": str(e), "responseCode": 13}),
                500,
            )

    @bp.route("/delta", methods=["GET"])
    def get_delta_crl():
        """
        GET /crl/delta
        Returns delta CRL
        """
        current_app.logger.info("Request for delta CRL")

        # Check if CA has crl_manager
        if not hasattr(bp.ca, "crl_manager"):
            return jsonify({"error": "CRL manager not available", "responseCode": 8}), 404

        # Try to get Delta CRL
        try:
            # Check if Delta CRL file exists
            crl_manager = bp.ca.crl_manager

            # Check if delta_crl_path attribute exists
            if not hasattr(crl_manager, "delta_crl_path"):
                return (
                    jsonify(
                        {
                            "info": "Delta CRL not supported",
                            "message": "CRL manager does not support delta CRL",
                            "responseCode": 8,
                        }
                    ),
                    404,
                )

            delta_crl_path = crl_manager.delta_crl_path

            import os

            if not os.path.exists(delta_crl_path):
                return (
                    jsonify(
                        {
                            "info": "No Delta CRL available",
                            "message": "Delta CRL not published yet or no new revocations",
                            "responseCode": 8,
                        }
                    ),
                    404,
                )

            # Read Delta CRL file
            with open(delta_crl_path, "rb") as f:
                delta_crl_der = f.read()

            current_app.logger.info(f"Returning Delta CRL: {len(delta_crl_der)} bytes")

            return (
                delta_crl_der,
                200,
                {
                    "Content-Type": "application/pkix-crl",
                    "Content-Disposition": 'attachment; filename="delta.crl"',
                },
            )

        except Exception as e:
            current_app.logger.error(f"Error getting Delta CRL: {e}")
            import traceback
            current_app.logger.error(traceback.format_exc())
            return (
                jsonify({"error": "Failed to retrieve Delta CRL", "message": str(e), "responseCode": 13}),
                500,
            )

    return bp
