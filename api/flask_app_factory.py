"""
Flask App Factory for ETSI-Compliant REST API

This module implements the Flask application factory pattern to create
REST API servers for PKI entities (EA, AA, TLM, RootCA) following
ETSI TS 102941 specifications.

Author: SecureRoad PKI Project
Date: October 2025
"""

import logging
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS


def create_app(
    entity_type: str, entity_instance: Any, config: Optional[Dict[str, Any]] = None
) -> Flask:
    """
    Factory function to create Flask app for PKI entities.

    Args:
        entity_type: Type of entity ('EA', 'AA', 'TLM', 'RootCA')
        entity_instance: Instance of the entity class
        config: Configuration dictionary

    Returns:
        Flask: Configured Flask application
    """

    # Validate entity type
    valid_types = ["EA", "AA", "TLM", "RootCA"]
    if entity_type not in valid_types:
        raise ValueError(f"Invalid entity_type '{entity_type}'. Must be one of {valid_types}")

    # Initialize Flask app
    app = Flask(__name__)

    # Default configuration
    default_config = {
        "secret_key": "dev-secret-key-CHANGE-IN-PRODUCTION",
        "api_keys": [],
        "cors_origins": ["http://localhost:3000"],
        "rate_limit": "100 per hour",
        "log_level": "INFO",
        "max_content_length": 10 * 1024 * 1024,  # 10MB
    }

    # Merge with user config
    if config:
        default_config.update(config)

    # Apply Flask configuration
    app.config.update(
        {
            "SECRET_KEY": default_config["secret_key"],
            "MAX_CONTENT_LENGTH": default_config["max_content_length"],
            "JSON_SORT_KEYS": False,
            "ENTITY_TYPE": entity_type,
            "ENTITY_ID": getattr(entity_instance, f"{entity_type.lower()}_id", "unknown"),
            "API_KEYS": default_config["api_keys"],
        }
    )

    # Setup CORS
    CORS(app, origins=default_config["cors_origins"])

    # Setup logging
    level = getattr(logging, default_config["log_level"].upper(), logging.INFO)
    app.logger.setLevel(level)

    # Log startup information
    app.logger.info("=" * 80)
    app.logger.info(f"Starting {entity_type} REST API Server")
    app.logger.info(f"Entity ID: {app.config['ENTITY_ID']}")
    app.logger.info(f"ETSI TS 102941 Compliant")
    app.logger.info("=" * 80)

    # Store entity instance in app config
    app.config["ENTITY_INSTANCE"] = entity_instance

    # Root endpoint
    @app.route("/")
    def index():
        return jsonify(
            {
                "name": f"{entity_type} REST API",
                "version": "1.0.0",
                "protocol": "ETSI TS 102941 V2.1.1",
                "encoding": "ASN.1 OER",
                "entity_type": entity_type,
                "entity_id": app.config["ENTITY_ID"],
                "endpoints": get_available_endpoints(entity_type),
            }
        )

    # Health check endpoint (no auth required)
    @app.route("/health")
    def health_check():
        return jsonify(
            {
                "status": "ok",
                "entity_type": entity_type,
                "entity_id": app.config["ENTITY_ID"],
                "protocol": "ETSI TS 102941 V2.1.1",
                "encoding": "ASN.1 OER",
            }
        )

    # Register blueprints based on entity type
    if entity_type == "EA":
        # Enrollment Authority endpoints
        try:
            from .blueprints.crl_bp import create_crl_blueprint
            from .blueprints.enrollment_bp import create_enrollment_blueprint

            enrollment_bp = create_enrollment_blueprint(entity_instance)
            app.register_blueprint(enrollment_bp, url_prefix="/enrollment")

            crl_bp = create_crl_blueprint(entity_instance)
            app.register_blueprint(crl_bp, url_prefix="/crl")

            app.logger.info("Registered EA endpoints:")
            app.logger.info("  POST /enrollment/request")
            app.logger.info("  POST /enrollment/validation")
            app.logger.info("  GET  /crl/full")
            app.logger.info("  GET  /crl/delta")
        except ImportError as e:
            app.logger.warning(f"Could not import blueprints: {e}")

    elif entity_type == "AA":
        # Authorization Authority endpoints
        try:
            from .blueprints.authorization_bp import create_authorization_blueprint
            from .blueprints.crl_bp import create_crl_blueprint

            authorization_bp = create_authorization_blueprint(entity_instance)
            if authorization_bp is None:
                app.logger.error("create_authorization_blueprint returned None!")
                raise ValueError("Failed to create authorization blueprint")

            app.register_blueprint(authorization_bp, url_prefix="/authorization")

            crl_bp = create_crl_blueprint(entity_instance)
            app.register_blueprint(crl_bp, url_prefix="/crl")

            app.logger.info("Registered AA endpoints:")
            app.logger.info("  POST /authorization/request")
            app.logger.info("  POST /authorization/request/butterfly")
            app.logger.info("  GET  /crl/full")
            app.logger.info("  GET  /crl/delta")
        except Exception as e:
            app.logger.error(f"Error registering AA blueprints: {e}")
            import traceback

            app.logger.error(traceback.format_exc())

    elif entity_type == "TLM":
        # Trust List Manager endpoints
        try:
            from .blueprints.trust_list_bp import create_trust_list_blueprint

            tlm_bp = create_trust_list_blueprint(entity_instance)
            app.register_blueprint(tlm_bp, url_prefix="/ctl")

            app.logger.info("Registered TLM endpoints:")
            app.logger.info("  GET /ctl/full")
            app.logger.info("  GET /ctl/delta")
        except ImportError as e:
            app.logger.warning(f"Could not import blueprints: {e}")

    # Global error handlers
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"error": "Bad Request", "message": str(e), "responseCode": 8}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return (
            jsonify(
                {
                    "error": "Unauthorized",
                    "message": "Invalid or missing API key",
                    "responseCode": 9,
                }
            ),
            401,
        )

    @app.errorhandler(404)
    def not_found(e):
        return (
            jsonify(
                {
                    "error": "Not Found",
                    "message": "The requested endpoint does not exist",
                    "responseCode": 8,
                }
            ),
            404,
        )

    @app.errorhandler(415)
    def unsupported_media_type(e):
        return (
            jsonify(
                {
                    "error": "Unsupported Media Type",
                    "message": "Content-Type must be application/octet-stream for ETSI messages",
                    "responseCode": 2,
                }
            ),
            415,
        )

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.error(f"Internal server error: {e}")
        return (
            jsonify(
                {
                    "error": "Internal Server Error",
                    "message": "An unexpected error occurred",
                    "responseCode": 13,
                }
            ),
            500,
        )

    return app


def get_available_endpoints(entity_type: str) -> list:
    """Get list of available endpoints for entity type"""
    endpoints = {
        "EA": [
            "POST /enrollment/request",
            "POST /enrollment/validation",
            "GET /crl/full",
            "GET /crl/delta",
        ],
        "AA": [
            "POST /authorization/request",
            "POST /authorization/request/butterfly",
            "GET /crl/full",
            "GET /crl/delta",
        ],
        "TLM": ["GET /ctl/full", "GET /ctl/delta"],
        "RootCA": ["GET /crl/full", "GET /crl/delta"],
    }
    return endpoints.get(entity_type, [])
