"""
Flask App Factory for ETSI-Compliant REST API

This module implements the Flask application factory pattern to create
REST API servers for PKI entities (EA, AA, TLM, RootCA) following
ETSI TS 102941 specifications.

Author: SecureRoad PKI Project
Date: October 2025
"""

import logging
import os
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_swagger_ui import get_swaggerui_blueprint


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
        "cors_origins": "*",  # "*" for dev, list of domains for production
        "rate_limit": "100 per hour",
        "log_level": "INFO",
        "max_content_length": 10 * 1024 * 1024,  # 10MB
        "environment": "development",  # "development" or "production"
    }

    # Merge with user config
    if config:
        default_config.update(config)

    # Determine CORS configuration based on environment
    cors_origins = default_config["cors_origins"]
    if default_config["environment"] == "production" and cors_origins == "*":
        # In production, if still using "*", log a warning
        app.logger.warning("⚠️  SECURITY: CORS set to '*' in production! Specify allowed domains.")
    
    # Apply Flask configuration
    app.config.update(
        {
            "SECRET_KEY": default_config["secret_key"],
            "MAX_CONTENT_LENGTH": default_config["max_content_length"],
            "JSON_SORT_KEYS": False,
            "ENTITY_TYPE": entity_type,
            "ENTITY_ID": getattr(entity_instance, f"{entity_type.lower()}_id", "unknown"),
            "API_KEYS": default_config["api_keys"],
            "ENVIRONMENT": default_config["environment"],
        }
    )

    # Setup CORS with environment-aware configuration
    CORS(
        app,
        resources={r"/*": {"origins": cors_origins}},
        allow_headers=["Content-Type", "X-API-Key", "Authorization"],
        methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        supports_credentials=False  # Set to False for simpler CORS during development
    )

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
    
    # Setup monitoring middleware
    from .middleware.monitoring import setup_monitoring
    setup_monitoring(app)

    # Configure Swagger UI
    SWAGGER_URL = '/api/docs'
    API_URL = '/api/openapi.yaml'
    
    # Swagger UI blueprint
    swaggerui_blueprint = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={
            'app_name': f"{entity_type} PKI API",
            'defaultModelsExpandDepth': -1,  # Hide schemas section by default
            'displayRequestDuration': True,
            'docExpansion': 'list',  # Expand operations list
            'filter': True,  # Enable search filter
            'showExtensions': True,
            'showCommonExtensions': True,
            'tryItOutEnabled': True
        }
    )
    app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)
    
    # Serve OpenAPI spec
    @app.route('/api/openapi.yaml')
    def openapi_spec():
        """Serve the OpenAPI specification file"""
        spec_path = os.path.join(os.path.dirname(__file__), 'openapi_spec.yaml')
        if os.path.exists(spec_path):
            return send_file(spec_path, mimetype='text/yaml')
        else:
            return jsonify({'error': 'OpenAPI spec not found'}), 404
    
    app.logger.info(f"Swagger UI available at: {SWAGGER_URL}")

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
                "documentation": {
                    "swagger_ui": SWAGGER_URL,
                    "openapi_spec": API_URL
                },
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
            from .blueprints.enrollment_simple_bp import create_simple_enrollment_blueprint
            from .blueprints.stats_bp import create_stats_blueprint

            enrollment_bp = create_enrollment_blueprint(entity_instance)
            app.register_blueprint(enrollment_bp, url_prefix="/api/enrollment")

            # Simplified JSON endpoint for testing (NOT ETSI compliant)
            enrollment_simple_bp = create_simple_enrollment_blueprint(entity_instance)
            app.register_blueprint(enrollment_simple_bp, url_prefix="/api/enrollment")

            crl_bp = create_crl_blueprint(entity_instance)
            app.register_blueprint(crl_bp, url_prefix="/api/crl")
            
            stats_bp = create_stats_blueprint(entity_instance, "EA")
            app.register_blueprint(stats_bp, url_prefix="/api/stats")

            app.logger.info("Registered EA endpoints:")
            app.logger.info("  POST /api/enrollment/request (ETSI ASN.1 OER)")
            app.logger.info("  POST /api/enrollment/request/simple (JSON - TESTING ONLY)")
            app.logger.info("  POST /api/enrollment/validation")
            app.logger.info("  GET  /api/crl/full")
            app.logger.info("  GET  /api/crl/delta")
            app.logger.info("  GET  /api/stats")
        except ImportError as e:
            app.logger.warning(f"Could not import blueprints: {e}")

    elif entity_type == "AA":
        # Authorization Authority endpoints
        try:
            from .blueprints.authorization_bp import create_authorization_blueprint
            from .blueprints.authorization_simple_bp import create_simple_authorization_blueprint
            from .blueprints.crl_bp import create_crl_blueprint
            from .blueprints.stats_bp import create_stats_blueprint

            authorization_bp = create_authorization_blueprint(entity_instance)
            if authorization_bp is None:
                app.logger.error("create_authorization_blueprint returned None!")
                raise ValueError("Failed to create authorization blueprint")

            app.register_blueprint(authorization_bp, url_prefix="/api/authorization")

            # Simplified JSON endpoint for testing (NOT ETSI compliant)
            authorization_simple_bp = create_simple_authorization_blueprint(entity_instance)
            app.register_blueprint(authorization_simple_bp, url_prefix="/api/authorization")

            crl_bp = create_crl_blueprint(entity_instance)
            app.register_blueprint(crl_bp, url_prefix="/api/crl")
            
            stats_bp = create_stats_blueprint(entity_instance, "AA")
            app.register_blueprint(stats_bp, url_prefix="/api/stats")

            app.logger.info("Registered AA endpoints:")
            app.logger.info("  POST /api/authorization/request (ETSI ASN.1 OER)")
            app.logger.info("  POST /api/authorization/request/simple (JSON - TESTING ONLY)")
            app.logger.info("  POST /api/authorization/butterfly-request (ETSI ASN.1 OER)")
            app.logger.info("  POST /api/authorization/butterfly-request/simple (JSON - TESTING ONLY)")
            app.logger.info("  GET  /api/crl/full")
            app.logger.info("  GET  /api/crl/delta")
            app.logger.info("  GET  /api/stats")
        except Exception as e:
            app.logger.error(f"Error registering AA blueprints: {e}")
            import traceback

            app.logger.error(traceback.format_exc())

    elif entity_type == "TLM":
        # Trust List Manager endpoints
        try:
            from .blueprints.trust_list_bp import create_trust_list_blueprint
            from .blueprints.stats_bp import create_stats_blueprint

            tlm_bp = create_trust_list_blueprint(entity_instance)
            app.register_blueprint(tlm_bp, url_prefix="/api/trust-list")
            
            stats_bp = create_stats_blueprint(entity_instance, "TLM")
            app.register_blueprint(stats_bp, url_prefix="/api/stats")

            app.logger.info("Registered TLM endpoints:")
            app.logger.info("  GET /api/trust-list/full")
            app.logger.info("  GET /api/trust-list/delta")
            app.logger.info("  GET /api/stats")
        except ImportError as e:
            app.logger.warning(f"Could not import blueprints: {e}")
    
    elif entity_type == "RootCA":
        # Root CA endpoints
        try:
            from .blueprints.crl_bp import create_crl_blueprint
            from .blueprints.stats_bp import create_stats_blueprint

            crl_bp = create_crl_blueprint(entity_instance)
            app.register_blueprint(crl_bp, url_prefix="/api/crl")
            
            stats_bp = create_stats_blueprint(entity_instance, "RootCA")
            app.register_blueprint(stats_bp, url_prefix="/api/stats")

            app.logger.info("Registered RootCA endpoints:")
            app.logger.info("  GET /api/crl/full")
            app.logger.info("  GET /api/crl/delta")
            app.logger.info("  GET /api/stats")
        except ImportError as e:
            app.logger.warning(f"Could not import blueprints: {e}")
    
    # Register monitoring blueprint (available for all entity types)
    try:
        from .blueprints.monitoring_bp import monitoring_bp
        
        # Attach entity instance and type to monitoring blueprint
        monitoring_bp.entity = entity_instance
        monitoring_bp.entity_type = entity_type
        
        app.register_blueprint(monitoring_bp, url_prefix="/api/monitoring")
        
        app.logger.info("Registered monitoring endpoints:")
        app.logger.info("  GET /api/monitoring/metrics")
        app.logger.info("  GET /api/monitoring/metrics/prometheus")
        app.logger.info("  GET /api/monitoring/metrics/errors")
        app.logger.info("  GET /api/monitoring/metrics/slowest")
        app.logger.info("  GET /api/monitoring/health")
        app.logger.info("  GET /api/monitoring/health/ready")
        app.logger.info("  GET /api/monitoring/health/live")
    except ImportError as e:
        app.logger.warning(f"Could not import monitoring blueprint: {e}")
    
    # Register management blueprint (available for all entity types)
    try:
        from .blueprints.management_bp import management_bp
        
        app.register_blueprint(management_bp, url_prefix="/api/management")
        
        app.logger.info("Registered management endpoints:")
        app.logger.info("  GET    /api/management/entities")
        app.logger.info("  DELETE /api/management/entities/<entity_id>")
        app.logger.info("  POST   /api/management/entities/bulk-delete")
    except ImportError as e:
        app.logger.warning(f"Could not import management blueprint: {e}")

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
            "POST /api/enrollment/request (ETSI ASN.1 OER)",
            "POST /api/enrollment/request/simple (JSON - Testing only)",
            "POST /api/enrollment/validation",
            "GET /api/crl/full",
            "GET /api/crl/delta",
        ],
        "AA": [
            "POST /api/authorization/request",
            "POST /api/authorization/request/butterfly",
            "GET /api/crl/full",
            "GET /api/crl/delta",
        ],
        "TLM": ["GET /api/trust-list/full", "GET /api/trust-list/delta"],
        "RootCA": ["GET /api/crl/full", "GET /api/crl/delta"],
    }
    return endpoints.get(entity_type, [])
