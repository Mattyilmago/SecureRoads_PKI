"""
Authentication Middleware

Implements API key authentication for REST endpoints.
ETSI TS 102941 recommends TLS client certificates, but API keys are acceptable for testing.

Author: SecureRoad PKI Project
Date: October 2025
"""

from functools import wraps

from flask import current_app, jsonify, request

from protocols.core.types import ResponseCode


def setup_auth(app, api_keys=None):
    """
    Configure authentication for Flask app

    Args:
        app: Flask application instance
        api_keys: List of valid API keys (optional)
    """
    if api_keys:
        app.config["API_KEYS"] = set(api_keys)
        with app.app_context():
            current_app.logger.info(f"Authentication configured with {len(api_keys)} API keys")
    else:
        app.config["API_KEYS"] = set()
        with app.app_context():
            current_app.logger.warning("No API keys configured - authentication disabled")


def require_api_key(f):
    """
    Decorator to require API key authentication

    Checks for API key in:
    1. Authorization header: "Bearer <api_key>"
    2. X-API-Key header: "<api_key>"
    3. Query parameter: ?api_key=<api_key>

    Usage:
        @bp.route('/protected')
        @require_api_key
        def protected_endpoint():
            return jsonify({'status': 'ok'})
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get configured API keys
        api_keys = current_app.config.get("API_KEYS", set())

        # If no keys configured, allow access (dev mode)
        if not api_keys:
            return f(*args, **kwargs)

        # Check Authorization header (Bearer token)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove "Bearer " prefix
            if token in api_keys:
                return f(*args, **kwargs)

        # Check X-API-Key header
        api_key_header = request.headers.get("X-API-Key", "")
        if api_key_header in api_keys:
            return f(*args, **kwargs)

        # Check query parameter
        api_key_param = request.args.get("api_key", "")
        if api_key_param in api_keys:
            return f(*args, **kwargs)

        # No valid authentication found
        current_app.logger.warning(
            f"Unauthorized access attempt to {request.path} from {request.remote_addr}"
        )

        return (
            jsonify(
                {
                    "error": "Unauthorized",
                    "message": "Valid API key required",
                    "responseCode": ResponseCode.UNAUTHORIZED.value,
                    "hint": "Provide API key via Authorization header, X-API-Key header, or api_key parameter",
                }
            ),
            401,
        )

    return decorated_function


def get_client_info():
    """
    Extract client information from request

    Returns:
        dict: Client IP, User-Agent, and other metadata
    """
    return {
        "ip": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "method": request.method,
        "path": request.path,
        "timestamp": request.environ.get("REQUEST_TIME", None),
    }


def optional_auth(f):
    """
    Decorator for endpoints with optional authentication

    Sets request.authenticated = True if valid API key provided
    Does not reject requests without authentication

    Usage:
        @bp.route('/public')
        @optional_auth
        def public_endpoint():
            if request.authenticated:
                # Enhanced features for authenticated users
                pass
            return jsonify({'status': 'ok'})
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_keys = current_app.config.get("API_KEYS", set())
        request.authenticated = False

        if not api_keys:
            request.authenticated = True
            return f(*args, **kwargs)

        # Check all authentication methods
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and auth_header[7:] in api_keys:
            request.authenticated = True

        api_key_header = request.headers.get("X-API-Key", "")
        if api_key_header in api_keys:
            request.authenticated = True

        api_key_param = request.args.get("api_key", "")
        if api_key_param in api_keys:
            request.authenticated = True

        return f(*args, **kwargs)

    return decorated_function
