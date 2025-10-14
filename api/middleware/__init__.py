"""
Middleware Package

Contains authentication, rate limiting, monitoring, and logging middleware.
"""

from .auth import get_client_info, optional_auth, require_api_key, setup_auth
from .rate_limiting import custom_rate_limit, rate_limit, setup_rate_limit
from .monitoring import setup_monitoring, track_operation
from .mtls_auth import require_mtls, get_client_cert_info, setup_mtls, get_mtls_authenticator

__all__ = [
    "setup_auth",
    "require_api_key",
    "optional_auth",
    "get_client_info",
    "setup_rate_limit",
    "rate_limit",
    "custom_rate_limit",
    "setup_monitoring",
    "track_operation",
    "require_mtls",
    "get_client_cert_info",
    "setup_mtls",
    "get_mtls_authenticator",
]
