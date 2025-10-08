"""
Rate Limiting Middleware

Implements token bucket rate limiting for REST endpoints.
Prevents abuse and ensures fair resource allocation.

Author: SecureRoad PKI Project
Date: October 2025
"""

import time
from collections import defaultdict
from functools import wraps
from threading import Lock

from flask import current_app, jsonify, request

from protocols.etsi_message_types import ResponseCode


class TokenBucket:
    """
    Token bucket rate limiter implementation

    Algorithm:
    - Bucket holds tokens (max = capacity)
    - Tokens refill at fixed rate
    - Each request consumes 1 token
    - Request rejected if no tokens available
    """

    def __init__(self, capacity, refill_rate):
        """
        Initialize token bucket

        Args:
            capacity: Maximum tokens in bucket
            refill_rate: Tokens added per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = Lock()

    def consume(self, tokens=1):
        """
        Try to consume tokens

        Args:
            tokens: Number of tokens to consume

        Returns:
            tuple: (success: bool, wait_time: float)
        """
        with self.lock:
            # Refill tokens based on time passed
            now = time.time()
            time_passed = now - self.last_refill
            tokens_to_add = time_passed * self.refill_rate

            self.tokens = min(self.capacity, self.tokens + tokens_to_add)
            self.last_refill = now

            # Check if enough tokens available
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True, 0.0
            else:
                # Calculate wait time until enough tokens available
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.refill_rate
                return False, wait_time


class RateLimiter:
    """
    Global rate limiter with per-client tracking
    """

    def __init__(self):
        self.buckets = defaultdict(lambda: None)
        self.lock = Lock()
        self.default_capacity = 100
        self.default_refill_rate = 10.0  # 10 requests per second

    def configure(self, capacity=100, refill_rate=10.0):
        """Configure default rate limits"""
        self.default_capacity = capacity
        self.default_refill_rate = refill_rate

    def get_bucket(self, client_id):
        """Get or create token bucket for client"""
        with self.lock:
            if self.buckets[client_id] is None:
                self.buckets[client_id] = TokenBucket(
                    self.default_capacity, self.default_refill_rate
                )
            return self.buckets[client_id]

    def check_rate_limit(self, client_id):
        """
        Check if client has exceeded rate limit

        Returns:
            tuple: (allowed: bool, wait_time: float)
        """
        bucket = self.get_bucket(client_id)
        return bucket.consume()

    def cleanup_old_buckets(self, max_age=3600):
        """Remove buckets that haven't been used in max_age seconds"""
        with self.lock:
            now = time.time()
            to_remove = []
            for client_id, bucket in self.buckets.items():
                if bucket and (now - bucket.last_refill) > max_age:
                    to_remove.append(client_id)

            for client_id in to_remove:
                del self.buckets[client_id]

            if to_remove:
                current_app.logger.debug(f"Cleaned up {len(to_remove)} old rate limit buckets")


# Global rate limiter instance
_rate_limiter = RateLimiter()


def setup_rate_limit(app, requests_per_second=10, burst_capacity=100):
    """
    Configure rate limiting for Flask app

    Args:
        app: Flask application instance
        requests_per_second: Sustained rate limit
        burst_capacity: Maximum burst size
    """
    _rate_limiter.configure(burst_capacity, requests_per_second)
    app.config["RATE_LIMIT_ENABLED"] = True
    app.config["RATE_LIMIT_PER_SECOND"] = requests_per_second
    app.config["RATE_LIMIT_BURST"] = burst_capacity

    with app.app_context():
        current_app.logger.info(
            f"Rate limiting configured: {requests_per_second} req/s, burst={burst_capacity}"
        )


def rate_limit(f):
    """
    Decorator to apply rate limiting to endpoint

    Uses client IP address as identifier
    Returns 429 Too Many Requests if limit exceeded

    Usage:
        @bp.route('/limited')
        @rate_limit
        def limited_endpoint():
            return jsonify({'status': 'ok'})
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if rate limiting is enabled
        if not current_app.config.get("RATE_LIMIT_ENABLED", False):
            return f(*args, **kwargs)

        # Use IP address as client identifier
        client_id = request.remote_addr

        # Check rate limit
        allowed, wait_time = _rate_limiter.check_rate_limit(client_id)

        if not allowed:
            current_app.logger.warning(f"Rate limit exceeded for {client_id} on {request.path}")

            response = jsonify(
                {
                    "error": "Too Many Requests",
                    "message": "Rate limit exceeded",
                    "responseCode": ResponseCode.BAD_REQUEST.value,
                    "retry_after": round(wait_time, 2),
                    "hint": f"Please wait {round(wait_time, 2)} seconds before retrying",
                }
            )
            response.status_code = 429
            response.headers["Retry-After"] = str(int(wait_time) + 1)
            response.headers["X-RateLimit-Limit"] = str(
                current_app.config.get("RATE_LIMIT_PER_SECOND")
            )
            response.headers["X-RateLimit-Remaining"] = "0"

            return response

        # Add rate limit headers to successful response
        response = f(*args, **kwargs)

        # If response is a tuple (response, status_code), extract response
        if isinstance(response, tuple):
            response_obj = response[0]
        else:
            response_obj = response

        # Add rate limit headers
        if hasattr(response_obj, "headers"):
            response_obj.headers["X-RateLimit-Limit"] = str(
                current_app.config.get("RATE_LIMIT_PER_SECOND")
            )

        return response

    return decorated_function


def custom_rate_limit(requests_per_second=10, burst_capacity=100):
    """
    Decorator with custom rate limit parameters

    Usage:
        @bp.route('/expensive')
        @custom_rate_limit(requests_per_second=1, burst_capacity=5)
        def expensive_endpoint():
            return jsonify({'status': 'ok'})
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_app.config.get("RATE_LIMIT_ENABLED", False):
                return f(*args, **kwargs)

            # Create custom rate limiter for this endpoint
            client_id = f"{request.remote_addr}:{f.__name__}"
            bucket = TokenBucket(burst_capacity, requests_per_second)

            allowed, wait_time = bucket.consume()

            if not allowed:
                current_app.logger.warning(
                    f"Custom rate limit exceeded for {request.remote_addr} on {request.path}"
                )

                response = jsonify(
                    {
                        "error": "Too Many Requests",
                        "message": f"Rate limit: {requests_per_second} req/s exceeded",
                        "responseCode": ResponseCode.BAD_REQUEST.value,
                        "retry_after": round(wait_time, 2),
                    }
                )
                response.status_code = 429
                response.headers["Retry-After"] = str(int(wait_time) + 1)

                return response

            return f(*args, **kwargs)

        return decorated_function

    return decorator
