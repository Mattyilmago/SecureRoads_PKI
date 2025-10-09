"""
Monitoring Middleware

Flask middleware for automatic metrics collection and request tracking.

Author: SecureRoad PKI Project
Date: October 2025
"""

import time
from functools import wraps

from flask import current_app, g, request

from utils.metrics import get_metrics_collector


def setup_monitoring(app):
    """
    Setup monitoring middleware for Flask app
    
    Args:
        app: Flask application instance
    """
    
    @app.before_request
    def before_request():
        """Record request start time"""
        g.start_time = time.time()
    
    @app.after_request
    def after_request(response):
        """Record metrics after request completes"""
        if hasattr(g, 'start_time'):
            # Calculate latency
            latency_ms = (time.time() - g.start_time) * 1000
            
            # Get entity info
            entity_type = current_app.config.get('ENTITY_TYPE', 'unknown')
            entity_id = current_app.config.get('ENTITY_ID', 'unknown')
            
            # Record metrics
            metrics = get_metrics_collector()
            metrics.record_request(
                endpoint=request.path,
                method=request.method,
                status_code=response.status_code,
                latency_ms=latency_ms,
                entity_type=entity_type,
                entity_id=entity_id,
                error=None if response.status_code < 400 else f"HTTP {response.status_code}"
            )
            
            # Add latency header for debugging
            response.headers['X-Response-Time'] = f"{latency_ms:.2f}ms"
        
        return response
    
    @app.teardown_request
    def teardown_request(exception=None):
        """Handle exceptions and record error metrics"""
        if exception and hasattr(g, 'start_time'):
            latency_ms = (time.time() - g.start_time) * 1000
            
            entity_type = current_app.config.get('ENTITY_TYPE', 'unknown')
            entity_id = current_app.config.get('ENTITY_ID', 'unknown')
            
            metrics = get_metrics_collector()
            metrics.record_request(
                endpoint=request.path,
                method=request.method,
                status_code=500,
                latency_ms=latency_ms,
                entity_type=entity_type,
                entity_id=entity_id,
                error=str(exception)
            )
    
    app.logger.info("✅ Monitoring middleware configured")


def track_operation(operation_name: str):
    """
    Decorator to track specific operations (non-HTTP)
    
    Usage:
        @track_operation("certificate_generation")
        def generate_certificate():
            ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            start = time.time()
            error = None
            
            try:
                result = f(*args, **kwargs)
                return result
            except Exception as e:
                error = str(e)
                raise
            finally:
                latency_ms = (time.time() - start) * 1000
                
                # Log operation metrics
                current_app.logger.info(
                    f"Operation: {operation_name} | "
                    f"Latency: {latency_ms:.2f}ms | "
                    f"Status: {'ERROR' if error else 'OK'}"
                )
        
        return wrapper
    return decorator
