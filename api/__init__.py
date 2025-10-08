"""
REST API Package for SecureRoad PKI

This package implements ETSI TS 102941 compliant REST API endpoints
for PKI entities (Enrollment Authority, Authorization Authority, Trust List Manager).

Author: SecureRoad PKI Project
Date: October 2025
"""

__version__ = "1.0.0"
__author__ = "SecureRoad PKI Project"

from .flask_app_factory import create_app

__all__ = ["create_app"]
