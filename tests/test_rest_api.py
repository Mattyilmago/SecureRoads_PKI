"""
Test Suite: REST API Endpoints

Tests Flask REST API implementation:
- EA endpoints (enrollment, CRL)
- AA endpoints (authorization, CRL)
- Health checks and error handling
- Content-Type validation

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.flask_app_factory import create_app
from entities.authorization_authority import AuthorizationAuthority
from entities.enrollment_authority import EnrollmentAuthority
from entities.root_ca import RootCA
from managers.trust_list_manager import TrustListManager


@pytest.fixture(scope="module")
def ea_app():
    """Create EA Flask app"""
    root_ca = RootCA(base_dir="data/root_ca")
    ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_API", base_dir="data/ea")

    config = {
        "api_keys": ["test-api-key-123"],
        "rate_limit": "1000 per hour",
        "log_level": "DEBUG",
    }

    app = create_app("EA", ea, config)
    app.config["TESTING"] = True
    return app


@pytest.fixture(scope="module")
def aa_app():
    """Create AA Flask app"""
    root_ca = RootCA(base_dir="data/root_ca")
    ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_API", base_dir="data/ea")

    tlm = TrustListManager(root_ca=root_ca, base_dir="data/tlm")
    tlm.add_trust_anchor(ea.certificate, authority_type="EA")

    aa = AuthorizationAuthority(
        root_ca=root_ca, tlm=tlm, aa_id="AA_API", base_dir="data/aa"
    )

    config = {
        "api_keys": ["test-api-key-456"],
        "rate_limit": "1000 per hour",
        "log_level": "DEBUG",
    }

    app = create_app("AA", aa, config)
    app.config["TESTING"] = True
    return app


class TestEAEndpoints:
    """Test EA API endpoints"""

    def test_health_check(self, ea_app):
        """Test EA health check"""
        with ea_app.test_client() as client:
            response = client.get("/health")
            assert response.status_code == 200
            data = response.get_json()
            assert data["status"] in ["healthy", "ok"]

    def test_root_endpoint(self, ea_app):
        """Test EA root endpoint"""
        with ea_app.test_client() as client:
            response = client.get("/")
            assert response.status_code == 200
            data = response.get_json()
            assert data["entity_type"] == "EA"

    def test_enrollment_request_requires_auth(self, ea_app):
        """Test enrollment requires auth or rejects empty body"""
        with ea_app.test_client() as client:
            response = client.post(
                "/enrollment/request",
                headers={"Content-Type": "application/octet-stream"},
            )
            assert response.status_code in [400, 401]

    def test_enrollment_request_invalid_content_type(self, ea_app):
        """Test enrollment rejects wrong content type"""
        with ea_app.test_client() as client:
            response = client.post(
                "/enrollment/request",
                headers={
                    "Authorization": "Bearer test-api-key-123",
                    "Content-Type": "application/json",
                },
                json={"test": "data"},
            )
            assert response.status_code == 415

    def test_crl_full_endpoint_exists(self, ea_app):
        """Test CRL endpoint exists"""
        with ea_app.test_client() as client:
            response = client.get("/crl/full")
            assert response.status_code in [200, 404]

    def test_404_error_handling(self, ea_app):
        """Test 404 handling"""
        with ea_app.test_client() as client:
            response = client.get("/nonexistent")
            assert response.status_code == 404


class TestAAEndpoints:
    """Test AA API endpoints"""

    def test_health_check(self, aa_app):
        """Test AA health check"""
        with aa_app.test_client() as client:
            response = client.get("/health")
            assert response.status_code == 200
            data = response.get_json()
            assert data["status"] in ["healthy", "ok"]

    def test_root_endpoint(self, aa_app):
        """Test AA root endpoint"""
        with aa_app.test_client() as client:
            response = client.get("/")
            assert response.status_code == 200
            data = response.get_json()
            assert data["entity_type"] == "AA"

    def test_authorization_request_requires_auth(self, aa_app):
        """Test authorization requires auth or rejects empty body"""
        with aa_app.test_client() as client:
            response = client.post(
                "/authorization/request",
                headers={"Content-Type": "application/octet-stream"},
            )
            assert response.status_code in [400, 401]

    def test_authorization_butterfly_endpoint_exists(self, aa_app):
        """Test butterfly endpoint exists"""
        with aa_app.test_client() as client:
            response = client.post(
                "/authorization/request/butterfly",
                headers={
                    "Authorization": "Bearer test-api-key-456",
                    "Content-Type": "application/octet-stream",
                },
            )
            # Will fail validation but endpoint exists
            assert response.status_code in [400, 500]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
