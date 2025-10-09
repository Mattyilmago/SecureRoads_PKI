"""
Test Suite: PKI Core Entities (RootCA, EA, AA)

Tests all core PKI entity operations:
- RootCA: Certificate signing, revocation, CRL management
- EnrollmentAuthority: EC issuance, revocation
- AuthorizationAuthority: AT issuance, validation, revocation

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from entities.authorization_authority import AuthorizationAuthority
from entities.enrollment_authority import EnrollmentAuthority
from entities.root_ca import RootCA
from managers.trust_list_manager import TrustListManager

# Fixture root_ca, ea, aa sono ora in conftest.py


class TestRootCA:
    """Test RootCA operations"""

    def test_initialization(self, root_ca):
        """Test RootCA initialization"""
        assert root_ca is not None
        assert root_ca.certificate is not None
        assert root_ca.private_key is not None

    def test_certificate_validity(self, root_ca):
        """Test RootCA certificate validity"""
        cert = root_ca.certificate
        now = datetime.now(timezone.utc)
        valid_from = cert.not_valid_before.replace(tzinfo=timezone.utc)
        valid_to = cert.not_valid_after.replace(tzinfo=timezone.utc)
        assert valid_from <= now
        assert valid_to > now

    def test_has_attributes(self, root_ca):
        """Test RootCA has required attributes"""
        assert hasattr(root_ca, "ca_certificate_path")
        assert hasattr(root_ca, "ca_key_path")
        assert hasattr(root_ca, "crl_manager")

    def test_sign_subordinate(self, root_ca):
        """Test signing subordinate certificate"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        cert = root_ca.sign_certificate(public_key, "Test Subordinate", is_ca=True)
        
        assert cert is not None
        assert cert.issuer == root_ca.certificate.subject

    def test_revoke_certificate(self, root_ca):
        """Test certificate revocation"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        cert = root_ca.sign_certificate(public_key, "Test Revoke", is_ca=True)
        
        initial_count = len(root_ca.crl_manager.revoked_certificates)
        root_ca.crl_manager.add_revoked_certificate(cert)
        assert len(root_ca.crl_manager.revoked_certificates) > initial_count

    def test_publish_crl(self, root_ca):
        """Test CRL publication"""
        crl = root_ca.publish_full_crl(validity_days=7)
        assert crl is not None

    def test_crl_statistics(self, root_ca):
        """Test CRL statistics"""
        stats = root_ca.get_crl_statistics()
        assert stats is not None
        assert "crl_number" in stats


class TestEnrollmentAuthority:
    """Test EnrollmentAuthority operations"""

    def test_initialization(self, ea):
        """Test EA initialization"""
        assert ea is not None
        assert ea.certificate is not None
        assert ea.private_key is not None

    def test_issue_enrollment_certificate(self, ea):
        """Test EC issuance"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        cert = ea.issue_enrollment_certificate("TEST_ITS", public_key, {"country": "IT"})
        assert cert is not None
        assert cert.issuer == ea.certificate.subject

    def test_has_crl_manager(self, ea):
        """Test EA has CRL manager"""
        assert hasattr(ea, "crl_manager")
        assert ea.crl_manager is not None

    def test_revoke_enrollment_certificate(self, ea):
        """Test EC revocation"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        cert = ea.issue_enrollment_certificate("TEST_REVOKE", public_key)
        
        initial_count = len(ea.crl_manager.revoked_certificates)
        ea.revoke_enrollment_certificate(cert)
        assert len(ea.crl_manager.revoked_certificates) > initial_count

    def test_publish_crl(self, ea):
        """Test EA CRL publication"""
        crl = ea.crl_manager.publish_full_crl(validity_days=7)
        assert crl is not None


class TestAuthorizationAuthority:
    """Test AuthorizationAuthority operations"""

    def test_initialization(self, aa):
        """Test AA initialization"""
        assert aa is not None
        assert aa.certificate is not None
        assert aa.private_key is not None

    def test_has_tlm(self, aa):
        """Test AA has TLM"""
        assert hasattr(aa, "tlm")
        assert aa.tlm is not None

    def test_issue_authorization_ticket(self, aa):
        """Test AT issuance"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        
        ticket = aa.issue_authorization_ticket("TEST_ITS", public_key, {"psid": "36"})
        assert ticket is not None
        assert ticket.issuer == aa.certificate.subject

    def test_revoke_authorization_ticket(self, aa):
        """Test AT revocation"""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        ticket = aa.issue_authorization_ticket("TEST_REVOKE_AT", public_key)
        
        initial_count = len(aa.crl_manager.revoked_certificates)
        aa.revoke_authorization_ticket(ticket)
        assert len(aa.crl_manager.revoked_certificates) > initial_count

    def test_publish_crl(self, aa):
        """Test AA CRL publication"""
        crl = aa.crl_manager.publish_full_crl(validity_days=7)
        assert crl is not None


class TestDirectoryStructure:
    """Test directory structure creation"""

    def test_root_ca_directories(self, root_ca):
        """Test RootCA creates directories"""
        import os
        # Usa i path dalle istanze invece di hardcoded paths
        assert os.path.exists(os.path.dirname(root_ca.ca_certificate_path))
        assert os.path.exists(os.path.dirname(root_ca.ca_key_path))
        assert os.path.exists(root_ca.crl_manager.crl_dir)

    def test_ea_directories(self, ea):
        """Test EA creates directories"""
        import os
        # Usa i path dalle istanze invece di hardcoded paths
        assert os.path.exists(os.path.dirname(ea.ea_certificate_path))
        assert os.path.exists(os.path.dirname(ea.ea_key_path))
        assert os.path.exists(ea.ec_dir)
        assert os.path.exists(ea.crl_manager.crl_dir)

    def test_aa_directories(self, aa):
        """Test AA creates directories"""
        import os
        # Usa i path dalle istanze invece di hardcoded paths
        assert os.path.exists(os.path.dirname(aa.aa_certificate_path))
        assert os.path.exists(os.path.dirname(aa.aa_key_path))
        assert os.path.exists(aa.ticket_dir)  # ticket_dir non at_dir
        assert os.path.exists(aa.crl_manager.crl_dir)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
