"""
Test suite per Managers (CRL Manager, Trust List Manager)

Testa le funzionalità principali di:
- CRL Manager (gestione Certificate Revocation Lists)
- Trust List Manager (gestione CTL - Certificate Trust Lists)
"""

import pytest
import os
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import hashes

from managers.crl_manager import CRLManager
from managers.trust_list_manager import TrustListManager
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority


@pytest.fixture
def test_data_dir():
    """Crea directory temporanea per i test"""
    test_dir = Path("./test_data_managers")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)
    yield test_dir
    # Cleanup dopo i test
    if test_dir.exists():
        shutil.rmtree(test_dir)


@pytest.fixture
def root_ca(test_data_dir):
    """Fixture per creare una Root CA di test"""
    root_ca_path = test_data_dir / "root_ca"
    root_ca = RootCA(
        base_dir=str(root_ca_path)
    )
    return root_ca


class TestCRLManager:
    """Test per CRL Manager"""

    def test_crl_manager_initialization(self, test_data_dir):
        """Test inizializzazione CRL Manager"""
        crl_path = test_data_dir / "test_crl.pem"
        metadata_path = test_data_dir / "crl_metadata.json"

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        # Crea issuer certificate
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, "TestIssuer"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        crl_manager = CRLManager(
            crl_path=str(crl_path),
            metadata_path=str(metadata_path),
            issuer_cert=cert,
            issuer_key=private_key,
            issuer_name="TestIssuer",
        )

        assert crl_manager is not None
        assert crl_manager.crl_path == str(crl_path)
        assert crl_manager.issuer_name == "TestIssuer"

    def test_crl_manager_add_revocation(self, test_data_dir):
        """Test aggiunta certificato revocato"""
        crl_path = test_data_dir / "test_crl.pem"
        metadata_path = test_data_dir / "crl_metadata.json"

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        # Crea issuer certificate
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, "TestIssuer"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        crl_manager = CRLManager(
            crl_path=str(crl_path),
            metadata_path=str(metadata_path),
            issuer_cert=cert,
            issuer_key=private_key,
            issuer_name="TestIssuer",
        )

        # Aggiungi revoca
        serial_to_revoke = 12345678901234567890
        result = crl_manager.add_revocation(
            serial_number=serial_to_revoke, reason="keyCompromise"
        )

        assert result is True
        assert crl_manager.is_revoked(serial_to_revoke) is True

    def test_crl_manager_generate_full_crl(self, test_data_dir):
        """Test generazione Full CRL"""
        crl_path = test_data_dir / "test_crl.pem"
        metadata_path = test_data_dir / "crl_metadata.json"

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        # Crea issuer certificate
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, "TestIssuer"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        crl_manager = CRLManager(
            crl_path=str(crl_path),
            metadata_path=str(metadata_path),
            issuer_cert=cert,
            issuer_key=private_key,
            issuer_name="TestIssuer",
        )

        # Aggiungi alcune revoche
        crl_manager.add_revocation(11111, "keyCompromise")
        crl_manager.add_revocation(22222, "cessationOfOperation")

        # Genera Full CRL
        crl_pem = crl_manager.generate_full_crl()

        assert crl_pem is not None
        assert b"BEGIN X509 CRL" in crl_pem
        assert crl_path.exists()

    def test_crl_manager_generate_delta_crl(self, test_data_dir):
        """Test generazione Delta CRL"""
        crl_path = test_data_dir / "test_crl.pem"
        metadata_path = test_data_dir / "crl_metadata.json"

        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        # Crea issuer certificate
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
                x509.NameAttribute(NameOID.COMMON_NAME, "TestIssuer"),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256(), default_backend())
        )

        crl_manager = CRLManager(
            crl_path=str(crl_path),
            metadata_path=str(metadata_path),
            issuer_cert=cert,
            issuer_key=private_key,
            issuer_name="TestIssuer",
        )

        # Genera Full CRL prima
        crl_manager.add_revocation(11111, "keyCompromise")
        crl_manager.generate_full_crl()

        # Aggiungi nuove revoche
        crl_manager.add_revocation(33333, "cessationOfOperation")

        # Genera Delta CRL
        delta_crl_pem = crl_manager.generate_delta_crl()

        assert delta_crl_pem is not None
        assert b"BEGIN X509 CRL" in delta_crl_pem


class TestTrustListManager:
    """Test per Trust List Manager"""

    def test_tlm_initialization(self, test_data_dir, root_ca):
        """Test inizializzazione TLM"""
        tlm_dir = test_data_dir / "tlm"
        tlm = TrustListManager(
            root_ca=root_ca,
            base_dir=str(tlm_dir),
        )

        assert tlm is not None
        assert tlm.base_dir == str(tlm_dir)

    def test_tlm_add_trusted_ea(self, test_data_dir, root_ca):
        """Test aggiunta EA alla trust list"""
        tlm_dir = test_data_dir / "tlm"
        tlm = TrustListManager(
            root_ca=root_ca,
            base_dir=str(tlm_dir),
        )

        # Crea EA
        ea = EnrollmentAuthority(
            root_ca=root_ca,
            ea_id="EA_TLM_TEST",
            base_dir=str(test_data_dir / "ea"),
        )

        # Aggiungi EA al TLM
        result = tlm.add_trusted_ea(
            ea_cert_path=str(test_data_dir / "ea" / "EA_TLM_TEST" / "certificates" / "ea_certificate.pem")
        )

        assert result is True

    def test_tlm_add_trusted_aa(self, test_data_dir, root_ca):
        """Test aggiunta AA alla trust list"""
        tlm_dir = test_data_dir / "tlm"
        tlm = TrustListManager(
            root_ca=root_ca,
            base_dir=str(tlm_dir),
        )

        # Crea AA
        from entities.authorization_authority import AuthorizationAuthority

        aa = AuthorizationAuthority(
            root_ca=root_ca,
            aa_id="AA_TLM_TEST",
            base_dir=str(test_data_dir / "aa"),
        )

        # Aggiungi AA al TLM
        result = tlm.add_trusted_aa(
            aa_cert_path=str(test_data_dir / "aa" / "AA_TLM_TEST" / "certificates" / "aa_certificate.pem")
        )

        assert result is True

    def test_tlm_generate_full_ctl(self, test_data_dir, root_ca):
        """Test generazione Full CTL"""
        tlm_dir = test_data_dir / "tlm"
        tlm = TrustListManager(
            root_ca=root_ca,
            base_dir=str(tlm_dir),
        )

        # Aggiungi alcune entità
        ea = EnrollmentAuthority(
            root_ca=root_ca,
            ea_id="EA_CTL_TEST",
            base_dir=str(test_data_dir / "ea"),
        )

        tlm.add_trusted_ea(str(test_data_dir / "ea" / "EA_CTL_TEST" / "certificates" / "ea_certificate.pem"))

        # Genera Full CTL
        full_ctl = tlm.generate_full_ctl()

        assert full_ctl is not None
        assert "version" in full_ctl
        assert "trusted_list" in full_ctl

    def test_tlm_generate_delta_ctl(self, test_data_dir, root_ca):
        """Test generazione Delta CTL"""
        tlm_dir = test_data_dir / "tlm"
        tlm = TrustListManager(
            root_ca=root_ca,
            base_dir=str(tlm_dir),
        )

        # Genera Full CTL prima
        full_ctl = tlm.generate_full_ctl()

        # Aggiungi nuova entità
        ea = EnrollmentAuthority(
            root_ca=root_ca,
            ea_id="EA_DELTA_TEST",
            base_dir=str(test_data_dir / "ea"),
        )

        tlm.add_trusted_ea(str(test_data_dir / "ea" / "EA_DELTA_TEST" / "certificates" / "ea_certificate.pem"))

        # Genera Delta CTL
        delta_ctl = tlm.generate_delta_ctl()

        assert delta_ctl is not None
        assert "version" in delta_ctl


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
