"""
Test suite per le entità PKI (RootCA, EA, AA)

Testa le funzionalità principali di:
- Root Certificate Authority (RootCA)
- Enrollment Authority (EA)
- Authorization Authority (AA)
"""

import pytest
import os
import shutil
from pathlib import Path
from datetime import datetime, timezone, timedelta

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority


@pytest.fixture
def test_data_dir():
    """Crea directory temporanea per i test"""
    test_dir = Path("./test_data_pki")
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


class TestRootCA:
    """Test per Root Certificate Authority"""

    def test_root_ca_initialization(self, root_ca):
        """Test inizializzazione Root CA"""
        assert root_ca is not None
        assert root_ca.certificate is not None
        assert root_ca.private_key is not None
        assert root_ca.crl_manager is not None

    def test_root_ca_certificate_validity(self, root_ca):
        """Test validità certificato Root CA"""
        cert = root_ca.certificate
        assert cert.not_valid_before_utc <= datetime.now(timezone.utc)
        assert cert.not_valid_after_utc > datetime.now(timezone.utc)

    def test_issue_subordinate_certificate(self, root_ca):
        """Test emissione certificato subordinato (EA/AA)"""
        # Genera chiave per subordinato
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        # Emetti certificato subordinato
        sub_cert = root_ca.issue_subordinate_certificate(
            subject_name="TestSubordinate",
            subject_type="EA",
            public_key=public_key,
            validity_days=365,
        )

        assert sub_cert is not None
        assert sub_cert.issuer == root_ca.certificate.subject
        assert "TestSubordinate" in sub_cert.subject.get_attributes_for_oid(
            sub_cert.subject.oid.COMMON_NAME
        )[0].value

    def test_revoke_certificate(self, root_ca):
        """Test revoca certificato"""
        # Genera e emetti un certificato
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend

        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()

        sub_cert = root_ca.issue_subordinate_certificate(
            subject_name="ToRevoke",
            subject_type="EA",
            public_key=public_key,
            validity_days=365,
        )

        serial_number = sub_cert.serial_number

        # Revoca il certificato
        result = root_ca.revoke_certificate(
            serial_number=serial_number, reason="cessationOfOperation"
        )

        assert result is True
        assert root_ca.crl_manager.is_revoked(serial_number) is True

    def test_get_crl(self, root_ca):
        """Test generazione CRL"""
        crl_pem = root_ca.get_crl()
        assert crl_pem is not None
        assert b"BEGIN X509 CRL" in crl_pem


class TestEnrollmentAuthority:
    """Test per Enrollment Authority"""

    def test_ea_initialization(self, root_ca, test_data_dir):
        """Test inizializzazione EA"""
        ea_dir = test_data_dir / "ea" / "EA_TEST"
        ea = EnrollmentAuthority(
            ea_id="EA_TEST",
            base_dir=str(ea_dir),
            root_ca_cert_path=str(
                Path(root_ca.cert_path).parent.parent / "certificates" / "root_ca_certificate.pem"
            ),
            root_ca=root_ca,
        )

        assert ea is not None
        assert ea.certificate is not None
        assert ea.private_key is not None
        assert ea.root_ca_cert is not None
        assert ea.crl_manager is not None

    def test_ea_issue_enrollment_certificate(self, root_ca, test_data_dir):
        """Test emissione Enrollment Certificate"""
        ea_dir = test_data_dir / "ea" / "EA_TEST"
        ea = EnrollmentAuthority(
            ea_id="EA_TEST",
            base_dir=str(ea_dir),
            root_ca_cert_path=str(
                Path(root_ca.cert_path).parent.parent / "certificates" / "root_ca_certificate.pem"
            ),
            root_ca=root_ca,
        )

        # Genera chiave per ITS-S
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend

        itss_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        itss_public_key = itss_private_key.public_key()

        # Emetti EC
        ec_cert = ea.issue_enrollment_certificate(
            itss_id="TestVehicle",
            public_key=itss_public_key,
            validity_days=365,
            attributes={"country": "IT", "organization": "Test"},
        )

        assert ec_cert is not None
        assert "TestVehicle" in ec_cert.subject.get_attributes_for_oid(
            ec_cert.subject.oid.COMMON_NAME
        )[0].value
        assert ec_cert.issuer == ea.certificate.subject

    def test_ea_revoke_enrollment_certificate(self, root_ca, test_data_dir):
        """Test revoca Enrollment Certificate"""
        ea_dir = test_data_dir / "ea" / "EA_TEST"
        ea = EnrollmentAuthority(
            ea_id="EA_TEST",
            base_dir=str(ea_dir),
            root_ca_cert_path=str(
                Path(root_ca.cert_path).parent.parent / "certificates" / "root_ca_certificate.pem"
            ),
            root_ca=root_ca,
        )

        # Emetti e revoca EC
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend

        itss_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        itss_public_key = itss_private_key.public_key()

        ec_cert = ea.issue_enrollment_certificate(
            itss_id="TestVehicleRevoke",
            public_key=itss_public_key,
            validity_days=365,
            attributes={"country": "IT", "organization": "Test"},
        )

        serial_number = ec_cert.serial_number

        # Revoca
        result = ea.revoke_enrollment_certificate(serial_number, reason="keyCompromise")

        assert result is True
        assert ea.crl_manager.is_revoked(serial_number) is True


class TestAuthorizationAuthority:
    """Test per Authorization Authority"""

    def test_aa_initialization(self, root_ca, test_data_dir):
        """Test inizializzazione AA"""
        aa_dir = test_data_dir / "aa" / "AA_TEST"
        aa = AuthorizationAuthority(
            aa_id="AA_TEST",
            base_dir=str(aa_dir),
            root_ca_cert_path=str(
                Path(root_ca.cert_path).parent.parent / "certificates" / "root_ca_certificate.pem"
            ),
            root_ca=root_ca,
        )

        assert aa is not None
        assert aa.certificate is not None
        assert aa.private_key is not None
        assert aa.root_ca_cert is not None
        assert aa.crl_manager is not None

    def test_aa_issue_authorization_ticket(self, root_ca, test_data_dir):
        """Test emissione Authorization Ticket"""
        aa_dir = test_data_dir / "aa" / "AA_TEST"
        aa = AuthorizationAuthority(
            aa_id="AA_TEST",
            base_dir=str(aa_dir),
            root_ca_cert_path=str(
                Path(root_ca.cert_path).parent.parent / "certificates" / "root_ca_certificate.pem"
            ),
            root_ca=root_ca,
        )

        # Genera chiave per AT
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend

        at_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        at_public_key = at_private_key.public_key()

        # Emetti AT
        at_cert = aa.issue_authorization_ticket(
            public_key=at_public_key,
            validity_days=7,
            attributes={"psid": "36"},
        )

        assert at_cert is not None
        assert at_cert.issuer == aa.certificate.subject
        # AT ha validità più breve
        validity_duration = at_cert.not_valid_after_utc - at_cert.not_valid_before_utc
        assert validity_duration <= timedelta(days=8)

    def test_aa_revoke_authorization_ticket(self, root_ca, test_data_dir):
        """Test revoca Authorization Ticket"""
        aa_dir = test_data_dir / "aa" / "AA_TEST"
        aa = AuthorizationAuthority(
            aa_id="AA_TEST",
            base_dir=str(aa_dir),
            root_ca_cert_path=str(
                Path(root_ca.cert_path).parent.parent / "certificates" / "root_ca_certificate.pem"
            ),
            root_ca=root_ca,
        )

        # Emetti e revoca AT
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.backends import default_backend

        at_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        at_public_key = at_private_key.public_key()

        at_cert = aa.issue_authorization_ticket(
            public_key=at_public_key,
            validity_days=7,
            attributes={"psid": "36"},
        )

        serial_number = at_cert.serial_number

        # Revoca
        result = aa.revoke_authorization_ticket(serial_number, reason="keyCompromise")

        assert result is True
        assert aa.crl_manager.is_revoked(serial_number) is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
