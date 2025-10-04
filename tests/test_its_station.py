"""
Test suite per ITS Station

Testa le funzionalità principali di:
- ITS Station (veicoli/dispositivi V2X)
- Gestione certificati (EC, AT)
- Comunicazione con EA e AA
"""

import pytest
import os
import shutil
from pathlib import Path

from entities.its_station import ITSStation
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority


@pytest.fixture
def test_data_dir():
    """Crea directory temporanea per i test"""
    test_dir = Path("./test_data_itss")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)
    yield test_dir
    # Cleanup dopo i test
    if test_dir.exists():
        shutil.rmtree(test_dir)


@pytest.fixture
def pki_infrastructure(test_data_dir):
    """Fixture per creare infrastruttura PKI completa"""
    # Root CA
    root_ca_path = test_data_dir / "root_ca"
    root_ca = RootCA(
        base_dir=str(root_ca_path)
    )

    # Enrollment Authority
    ea = EnrollmentAuthority(
        root_ca=root_ca,
        ea_id="EA_TEST",
        base_dir=str(test_data_dir / "ea"),
    )

    # Authorization Authority
    aa = AuthorizationAuthority(
        root_ca=root_ca,
        aa_id="AA_TEST",
        base_dir=str(test_data_dir / "aa"),
    )

    return {"root_ca": root_ca, "ea": ea, "aa": aa}


class TestITSStation:
    """Test per ITS Station"""

    def test_itss_initialization(self, test_data_dir):
        """Test inizializzazione ITS-S"""
        itss_dir = test_data_dir / "itss" / "TestVehicle"
        itss = ITSStation(
            its_id="TestVehicle",
            base_dir=str(itss_dir),
        )

        assert itss is not None
        assert itss.its_id == "TestVehicle"
        assert itss.base_dir == str(itss_dir)
        assert itss.message_encoder is not None

    def test_itss_generate_key_pair(self, test_data_dir):
        """Test generazione coppia di chiavi"""
        itss_dir = test_data_dir / "itss" / "TestVehicle"
        itss = ITSStation(
            its_id="TestVehicle",
            base_dir=str(itss_dir),
        )

        # Genera chiave
        private_key = itss.generate_key_pair()

        assert private_key is not None
        assert (itss_dir / "own_certificates" / "TestVehicle_key.pem").exists()

    def test_itss_request_enrollment_certificate(self, test_data_dir, pki_infrastructure):
        """Test richiesta Enrollment Certificate"""
        ea = pki_infrastructure["ea"]
        itss_dir = test_data_dir / "itss" / "TestVehicle"
        itss = ITSStation(
            its_id="TestVehicle",
            base_dir=str(itss_dir),
        )

        # Genera chiave
        itss.generate_key_pair()

        # Crea enrollment request
        enrollment_request = itss.create_enrollment_request(
            ea_public_key=ea.public_key,
            attributes={"country": "IT", "organization": "Test"},
        )

        assert enrollment_request is not None
        assert len(enrollment_request) > 0

        # Processa la request tramite EA
        enrollment_response = ea.process_enrollment_request(enrollment_request)

        assert enrollment_response is not None

        # ITS-S processa la response
        ec_cert = itss.process_enrollment_response(enrollment_response)

        assert ec_cert is not None
        assert (itss_dir / "own_certificates" / "TestVehicle_ec.pem").exists()

    def test_itss_request_authorization_ticket(self, test_data_dir, pki_infrastructure):
        """Test richiesta Authorization Ticket"""
        ea = pki_infrastructure["ea"]
        aa = pki_infrastructure["aa"]
        itss_dir = test_data_dir / "itss" / "TestVehicle"
        itss = ITSStation(
            its_id="TestVehicle",
            base_dir=str(itss_dir),
        )

        # Prima ottieni EC
        itss.generate_key_pair()
        enrollment_request = itss.create_enrollment_request(
            ea_public_key=ea.public_key,
            attributes={"country": "IT", "organization": "Test"},
        )
        enrollment_response = ea.process_enrollment_request(enrollment_request)
        itss.process_enrollment_response(enrollment_response)

        # Ora richiedi AT
        authorization_request = itss.create_authorization_request(
            aa_public_key=aa.public_key,
            attributes={},
        )

        assert authorization_request is not None
        assert len(authorization_request) > 0

        # Processa la request tramite AA
        authorization_response = aa.process_authorization_request(authorization_request)

        assert authorization_response is not None

        # ITS-S processa la response
        at_cert = itss.process_authorization_response(authorization_response)

        assert at_cert is not None
        # Verifica che AT sia salvato
        at_files = list((itss_dir / "received_tickets").glob("AT_*.pem"))
        assert len(at_files) > 0

    def test_itss_full_enrollment_authorization_flow(self, test_data_dir, pki_infrastructure):
        """Test flusso completo enrollment + authorization"""
        ea = pki_infrastructure["ea"]
        aa = pki_infrastructure["aa"]
        itss_dir = test_data_dir / "itss" / "TestVehicleFlow"
        itss = ITSStation(
            its_id="TestVehicleFlow",
            base_dir=str(itss_dir),
        )

        # 1. Genera chiave
        private_key = itss.generate_key_pair()
        assert private_key is not None

        # 2. Enrollment
        enrollment_request = itss.create_enrollment_request(
            ea_public_key=ea.public_key,
            attributes={"country": "IT", "organization": "TestOrg"},
        )
        enrollment_response = ea.process_enrollment_request(enrollment_request)
        ec_cert = itss.process_enrollment_response(enrollment_response)
        assert ec_cert is not None

        # 3. Authorization
        authorization_request = itss.create_authorization_request(
            aa_public_key=aa.public_key,
            attributes={},
        )
        authorization_response = aa.process_authorization_request(authorization_request)
        at_cert = itss.process_authorization_response(authorization_response)
        assert at_cert is not None

        # 4. Verifica file salvati
        assert (itss_dir / "own_certificates" / "TestVehicleFlow_key.pem").exists()
        assert (itss_dir / "own_certificates" / "TestVehicleFlow_ec.pem").exists()
        at_files = list((itss_dir / "received_tickets").glob("AT_*.pem"))
        assert len(at_files) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
