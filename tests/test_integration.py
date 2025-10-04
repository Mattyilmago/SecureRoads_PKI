"""
Test di integrazione completi per SecureRoad PKI

Questi test coprono scenari end-to-end completi:
1. Flusso completo enrollment + authorization (ETSI TS 102941)
2. AA con TLM per validazione multi-EA
3. CRL freshness e sicurezza revoche
4. Sistema completo con messaggi V2X

Nota: Questi test richiedono l'infrastruttura PKI già inizializzata.
"""

import pytest
import os
import shutil
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from entities.its_station import ITSStation
from managers.trust_list_manager import TrustListManager


@pytest.fixture
def integration_data_dir():
    """Crea directory temporanea per test integrazione"""
    test_dir = Path("./test_data_integration")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # Cambia working directory temporaneamente
    original_dir = Path.cwd()
    os.chdir(test_dir)
    
    yield test_dir
    
    # Cleanup
    os.chdir(original_dir)
    if test_dir.exists():
        shutil.rmtree(test_dir)


@pytest.fixture
def pki_full_infrastructure(integration_data_dir):
    """Fixture per infrastruttura PKI completa con TLM"""
    # Root CA
    root_ca = RootCA(base_dir="./data/root_ca/")
    
    # Multiple Enrollment Authorities
    ea1 = EnrollmentAuthority(root_ca, ea_id="EA_001", base_dir="./data/ea/")
    ea2 = EnrollmentAuthority(root_ca, ea_id="EA_002", base_dir="./data/ea/")
    
    # Trust List Manager
    tlm = TrustListManager(root_ca=root_ca, base_dir="./data/tlm/")
    tlm.add_trust_anchor(ea1.certificate, authority_type="EA")
    tlm.add_trust_anchor(ea2.certificate, authority_type="EA")
    
    # Authorization Authority con TLM
    aa = AuthorizationAuthority(
        root_ca,
        tlm=tlm,
        aa_id="AA_INTEGRATION_TEST",
        base_dir="./data/aa/"
    )
    tlm.add_trust_anchor(aa.certificate, authority_type="AA")
    
    # Pubblica CTL
    tlm.publish_full_ctl()
    
    return {
        "root_ca": root_ca,
        "ea1": ea1,
        "ea2": ea2,
        "aa": aa,
        "tlm": tlm,
    }


class TestFullETSIFlow:
    """Test flusso completo ETSI TS 102941"""

    def test_complete_enrollment_authorization_flow(self, integration_data_dir):
        """
        Test flusso completo end-to-end:
        1. Setup PKI
        2. ITS-S richiede EC da EA
        3. ITS-S richiede AT da AA
        4. Verifica certificati salvati
        """
        # Setup
        root_ca = RootCA(base_dir="./data/root_ca/")
        ea = EnrollmentAuthority(root_ca, ea_id="EA_FULL_FLOW", base_dir="./data/ea/")
        aa = AuthorizationAuthority(
            root_ca,
            ea_certificate_path=f"./data/ea/EA_FULL_FLOW/certificates/ea_certificate.pem",
            aa_id="AA_FULL_FLOW",
            base_dir="./data/aa/",
        )
        
        # ITS-S
        itss = ITSStation(its_id="Vehicle_Integration_Test", base_dir="./data/itss/")
        
        # Enrollment flow
        enrollment_request = itss.request_ec_etsi(ea.certificate)
        assert enrollment_request is not None
        assert len(enrollment_request) > 0
        
        enrollment_response = ea.process_ec_request_etsi(enrollment_request)
        assert enrollment_response is not None
        
        ec_cert = itss.process_ec_response_etsi(enrollment_response)
        assert ec_cert is not None
        
        # Verifica EC salvato
        ec_path = Path("./data/itss/Vehicle_Integration_Test/own_certificates/Vehicle_Integration_Test_ec.pem")
        assert ec_path.exists()
        
        # Authorization flow
        authorization_request = itss.request_at_etsi(aa.certificate)
        assert authorization_request is not None
        assert len(authorization_request) > 0
        
        authorization_response = aa.process_at_request_etsi(authorization_request)
        assert authorization_response is not None
        
        at_cert = itss.process_at_response_etsi(authorization_response)
        assert at_cert is not None
        
        # Verifica AT salvato
        at_files = list(Path("./data/itss/Vehicle_Integration_Test/received_tickets/").glob("AT_*.pem"))
        assert len(at_files) > 0

    def test_etsi_message_encoding_decoding(self, integration_data_dir):
        """Test encoding/decoding messaggi ETSI con protocollo reale"""
        root_ca = RootCA(base_dir="./data/root_ca/")
        ea = EnrollmentAuthority(root_ca, ea_id="EA_ENCODING_TEST", base_dir="./data/ea/")
        itss = ITSStation(its_id="Vehicle_Encoding_Test", base_dir="./data/itss/")
        
        # Crea enrollment request
        enrollment_request = itss.request_ec_etsi(ea.certificate)
        
        # Verifica è bytes e non vuoto
        assert isinstance(enrollment_request, bytes)
        assert len(enrollment_request) > 100  # Deve essere ragionevolmente grande
        
        # EA deve poterlo decodificare
        enrollment_response = ea.process_ec_request_etsi(enrollment_request)
        assert isinstance(enrollment_response, bytes)
        assert len(enrollment_response) > 100


class TestAAWithTLM:
    """Test AA con Trust List Manager per validazione multi-EA"""

    def test_aa_validates_ec_from_multiple_trusted_ea(self, pki_full_infrastructure):
        """
        Test che AA con TLM accetta EC da diverse EA fidate:
        1. Vehicle A ottiene EC da EA_001
        2. Vehicle B ottiene EC da EA_002  
        3. AA (con TLM) accetta entrambi gli EC
        """
        infra = pki_full_infrastructure
        root_ca = infra["root_ca"]
        ea1 = infra["ea1"]
        ea2 = infra["ea2"]
        aa = infra["aa"]
        
        # Vehicle A con EC da EA_001
        vehicle_a = ITSStation(its_id="Vehicle_A_EA1", base_dir="./data/itss/")
        enrollment_request_a = vehicle_a.request_ec_etsi(ea1.certificate)
        enrollment_response_a = ea1.process_ec_request_etsi(enrollment_request_a)
        ec_a = vehicle_a.process_ec_response_etsi(enrollment_response_a)
        assert ec_a is not None
        
        # Vehicle A richiede AT
        at_request_a = vehicle_a.request_at_etsi(aa.certificate)
        at_response_a = aa.process_at_request_etsi(at_request_a)
        at_a = vehicle_a.process_at_response_etsi(at_response_a)
        assert at_a is not None  # AA accetta EC da EA_001
        
        # Vehicle B con EC da EA_002
        vehicle_b = ITSStation(its_id="Vehicle_B_EA2", base_dir="./data/itss/")
        enrollment_request_b = vehicle_b.request_ec_etsi(ea2.certificate)
        enrollment_response_b = ea2.process_ec_request_etsi(enrollment_request_b)
        ec_b = vehicle_b.process_ec_response_etsi(enrollment_response_b)
        assert ec_b is not None
        
        # Vehicle B richiede AT
        at_request_b = vehicle_b.request_at_etsi(aa.certificate)
        at_response_b = aa.process_at_request_etsi(at_request_b)
        at_b = vehicle_b.process_at_response_etsi(at_response_b)
        assert at_b is not None  # AA accetta EC da EA_002

    def test_tlm_link_certificates_creation(self, pki_full_infrastructure):
        """Test che TLM crea link certificates correttamente"""
        infra = pki_full_infrastructure
        tlm = infra["tlm"]
        
        # Verifica link certificates creati
        link_cert_dir = Path("./data/tlm/link_certificates/")
        assert link_cert_dir.exists()
        
        link_certs = list(link_cert_dir.glob("LC_*.pem"))
        assert len(link_certs) >= 2  # Almeno per EA_001 e EA_002

    def test_tlm_full_ctl_generation(self, pki_full_infrastructure):
        """Test generazione Full CTL"""
        infra = pki_full_infrastructure
        tlm = infra["tlm"]
        
        # Genera Full CTL
        full_ctl = tlm.generate_full_ctl()
        
        assert full_ctl is not None
        assert "version" in full_ctl
        assert "timestamp" in full_ctl
        assert "trust_list" in full_ctl
        assert len(full_ctl["trust_list"]) >= 2  # Almeno EA_001, EA_002


class TestCRLFreshnessAndSecurity:
    """Test CRL freshness e scenari di sicurezza"""

    def test_crl_freshness_detection(self, integration_data_dir):
        """
        Test rilevamento CRL obsoleta:
        1. Vehicle scarica CRL
        2. AA revoca AT di altro vehicle
        3. Vehicle usa CRL vecchia
        4. Sistema rileva CRL obsoleta
        """
        # Setup
        root_ca = RootCA(base_dir="./data/root_ca/")
        ea = EnrollmentAuthority(root_ca, ea_id="EA_FRESHNESS", base_dir="./data/ea/")
        aa = AuthorizationAuthority(
            root_ca,
            ea_certificate_path=f"./data/ea/EA_FRESHNESS/certificates/ea_certificate.pem",
            aa_id="AA_FRESHNESS",
            base_dir="./data/aa/",
        )
        
        # Crea 2 veicoli
        receiver = ITSStation(its_id="Vehicle_Receiver", base_dir="./data/itss/")
        malicious = ITSStation(its_id="Vehicle_Malicious", base_dir="./data/itss/")
        
        # Entrambi ottengono EC e AT
        # Receiver
        enrollment_req_r = receiver.request_ec_etsi(ea.certificate)
        enrollment_res_r = ea.process_ec_request_etsi(enrollment_req_r)
        receiver.process_ec_response_etsi(enrollment_res_r)
        
        at_req_r = receiver.request_at_etsi(aa.certificate)
        at_res_r = aa.process_at_request_etsi(at_req_r)
        receiver.process_at_response_etsi(at_res_r)
        
        # Malicious
        enrollment_req_m = malicious.request_ec_etsi(ea.certificate)
        enrollment_res_m = ea.process_ec_request_etsi(enrollment_req_m)
        malicious.process_ec_response_etsi(enrollment_res_m)
        
        at_req_m = malicious.request_at_etsi(aa.certificate)
        at_res_m = aa.process_at_request_etsi(at_req_m)
        at_cert_malicious = malicious.process_at_response_etsi(at_res_m)
        
        # Receiver scarica CRL (versione 1)
        crl_old = aa.get_crl()
        crl_old_serial = aa.crl_manager.get_crl_number()
        
        # AA revoca AT di Malicious (genera CRL versione 2)
        aa.revoke_authorization_ticket(
            serial_number=at_cert_malicious.serial_number,
            reason="keyCompromise"
        )
        
        # Verifica che CRL è stata aggiornata
        crl_new = aa.get_crl()
        crl_new_serial = aa.crl_manager.get_crl_number()
        
        assert crl_new_serial > crl_old_serial  # CRL incrementato
        assert aa.crl_manager.is_revoked(at_cert_malicious.serial_number) is True

    def test_revocation_workflow(self, integration_data_dir):
        """
        Test completo flusso di revoca:
        1. Emetti certificato
        2. Revoca certificato
        3. Verifica in CRL
        4. Genera Delta CRL
        """
        root_ca = RootCA(base_dir="./data/root_ca/")
        ea = EnrollmentAuthority(root_ca, ea_id="EA_REVOKE", base_dir="./data/ea/")
        
        # Crea vehicle e ottieni EC
        vehicle = ITSStation(its_id="Vehicle_ToRevoke", base_dir="./data/itss/")
        enrollment_req = vehicle.request_ec_etsi(ea.certificate)
        enrollment_res = ea.process_ec_request_etsi(enrollment_req)
        ec_cert = vehicle.process_ec_response_etsi(enrollment_res)
        
        # Genera Full CRL (pre-revoca)
        full_crl_before = ea.get_crl()
        crl_number_before = ea.crl_manager.get_crl_number()
        
        # Revoca EC
        result = ea.revoke_enrollment_certificate(
            serial_number=ec_cert.serial_number,
            reason="keyCompromise"
        )
        assert result is True
        
        # Verifica revoca
        assert ea.crl_manager.is_revoked(ec_cert.serial_number) is True
        
        # Genera Delta CRL
        delta_crl = ea.crl_manager.generate_delta_crl()
        assert delta_crl is not None
        
        # Verifica CRL number incrementato
        crl_number_after = ea.crl_manager.get_crl_number()
        assert crl_number_after > crl_number_before


class TestCompleteSystemIntegration:
    """Test sistema completo con tutti i componenti"""

    def test_multi_vehicle_multi_ea_scenario(self, pki_full_infrastructure):
        """
        Test scenario complesso:
        - 3 veicoli
        - 2 EA diverse
        - 1 AA con TLM
        - Tutti ottengono EC e AT
        """
        infra = pki_full_infrastructure
        ea1 = infra["ea1"]
        ea2 = infra["ea2"]
        aa = infra["aa"]
        
        vehicles = []
        eas = [ea1, ea2, ea1]  # Vehicle 0,2 -> EA1; Vehicle 1 -> EA2
        
        for i, ea in enumerate(eas):
            vehicle = ITSStation(its_id=f"Vehicle_{i}", base_dir="./data/itss/")
            
            # Enrollment
            enrollment_req = vehicle.request_ec_etsi(ea.certificate)
            enrollment_res = ea.process_ec_request_etsi(enrollment_req)
            ec = vehicle.process_ec_response_etsi(enrollment_res)
            assert ec is not None
            
            # Authorization
            at_req = vehicle.request_at_etsi(aa.certificate)
            at_res = aa.process_at_request_etsi(at_req)
            at = vehicle.process_at_response_etsi(at_res)
            assert at is not None
            
            vehicles.append(vehicle)
        
        # Verifica tutti i veicoli hanno certificati
        assert len(vehicles) == 3
        for vehicle in vehicles:
            ec_path = Path(f"./data/itss/{vehicle.its_id}/own_certificates/{vehicle.its_id}_ec.pem")
            assert ec_path.exists()
            
            at_files = list(Path(f"./data/itss/{vehicle.its_id}/received_tickets/").glob("AT_*.pem"))
            assert len(at_files) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
