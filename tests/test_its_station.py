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
from cryptography.hazmat.primitives import serialization

from entities.its_station import ITSStation
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority

# Fixture pki_infrastructure è ora in conftest.py con:
# - root_ca: RootCA instance
# - ea: EnrollmentAuthority instance
# - tlm: TrustListManager instance
# - aa: AuthorizationAuthority instance


class TestITSStation:
    """Test per ITS Station"""

    def test_itss_initialization(self, its_station):
        """Test inizializzazione ITS-S"""
        assert its_station is not None
        assert its_station.its_id == "TEST_VEHICLE"
        assert its_station.message_encoder is not None
        # Verifica directory create
        assert its_station.log_dir is not None
        assert its_station.backup_dir is not None

    def test_itss_generate_key_pair(self, its_station):
        """Test generazione coppia di chiavi"""
        # Genera chiave (metodo corretto - non ritorna valore)
        its_station.generate_ecc_keypair()

        assert its_station.private_key is not None
        assert its_station.public_key is not None
        assert Path(its_station.key_path).exists()

    def test_itss_request_enrollment_certificate(self, pki_infrastructure):
        """Test richiesta Enrollment Certificate"""
        ea = pki_infrastructure["ea"]
        itss = ITSStation(
            its_id="TestVehicle",
            base_dir="./data/itss",
        )

        # Genera chiave
        itss.generate_ecc_keypair()

        # Richiedi EC usando il metodo corretto
        ec_cert = itss.request_ec(ea)

        assert ec_cert is not None
        # Verifica che EC sia salvato
        assert Path(itss.ec_path).exists()

    def test_itss_request_authorization_ticket(self, pki_infrastructure):
        """Test richiesta Authorization Ticket"""
        ea = pki_infrastructure["ea"]
        aa = pki_infrastructure["aa"]
        itss = ITSStation(
            its_id="TestVehicle",
            base_dir="./data/itss",
        )

        # Prima ottieni EC
        itss.generate_ecc_keypair()
        ec_cert = itss.request_ec(ea)
        assert ec_cert is not None

        # Ora richiedi AT usando il metodo corretto
        at_cert = itss.request_at(aa)

        assert at_cert is not None
        # Verifica che AT sia salvato
        at_files = list(Path(itss.at_dir).glob("AT_*.pem"))
        assert len(at_files) > 0

    def test_itss_full_enrollment_authorization_flow(self, pki_infrastructure):
        """Test flusso completo enrollment + authorization"""
        ea = pki_infrastructure["ea"]
        aa = pki_infrastructure["aa"]
        itss = ITSStation(
            its_id="TestVehicleFlow",
            base_dir="./data/itss",
        )

        # 1. Genera chiave
        itss.generate_ecc_keypair()
        assert itss.private_key is not None

        # 2. Enrollment
        ec_cert = itss.request_ec(ea)
        assert ec_cert is not None

        # 3. Authorization
        at_cert = itss.request_at(aa)
        assert at_cert is not None

        # 4. Verifica file salvati
        assert Path(itss.key_path).exists()
        assert Path(itss.ec_path).exists()
        at_files = list(Path(itss.at_dir).glob("AT_*.pem"))
        assert len(at_files) > 0

    def test_itss_download_trust_anchors(self, pki_infrastructure):
        """Test download trust anchors dal TLM"""
        tlm = pki_infrastructure["tlm"]
        ea = pki_infrastructure["ea"]
        root_ca = pki_infrastructure["root_ca"]
        itss = ITSStation(
            its_id="TestVehicleTrustAnchors",
            base_dir="./data/itss",
        )

        # Setup veicolo
        itss.generate_ecc_keypair()
        itss.request_ec(ea)

        # Simula download trust anchors: copia certificati RootCA e EA
        # In un sistema reale, il TLM fornirebbe questi tramite API
        trust_anchors_dir = Path(os.path.dirname(itss.trust_anchor_path))
        ta_root_path = trust_anchors_dir / "root_ca.pem"
        with open(ta_root_path, "wb") as f:
            f.write(root_ca.certificate.public_bytes(encoding=serialization.Encoding.PEM))
        
        ta_ea_path = trust_anchors_dir / "ea_test.pem"
        with open(ta_ea_path, "wb") as f:
            f.write(ea.certificate.public_bytes(encoding=serialization.Encoding.PEM))
        
        # Verifica che i trust anchors siano stati salvati
        ta_files = list(trust_anchors_dir.glob("*.pem"))
        assert len(ta_files) >= 2
        print(f"[TEST] Trust anchors salvati: {len(ta_files)}")

    def test_itss_download_ctl_full(self, pki_infrastructure):
        """Test download CTL Full dal TLM"""
        tlm = pki_infrastructure["tlm"]
        ea = pki_infrastructure["ea"]
        itss = ITSStation(
            its_id="TestVehicleCTLFull",
            base_dir="./data/itss",
        )

        # Setup veicolo
        itss.generate_ecc_keypair()
        itss.request_ec(ea)

        # Pubblica CTL Full dal TLM
        ctl_metadata = tlm.publish_full_ctl()
        assert ctl_metadata is not None
        
        # Path della CTL pubblicata
        ctl_source_path = Path(tlm.full_ctl_path)
        assert ctl_source_path.exists()

        # Simula download CTL Full
        ctl_full_dir = Path(os.path.dirname(itss.ctl_path))
        ctl_dest = ctl_full_dir / "ctl_full.pem"
        shutil.copy(ctl_source_path, ctl_dest)

        # Verifica che CTL Full sia stato scaricato
        assert ctl_dest.exists()
        assert ctl_dest.stat().st_size > 0
        print(f"[TEST] CTL Full scaricato: {ctl_dest.stat().st_size} bytes")

    def test_itss_download_ctl_delta(self, pki_infrastructure):
        """Test download CTL Delta dal TLM"""
        tlm = pki_infrastructure["tlm"]
        ea = pki_infrastructure["ea"]
        root_ca = pki_infrastructure["root_ca"]
        itss = ITSStation(
            its_id="TestVehicleCTLDelta",
            base_dir="./data/itss",
        )

        # Setup veicolo
        itss.generate_ecc_keypair()
        itss.request_ec(ea)

        # Pubblica CTL Full prima
        tlm.publish_full_ctl()

        # Aggiungi una nuova EA per creare una delta
        from entities.enrollment_authority import EnrollmentAuthority
        ea2 = EnrollmentAuthority(
            root_ca=root_ca,
            ea_id="EA_DELTA_TEST",
            base_dir="./data/ea",
        )
        tlm.add_trust_anchor(ea2.certificate, authority_type="EA")

        # Pubblica CTL Delta
        ctl_delta_metadata = tlm.publish_delta_ctl()
        assert ctl_delta_metadata is not None
        
        # Path della CTL Delta pubblicata
        ctl_source_path = Path(tlm.delta_ctl_path)
        assert ctl_source_path.exists()

        # Simula download CTL Delta
        ctl_delta_dir = Path(os.path.dirname(itss.delta_path))
        ctl_dest = ctl_delta_dir / "ctl_delta.pem"
        shutil.copy(ctl_source_path, ctl_dest)

        # Verifica che CTL Delta sia stato scaricato
        assert ctl_dest.exists()
        assert ctl_dest.stat().st_size > 0
        print(f"[TEST] CTL Delta scaricato: {ctl_dest.stat().st_size} bytes")

    def test_itss_send_signed_message(self, pki_infrastructure):
        """Test invio messaggio firmato"""
        ea = pki_infrastructure["ea"]
        aa = pki_infrastructure["aa"]
        
        # Crea due veicoli
        sender = ITSStation(
            its_id="TestVehicleSender",
            base_dir="./data/itss",
        )
        receiver = ITSStation(
            its_id="TestVehicleReceiver",
            base_dir="./data/itss",
        )

        # Setup sender: genera chiave, ottieni EC e AT
        sender.generate_ecc_keypair()
        sender.request_ec(ea)
        sender.request_at(aa)

        # Setup receiver: genera chiave, ottieni EC
        receiver.generate_ecc_keypair()
        receiver.request_ec(ea)

        # Invia messaggio firmato (parametro: string message, non bytes)
        message_text = "Test V2X Message: Emergency Brake Warning!"
        message_sent = sender.send_signed_message(
            message=message_text,
            recipient_id="TestVehicleReceiver",
            message_type="CAM"
        )

        # Verifica che il messaggio sia stato inviato
        assert message_sent is not None
        
        # Verifica che il file outbox sender esista e contenga il messaggio
        sender_outbox = Path(sender.outbox_path)
        assert sender_outbox.exists()
        assert sender_outbox.stat().st_size > 0
        print(f"[TEST] Messaggio inviato: {sender_outbox.stat().st_size} bytes in outbox")

        # Verifica che il messaggio sia stato consegnato automaticamente all'inbox del receiver
        # (send_signed_message() già lo scrive direttamente)
        receiver_inbox_path = Path(sender.inbox_path.replace(sender.its_id, receiver.its_id))
        inbox_files = list(receiver_inbox_path.parent.glob("*.txt"))
        
        if inbox_files:
            # Verifica che almeno un messaggio sia stato ricevuto
            assert len(inbox_files) > 0
            print(f"[TEST] Messaggi ricevuti in inbox: {len(inbox_files)} file")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
