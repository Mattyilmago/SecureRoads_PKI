import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from entities.its_station import ITSStation
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509

def main():
    print("=== TEST ITS STATION ===")
    
    print("\n1. Inizializzazione infrastruttura PKI")
    root_ca = RootCA()
    ea = EnrollmentAuthority(root_ca)
    aa = AuthorizationAuthority(ea.ea_certificate_path, root_ca)
    
    print("\n2. Inizializzazione prima ITS Station")
    its_id_1 = "Vehicle_001"
    itss1 = ITSStation(its_id_1)
    
    print("\n3. Test generazione chiavi ECC per ITS Station")
    itss1.generate_ecc_keypair()
    print(f"Chiave privata generata per {its_id_1}")
    
    print("\n4. Test richiesta Enrollment Certificate")
    ec_cert1 = itss1.request_ec(ea)
    if ec_cert1:
        print(f"Enrollment Certificate ottenuto per {its_id_1}")
        print(f"EC Serial: {ec_cert1.serial_number}")
        print(f"EC Subject: {ec_cert1.subject}")
    
    print("\n5. Test richiesta Authorization Ticket")
    at_cert1 = itss1.request_at(aa, permissions=["CAM", "DENM"], region="EU")
    if at_cert1:
        print(f"Authorization Ticket ottenuto per {its_id_1}")
        print(f"AT Serial: {at_cert1.serial_number}")
        print(f"AT Subject: {at_cert1.subject}")
    
    print("\n6. Inizializzazione seconda ITS Station")
    its_id_2 = "Vehicle_002"
    itss2 = ITSStation(its_id_2)
    itss2.generate_ecc_keypair()
    
    print("\n7. Enrollment e Authorization per seconda ITS Station")
    ec_cert2 = itss2.request_ec(ea)
    at_cert2 = itss2.request_at(aa, permissions=["CAM", "DENM", "CPM"], region="EU")
    
    print("\n8. Test invio messaggio firmato")
    message_content = "Ciao da Vehicle_001! Questo è un messaggio CAM di test."
    success = itss1.send_signed_message(message_content, its_id_2, message_type="CAM")
    if success:
        print(f"Messaggio inviato con successo da {its_id_1} a {its_id_2}")
    
    print("\n9. Test ricezione messaggio firmato")
    received_messages = itss2.receive_signed_message()
    if received_messages:
        print(f"Messaggi ricevuti da {its_id_2}:")
        for i, msg in enumerate(received_messages, 1):
            print(f"  {i}. {msg}")
    
    print("\n10. Test invio risposta")
    response_message = "Messaggio ricevuto! Risposta da Vehicle_002."
    itss2.send_signed_message(response_message, its_id_1, message_type="DENM")
    
    print("\n11. Test ricezione risposta")
    responses = itss1.receive_signed_message()
    if responses:
        print(f"Risposte ricevute da {its_id_1}:")
        for i, resp in enumerate(responses, 1):
            print(f"  {i}. {resp}")
    
    print("\n12. Test aggiornamento trust anchors")
    # Test caricamento certificato Root CA come trust anchor
    itss1.update_trust_anchors([root_ca.certificate])
    itss2.update_trust_anchors([root_ca.certificate])
    print("Trust anchors aggiornati per entrambe le ITS Stations")
    
    print("\n13. Test validazione certificati")
    # Test validazione del certificato EA contro Root CA
    ea_valid = itss1.validate_certificate_chain(ea.certificate)
    print(f"Certificato EA validato: {ea_valid}")
    
    # Test validazione del certificato AA contro Root CA
    aa_valid = itss1.validate_certificate_chain(aa.certificate)
    print(f"Certificato AA validato: {aa_valid}")
    
    print("\n14. Test terza ITS Station con workflow completo")
    its_id_3 = "Emergency_001"
    itss3 = ITSStation(its_id_3)
    
    # Workflow completo: generazione chiavi → EC → AT → invio messaggio
    itss3.generate_ecc_keypair()
    ec_cert3 = itss3.request_ec(ea)
    at_cert3 = itss3.request_at(aa, permissions=["CAM", "DENM", "CPM", "VAM"], region="EU")
    
    # Messaggio di emergenza
    emergency_msg = "ATTENZIONE: Veicolo di emergenza in arrivo! Liberare la strada."
    itss3.send_signed_message(emergency_msg, its_id_1, message_type="VAM")
    itss3.send_signed_message(emergency_msg, its_id_2, message_type="VAM")
    
    print(f"\n15. Verifica messaggi di emergenza ricevuti")
    emergency_msgs_1 = itss1.receive_signed_message()
    emergency_msgs_2 = itss2.receive_signed_message()
    
    print(f"Vehicle_001 ha ricevuto {len(emergency_msgs_1)} nuovi messaggi")
    print(f"Vehicle_002 ha ricevuto {len(emergency_msgs_2)} nuovi messaggi")
    
    print("\n16. Statistiche finali")
    print(f"ITS Stations attive: 3")
    print(f"Enrollment Certificates emessi: 3")
    print(f"Authorization Tickets emessi: 3") 
    print(f"Messaggi scambiati: multipli CAM/DENM/VAM")
    
    print("\n=== TEST ITS STATION COMPLETATI ===")

if __name__ == "__main__":
    main()