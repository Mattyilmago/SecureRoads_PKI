import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from entities.root_ca import RootCA
from entities.authorization_authority import AuthorizationAuthority
from entities.enrollment_authority import EnrollmentAuthority
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import time

def main():
    print("=== TEST AUTHORIZATION AUTHORITY (AA) ===")
    
    print("\n1. Inizializzazione Root CA")
    root_ca = RootCA()
    
    print("\n2. Inizializzazione Enrollment Authority")
    ea = EnrollmentAuthority(root_ca)
    
    print("\n3. Inizializzazione Authorization Authority")
    aa = AuthorizationAuthority(ea.ea_certificate_path, root_ca)
    
    print("\n4. Verifica certificato AA")
    print(f"AA Subject: {aa.certificate.subject}")
    print(f"AA Serial: {aa.certificate.serial_number}")
    print(f"AA Validità: dal {aa.certificate.not_valid_before_utc} al {aa.certificate.not_valid_after_utc}")
    print(f"AA Issuer: {aa.certificate.issuer}")
    
    print("\n5. Test emissione primo Authorization Ticket")
    # Genera chiave per ITS-S che richiede AT
    its1_private_key = ec.generate_private_key(ec.SECP256R1())
    its1_public_key = its1_private_key.public_key()
    
    # Prima deve avere un EC dall'EA
    ec_cert1 = ea.issue_enrollment_certificate("Vehicle_AT_001", its1_public_key, 
                                              attributes={"region": "EU", "type": "passenger"})
    
    # Ora può richiedere un AT usando l'EC (flusso corretto)
    ec_pem1 = ec_cert1.public_bytes(serialization.Encoding.PEM)
    at_cert1 = aa.process_authorization_request(ec_pem1, "Vehicle_AT_001", 
                                              attributes={"permissions": ["CAM", "DENM"], "region": "EU"})
    
    if at_cert1:
        print(f"Authorization Ticket emesso con successo!")
        print(f"AT Serial: {at_cert1.serial_number}")
        print(f"AT Subject: {at_cert1.subject}")
        print(f"AT Validità: dal {at_cert1.not_valid_before_utc} al {at_cert1.not_valid_after_utc}")
    
    print("\n6. Test emissione secondo Authorization Ticket")
    # Genera seconda ITS-S
    its2_private_key = ec.generate_private_key(ec.SECP256R1())
    its2_public_key = its2_private_key.public_key()
    
    # EC per la seconda ITS-S
    ec_cert2 = ea.issue_enrollment_certificate("Vehicle_AT_002", its2_public_key, 
                                              attributes={"region": "EU", "type": "truck"})
    
    # AT per la seconda ITS-S usando l'EC (flusso corretto)
    ec_pem2 = ec_cert2.public_bytes(serialization.Encoding.PEM)
    at_cert2 = aa.process_authorization_request(ec_pem2, "Vehicle_AT_002", 
                                              attributes={"permissions": ["CAM", "DENM", "CPM"], "region": "EU"})
    
    print("\n7. Test emissione terzo Authorization Ticket")
    # Genera terza ITS-S
    its3_private_key = ec.generate_private_key(ec.SECP256R1())
    its3_public_key = its3_private_key.public_key()
    
    # EC per la terza ITS-S
    ec_cert3 = ea.issue_enrollment_certificate("Vehicle_AT_003", its3_public_key, 
                                              attributes={"region": "EU", "type": "emergency"})
    
    # AT per la terza ITS-S con permessi estesi usando l'EC (flusso corretto)
    ec_pem3 = ec_cert3.public_bytes(serialization.Encoding.PEM)
    at_cert3 = aa.process_authorization_request(ec_pem3, "Vehicle_AT_003", 
                                              attributes={"permissions": ["CAM", "DENM", "CPM", "VAM"], "region": "EU"})
    
    time.sleep(2)

    print("\n8. Test revoca primo Authorization Ticket")
    from cryptography.x509 import ReasonFlags
    aa.revoke_authorization_ticket(at_cert1, reason=ReasonFlags.key_compromise)
    
    time.sleep(2)

    print("\n9. Test revoca secondo certificato con motivo diverso")
    aa.revoke_authorization_ticket(at_cert2, reason=ReasonFlags.superseded)

    time.sleep(2)

    
    print("\n10. Test caricamento e verifica CRL AA")
    aa_crl = aa.load_crl()
    if aa_crl:
        revoked_list = list(aa_crl)
        print(f"CRL AA caricata con {len(revoked_list)} certificati revocati:")
        for revoked in revoked_list:
            print(f"  - Serial revocato: {revoked.serial_number}")
            print(f"    Data revoca: {revoked.revocation_date_utc}")
            # Verifica estensioni per il motivo
            if revoked.extensions:
                for ext in revoked.extensions:
                    if 'CRLReason' in str(ext.oid):
                        print(f"    Motivo: {ext.value.reason}")
    
    print("\n11. Test pubblicazione CRL aggiuntiva")
    aa.publish_crl()
    
    print("\n12. Test revoca terzo certificato")
    aa.revoke_authorization_ticket(at_cert3, reason=ReasonFlags.cessation_of_operation)
    
    print("\n13. Verifica finale stato AA")
    print(f"Authorization Tickets revocati in memoria: {len(aa.revoked)}")
    
    print("\n14. Verifica finale CRL AA")
    final_crl = aa.load_crl()
    if final_crl:
        final_revoked_list = list(final_crl)
        print(f"CRL AA finale con {len(final_revoked_list)} certificati revocati")
    
    print("\n=== TEST AUTHORIZATION AUTHORITY COMPLETATI ===")

if __name__ == "__main__":
    main()