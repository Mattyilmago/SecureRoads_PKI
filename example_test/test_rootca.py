import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from entities.root_ca import RootCA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
import time

def main():
    print("=== TEST ROOT CA ===")
    
    print("\n1. Inizializzazione Root CA")
    root_ca = RootCA()
    
    print("\n2. Verifica certificato Root CA caricato")
    print(f"Subject: {root_ca.certificate.subject}")
    print(f"Serial Number: {root_ca.certificate.serial_number}")
    print(f"Validità: dal {root_ca.certificate.not_valid_before} al {root_ca.certificate.not_valid_after}")
    
    print("\n3. Test firma certificato subordinato CA (Enrollment Authority)")
    # Genera chiave per Enrollment Authority
    ea_private_key = ec.generate_private_key(ec.SECP256R1())
    ea_public_key = ea_private_key.public_key()
    
    # Firma certificato EA come CA
    ea_certificate = root_ca.sign_certificate(
        subject_public_key=ea_public_key,
        subject_name="EnrollmentAuthority_Test",
        is_ca=True
    )
    
    print("\n4. Test salvataggio certificato subordinato")
    root_ca.save_subordinate_certificate(ea_certificate)
    
    print("\n5. Test firma certificato end-entity (Authorization Authority)")
    # Genera chiave per Authorization Authority
    aa_private_key = ec.generate_private_key(ec.SECP256R1())
    aa_public_key = aa_private_key.public_key()
    
    # Firma certificato AA come CA
    aa_certificate = root_ca.sign_certificate(
        subject_public_key=aa_public_key,
        subject_name="AuthorizationAuthority_Test",
        is_ca=True
    )
    
    print("\n6. Test salvataggio secondo certificato subordinato")
    root_ca.save_subordinate_certificate(aa_certificate)
    
    print("\n7. Test firma certificato end-entity (ITS Station)")
    # Genera chiave per ITS Station
    its_private_key = ec.generate_private_key(ec.SECP256R1())
    its_public_key = its_private_key.public_key()
    
    time.sleep(3)


    # Firma certificato ITS-S come end entity
    its_certificate = root_ca.sign_certificate(
        subject_public_key=its_public_key,
        subject_name="ITS_Station_Test",
        is_ca=False
    )
    
    print("\n8. Test revoca primo certificato")
    root_ca.revoke_certificate(ea_certificate)
    
    print("\n9. Test revoca secondo certificato con motivo specifico")
    from cryptography.x509 import ReasonFlags
    root_ca.revoke_certificate(aa_certificate, reason=ReasonFlags.key_compromise)
    
    print("\n10. Test pubblicazione Full CRL")
    root_ca.publish_full_crl(validity_days=7)
    
    print("\n11. Test caricamento e verifica Full CRL")
    full_crl = root_ca.load_full_crl()
    if full_crl:
        revoked_list = list(full_crl)
        print(f"Full CRL caricata con {len(revoked_list)} certificati revocati:")
        for revoked in revoked_list:
            print(f"  - Serial revocato: {revoked.serial_number}")
            print(f"    Data revoca: {revoked.revocation_date}")
            # Verifica se ci sono estensioni
            if revoked.extensions:
                print(f"    Estensioni presenti: {len(revoked.extensions)}")
                for ext in revoked.extensions:
                    if 'CRLReason' in str(ext.oid):
                        print(f"    Motivo: {ext.value.reason}")
            else:
                print(f"    Motivo: Non specificato")
    
    print("\n12. Test pubblicazione Delta CRL (dovrebbe essere vuota)")
    delta_crl = root_ca.publish_delta_crl(validity_hours=24)
    if delta_crl is None:
        print("Delta CRL non pubblicata (nessuna nuova revoca)")
    
    print("\n13. Test revoca certificato ITS Station")
    root_ca.revoke_certificate(its_certificate, reason=ReasonFlags.cessation_of_operation)
    
    print("\n14. Test pubblicazione Delta CRL con nuova revoca")
    delta_crl = root_ca.publish_delta_crl(validity_hours=24)
    if delta_crl:
        delta_revoked_list = list(delta_crl)
        print(f"Delta CRL pubblicata con {len(delta_revoked_list)} nuove revoche")
    
    print("\n15. Test caricamento Delta CRL")
    loaded_delta_crl = root_ca.load_delta_crl()
    if loaded_delta_crl:
        print(f"Delta CRL caricata con {len(list(loaded_delta_crl))} revoche")
    
    print("\n16. Test statistiche CRL")
    stats = root_ca.get_crl_statistics()
    
    print("\n17. Verifica finale Full CRL con tutte le revoche")
    root_ca.publish_full_crl(validity_days=7)
    final_crl = root_ca.load_full_crl()
    if final_crl:
        final_revoked_list = list(final_crl)
        print(f"Full CRL finale con {len(final_revoked_list)} certificati revocati")
    
    
    print("\n=== TUTTI I TEST ROOT CA COMPLETATI ===")

if __name__ == "__main__":
    main()