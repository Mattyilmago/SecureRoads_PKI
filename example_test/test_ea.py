import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import time

def main():
    print("=== TEST ENROLLMENT AUTHORITY (EA) ===")
    
    print("\n1. Inizializzazione Root CA")
    root_ca = RootCA()
    
    print("\n2. Inizializzazione Enrollment Authority")
    ea = EnrollmentAuthority(root_ca)
    
    print("\n3. Verifica certificato EA")
    print(f"EA Subject: {ea.certificate.subject}")
    print(f"EA Serial: {ea.certificate.serial_number}")
    print(f"EA Validità: dal {ea.certificate.not_valid_before} al {ea.certificate.not_valid_after}")
    print(f"EA Issuer: {ea.certificate.issuer}")
    
    print("\n4. Test generazione CSR da ITS-S simulata")
    # Simula una ITS-S che genera una CSR
    its_private_key = ec.generate_private_key(ec.SECP256R1())
    its_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ITS-S"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Vehicle_001"),
    ])
    
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        its_subject
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    ).sign(its_private_key, hashes.SHA256())
    
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    print(f"CSR generata per ITS-S: Vehicle_001")
    print(f"CSR Subject: {csr.subject}")

    
    print("\n5. Test processamento CSR da parte dell'EA")
    ec_cert = ea.process_csr(csr_pem, "Vehicle_001", attributes={"region": "EU", "type": "passenger"})
    
    if ec_cert:
        print(f"Enrollment Certificate emesso con successo!")
        print(f"EC Serial: {ec_cert.serial_number}")
        print(f"EC Subject: {ec_cert.subject}")
        print(f"EC Validità: dal {ec_cert.not_valid_before} al {ec_cert.not_valid_after}")
    
    print("\n6. Test emissione secondo Enrollment Certificate")
    # Genera seconda ITS-S
    its2_private_key = ec.generate_private_key(ec.SECP256R1())
    ec_cert2 = ea.issue_enrollment_certificate("Vehicle_002", its2_private_key.public_key(), 
                                              attributes={"region": "EU", "type": "truck"})

    time.sleep(2)

    print("\n7. Test emissione terzo Enrollment Certificate")
    # Test metodo diretto issue_enrollment_certificate
    its3_private_key = ec.generate_private_key(ec.SECP256R1())
    its3_public_key = its3_private_key.public_key()
    ec_cert3 = ea.issue_enrollment_certificate("Vehicle_003", its3_public_key, 
                                              attributes={"region": "EU", "type": "motorcycle"})
    
    print("\n8. Test revoca Enrollment Certificate")
    from cryptography.x509 import ReasonFlags
    ea.revoke_enrollment_certificate(ec_cert, reason=ReasonFlags.key_compromise)
    
    print("\n9. Test revoca secondo certificato con motivo diverso")
    ea.revoke_enrollment_certificate(ec_cert2, reason=ReasonFlags.superseded)
    
    print("\n10. Test pubblicazione Full CRL")
    ea.crl_manager.publish_full_crl(validity_days=7)
    
    print("\n11. Test caricamento e verifica Full CRL EA")
    ea_crl = ea.crl_manager.load_full_crl()
    if ea_crl:
        revoked_list = list(ea_crl)
        print(f"Full CRL EA caricata con {len(revoked_list)} certificati revocati:")
        for revoked in revoked_list:
            print(f"  - Serial revocato: {revoked.serial_number}")
            print(f"    Data revoca: {revoked.revocation_date}")
            # Verifica estensioni per il motivo
            if revoked.extensions:
                for ext in revoked.extensions:
                    if 'CRLReason' in str(ext.oid):
                        print(f"    Motivo: {ext.value.reason}")
    
    print("\n12. Test revoca terzo certificato")
    ea.revoke_enrollment_certificate(ec_cert3, reason=ReasonFlags.cessation_of_operation)
    
    print("\n13. Test pubblicazione Delta CRL")
    ea.crl_manager.publish_delta_crl(validity_hours=24)
    
    print("\n14. Test statistiche CRL")
    stats = ea.crl_manager.get_statistics()
    print(f"Statistiche CRL EA: {stats}")
    
    print("\n15. Verifica finale stato EA")
    print(f"Certificati revocati in memoria: {len(ea.revoked)}")
    
    print("\n=== TEST ENROLLMENT AUTHORITY COMPLETATI ===")

if __name__ == "__main__":
    main()