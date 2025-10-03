import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.crl_manager import CRLManager
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ReasonFlags
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone
import time

def create_test_certificate(ea, its_id, validity_days=30):
    """
    Crea un certificato di test con validità personalizzata.
    
    Args:
        ea: Enrollment Authority
        its_id: ID del veicolo
        validity_days: Giorni di validità (default 30)
    
    Returns:
        Certificato X.509
    """
    its_key = ec.generate_private_key(ec.SECP256R1())
    its_public = its_key.public_key()
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-S"),
        x509.NameAttribute(NameOID.COMMON_NAME, its_id),
    ])
    
    serial_number = x509.random_serial_number()
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ea.certificate.subject
    ).public_key(
        its_public
    ).serial_number(
        serial_number
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ea.private_key, hashes.SHA256())
    
    print(f"Certificato test creato: Serial={cert.serial_number}")
    print(f"  Validità: dal {cert.not_valid_before_utc} al {cert.not_valid_after_utc}")
    
    return cert

def main():
    print("=" * 80)
    print("TEST CRL MANAGER - Full CRL e Delta CRL")
    print("=" * 80)
    
    # Step 1: Inizializza infrastruttura PKI
    print("\n" + "=" * 80)
    print("STEP 1: Inizializzazione PKI")
    print("=" * 80)
    
    root_ca = RootCA()
    ea = EnrollmentAuthority(root_ca, ea_id="EA_CRL_TEST")
    
    # Step 2: Crea CRL Manager per l'EA
    print("\n" + "=" * 80)
    print("STEP 2: Creazione CRL Manager")
    print("=" * 80)
    
    crl_manager = CRLManager(
        authority_id=ea.ea_id,
        base_dir=f"./data/ea/{ea.ea_id}/",
        issuer_certificate=ea.certificate,
        issuer_private_key=ea.private_key
    )
    
    # Step 3: Genera alcuni certificati
    print("\n" + "=" * 80)
    print("STEP 3: Generazione Certificati Test")
    print("=" * 80)
    
    certificates = []
    for i in range(1, 6):
        print(f"\n--- Certificato {i} ---")
        its_key = ec.generate_private_key(ec.SECP256R1())
        its_public = its_key.public_key()
        
        cert = ea.issue_enrollment_certificate(
            f"Vehicle_CRL_{i:03d}",
            its_public,
            attributes={"region": "EU", "type": "passenger"}
        )
        certificates.append(cert)
        print(f"Certificato emesso: Serial={cert.serial_number}")
    
    # Step 4: Pubblica FULL CRL iniziale (vuota)
    print("\n" + "=" * 80)
    print("STEP 4: Pubblicazione Full CRL Iniziale (Vuota)")
    print("=" * 80)
    
    full_crl_1 = crl_manager.publish_full_crl(validity_days=7)
    print(f"\n✅ Full CRL #1 pubblicata")
    print(f"   CRL Number: {crl_manager.crl_number}")
    print(f"   Certificati revocati: {len(list(full_crl_1))}")
    
    # Step 5: Revoca PRIMI 2 certificati
    print("\n" + "=" * 80)
    print("STEP 5: Revoca Prima Batch (2 certificati)")
    print("=" * 80)
    
    print("\n🚫 Revocando certificato 1...")
    crl_manager.add_revoked_certificate(certificates[0], ReasonFlags.key_compromise)
    
    print("\n🚫 Revocando certificato 2...")
    crl_manager.add_revoked_certificate(certificates[1], ReasonFlags.cessation_of_operation)
    
    # Step 6: Pubblica DELTA CRL #1
    print("\n" + "=" * 80)
    print("STEP 6: Pubblicazione Delta CRL #1")
    print("=" * 80)
    
    delta_crl_1 = crl_manager.publish_delta_crl(validity_hours=24)
    
    if delta_crl_1:
        print(f"\n✅ Delta CRL #1 pubblicata")
        print(f"   CRL Number: {crl_manager.crl_number}")
        print(f"   Base CRL Number: {crl_manager.base_crl_number}")
        print(f"   Nuove revoche: {len(list(delta_crl_1))}")
        
        # Verifica Delta CRL Indicator extension
        for ext in delta_crl_1.extensions:
            if ext.oid._name == "deltaCRLIndicator":
                print(f"   ✓ Delta CRL Indicator presente: punta a CRL #{ext.value.crl_number}")
    
    # Step 7: Revoca ALTRI 2 certificati
    print("\n" + "=" * 80)
    print("STEP 7: Revoca Seconda Batch (2 certificati)")
    print("=" * 80)
    
    time.sleep(1)  # Simula tempo passato
    
    print("\n🚫 Revocando certificato 3...")
    crl_manager.add_revoked_certificate(certificates[2], ReasonFlags.superseded)
    
    print("\n🚫 Revocando certificato 4...")
    crl_manager.add_revoked_certificate(certificates[3], ReasonFlags.affiliation_changed)
    
    # Step 8: Pubblica DELTA CRL #2
    print("\n" + "=" * 80)
    print("STEP 8: Pubblicazione Delta CRL #2")
    print("=" * 80)
    
    delta_crl_2 = crl_manager.publish_delta_crl(validity_hours=24)
    
    if delta_crl_2:
        print(f"\n✅ Delta CRL #2 pubblicata")
        print(f"   CRL Number: {crl_manager.crl_number}")
        print(f"   Base CRL Number: {crl_manager.base_crl_number}")
        print(f"   Nuove revoche: {len(list(delta_crl_2))}")
    
    # Step 9: Pubblica nuova FULL CRL (consolida tutto)
    print("\n" + "=" * 80)
    print("STEP 9: Pubblicazione Full CRL #2 (Consolidamento)")
    print("=" * 80)
    
    print("\n📋 Consolidando tutte le revoche in nuova Full CRL...")
    full_crl_2 = crl_manager.publish_full_crl(validity_days=7)
    
    print(f"\n✅ Full CRL #2 pubblicata")
    print(f"   CRL Number: {crl_manager.crl_number}")
    print(f"   Base CRL Number: {crl_manager.base_crl_number}")
    print(f"   Certificati revocati totali: {len(list(full_crl_2))}")
    
    # Step 10: Revoca ULTIMO certificato
    print("\n" + "=" * 80)
    print("STEP 10: Revoca Terza Batch (1 certificato)")
    print("=" * 80)
    
    time.sleep(1)
    
    print("\n🚫 Revocando certificato 5...")
    crl_manager.add_revoked_certificate(certificates[4], ReasonFlags.privilege_withdrawn)
    
    # Step 11: Pubblica DELTA CRL #3 (relativo alla nuova Full CRL)
    print("\n" + "=" * 80)
    print("STEP 11: Pubblicazione Delta CRL #3 (da nuova Full CRL)")
    print("=" * 80)
    
    delta_crl_3 = crl_manager.publish_delta_crl(validity_hours=24)
    
    if delta_crl_3:
        print(f"\n✅ Delta CRL #3 pubblicata")
        print(f"   CRL Number: {crl_manager.crl_number}")
        print(f"   Base CRL Number: {crl_manager.base_crl_number}")
        print(f"   Nuove revoche: {len(list(delta_crl_3))}")
    
    # Step 12: Test caricamento CRL
    print("\n" + "=" * 80)
    print("STEP 12: Test Caricamento CRL da File")
    print("=" * 80)
    
    print("\n📂 Caricamento Full CRL...")
    loaded_full = crl_manager.load_full_crl()
    
    print("\n📂 Caricamento Delta CRL...")
    loaded_delta = crl_manager.load_delta_crl()
    
    # Step 13: Statistiche finali
    print("\n" + "=" * 80)
    print("STEP 13: Statistiche Finali CRL Manager")
    print("=" * 80)
    
    stats = crl_manager.get_statistics()
    print(f"\n📊 Statistiche:")
    print(f"   Authority ID: {stats['authority_id']}")
    print(f"   CRL Number corrente: {stats['crl_number']}")
    print(f"   Base CRL Number: {stats['base_crl_number']}")
    print(f"   Totale certificati revocati: {stats['total_revoked']}")
    print(f"   Revoche delta pending: {stats['delta_pending']}")
    print(f"   Ultima Full CRL: {stats['last_full_crl']}")
    
    # Step 14: Verifica contenuto CRL
    print("\n" + "=" * 80)
    print("STEP 14: Verifica Contenuto Full CRL vs Delta CRL")
    print("=" * 80)
    
    print(f"\n📋 Full CRL contiene {len(list(loaded_full))} certificati:")
    for revoked in loaded_full:
        print(f"   - Serial: {revoked.serial_number}")
    
    print(f"\n📋 Delta CRL contiene {len(list(loaded_delta))} nuove revoche:")
    for revoked in loaded_delta:
        print(f"   - Serial: {revoked.serial_number}")
    
    # Step 15: Scenario ITS-S - Come usa le CRL
    print("\n" + "=" * 80)
    print("STEP 15: SCENARIO ITS-S - Aggiornamento CRL")
    print("=" * 80)
    
    print("""
📱 ITS-S alla prima accensione:
   1. Scarica Full CRL (grande, ma completa)
   2. Salva localmente
   
⏰ ITS-S aggiornamento periodico (ogni ora):
   1. Scarica solo Delta CRL (piccola, veloce)
   2. Applica nuove revoche alla Full CRL locale
   3. Salva stato aggiornato
   
📅 ITS-S aggiornamento settimanale:
   1. Scarica nuova Full CRL
   2. Sostituisce vecchia Full CRL + tutte le Delta
   3. Riparte da zero con nuova baseline
    """)
    
    print("\n" + "=" * 80)
    print("✅ TEST CRL MANAGER COMPLETATO CON SUCCESSO")
    print("=" * 80)
    
    print(f"""
📁 File generati:
   - Full CRL: {crl_manager.full_crl_path}
   - Delta CRL: {crl_manager.delta_crl_path}
   - Metadata: {crl_manager.metadata_path}
    """)

if __name__ == "__main__":
    main()
