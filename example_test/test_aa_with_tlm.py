"""
Test AA con TLM

Questo script dimostra come usare AA con TLM invece di ea_certificate_path singola.

Scenario:
1. Setup Root CA e TLM con multiple EA
2. Vehicle richiede EC da EA_001
3. AA (configurata con TLM) valida EC da EA_001 [OK]
4. Vehicle richiede EC da EA_002
5. AA (configurata con TLM) valida EC da EA_002 [OK]

Senza TLM, l'AA accetterebbe solo EC da una EA specifica.
Con TLM, l'AA accetta EC da qualsiasi EA fidata.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from entities.its_station import ITSStation
from managers.trust_list_manager import TrustListManager


def print_section(title):
    print(f"\n{'='*80}")
    print(f"  {title}")
    print(f"{'='*80}\n")


def main():
    print_section("TEST: AA con TLM - Validazione Multiple EA")
    
    # ==========================================
    # SETUP INFRASTRUCTURE
    # ==========================================
    print_section("STEP 1: Setup PKI Infrastructure")
    
    # Root CA
    root_ca = RootCA(base_dir="./data/root_ca/")
    
    # Trust List Manager
    tlm = TrustListManager(root_ca=root_ca, base_dir="./data/tlm/")
    
    # Crea 3 Enrollment Authorities
    print("\n[TEST] Creazione 3 Enrollment Authorities...")
    ea1 = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_001", base_dir="./data/ea/")
    ea2 = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_002", base_dir="./data/ea/")
    ea3 = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_003", base_dir="./data/ea/")
    
    # Registra EA nel TLM
    print("\n[TEST] Registrazione EA nel TLM...")
    tlm.add_trust_anchor(ea1.certificate, authority_type="EA")
    tlm.add_trust_anchor(ea2.certificate, authority_type="EA")
    tlm.add_trust_anchor(ea3.certificate, authority_type="EA")
    
    # Pubblica CTL
    print("\n[TEST] Pubblicazione Full CTL...")
    tlm.publish_full_ctl(validity_days=30)
    
    stats = tlm.get_statistics()
    print(f"\n[OK] TLM configurato:")
    print(f"   Trust Anchors: {stats['total_trust_anchors']}")
    print(f"   EA: {stats['trust_anchors_by_type'].get('EA', 0)}")
    
    # ==========================================
    # TEST 1: AA con TLM (NUOVO APPROCCIO)
    # ==========================================
    print_section("STEP 2: Authorization Authority con TLM")
    
    # Crea AA con TLM (nuovo approccio)
    aa_with_tlm = AuthorizationAuthority(
        root_ca=root_ca,
        tlm=tlm,  # ← Passa TLM invece di ea_certificate_path
        aa_id="AA_TLM_TEST",
        base_dir="./data/aa/"
    )
    
    print(f"[OK] AA creata con modalità: {aa_with_tlm.validation_mode}")
    
    # ==========================================
    # TEST 2: AA Legacy (VECCHIO APPROCCIO)
    # ==========================================
    print_section("STEP 3: Authorization Authority Legacy (solo per confronto)")
    
    # Crea AA con ea_certificate_path (vecchio approccio)
    aa_legacy = AuthorizationAuthority(
        root_ca=root_ca,
        ea_certificate_path=ea1.ea_certificate_path,  # ← Solo EA_001
        aa_id="AA_LEGACY_TEST",
        base_dir="./data/aa/"
    )
    
    print(f"[OK] AA legacy creata con modalità: {aa_legacy.validation_mode}")
    print(f"[WARNING] AA legacy può validare solo EC da EA_001")
    
    # ==========================================
    # TEST 3: Vehicle con EC da EA_001
    # ==========================================
    print_section("STEP 4: Test Vehicle con EC da EA_001")
    
    vehicle1 = ITSStation("Vehicle_TLM_001", base_dir="./data/itss/")
    vehicle1.generate_ecc_keypair()
    
    print(f"\n[TEST] Vehicle richiede EC a EA_001...")
    ec1 = vehicle1.request_ec(ea1)
    
    # Test con AA TLM
    print(f"\n[TEST] Vehicle richiede AT ad AA con TLM...")
    at1_tlm = vehicle1.request_at(aa_with_tlm)
    if at1_tlm:
        print(f"[OK] AT ottenuto da AA con TLM (EC da EA_001)")
    else:
        print(f"[ERROR] AT rifiutato da AA con TLM (EC da EA_001)")
    
    # Test con AA Legacy
    print(f"\n[TEST] Vehicle richiede AT ad AA legacy...")
    at1_legacy = vehicle1.request_at(aa_legacy)
    if at1_legacy:
        print(f"[OK] AT ottenuto da AA legacy (EC da EA_001)")
    else:
        print(f"[ERROR] AT rifiutato da AA legacy (EC da EA_001)")
    
    # ==========================================
    # TEST 4: Vehicle con EC da EA_002
    # ==========================================
    print_section("STEP 5: Test Vehicle con EC da EA_002")
    
    vehicle2 = ITSStation("Vehicle_TLM_002", base_dir="./data/itss/")
    vehicle2.generate_ecc_keypair()
    
    print(f"\n[TEST] Vehicle richiede EC a EA_002...")
    ec2 = vehicle2.request_ec(ea2)
    
    # Test con AA TLM (dovrebbe ACCETTARE)
    print(f"\n[TEST] Vehicle richiede AT ad AA con TLM...")
    at2_tlm = vehicle2.request_at(aa_with_tlm)
    if at2_tlm:
        print(f"[OK] AT ottenuto da AA con TLM (EC da EA_002)")
        print(f"   [OK] TLM permette validazione EC da multiple EA!")
    else:
        print(f"[ERROR] AT rifiutato da AA con TLM (EC da EA_002)")
    
    # Test con AA Legacy (dovrebbe RIFIUTARE)
    print(f"\n[TEST] Vehicle richiede AT ad AA legacy...")
    at2_legacy = vehicle2.request_at(aa_legacy)
    if at2_legacy:
        print(f"[OK] AT ottenuto da AA legacy (EC da EA_002)")
    else:
        print(f"[ERROR] AT rifiutato da AA legacy (EC da EA_002)")
        print(f"   [WARNING] AA legacy accetta solo EC da EA_001!")
    
    # ==========================================
    # TEST 5: Vehicle con EC da EA_003
    # ==========================================
    print_section("STEP 6: Test Vehicle con EC da EA_003")
    
    vehicle3 = ITSStation("Vehicle_TLM_003", base_dir="./data/itss/")
    vehicle3.generate_ecc_keypair()
    
    print(f"\n[TEST] Vehicle richiede EC a EA_003...")
    ec3 = vehicle3.request_ec(ea3)
    
    # Test con AA TLM (dovrebbe ACCETTARE)
    print(f"\n[TEST] Vehicle richiede AT ad AA con TLM...")
    at3_tlm = vehicle3.request_at(aa_with_tlm)
    if at3_tlm:
        print(f"[OK] AT ottenuto da AA con TLM (EC da EA_003)")
    else:
        print(f"[ERROR] AT rifiutato da AA con TLM (EC da EA_003)")
    
    # Test con AA Legacy (dovrebbe RIFIUTARE)
    print(f"\n[TEST] Vehicle richiede AT ad AA legacy...")
    at3_legacy = vehicle3.request_at(aa_legacy)
    if at3_legacy:
        print(f"[OK] AT ottenuto da AA legacy (EC da EA_003)")
    else:
        print(f"[ERROR] AT rifiutato da AA legacy (EC da EA_003)")
        print(f"   [WARNING] AA legacy accetta solo EC da EA_001!")
    
    # ==========================================
    # RISULTATI
    # ==========================================
    print_section("RISULTATI FINALI")
    
    print("[STATS] AA con TLM (Nuovo Approccio):")
    print(f"  Vehicle 1 (EC da EA_001): {'[OK] AT Ottenuto' if at1_tlm else '[ERROR] AT Rifiutato'}")
    print(f"  Vehicle 2 (EC da EA_002): {'[OK] AT Ottenuto' if at2_tlm else '[ERROR] AT Rifiutato'}")
    print(f"  Vehicle 3 (EC da EA_003): {'[OK] AT Ottenuto' if at3_tlm else '[ERROR] AT Rifiutato'}")
    
    print("\n[STATS] AA Legacy (Vecchio Approccio):")
    print(f"  Vehicle 1 (EC da EA_001): {'[OK] AT Ottenuto' if at1_legacy else '[ERROR] AT Rifiutato'}")
    print(f"  Vehicle 2 (EC da EA_002): {'[OK] AT Ottenuto' if at2_legacy else '[ERROR] AT Rifiutato'}")
    print(f"  Vehicle 3 (EC da EA_003): {'[OK] AT Ottenuto' if at3_legacy else '[ERROR] AT Rifiutato'}")
    
    # Verifica risultati attesi
    print("\n[CHECK] Verifica:")
    success = True
    
    # AA con TLM dovrebbe accettare TUTTI gli EC
    if not (at1_tlm and at2_tlm and at3_tlm):
        print("[ERROR] FAIL: AA con TLM dovrebbe accettare EC da tutte le EA fidate")
        success = False
    else:
        print("[OK] PASS: AA con TLM accetta EC da tutte le EA fidate")
    
    # AA Legacy dovrebbe accettare solo EC da EA_001
    if not (at1_legacy and not at2_legacy and not at3_legacy):
        print("[WARNING] INFO: AA legacy dovrebbe accettare solo EC da EA_001")
    else:
        print("[OK] PASS: AA legacy accetta solo EC da EA_001 (comportamento corretto)")
    
    print("\n" + "="*80)
    if success:
        print("  [OK] TEST COMPLETATO CON SUCCESSO!")
        print("  [TARGET] TLM permette validazione EC da multiple EA fidate")
    else:
        print("  [ERROR] TEST FALLITO")
    print("="*80)


if __name__ == "__main__":
    main()
