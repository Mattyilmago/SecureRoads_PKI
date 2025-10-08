"""
Script di verifica delle migliorie ETSI implementate:
1. Logging e Audit (data/logs/)
2. Backup e Disaster Recovery (data/backup/)
3. CRL Full/Delta Separation (crl/full/ e crl/delta/)
4. Rename received_tickets → authorization_tickets
"""

import os
import shutil
from pathlib import Path

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from entities.its_station import ITSStation
from managers.trust_list_manager import TrustListManager


def cleanup_test_data():
    """Pulisce i dati di test precedenti"""
    test_dirs = [
        "./data_verification_test/",
    ]
    for test_dir in test_dirs:
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
            print(f"✓ Rimosso {test_dir}")


def verify_directory_structure(base_path, entity_name):
    """Verifica che tutte le directory richieste esistano"""
    print(f"\n{'='*60}")
    print(f"Verificando struttura: {entity_name}")
    print(f"{'='*60}")
    
    required_dirs = {
        "logs": os.path.join(base_path, "logs/"),
        "backup": os.path.join(base_path, "backup/"),
    }
    
    # Verifica CRL structure per CA
    if "root_ca" in base_path or "ea" in base_path or "aa" in base_path:
        required_dirs["crl_full"] = os.path.join(base_path, "crl/full/")
        required_dirs["crl_delta"] = os.path.join(base_path, "crl/delta/")
    
    all_good = True
    for dir_name, dir_path in required_dirs.items():
        exists = os.path.exists(dir_path)
        status = "✓" if exists else "✗"
        print(f"  {status} {dir_name:20} -> {dir_path}")
        if not exists:
            all_good = False
    
    return all_good


def verify_itss_structure(base_path, vehicle_name):
    """Verifica struttura ITS-S con authorization_tickets"""
    print(f"\n{'='*60}")
    print(f"Verificando ITS-S: {vehicle_name}")
    print(f"{'='*60}")
    
    required_dirs = {
        "authorization_tickets": os.path.join(base_path, "authorization_tickets/"),
        "logs": os.path.join(base_path, "logs/"),
        "backup": os.path.join(base_path, "backup/"),
        "own_certificates": os.path.join(base_path, "own_certificates/"),
        "trust_anchors": os.path.join(base_path, "trust_anchors/"),
    }
    
    all_good = True
    for dir_name, dir_path in required_dirs.items():
        exists = os.path.exists(dir_path)
        status = "✓" if exists else "✗"
        print(f"  {status} {dir_name:25} -> {dir_path}")
        if not exists:
            all_good = False
    
    # Verifica che NON esista più received_tickets
    old_dir = os.path.join(base_path, "received_tickets/")
    if os.path.exists(old_dir):
        print(f"  ✗ received_tickets (DEPRECATO) -> {old_dir}")
        all_good = False
    else:
        print(f"  ✓ received_tickets rimosso correttamente")
    
    return all_good


def test_logging_functionality(crl_manager, entity_name):
    """Test funzionalità di logging"""
    print(f"\n{'='*60}")
    print(f"Test Logging: {entity_name}")
    print(f"{'='*60}")
    
    # Test log operation
    crl_manager.log_operation("TEST_OPERATION", {
        "test": "verification",
        "status": "success"
    })
    
    log_file = os.path.join(crl_manager.log_dir, f"{crl_manager.authority_id}_crl_audit.log")
    
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            content = f.read()
            if "TEST_OPERATION" in content:
                print(f"  ✓ Log file creato: {log_file}")
                print(f"  ✓ Log entry presente")
                return True
            else:
                print(f"  ✗ Log entry non trovato")
                return False
    else:
        print(f"  ✗ Log file non creato")
        return False


def test_backup_functionality(crl_manager, entity_name):
    """Test funzionalità di backup"""
    print(f"\n{'='*60}")
    print(f"Test Backup: {entity_name}")
    print(f"{'='*60}")
    
    # Pubblica una CRL per avere qualcosa da backuppare
    crl_manager.publish_full_crl(validity_days=7)
    
    # Test backup
    crl_manager.backup_crl("full")
    
    backup_files = list(Path(crl_manager.backup_dir).glob("full_crl_backup_*.pem"))
    
    if len(backup_files) > 0:
        print(f"  ✓ Backup creato: {backup_files[0].name}")
        return True
    else:
        print(f"  ✗ Backup non creato")
        return False


def test_crl_separation(crl_manager, entity_name):
    """Test separazione Full/Delta CRL"""
    print(f"\n{'='*60}")
    print(f"Test CRL Separation: {entity_name}")
    print(f"{'='*60}")
    
    # Pubblica Full CRL
    crl_manager.publish_full_crl(validity_days=7)
    
    full_exists = os.path.exists(crl_manager.full_crl_path)
    full_in_subdir = "/full/" in crl_manager.full_crl_path
    
    print(f"  Full CRL path: {crl_manager.full_crl_path}")
    print(f"  {'✓' if full_exists else '✗'} Full CRL creato")
    print(f"  {'✓' if full_in_subdir else '✗'} Full CRL in subdirectory /full/")
    
    # Aggiungi revoca e pubblica Delta
    from cryptography.x509 import ReasonFlags
    if hasattr(crl_manager, 'issuer_certificate'):
        crl_manager.add_revoked_certificate(
            crl_manager.issuer_certificate,
            reason=ReasonFlags.superseded
        )
        crl_manager.publish_delta_crl(validity_hours=24)
        
        delta_exists = os.path.exists(crl_manager.delta_crl_path)
        delta_in_subdir = "/delta/" in crl_manager.delta_crl_path
        
        print(f"  Delta CRL path: {crl_manager.delta_crl_path}")
        print(f"  {'✓' if delta_exists else '✗'} Delta CRL creato")
        print(f"  {'✓' if delta_in_subdir else '✗'} Delta CRL in subdirectory /delta/")
        
        return full_exists and full_in_subdir and delta_exists and delta_in_subdir
    
    return full_exists and full_in_subdir


def main():
    """Esegue tutti i test di verifica"""
    print("\n" + "="*60)
    print("VERIFICA MIGLIORIE ETSI IMPLEMENTATE")
    print("="*60)
    
    # Cleanup
    cleanup_test_data()
    
    results = {}
    
    # Setup test environment
    base_dir = "./data_verification_test/"
    
    print("\n[1/5] Inizializzazione PKI...")
    root_ca = RootCA(base_dir=os.path.join(base_dir, "root_ca/"))
    ea = EnrollmentAuthority(root_ca, ea_id="EA_VERIFY", base_dir=os.path.join(base_dir, "ea/"))
    aa = AuthorizationAuthority(root_ca, aa_id="AA_VERIFY", base_dir=os.path.join(base_dir, "aa/"))
    tlm = TrustListManager(root_ca, base_dir=os.path.join(base_dir, "tlm/"))
    itss = ITSStation(its_id="Vehicle_Verify", base_dir=os.path.join(base_dir, "itss/"))
    
    # Test 1: Directory Structure
    print("\n[2/5] Verifica strutture directory...")
    results['root_ca_structure'] = verify_directory_structure(
        os.path.join(base_dir, "root_ca/"), "Root CA"
    )
    results['ea_structure'] = verify_directory_structure(
        os.path.join(base_dir, "ea/EA_VERIFY/"), "Enrollment Authority"
    )
    results['aa_structure'] = verify_directory_structure(
        os.path.join(base_dir, "aa/AA_VERIFY/"), "Authorization Authority"
    )
    results['tlm_structure'] = verify_directory_structure(
        os.path.join(base_dir, "tlm/"), "Trust List Manager"
    )
    results['itss_structure'] = verify_itss_structure(
        os.path.join(base_dir, "itss/Vehicle_Verify/"), "ITS Station"
    )
    
    # Test 2: Logging
    print("\n[3/5] Test funzionalità logging...")
    results['root_ca_logging'] = test_logging_functionality(root_ca.crl_manager, "Root CA")
    results['ea_logging'] = test_logging_functionality(ea.crl_manager, "EA")
    results['aa_logging'] = test_logging_functionality(aa.crl_manager, "AA")
    
    # Test 3: Backup
    print("\n[4/5] Test funzionalità backup...")
    results['root_ca_backup'] = test_backup_functionality(root_ca.crl_manager, "Root CA")
    results['ea_backup'] = test_backup_functionality(ea.crl_manager, "EA")
    results['aa_backup'] = test_backup_functionality(aa.crl_manager, "AA")
    
    # Test 4: CRL Separation
    print("\n[5/5] Test separazione CRL...")
    results['root_ca_crl_sep'] = test_crl_separation(root_ca.crl_manager, "Root CA")
    results['ea_crl_sep'] = test_crl_separation(ea.crl_manager, "EA")
    results['aa_crl_sep'] = test_crl_separation(aa.crl_manager, "AA")
    
    # Summary
    print("\n" + "="*60)
    print("RIEPILOGO RISULTATI")
    print("="*60)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test_name, result in results.items():
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"  {status:8} {test_name}")
    
    print(f"\n{'='*60}")
    print(f"Risultato: {passed}/{total} test passati ({passed*100//total}%)")
    print(f"{'='*60}")
    
    if passed == total:
        print("\n🎉 TUTTE LE MIGLIORIE ETSI IMPLEMENTATE CORRETTAMENTE!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} test falliti - verificare implementazione")
        return 1


if __name__ == "__main__":
    exit(main())
