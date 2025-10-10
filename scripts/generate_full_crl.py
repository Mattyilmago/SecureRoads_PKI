"""
Script per generare manualmente una Full CRL per qualsiasi autorità.

Usage:
    # Per Root CA
    python scripts/generate_full_crl.py --entity root_ca
    
    # Per Enrollment Authority
    python scripts/generate_full_crl.py --entity ea --id EA_001
    
    # Per Authorization Authority
    python scripts/generate_full_crl.py --entity aa --id AA_001
    
    # Con validità personalizzata (default 7 giorni)
    python scripts/generate_full_crl.py --entity root_ca --validity 30
"""

import argparse
import sys
import os
from pathlib import Path
from cryptography import x509

# Aggiungi root del progetto al path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority


def generate_root_ca_crl(validity_days):
    """Genera Full CRL per Root CA"""
    print(f"\n{'='*70}")
    print(f"  GENERAZIONE FULL CRL - ROOT CA")
    print(f"{'='*70}\n")
    
    # Carica Root CA esistente
    root_ca = RootCA(base_dir="./data/root_ca")
    
    # Get subject from certificate
    subject = root_ca.certificate.subject
    subject_cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    
    print(f"Root CA caricata: {subject_cn}")
    print(f"CRL Number attuale: {root_ca.crl_manager.crl_number}")
    print(f"Certificati revocati: {len(root_ca.crl_manager.revoked_certificates)}")
    print(f"Validità: {validity_days} giorni")
    print(f"\nGenerazione in corso...")
    
    # Genera Full CRL
    crl_path = root_ca.publish_full_crl(validity_days=validity_days)
    
    print(f"\n✅ Full CRL generata con successo!")
    print(f"   Path: {crl_path}")
    print(f"   CRL Number: {root_ca.crl_manager.crl_number}")
    print(f"   Base CRL Number: {root_ca.crl_manager.base_crl_number}")
    print(f"   Certificati revocati inclusi: {len(root_ca.crl_manager.revoked_certificates)}")
    

def generate_ea_crl(entity_id, validity_days):
    """Genera Full CRL per Enrollment Authority"""
    print(f"\n{'='*70}")
    print(f"  GENERAZIONE FULL CRL - {entity_id}")
    print(f"{'='*70}\n")
    
    base_dir = f"./data/ea/{entity_id}"
    
    if not os.path.exists(base_dir):
        print(f"❌ Errore: Directory {base_dir} non trovata!")
        print(f"   L'entità {entity_id} non esiste.")
        return
    
    # Carica Root CA prima (necessario per EA)
    root_ca = RootCA(base_dir="./data/root_ca")
    
    # Carica EA esistente
    ea = EnrollmentAuthority(
        root_ca=root_ca,
        ea_id=entity_id,
        base_dir=f"./data/ea/"
    )
    
    print(f"EA caricata: {entity_id}")
    print(f"CRL Number attuale: {ea.crl_manager.crl_number}")
    print(f"Certificati revocati: {len(ea.crl_manager.revoked_certificates)}")
    print(f"Validità: {validity_days} giorni")
    print(f"\nGenerazione in corso...")
    
    # Genera Full CRL (EA usa publish_crl che chiama internamente publish_full_crl)
    crl_path = ea.publish_crl(validity_days=validity_days)
    
    print(f"\n✅ Full CRL generata con successo!")
    print(f"   Path: {crl_path}")
    print(f"   CRL Number: {ea.crl_manager.crl_number}")
    print(f"   Base CRL Number: {ea.crl_manager.base_crl_number}")
    print(f"   Certificati revocati inclusi: {len(ea.crl_manager.revoked_certificates)}")
    
    print(f"\n✅ Full CRL generata con successo!")
    print(f"   CRL Number: {ea.crl_manager.crl_number}")
    print(f"   Base CRL Number: {ea.crl_manager.base_crl_number}")
    print(f"   Certificati revocati inclusi: {len(ea.crl_manager.revoked_certificates)}")


def generate_aa_crl(entity_id, validity_days):
    """Genera Full CRL per Authorization Authority"""
    print(f"\n{'='*70}")
    print(f"  GENERAZIONE FULL CRL - {entity_id}")
    print(f"{'='*70}\n")
    
    base_dir = f"./data/aa/{entity_id}"
    
    if not os.path.exists(base_dir):
        print(f"❌ Errore: Directory {base_dir} non trovata!")
        print(f"   L'entità {entity_id} non esiste.")
        return
    
    # Carica Root CA prima (necessario per AA)
    root_ca = RootCA(base_dir="./data/root_ca")
    
    # Carica AA esistente
    aa = AuthorizationAuthority(
        root_ca=root_ca,
        aa_id=entity_id,
        base_dir=f"./data/aa/"
    )
    
    print(f"AA caricata: {entity_id}")
    print(f"CRL Number attuale: {aa.crl_manager.crl_number}")
    print(f"Certificati revocati: {len(aa.crl_manager.revoked_certificates)}")
    print(f"Validità: {validity_days} giorni")
    print(f"\nGenerazione in corso...")
    
    # Genera Full CRL (AA usa publish_crl che chiama internamente publish_full_crl)
    crl_path = aa.publish_crl(validity_days=validity_days)
    
    print(f"\n✅ Full CRL generata con successo!")
    print(f"   Path: {crl_path}")
    print(f"   CRL Number: {aa.crl_manager.crl_number}")
    print(f"   Base CRL Number: {aa.crl_manager.base_crl_number}")
    print(f"   Certificati revocati inclusi: {len(aa.crl_manager.revoked_certificates)}")
    print(f"   Base CRL Number: {aa.crl_manager.base_crl_number}")
    print(f"   Certificati revocati inclusi: {len(aa.crl_manager.revoked_certificates)}")


def main():
    parser = argparse.ArgumentParser(
        description="Genera Full CRL per un'autorità PKI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        "--entity",
        required=True,
        choices=["root_ca", "ea", "aa"],
        help="Tipo di entità"
    )
    
    parser.add_argument(
        "--id",
        help="ID dell'entità (richiesto per EA e AA, es: EA_001, AA_001)"
    )
    
    parser.add_argument(
        "--validity",
        type=int,
        default=7,
        help="Giorni di validità della CRL (default: 7)"
    )
    
    args = parser.parse_args()
    
    # Validazione
    if args.entity in ["ea", "aa"] and not args.id:
        print("❌ Errore: --id richiesto per EA e AA")
        print("   Esempio: python scripts/generate_full_crl.py --entity ea --id EA_001")
        sys.exit(1)
    
    try:
        if args.entity == "root_ca":
            generate_root_ca_crl(args.validity)
        elif args.entity == "ea":
            generate_ea_crl(args.id, args.validity)
        elif args.entity == "aa":
            generate_aa_crl(args.id, args.validity)
    
    except Exception as e:
        print(f"\n❌ Errore durante la generazione della CRL:")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
