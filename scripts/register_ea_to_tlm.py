"""
Register Enrollment Authority to central TLM

Questo script aggiunge un'EA ai trust anchors del TLM_MAIN centralizzato.
Tutte le AA useranno questo TLM per validare gli EC emessi dalle EA registrate.

Usage:
    python scripts/register_ea_to_tlm.py EA_001
    python scripts/register_ea_to_tlm.py EA_002 --remove  # Rimuovi EA dal TLM
    python scripts/register_ea_to_tlm.py --list           # Lista EA registrate
"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from managers.trust_list_manager import TrustListManager
from utils.cert_utils import get_certificate_ski


# Cache RootCA per evitare re-inizializzazioni multiple
_root_ca_cache = None


def get_root_ca():
    """Ottiene istanza condivisa di RootCA"""
    global _root_ca_cache
    if _root_ca_cache is None:
        _root_ca_cache = RootCA(base_dir="data/root_ca")
    return _root_ca_cache


def list_registered_eas():
    """Mostra tutte le EA registrate nel TLM_MAIN"""
    print("\n" + "="*70)
    print("  ENROLLMENT AUTHORITIES REGISTRATE IN TLM_MAIN")
    print("="*70)
    
    try:
        root_ca = get_root_ca()
        tlm = TrustListManager(root_ca, base_dir="./data/tlm/TLM_MAIN/")
        
        if not tlm.trust_anchors:
            print("\n⚠️  Nessuna EA registrata nel TLM_MAIN")
            print("   Aggiungi EA con: python scripts/register_ea_to_tlm.py <EA_ID>")
            return
        
        print(f"\n✅ {len(tlm.trust_anchors)} trust anchor(s) registrati:\n")
        
        for i, anchor in enumerate(tlm.trust_anchors, 1):
            auth_type = anchor.get('authority_type', 'UNKNOWN')
            subject = anchor.get('subject_name', 'Unknown')
            ski = anchor.get('ski', 'N/A')[:16]
            added = anchor.get('added_date', 'Unknown')
            
            print(f"  [{i}] {auth_type}")
            print(f"      Subject: {subject}")
            print(f"      SKI: {ski}...")
            print(f"      Added: {added}")
            print()
        
    except Exception as e:
        print(f"❌ Errore: {e}")


def register_ea(ea_id):
    """Registra un'EA nel TLM_MAIN"""
    print("\n" + "="*70)
    print(f"  REGISTRAZIONE EA NEL TLM_MAIN")
    print("="*70)
    print(f"\nEA ID: {ea_id}")
    
    try:
        # Carica RootCA
        print("\n1. Caricamento RootCA...")
        root_ca = get_root_ca()
        print("   ✅ RootCA caricata")
        
        # Carica o crea EA
        print(f"\n2. Caricamento EA '{ea_id}'...")
        ea = EnrollmentAuthority(root_ca, ea_id=ea_id)
        print(f"   ✅ EA '{ea_id}' caricata")
        
        # Carica o crea TLM_MAIN
        print(f"\n3. Caricamento TLM_MAIN...")
        tlm = TrustListManager(root_ca, base_dir="./data/tlm/TLM_MAIN/")
        print("   ✅ TLM_MAIN caricato")
        
        # Verifica se EA è già registrata
        ea_ski = get_certificate_ski(ea.certificate)
        already_registered = any(anchor.get("ski") == ea_ski for anchor in tlm.trust_anchors)
        
        if already_registered:
            print(f"\n⚠️  EA '{ea_id}' è già registrata nel TLM_MAIN")
            print(f"   SKI: {ea_ski[:16]}...")
            return
        
        # Aggiungi EA ai trust anchors
        print(f"\n4. Aggiunta EA ai trust anchors...")
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")
        print(f"   ✅ EA '{ea_id}' aggiunta al TLM_MAIN")
        
        # Pubblica Full CTL
        print(f"\n5. Pubblicazione Full CTL...")
        tlm.publish_full_ctl()
        print("   ✅ Full CTL pubblicata")
        
        print(f"\n" + "="*70)
        print(f"  ✅ REGISTRAZIONE COMPLETATA")
        print("="*70)
        print(f"\nEA '{ea_id}' è ora un trust anchor nel TLM_MAIN")
        print(f"Tutte le AA potranno validare EC emessi da questa EA.")
        print(f"\nTrust anchors totali: {len(tlm.trust_anchors)}")
        
    except Exception as e:
        print(f"\n❌ Errore durante registrazione: {e}")
        import traceback
        traceback.print_exc()


def unregister_ea(ea_id):
    """Rimuovi un'EA dal TLM_MAIN"""
    print("\n" + "="*70)
    print(f"  RIMOZIONE EA DAL TLM_MAIN")
    print("="*70)
    print(f"\nEA ID: {ea_id}")
    
    try:
        # Carica RootCA e TLM
        root_ca = get_root_ca()
        tlm = TrustListManager(root_ca, base_dir="./data/tlm/TLM_MAIN/")
        
        # Carica EA per ottenere SKI
        ea = EnrollmentAuthority(root_ca, ea_id=ea_id)
        ea_ski = get_certificate_ski(ea.certificate)
        
        # Cerca e rimuovi EA
        found = False
        for anchor in tlm.trust_anchors[:]:  # Copia per iterare durante modifica
            if anchor.get("ski") == ea_ski:
                tlm.trust_anchors.remove(anchor)
                tlm.delta_removals.append(anchor)
                found = True
                break
        
        if found:
            # Pubblica Delta CTL con rimozione
            tlm.publish_delta_ctl()
            print(f"\n✅ EA '{ea_id}' rimossa dal TLM_MAIN")
            print(f"   Trust anchors rimanenti: {len(tlm.trust_anchors)}")
        else:
            print(f"\n⚠️  EA '{ea_id}' non trovata nel TLM_MAIN")
            
    except Exception as e:
        print(f"\n❌ Errore: {e}")
        import traceback
        traceback.print_exc()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Register/Unregister EA to/from central TLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Registra EA_001 nel TLM_MAIN
  python scripts/register_ea_to_tlm.py EA_001
  
  # Lista tutte le EA registrate
  python scripts/register_ea_to_tlm.py --list
  
  # Rimuovi EA_002 dal TLM_MAIN
  python scripts/register_ea_to_tlm.py EA_002 --remove
"""
    )
    
    parser.add_argument(
        "ea_id",
        nargs="?",
        help="ID dell'Enrollment Authority (es: EA_001)"
    )
    
    parser.add_argument(
        "--list",
        action="store_true",
        help="Lista tutte le EA registrate nel TLM_MAIN"
    )
    
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Rimuovi EA dal TLM_MAIN invece di aggiungerla"
    )
    
    args = parser.parse_args()
    
    # Lista EA registrate
    if args.list:
        list_registered_eas()
        return
    
    # Richiedi EA ID se non fornito
    if not args.ea_id:
        parser.print_help()
        print("\n❌ Errore: Specifica EA_ID o usa --list")
        sys.exit(1)
    
    # Rimuovi o registra EA
    if args.remove:
        unregister_ea(args.ea_id)
    else:
        register_ea(args.ea_id)


if __name__ == "__main__":
    main()
