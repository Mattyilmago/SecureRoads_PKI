"""
Script di Verifica Enrollment Certificates

Verifica dove sono salvati i certificati EC:
1. Nella directory EA (certificati emessi)
2. Nella directory ITS-S (certificati ricevuti dai veicoli)

Usage:
    python scripts/verify_enrollment_certificates.py
"""

import os
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from cryptography import x509
from cryptography.hazmat.primitives import serialization

def count_files_in_dir(directory):
    """Conta i file in una directory"""
    if not os.path.exists(directory):
        return 0
    return len([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])

def list_directories(base_path):
    """Lista tutte le sottodirectory"""
    if not os.path.exists(base_path):
        return []
    return [d for d in os.listdir(base_path) if os.path.isdir(os.path.join(base_path, d))]

def verify_certificate(cert_path):
    """Verifica che un file sia un certificato valido"""
    try:
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return {
            'valid': True,
            'serial': cert.serial_number,
            'subject': cert.subject.rfc4514_string(),
            'not_before': cert.not_valid_before_utc,
            'not_after': cert.not_valid_after_utc
        }
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }

def main():
    print("\n" + "="*80)
    print("  VERIFICA ENROLLMENT CERTIFICATES")
    print("="*80)
    
    project_root = Path(__file__).parent.parent
    pki_data_dir = project_root / "pki_data"
    
    # 1. Verifica certificati emessi dalle EA
    print("\n[1] CERTIFICATI EMESSI DALLE EA")
    print("-" * 80)
    
    ea_base = pki_data_dir / "ea"
    if not ea_base.exists():
        print("  ⚠️  Directory EA non trovata!")
    else:
        ea_dirs = list_directories(ea_base)
        total_ea_certs = 0
        
        for ea_id in ea_dirs:
            ea_cert_dir = ea_base / ea_id / "enrollment_certificates"
            if ea_cert_dir.exists():
                num_certs = count_files_in_dir(ea_cert_dir)
                total_ea_certs += num_certs
                print(f"  {ea_id}: {num_certs} certificati EC")
                print(f"    📁 {ea_cert_dir}")
            else:
                print(f"  {ea_id}: Directory enrollment_certificates non trovata")
        
        print(f"\n  TOTALE CERTIFICATI EMESSI: {total_ea_certs}")
    
    # 2. Verifica certificati ricevuti dai veicoli ITS-S
    print("\n[2] CERTIFICATI RICEVUTI DAI VEICOLI ITS-S")
    print("-" * 80)
    
    itss_base = pki_data_dir / "itss"
    if not itss_base.exists():
        print("  ⚠️  Directory ITSS non trovata!")
    else:
        vehicle_dirs = list_directories(itss_base)
        total_itss_certs = 0
        
        if not vehicle_dirs:
            print("  ⚠️  Nessun veicolo trovato!")
        else:
            for vehicle_id in vehicle_dirs:
                vehicle_base = itss_base / vehicle_id
                
                # Directory che dovrebbero esistere per ogni veicolo ITS-S
                expected_dirs = {
                    'certificates': vehicle_base / "certificates",
                    'private_keys': vehicle_base / "private_keys",
                    'crl': vehicle_base / "crl",
                    'logs': vehicle_base / "logs",
                    'backup': vehicle_base / "backup",
                    'received_messages': vehicle_base / "received_messages",
                    'inbox': vehicle_base / "inbox",
                    'outbox': vehicle_base / "outbox",
                    'authorization_tickets': vehicle_base / "authorization_tickets",
                    'trust_anchors': vehicle_base / "trust_anchors",
                    'ctl_full': vehicle_base / "ctl_full",
                    'ctl_delta': vehicle_base / "ctl_delta",
                    'own_certificates': vehicle_base / "own_certificates"
                }
                
                num_certs = count_files_in_dir(expected_dirs['certificates']) if expected_dirs['certificates'].exists() else 0
                num_keys = count_files_in_dir(expected_dirs['private_keys']) if expected_dirs['private_keys'].exists() else 0
                num_at = count_files_in_dir(expected_dirs['authorization_tickets']) if expected_dirs['authorization_tickets'].exists() else 0
                
                total_itss_certs += num_certs
                
                print(f"\n  {vehicle_id}:")
                print(f"    📄 Certificati: {num_certs}")
                print(f"    🔑 Chiavi private: {num_keys}")
                print(f"    🎫 Authorization Tickets: {num_at}")
                
                # Verifica directory esistenti
                existing_dirs = []
                missing_dirs = []
                for dir_name, dir_path in expected_dirs.items():
                    if dir_path.exists():
                        existing_dirs.append(dir_name)
                    else:
                        missing_dirs.append(dir_name)
                
                print(f"    ✅ Directory presenti ({len(existing_dirs)}/13): {', '.join(existing_dirs)}")
                if missing_dirs:
                    print(f"    ⚠️  Directory mancanti: {', '.join(missing_dirs)}")
            
            print(f"\n  TOTALE VEICOLI: {len(vehicle_dirs)}")
            print(f"  TOTALE CERTIFICATI RICEVUTI: {total_itss_certs}")
    
    # 3. Riepilogo e analisi
    print("\n[3] RIEPILOGO")
    print("-" * 80)
    
    if total_ea_certs > 0 and total_itss_certs > 0:
        print(f"  ✅ Sistema funzionante!")
        print(f"     - EA ha emesso {total_ea_certs} certificati")
        print(f"     - {len(vehicle_dirs)} veicoli hanno ricevuto certificati")
        
        if total_ea_certs > total_itss_certs:
            missing = total_ea_certs - total_itss_certs
            print(f"\n  ⚠️  ATTENZIONE: {missing} certificati emessi ma non salvati nei veicoli")
            print(f"     Questo può succedere se:")
            print(f"     1. I veicoli non hanno completato il salvataggio su disco")
            print(f"     2. Hai usato il batch enrollment senza salvataggio")
            print(f"     3. Hai cancellato manualmente alcune directory veicoli")
    elif total_ea_certs > 0:
        print(f"  ⚠️  EA ha emesso {total_ea_certs} certificati")
        print(f"     MA nessun veicolo ha salvato il proprio certificato!")
        print(f"\n  CAUSA PROBABILE:")
        print(f"     - Il test enrollment non salva i certificati nella directory veicolo")
        print(f"     - Aggiorna interactive_pki_tester.py per salvare i certificati ricevuti")
    else:
        print(f"  ⚠️  Nessun certificato trovato!")
        print(f"     - Esegui enrollment di veicoli con interactive_pki_tester.py")
    
    # 4. Suggerimenti
    print("\n[4] COME CORREGGERE")
    print("-" * 80)
    print("  Se vedi certificati emessi ma non ricevuti:")
    print("  1. Esegui nuovamente l'enrollment con la versione aggiornata del tester")
    print("  2. I certificati saranno salvati in pki_data/itss/VEHICLE_xxx/certificates/")
    print("  3. Verifica i log per errori di salvataggio")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    main()
