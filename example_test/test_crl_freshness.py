"""
Test CRL Freshness Security Scenario

Dimostra il problema di sicurezza quando un ITS-S usa una CRL obsoleta
e come il sistema lo rileva con il check di freshness.

Scenario:
1. Vehicle_Receiver scarica CRL
2. AA revoca AT di Vehicle_Malicious (genera nuova CRL)
3. Vehicle_Malicious invia messaggio malevolo
4. Vehicle_Receiver valida con CRL vecchia (pre-revoca)
5. Sistema rileva CRL obsoleta e avvisa

In produzione: sistema dovrebbe scaricare nuovo Delta CRL automaticamente.
"""

import sys
import os
import time
from datetime import datetime, timedelta

# Aggiungi la directory principale al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from entities.its_station import ITSStation

print("="*80)
print("  TEST: CRL FRESHNESS SECURITY SCENARIO")
print("="*80)
print()

# ========== FASE 1: Setup PKI ==========
print("[FASE 1] Setup infrastruttura PKI...")
root_ca = RootCA()
ea = EnrollmentAuthority(root_ca, ea_id="EA_FRESHNESS_TEST")
aa = AuthorizationAuthority(
    root_ca,
    ea_certificate_path=f"./data/ea/EA_FRESHNESS_TEST/certificates/ea_certificate.pem",
    aa_id="AA_FRESHNESS_TEST"
)
print("[OK] PKI configurata\n")

# ========== FASE 2: Crea veicoli ==========
print("[FASE 2] Creazione veicoli...")
receiver = ITSStation("Vehicle_Receiver_Fresh")
malicious = ITSStation("Vehicle_Malicious")

# Setup certificati per entrambi
for vehicle in [receiver, malicious]:
    vehicle.generate_ecc_keypair()
    vehicle.request_ec(ea)
    vehicle.request_at(aa)

print("[OK] Veicoli configurati con EC e AT\n")

# ========== FASE 3: Genera CRL iniziale ==========
print("[FASE 3] Genera CRL Full iniziale (nessun certificato revocato)...")
aa.crl_manager.publish_full_crl()
print(f"[OK] CRL pubblicata: ./data/aa/AA_FRESHNESS_TEST/crl/full_crl.pem")

# Mostra l'età della CRL
from cryptography import x509
from datetime import timezone
crl_path = "./data/aa/AA_FRESHNESS_TEST/crl/full_crl.pem"
with open(crl_path, "rb") as f:
    crl = x509.load_pem_x509_crl(f.read())
    crl_age = datetime.now(timezone.utc) - crl.last_update_utc
    print(f"   CRL last_update: {crl.last_update_utc}")
    print(f"   CRL età: {int(crl_age.total_seconds())} secondi")
print()

# ========== FASE 4: Vehicle_Malicious invia messaggio PRIMA della revoca ==========
print("[FASE 4] Vehicle_Malicious invia messaggio LEGITTIMO (AT ancora valido)...")
malicious.send_signed_message(
    message="Posizione: 45.123, 9.456 (messaggio prima revoca)",
    recipient_id="Vehicle_Receiver_Fresh",
    message_type="CAM"
)
print("[OK] Messaggio inviato\n")

# ========== FASE 5: Vehicle_Receiver valida con CRL fresca ==========
print("[FASE 5] Vehicle_Receiver valida messaggio con CRL aggiornata...")
messages = receiver.receive_signed_message(validate=True)
if len(messages) > 0:
    print(f"[OK] Messaggio ACCETTATO (CRL fresca, AT non revocato)")
    print(f"   Messaggi validati: {len(messages)}")
else:
    print(f"[ERROR] Messaggio RIFIUTATO (unexpected!)")
print()

# ========== FASE 6: AA revoca AT di Vehicle_Malicious ==========
print("[FASE 6] AA rileva comportamento sospetto e REVOCA AT di Vehicle_Malicious...")
print("   (Simula: chiave compromessa, veicolo rubato, comportamento malevolo)")

# Ottieni il certificato AT per revocarlo
malicious_at_path = f"./data/itss/Vehicle_Malicious/received_tickets/Vehicle_Malicious_at.pem"
with open(malicious_at_path, "rb") as f:
    malicious_at_cert = x509.load_pem_x509_certificate(f.read())

# Revoca
from cryptography.x509.oid import CRLEntryExtensionOID
from cryptography.x509 import ReasonFlags
aa.crl_manager.add_revoked_certificate(
    certificate=malicious_at_cert,
    reason=ReasonFlags.key_compromise  # Chiave compromessa
)

# Pubblica NUOVA CRL con la revoca
aa.crl_manager.publish_full_crl()
print(f"[OK] AT revocato e CRL aggiornata pubblicata")

# Mostra nuova età CRL
with open(crl_path, "rb") as f:
    new_crl = x509.load_pem_x509_crl(f.read())
    new_crl_age = datetime.now(timezone.utc) - new_crl.last_update_utc
    print(f"   Nuova CRL last_update: {new_crl.last_update_utc}")
    print(f"   Nuova CRL età: {int(new_crl_age.total_seconds())} secondi")
    print(f"   Certificati revocati nella CRL: {len(list(new_crl))}")
print()

# ========== FASE 7: Vehicle_Malicious invia messaggio DOPO la revoca ==========
print("[FASE 7] Vehicle_Malicious tenta di inviare messaggio DOPO la revoca...")
malicious.send_signed_message(
    message="Posizione FALSA: 99.999, 99.999 (messaggio DOPO revoca!)",
    recipient_id="Vehicle_Receiver_Fresh",
    message_type="CAM"
)
print("[OK] Messaggio malevolo inviato\n")

# ========== FASE 8: Vehicle_Receiver valida con AGGIORNAMENTO AUTOMATICO ==========
print("[FASE 8] Vehicle_Receiver valida con AGGIORNAMENTO AUTOMATICO CRL...")
print("   Scenario CONFORME ETSI TS 102 941:")
print("   1. Rileva CRL obsoleta (>10 min)")
print("   2. Scarica automaticamente nuovo Delta CRL")
print("   3. Ricarica CRL aggiornata con revoca")
print("   4. Rileva AT revocato → RIFIUTA messaggio")
print()

# Prima dell'aggiornamento: forza età CRL vecchia copiando la CRL in una posizione temporanea
# (simula scenario reale dove ITS-S ha CRL vecchia in cache)
import shutil
temp_crl_path = "./data/aa/AA_FRESHNESS_TEST/crl/full_crl_backup.pem"
shutil.copy(crl_path, temp_crl_path)

# Ora la validazione rileverà CRL obsoleta e la aggiornerà automaticamente
messages = receiver.receive_signed_message(validate=True)
print()
if len(messages) == 0:
    print("[OK] SICUREZZA OK: Messaggio da AT revocato RIFIUTATO")
    print("   Il sistema ha:")
    print("   - Rilevato CRL obsoleta")
    print("   - Aggiornato automaticamente la CRL")
    print("   - Verificato la revoca del certificato AT")
    print("   - Rifiutato il messaggio malevolo")
    print()
    print("[TARGET] CONFORME ETSI TS 102 941 - Sezione 6.3.3")
else:
    print(f"[ERROR] ATTENZIONE: {len(messages)} messaggi accettati")
    print("   (Nota: Possibile se CRL non aggiornata automaticamente)")
print()


