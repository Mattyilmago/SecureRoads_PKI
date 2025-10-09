#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script per creare una PKI di esempio nella cartella data/
Utile per documentazione e per vedere la struttura del sistema.

Questo script crea:
- 1 Root CA
- 1 Enrollment Authority (EA)
- 1 Authorization Authority (AA)
- 1 Trust List Manager (TLM)
- 1 ITS Station di esempio

Tutti i dati vengono salvati in data/ per riferimento.
"""

import os
import sys
from datetime import datetime, timedelta

# Fix encoding per Windows
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Aggiungi la directory root al path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from entities.its_station import ITSStation
from managers.trust_list_manager import TrustListManager


def create_sample_pki():
    """Crea una PKI di esempio completa."""
    
    print("=" * 80)
    print("SECUREROAD PKI - ESEMPIO DI PKI COMPLETA")
    print("=" * 80)
    print()
    
    # 1. Crea Root CA
    print("[Step 1] Creazione Root Certificate Authority...")
    root_ca = RootCA(base_dir="data/root_ca")
    print(f"✅ Root CA creata: {root_ca.ca_certificate_path}")
    print()
    
    # 2. Crea Enrollment Authority
    print("📋 Step 2: Creazione Enrollment Authority...")
    ea = EnrollmentAuthority(
        ea_id="EA_EXAMPLE",
        root_ca=root_ca,
        base_dir="data/ea"
    )
    print(f"✅ EA creata: {ea.ea_certificate_path}")
    print()
    
    # 3. Crea Trust List Manager
    print("📋 Step 3: Creazione Trust List Manager...")
    tlm = TrustListManager(
        root_ca=root_ca,
        base_dir="data/tlm"
    )
    
    # Aggiungi EA come trust anchor
    tlm.add_trust_anchor(ea.certificate, "EA_EXAMPLE")
    
    # Pubblica CTL
    tlm.publish_full_ctl()
    ctl_full = tlm.get_ctl_for_download()
    print(f"✅ TLM creato con {len(tlm.trust_anchors)} trust anchor")
    print(f"   CTL Full generato: {len(ctl_full)} bytes")
    print()
    
    # 4. Crea Authorization Authority
    print("📋 Step 4: Creazione Authorization Authority...")
    aa = AuthorizationAuthority(
        aa_id="AA_EXAMPLE",
        root_ca=root_ca,
        ea_certificate_path=ea.ea_certificate_path,
        tlm=tlm,
        base_dir="data/aa"
    )
    print(f"✅ AA creata: {aa.aa_certificate_path}")
    print()
    
    # 5. Crea ITS Station di esempio
    print("📋 Step 5: Creazione ITS Station di esempio...")
    its = ITSStation(
        its_id="VehicleExample",
        base_dir="data/itss"
    )
    
    print(f"✅ ITS Station creata: data/itss/VehicleExample/")
    print()
    
    # 7. Riepilogo
    print("=" * 80)
    print("📊 RIEPILOGO PKI CREATA")
    print("=" * 80)
    print()
    print(f"Root CA:")
    print(f"  └─ Certificato: {root_ca.ca_certificate_path}")
    print(f"  └─ Chiave privata: {root_ca.ca_key_path}")
    print()
    print(f"Enrollment Authority (EA_EXAMPLE):")
    print(f"  └─ Certificato: {ea.ea_certificate_path}")
    print(f"  └─ Chiave privata: {ea.ea_key_path}")
    print()
    print(f"Authorization Authority (AA_EXAMPLE):")
    print(f"  └─ Certificato: {aa.aa_certificate_path}")
    print(f"  └─ Chiave privata: {aa.aa_key_path}")
    print()
    print(f"Trust List Manager:")
    print(f"  └─ Base directory: data/tlm/")
    print(f"  └─ Trust anchors: {len(tlm.trust_anchors)}")
    print(f"  └─ CTL Number: {tlm.ctl_number}")
    print()
    print(f"ITS Station (VehicleExample):")
    print(f"  └─ Base directory: data/itss/VehicleExample/")
    print()
    print("=" * 80)
    print("✨ PKI di esempio creata con successo!")
    print()
    print("📂 Puoi esplorare la struttura in:")
    print("   data/root_ca/  - Root Certificate Authority")
    print("   data/ea/       - Enrollment Authorities")
    print("   data/aa/       - Authorization Authorities")
    print("   data/tlm/      - Trust List Manager")
    print("   data/itss/     - ITS Stations")
    print("=" * 80)


if __name__ == "__main__":
    try:
        create_sample_pki()
    except Exception as e:
        print(f"❌ Errore durante la creazione della PKI: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
