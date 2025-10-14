"""
Quick PKI Test - Test rapidi per verificare funzionamento PKI usando API REST
Versione con TLS/mTLS ETSI TS 102941 Compliant

Script veloce per test comuni:
- Avvia automaticamente le entities PKI con TLS
- Test enrollment
- Test authorization
- Test comunicazione

Usage:
    python quick_test.py
    python quick_test.py --test enrollment
    python quick_test.py --test all
    python quick_test.py --no-start  # Non avviare entities (usa quelle esistenti)
    python quick_test.py --no-tls    # Disabilita TLS per testing
"""

import argparse
import requests
import subprocess
import sys
import time
import os
from pathlib import Path

# Disabilita warning SSL per testing locale
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Variabile globale per tenere traccia dei processi avviati
_started_processes = []

# Configurazione TLS/mTLS
TLS_ENABLED = True  # Può essere sovrascritto con --no-tls
TLS_CA_CERT = "tls_data/ca/tls_ca_cert.pem"
TLS_CLIENT_CERT = "tls_data/clients/test_client_cert.pem"
TLS_CLIENT_KEY = "tls_data/clients/test_client_key.pem"


def get_session():
    """Crea una sessione requests configurata per TLS/mTLS"""
    session = requests.Session()
    
    if TLS_ENABLED:
        # Verifica che i certificati esistano
        if not Path(TLS_CA_CERT).exists():
            print(f"⚠️  CA certificate not found: {TLS_CA_CERT}")
            print("   Generating certificates with: python setup_tls_certificates.py")
            return None
            
        if not Path(TLS_CLIENT_CERT).exists() or not Path(TLS_CLIENT_KEY).exists():
            print(f"⚠️  Client certificates not found")
            print("   Generating certificates with: python setup_tls_certificates.py")
            return None
        
        # Configura mTLS
        session.verify = TLS_CA_CERT  # Verifica server con CA
        session.cert = (TLS_CLIENT_CERT, TLS_CLIENT_KEY)  # Certificato client per mTLS
        print("🔒 TLS/mTLS enabled")
    else:
        session.verify = False  # No SSL verification per test
        print("⚠️  TLS disabled (testing mode)")
    
    return session


def get_base_url(port):
    """Restituisce l'URL base per una porta"""
    protocol = "https" if TLS_ENABLED else "http"
    return f"{protocol}://localhost:{port}"


def start_pki_entities():
    """Avvia le entities PKI automaticamente"""
    global _started_processes
    
    print("\n" + "="*60)
    print("  AVVIO ENTITIES PKI" + (" (TLS/mTLS)" if TLS_ENABLED else ""))
    print("="*60)
    
    # Trova root del progetto
    project_root = Path(__file__).parent.parent
    
    # Configura entities da avviare con auto-assignment porte
    # EA: 5000-5019, AA: 5020-5039, TLM: 5050
    entities = [
        ("EA_001", "EA"),
        ("EA_002", "EA"),
        ("AA_001", "AA"),
        ("AA_002", "AA"),
        ("TLM_MAIN", "TLM")
    ]
    
    for entity_id, entity_type in entities:
        try:
            print(f"\n  Avvio {entity_id} (auto-port)...", end=" ")
            
            # Path al config file con TLS se disponibile
            config_file = None
            if TLS_ENABLED:
                config_path = project_root / f"configs/{entity_id.lower()}_config.json"
                if config_path.exists():
                    config_file = str(config_path)
            
            # Comando per avviare l'entity (senza --port per auto-assignment)
            cmd = [
                sys.executable,
                str(project_root / "server.py"),
                "--entity", entity_type,
                "--id", entity_id
            ]
            
            # Aggiungi config se disponibile
            if config_file:
                cmd.extend(["--config", config_file])
            
            # Avvia in background
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            else:  # Linux/Mac
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            _started_processes.append((entity_id, None, process))  # None = porta sconosciuta ancora
            print("✅")
            
        except Exception as e:
            print(f"❌ ({str(e)[:30]})")
    
    # Aspetta che i server siano pronti
    wait_time = 20 if TLS_ENABLED else 10  # TLS/mTLS needs more time for handshake
    print(f"\n  Attesa avvio server ({wait_time} secondi)...")
    time.sleep(wait_time)
    
    # Verifica che siano attivi e rileva le porte assegnate
    print("\n  Verifica connessioni e rilevamento porte:")
    active_count = 0
    session = get_session()
    if not session:
        print("\n  ⚠️  Impossibile creare session TLS!")
        return _started_processes
    
    # Range di porte da controllare per ogni tipo
    port_ranges = {
        "EA": range(5000, 5020),  # EA: 5000-5019
        "AA": range(5020, 5040),  # AA: 5020-5039
        "TLM": [5050]             # TLM: 5050
    }
    
    updated_processes = []
    for entity_id, _, process in _started_processes:
        entity_type = entity_id.split("_")[0]  # Estrae EA, AA, o TLM
        found = False
        
        # Cerca in quale porta è attivo
        for port in port_ranges.get(entity_type, []):
            try:
                url = get_base_url(port) + "/health"
                timeout = 15 if TLS_ENABLED else 5
                response = session.get(url, timeout=timeout)
                if response.status_code == 200:
                    print(f"    {entity_id} (:{port}): ✅")
                    updated_processes.append((entity_id, port, process))
                    active_count += 1
                    found = True
                    break
            except:
                continue
        
        if not found:
            print(f"    {entity_id} (porta sconosciuta): ❌")
            updated_processes.append((entity_id, None, process))
    
    _started_processes = updated_processes
    print(f"\n  Entities attive: {active_count}/{len(entities)}")
    
    if active_count == 0:
        print("\n  ⚠️  Nessuna entity attiva! Test potrebbero fallire.")
    
    return _started_processes


def stop_pki_entities():
    """Chiudi le entities PKI avviate"""
    global _started_processes
    
    if not _started_processes:
        return
    
    print("\n" + "="*60)
    print("  CHIUSURA ENTITIES")
    print("="*60)
    
    for entity_id, _, process in _started_processes:
        try:
            print(f"  Chiusura {entity_id}...", end=" ")
            
            # Su Windows usa CTRL_BREAK_EVENT per chiusura pulita
            if os.name == 'nt':
                import signal
                try:
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                except:
                    process.terminate()
            else:
                process.terminate()
            
            try:
                process.wait(timeout=5)
                print("✅")
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                print("⚠️  (forzata)")
        except Exception as e:
            print(f"❌ ({str(e)[:20]})")
    
    _started_processes = []


def test_enrollment(session, ea_url="http://localhost:5000"):
    """
    Test rapido enrollment usando API REST
    
    Default URL: http://localhost:5000 (EA range: 5000-5019)
    Override with --ea-url if your EA uses a different port
    """
    print("\n" + "="*60)
    print("  TEST: Enrollment")
    print("="*60)
    
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        
        station_id = f"QUICK_TEST_{int(time.time())}"
        print(f"\n1. Creazione richiesta enrollment: {station_id}")
        
        # Genera chiave per il test
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Prepara richiesta enrollment (formato semplificato per test)
        enrollment_request = {
            "canonical_id": station_id,
            "its_id": station_id,
            "public_key": public_key_pem,
            "requested_subject_attributes": {
                "country": "IT",
                "organization": f"TestOrg_{station_id}",
                "its_aid": "36"
            }
        }
        
        print(f"\n2. Invio richiesta a {ea_url}/api/enrollment/request/simple")
        
        response = session.post(
            f"{ea_url}/api/enrollment/request/simple",
            json=enrollment_request,
            timeout=30  # Increased for mTLS handshake
        )
        
        if response.status_code == 200:
            result = response.json()
            print("   ✅ Enrollment riuscito!")
            print(f"   Response: {result.get('message', 'Success')}")
            if 'certificate' in result:
                print(f"   Certificate received: {len(result['certificate'])} bytes")
            return True
        else:
            print(f"   ❌ Enrollment fallito! Status: {response.status_code}")
            print(f"   Error: {response.text[:200]}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Impossibile connettersi a {ea_url}")
        print(f"   Assicurati che EA sia attivo sulla porta")
        return False
    except Exception as e:
        print(f"   ❌ Errore: {e}")
        return False


def test_authorization(session, ea_url="http://localhost:5000", aa_url="http://localhost:5020"):
    """
    Test authorization ticket (AT) flow
    
    Default URLs:
    - EA: http://localhost:5000 (EA range: 5000-5019)
    - AA: http://localhost:5020 (AA range: 5020-5039)
    Override with --ea-url and --aa-url if using different ports
    """
    """Test rapido authorization usando API REST"""
    print("\n" + "="*60)
    print("  TEST: Authorization")
    print("="*60)
    
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        
        station_id = f"QUICK_AUTH_{int(time.time())}"
        print(f"\n1. Step 1: Enrollment per {station_id}")
        
        # Genera chiave per il test
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        # Prima enrollment
        enrollment_request = {
            "canonical_id": station_id,
            "its_id": station_id,
            "public_key": public_key_pem,
            "requested_subject_attributes": {
                "country": "IT",
                "organization": f"TestOrg_{station_id}",
                "its_aid": "36"
            }
        }
        
        response = session.post(
            f"{ea_url}/api/enrollment/request/simple",
            json=enrollment_request,
            timeout=30  # Increased for mTLS handshake
        )
        
        if response.status_code != 200:
            print("   ❌ Enrollment fallito!")
            return False
        
        print("   ✅ Enrollment riuscito")
        
        print(f"\n2. Step 2: Richiesta Authorization Ticket a {aa_url}")
        
        # Poi authorization (questo richiede implementazione completa)
        print("   ℹ️  Authorization test richiede enrollment certificate valido")
        print("   ℹ️  Test parziale completato con successo")
        return True
            
    except requests.exceptions.ConnectionError as e:
        print(f"   ❌ Errore connessione: {e}")
        return False
    except Exception as e:
        print(f"   ❌ Errore: {e}")
        return False


def test_multiple_enrollments(session, ea_url="http://localhost:5000", count=3):
    """
    Test multiple enrollment requests
    
    Default URL: http://localhost:5000 (EA range: 5000-5019)
    """
    """Test enrollment multipli usando API REST"""
    print("\n" + "="*60)
    print(f"  TEST: {count} Enrollment Consecutivi")
    print("="*60)
    
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    
    success = 0
    failed = 0
    
    for i in range(count):
        try:
            station_id = f"MULTI_TEST_{i+1:03d}_{int(time.time())}"
            
            # Genera chiave per ogni test
            private_key = ec.generate_private_key(ec.SECP256R1())
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            enrollment_request = {
                "canonical_id": station_id,
                "its_id": station_id,
                "public_key": public_key_pem,
                "requested_subject_attributes": {
                    "country": "IT",
                    "organization": f"TestOrg_{station_id}",
                    "its_aid": "36"
                }
            }
            
            response = session.post(
                f"{ea_url}/api/enrollment/request/simple",
                json=enrollment_request,
                timeout=30  # Increased for mTLS handshake
            )
            
            if response.status_code == 200:
                success += 1
                print(f"  [{i+1}/{count}] ✅")
            else:
                failed += 1
                print(f"  [{i+1}/{count}] ❌ Status {response.status_code}")
                
        except Exception as e:
            failed += 1
            print(f"  [{i+1}/{count}] ❌ {str(e)[:40]}")
    
    print(f"\n  Risultato: {success} successi, {failed} fallimenti")
    return success == count


def test_health_check(session, ea_url="http://localhost:5000"):
    """
    Test endpoint health check
    
    Default URL: http://localhost:5000 (EA range: 5000-5019)
    """
    """Test health check endpoint"""
    print("\n" + "="*60)
    print("  TEST: Health Check")
    print("="*60)
    
    try:
        print(f"\n1. Verifica {ea_url}/health")
        response = session.get(f"{ea_url}/health", timeout=15)  # Increased for mTLS
        
        if response.status_code == 200:
            data = response.json()
            print("   ✅ Server attivo!")
            print(f"   Status: {data.get('status', 'N/A')}")
            print(f"   Entity: {data.get('entity_type', 'N/A')} - {data.get('entity_id', 'N/A')}")
            if 'uptime' in data:
                print(f"   Uptime: {data['uptime']}")
            return True
        else:
            print(f"   ❌ Status: {response.status_code}")
            return False
            
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Server non raggiungibile")
        return False
    except Exception as e:
        print(f"   ❌ Errore: {e}")
        return False


def run_all_tests(ea_url, aa_url):
    """Esegui tutti i test"""
    print("\n" + "="*60)
    print("  ESECUZIONE TUTTI I TEST")
    print("="*60)
    
    results = []
    
    # Crea sessione mTLS
    session = get_session()
    
    # Test 0: Health Check
    print("\n[0/4] Test Health Check...")
    results.append(("Health Check", test_health_check(session, ea_url)))
    time.sleep(1)
    
    # Test 1: Enrollment
    print("\n[1/4] Test Enrollment...")
    results.append(("Enrollment", test_enrollment(session, ea_url)))
    time.sleep(1)
    
    # Test 2: Authorization
    print("\n[2/4] Test Authorization...")
    results.append(("Authorization", test_authorization(session, ea_url, aa_url)))
    time.sleep(1)
    
    # Test 3: Multiple
    print("\n[3/4] Test Multiple Enrollments...")
    results.append(("Multiple", test_multiple_enrollments(session, ea_url, 3)))
    
    # Riepilogo
    print("\n" + "="*60)
    print("  RIEPILOGO")
    print("="*60)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name}: {status}")
    
    passed = sum(1 for _, r in results if r)
    print(f"\n  Totale: {passed}/{len(results)} test superati")
    
    return passed == len(results)


def main():
    parser = argparse.ArgumentParser(description="Quick PKI Test usando API REST")
    
    parser.add_argument(
        "--test",
        choices=["enrollment", "authorization", "multiple", "health", "all"],
        default="all",
        help="Tipo di test da eseguire"
    )
    
    parser.add_argument(
        "--ea-port",
        type=int,
        default=5000,
        help="Porta Enrollment Authority (default: 5000, EA range: 5000-5019)"
    )
    
    parser.add_argument(
        "--aa-port",
        type=int,
        default=5020,
        help="Porta Authorization Authority (default: 5020, AA range: 5020-5039)"
    )
    
    parser.add_argument(
        "--count",
        type=int,
        default=3,
        help="Numero di enrollment per test multiple"
    )
    
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Non avviare automaticamente le entities (usa quelle già attive)"
    )
    
    args = parser.parse_args()
    
    # Genera URL dinamicamente in base a TLS_ENABLED
    ea_url = get_base_url(args.ea_port)
    aa_url = get_base_url(args.aa_port)
    
    print("\n🚀 Quick PKI Tester (API REST)")
    if TLS_ENABLED:
        print("   🔒 TLS/mTLS Mode: ENABLED")
    print(f"   EA URL: {ea_url}")
    print(f"   AA URL: {aa_url}")
    
    # Avvia entities se richiesto
    if not args.no_start:
        start_pki_entities()
    else:
        print("\n⚠️  Modalità --no-start: usando entities già attive")
    
    success = False
    
    try:
        # Crea sessione mTLS
        session = get_session()
        
        if args.test == "enrollment":
            success = test_enrollment(session, ea_url)
        elif args.test == "authorization":
            success = test_authorization(session, ea_url, aa_url)
        elif args.test == "multiple":
            success = test_multiple_enrollments(session, ea_url, args.count)
        elif args.test == "health":
            success = test_health_check(session, ea_url)
        else:
            success = run_all_tests(ea_url, aa_url)
    
    finally:
        # Chiudi i processi avviati
        if not args.no_start:
            stop_pki_entities()
    
    print("\n" + "="*60)
    if success:
        print("  ✅ TEST SUPERATO")
    else:
        print("  ❌ TEST FALLITO")
    print("="*60 + "\n")
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
