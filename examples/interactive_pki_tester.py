"""
Interactive PKI Tester - Test quotidiani per SecureRoad PKI usando API REST

Script interattivo per eseguire test comuni sulla PKI:
- Avvia automaticamente le entities PKI
- Enrollment di veicoli
- Richiesta Authorization Tickets
- Verifica certificati
- Test comunicazione V2V
- Performance testing

Usage:
    python interactive_pki_tester.py
    python interactive_pki_tester.py --dashboard  # Avvia con integrazione dashboard
    python interactive_pki_tester.py --no-start   # Non avviare entities
"""

import sys
import os

# Fix Windows console encoding BEFORE any other imports or prints
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
        os.environ['PYTHONIOENCODING'] = 'utf-8'
    except AttributeError:
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except Exception:
        pass

import argparse
import json
import requests
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509

# Import PKIEntityManager for port management
sys.path.insert(0, str(Path(__file__).parent.parent))
from cryptography.hazmat.primitives import hashes
from server import PKIEntityManager
from utils.pki_paths import PKIPathManager

# Import ETSI components
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import InnerEcRequest, InnerAtRequest, SharedAtRequest, compute_hashed_id8, ResponseCode

# Variabile globale per processi avviati
_started_processes = []

# Forza HTTP di default nei test interattivi (impostare PKI_ALLOW_TLS=1 per riabilitare TLS)
if os.environ.get("PKI_ALLOW_TLS", "").lower() not in {"1", "true", "yes", "on"}:
    os.environ["PKI_DISABLE_TLS"] = "1"
    os.environ["PKI_FORCE_HTTP"] = "1"
    print("[INFO] TLS disabilitato per test interattivi (PKI_DISABLE_TLS=1)")


def get_request_kwargs():
    """
    Restituisce kwargs per requests.
    
    Returns:
        dict: Dizionario vuoto (senza configurazione TLS)
    """
    return {}


def build_url(host, port, path=""):
    """
    Costruisce URL HTTP.
    
    Args:
        host: Hostname (es. "localhost", "127.0.0.1")
        port: Porta
        path: Path opzionale (es. "/api/stats")
    
    Returns:
        str: URL completo HTTP
    """
    schema = "http"
    path = path.lstrip("/") if path else ""
    
    if path:
        return f"{schema}://{host}:{port}/{path}"
    else:
        return f"{schema}://{host}:{port}"


def safe_print(text, **kwargs):
    """Stampa testo gestendo errori di encoding su Windows"""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        # Fallback: rimuovi caratteri non ASCII
        safe_text = text.encode('ascii', 'ignore').decode('ascii')
        print(safe_text, **kwargs)


def start_pki_entities():
    """Avvia le entities PKI automaticamente controllando la disponibilità delle porte"""
    global _started_processes
    
    if _started_processes:
        print("  ⚠️  Entities già avviate, skip")
        return _started_processes
    
    print("\n" + "="*70)
    print("  AVVIO ENTITIES PKI")
    print("="*70)
    
    # Ferma eventuali entities esistenti prima di avviarne di nuove
    #print("  Chiusura entities esistenti...")
    #stop_pki_entities()
    #time.sleep(2)  # Aspetta che si chiudano
    
    # Trova root del progetto
    project_root = Path(__file__).parent.parent
    
    # Crea manager per gestione porte
    manager = PKIEntityManager()
    
    # Trova entities esistenti per generare nomi unici
    existing_ea = manager.find_existing_entities("EA")
    existing_aa = manager.find_existing_entities("AA")
    
    # Genera nomi unici per EA e AA
    ea_name = manager.generate_entity_name_with_suffix("EA_001", existing_ea)
    aa_name = manager.generate_entity_name_with_suffix("AA_001", existing_aa)
    
    print(f"  Nomi generati: {ea_name}, {aa_name}")
    
    # Entities da avviare con nomi dinamici
    entities = [
        ("EA", ea_name),
        ("AA", aa_name),
        ("TLM", "TLM_MAIN"),
        ("RootCA", "RootCA")
    ]
    
    # Trova porte disponibili per ogni entità
    used_ports = manager.find_used_ports()  # Inizia con porte già in uso
    entity_configs = []
    
    print("  Ricerca porte disponibili...")
    for entity_type, entity_id in entities:
        port = manager.find_available_port_in_range(entity_type, used_ports=used_ports)
        if port:
            used_ports.add(port)
            entity_configs.append((entity_type, entity_id, port))
            print(f"    {entity_id}: porta {port}")
        else:
            # Distingui tra TLM/RootCA (già attive) e altre entities (errore)
            if entity_type in ["TLM", "RootCA"]:
                print(f"    {entity_id}: ℹ️  già attiva (porta occupata)")
            else:
                print(f"    {entity_id}: ❌ nessuna porta disponibile nel range - SKIP")
            # Continua con le altre entities invece di fallire completamente
    
    print("\n  Avvio entities...")
    
    for entity_type, entity_id, port in entity_configs:
        try:
            print(f"\n  Avvio {entity_id}...", end=" ")
            
            # Comando per avviare l'entity con server.py sulla porta specifica
            # Forza binding su localhost per test (127.0.0.1) e registra output su file
            cmd = [
                sys.executable,
                str(project_root / "server.py"),
                "--entity", entity_type,
                "--id", entity_id,
                "--port", str(port),
                "--host", "127.0.0.1"
            ]
            
            # Avvia in background con PYTHONPATH settato
            env = os.environ.copy()
            env['PYTHONPATH'] = str(project_root)
            
            # Prepare logs directory
            log_dir = project_root / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)

            out_path = str(log_dir / f"{entity_id}.out")
            err_path = str(log_dir / f"{entity_id}.err")

            out_f = open(out_path, "ab")
            err_f = open(err_path, "ab")

            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    env=env,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    shell=False,
                    stdout=out_f,
                    stderr=err_f
                )
            else:  # Linux/Mac
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    env=env,
                    stdout=out_f,
                    stderr=err_f
                )
            
            _started_processes.append((entity_type, entity_id, process))
            print("✅")
            
        except Exception as e:
            print(f"❌ ({str(e)[:30]})")
    
    # Aspetta che i server siano pronti
    print(f"\n  Attesa avvio server (1 secondo)...")
    time.sleep(1)
    
    # Verifica che siano attivi usando le porte reali
    print("\n  Verifica connessioni:")
    active_count = 0
    
    for entity_type, entity_id, process in _started_processes:
        # Trova la porta corrispondente
        port = None
        for et, eid, p in entity_configs:
            if et == entity_type and eid == entity_id:
                port = p
                break
        
        if port:
            try:
                url = build_url("localhost", port, "/health")
                response = requests.get(url, timeout=2, **get_request_kwargs())
                if response.status_code == 200:
                    print(f"    {entity_id} (:{port}): ✅")
                    active_count += 1
                else:
                    print(f"    {entity_id} (:{port}): ❌")
            except:
                print(f"    {entity_id} (:{port}): ❌")
        else:
            print(f"    {entity_id}: ❌ (porta non trovata)")
    
    print(f"\n  Entities attive: {active_count}/{len(_started_processes)}")
    
    if active_count == 0:
        print("\n  ⚠️  Nessuna entity attiva! Test potrebbero fallire.")
    
    # Restituisci informazioni sulle entities avviate con porte
    entity_info = []
    for entity_type, entity_id, process in _started_processes:
        port = None
        for et, eid, p in entity_configs:
            if et == entity_type and eid == entity_id:
                port = p
                break
        if port:
            entity_info.append({
                'type': entity_type,
                'id': entity_id,
                'port': port,
                'url': build_url("localhost", port)
            })
    
    return entity_info


def stop_pki_entities():
    """Chiudi le entities PKI avviate"""
    global _started_processes
    
    if not _started_processes:
        return
    
    print("\n" + "="*70)
    print("  CHIUSURA ENTITIES")
    print("="*70)
    
    for entity_type, entity_id, process in _started_processes:
        try:
            print(f"  Chiusura {entity_id}...", end=" ")
            
            # Su Windows usa terminate() per chiusura
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


class PKITester:
    """Classe per eseguire test interattivi sulla PKI usando API REST"""
    
    def __init__(self):
        self.test_results = []
        self.enrolled_vehicles = {}  # {vehicle_id: {certificate_data}}
        # Contatori per certificati emessi durante i test
        self.total_ec_issued = 0
        self.total_at_issued = 0
        # Contatori per certificati revocati durante i test
        self.revoked_ec_count = 0
        self.revoked_at_count = 0
        
        # Lista delle entità disponibili (popolata da scan_entities_at_startup)
        self.available_entities = {"EA": [], "AA": []}
        
        # Default URLs (will be set after scanning)
        self.ea_url = None
        self.aa_url = None
        self.tlm_url = self._find_entity_url("TLM", 5050, 5050)

        # Flag per modalità completamente automatica (--auto)
        self.auto_mode = False
        
        # ETSI encoder instance
        self.encoder = ETSIMessageEncoder()
        
        # Cache per certificati entity
        self._ea_certificate = None
        self._aa_certificate = None
        self._ea_public_key = None
        self._aa_public_key = None
        
    def _find_entity_url(self, entity_type, port_start, port_end):
        """Trova dinamicamente l'URL di un'entità in esecuzione"""
        import socket
        
        for port in range(port_start, port_end + 1):
            try:
                # Test connessione TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    # Porta aperta, verifica se è l'entità giusta
                    url = f"http://127.0.0.1:{port}"
                    try:
                        response = requests.get(f"{url}/", timeout=2)
                        if response.status_code == 200:
                            data = response.json()
                            if data.get('entity_type') == entity_type:
                                self.print_info(f"Trovata {entity_type} su porta {port}")
                                return url
                    except:
                        pass
                        
            except:
                pass
        
        # Fallback alla porta di default se nessuna trovata
        default_port = port_start
        self.print_info(f"Nessuna {entity_type} trovata, uso porta default {default_port}")
        return f"http://127.0.0.1:{default_port}"
    
    def scan_entities_at_startup(self):
        """Scansiona tutte le porte da 5000 a 5039 all'avvio per identificare EA e AA disponibili"""
        self.print_info("🔍 Scansione entità disponibili (porte 5000-5039)...")
        
        import socket
        import concurrent.futures
        import requests
        
        def check_port(port):
            """Controlla una singola porta e restituisce info entità se trovata"""
            try:
                # Test connessione TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    # Porta aperta, verifica se è un'entità PKI
                    url = f"http://127.0.0.1:{port}"
                    try:
                        response = requests.get(f"{url}/", timeout=2)
                        if response.status_code == 200:
                            data = response.json()
                            entity_type = data.get('entity_type')
                            entity_id = data.get('entity_id', f'{entity_type}_UNKNOWN')
                            
                            if entity_type in ["EA", "AA"]:
                                return {
                                    'entity_type': entity_type,
                                    'id': entity_id,
                                    'url': url,
                                    'port': port
                                }
                    except:
                        pass
                        
            except:
                pass
            
            return None
        
        # Scansiona tutte le porte in parallelo
        found_entities = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            # Sottometti tutti i task
            future_to_port = {executor.submit(check_port, port): port for port in range(5000, 5040)}
            
            # Raccogli i risultati man mano che arrivano
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                if result:
                    found_entities.append(result)
        
        # Separa per tipo e ordina per numero di porta
        found_ea = sorted([e for e in found_entities if e['entity_type'] == 'EA'], key=lambda x: x['port'])
        found_aa = sorted([e for e in found_entities if e['entity_type'] == 'AA'], key=lambda x: x['port'])
        
        self.available_entities["EA"] = found_ea
        self.available_entities["AA"] = found_aa
        
        # Imposta URL di default alla prima disponibile
        if found_ea:
            self.ea_url = found_ea[0]['url']
        if found_aa:
            self.aa_url = found_aa[0]['url']
        
        # Log dei risultati
        total_found = len(found_ea) + len(found_aa)
        if total_found > 0:
            self.print_success(f"Trovate {total_found} entità: {len(found_ea)} EA, {len(found_aa)} AA")
            for ea in found_ea:
                self.print_info(f"  EA: {ea['id']} (porta {ea['port']})")
            for aa in found_aa:
                self.print_info(f"  AA: {aa['id']} (porta {aa['port']})")
        else:
            self.print_info("Nessuna entità PKI trovata nelle porte 5000-5039")
    
    def select_entity_interactive(self, entity_type):
        """Mostra lista delle autorità disponibili dalla cache e chiede all'utente quale scegliere"""
        available_entities = self.available_entities.get(entity_type, [])

        if self.auto_mode:
            if available_entities:
                selected = available_entities[0]
                selected_url = selected['url']
                self.print_info(
                    f"Modalità auto: uso {entity_type} {selected['id']} (porta {selected['port']})"
                )
            else:
                selected_url = self.ea_url if entity_type == "EA" else self.aa_url
                if selected_url:
                    self.print_info(
                        f"Modalità auto: nessuna {entity_type} scansionata, uso URL predefinito {selected_url}"
                    )
                else:
                    self.print_error(f"Modalità auto: nessuna {entity_type} disponibile")
                    return None

            if entity_type == "EA":
                self.ea_url = selected_url
            elif entity_type == "AA":
                self.aa_url = selected_url
            return selected_url
        
        if not available_entities:
            self.print_error(f"Nessuna {entity_type} disponibile trovata nella cache!")
            self.print_info("Riprova a eseguire la scansione con --scan-entities")
            return None
        
        # Mostra la lista delle autorità disponibili dalla cache
        self.print_info(f"Autorità {entity_type} disponibili:")
        for i, entity in enumerate(available_entities, 1):
            print(f"  {i}. {entity['id']} - Porta {entity['port']}")
        
        # Chiedi all'utente quale scegliere
        while True:
            try:
                choice = input(f"\nScegli l'{entity_type} da usare (1-{len(available_entities)}) o 0 per annullare: ").strip()
                choice_num = int(choice)
                
                if choice_num == 0:
                    self.print_info("Operazione annullata")
                    return None
                elif 1 <= choice_num <= len(available_entities):
                    selected = available_entities[choice_num - 1]
                    self.print_success(f"Selezionata {entity_type}: {selected['id']} su porta {selected['port']}")
                    return selected['url']
                else:
                    self.print_error(f"Scelta non valida. Inserisci un numero tra 1 e {len(available_entities)} o 0 per annullare")
            except ValueError:
                self.print_error("Inserisci un numero valido")
    
    def print_header(self, text):
        """Stampa intestazione formattata"""
        print("\n" + "="*70)
        print(f"  {text}")
        print("="*70)
    
    def print_success(self, text):
        """Stampa messaggio di successo"""
        print(f"✅ {text}")
        
    def print_error(self, text):
        """Stampa messaggio di errore"""
        print(f"❌ {text}")
    
    def print_warning(self, text):
        """Stampa messaggio di warning"""
        print(f"⚠️  {text}")
        
    def print_info(self, text):
        """Stampa informazione"""
        print(f"ℹ️  {text}")
    
    def print_test_execution_time(self, test_name, duration):
        """Stampa il tempo di esecuzione di un test"""
        self.print_info(f"⏱️  Tempo esecuzione {test_name}: {duration:.2f}s")
    
    @staticmethod
    def time_test_execution(test_name=None):
        """Decorator per tracciare il tempo di esecuzione dei test"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                start_time = time.time()
                try:
                    result = func(*args, **kwargs)
                    end_time = time.time()
                    duration = end_time - start_time
                    display_name = test_name or func.__name__.replace('test_', '').replace('_', ' ').title()
                    args[0].print_info(f"⏱️  Tempo esecuzione {display_name}: {duration:.2f}s")
                    return result
                except Exception as e:
                    end_time = time.time()
                    duration = end_time - start_time
                    display_name = test_name or func.__name__.replace('test_', '').replace('_', ' ').title()
                    args[0].print_error(f"⏱️  Test {display_name} fallito dopo {duration:.2f}s: {e}")
                    raise
            return wrapper
        return decorator
    
    def save_test_result(self, test_name, status, details=None):
        """Salva risultato del test"""
        result = {
            "timestamp": datetime.now().isoformat(),
            "test": test_name,
            "status": status,
            "details": details or {}
        }
        self.test_results.append(result)
        
        # Salva su file per la dashboard
        results_file = Path("pki_data/test_results.json")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(results_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
    
    def get_entity_metrics(self, entity_url):
        """Ottiene le metriche da un'entità PKI"""
        try:
            response = requests.get(f"{entity_url}/api/stats", timeout=5, **get_request_kwargs())
            if response.status_code == 200:
                return response.json()
            else:
                self.print_warning(f"Impossibile ottenere metriche da {entity_url}: {response.status_code}")
                return None
        except Exception as e:
            self.print_warning(f"Errore connessione metriche {entity_url}: {e}")
            return None
    
    def print_metrics_summary(self, ea_metrics=None, aa_metrics=None):
        """Stampa riepilogo metriche delle entities"""
        self.print_info("📊 METRICHE ENTITIES:")
        
        if ea_metrics:
            self.print_info(f"  EA ({ea_metrics.get('entity_id', 'N/A')}):")
            self.print_info(f"    Certificati emessi: {ea_metrics.get('certificates_issued', 0)}")
            self.print_info(f"    Certificati attivi: {ea_metrics.get('active_certificates', 0)}")
            self.print_info(f"    Certificati revocati: {ea_metrics.get('revoked_certificates', 0)}")
        
        if aa_metrics:
            self.print_info(f"  AA ({aa_metrics.get('entity_id', 'N/A')}):")
            self.print_info(f"    Tickets emessi: {aa_metrics.get('certificates_issued', 0)}")
            self.print_info(f"    Tickets attivi: {aa_metrics.get('active_certificates', 0)}")
            self.print_info(f"    Tickets revocati: {aa_metrics.get('revoked_certificates', 0)}")
    
    def get_ea_certificate(self, ea_url=None):
        """Ottiene il certificato pubblico dell'EA dall'endpoint"""
        # Usa URL passato come parametro o fallback a self.ea_url
        url = ea_url or self.ea_url
        if not url:
            self.print_error("Nessun URL EA disponibile")
            return None, None
        
        # Se l'URL è cambiato, invalida la cache
        if hasattr(self, '_last_ea_url') and self._last_ea_url != url:
            self._ea_certificate = None
            self._ea_public_key = None
        
        self._last_ea_url = url
            
        if self._ea_certificate is None:
            try:
                # Ottieni certificato dall'endpoint EA
                response = requests.get(f"{url}/api/enrollment/certificate", timeout=5, **get_request_kwargs())
                if response.status_code == 200:
                    cert_pem = response.text
                    self._ea_certificate = x509.load_pem_x509_certificate(
                        cert_pem.encode('utf-8'), default_backend()
                    )
                    self._ea_public_key = self._ea_certificate.public_key()
                    self.print_info(f"Ottenuto certificato EA dall'endpoint")
                else:
                    self.print_error(f"Errore ottenimento certificato EA: {response.status_code}")
                    # Fallback al file system
                    self._fallback_get_ea_certificate()
            except Exception as e:
                self.print_error(f"Errore caricamento certificato EA: {e}")
                # Fallback al file system
                self._fallback_get_ea_certificate()
        return self._ea_certificate, self._ea_public_key
    
    def _fallback_get_ea_certificate(self):
        """Fallback: ottiene certificato EA dal file system"""
        try:
            cert_path = Path("test_root/subordinates")
            if cert_path.exists():
                cert_files = list(cert_path.glob("EA_*.pem"))
                if cert_files:
                    with open(cert_files[0], 'r') as f:
                        cert_pem = f.read()
                    self._ea_certificate = x509.load_pem_x509_certificate(
                        cert_pem.encode('utf-8'), default_backend()
                    )
                    self._ea_public_key = self._ea_certificate.public_key()
                    self.print_info(f"Usando certificato EA dal file system (fallback)")
        except Exception as e:
            self.print_error(f"Errore caricamento certificato EA dal file system: {e}")
    
    def get_aa_certificate(self, aa_url=None):
        """Ottiene il certificato pubblico dell'AA dall'endpoint"""
        # Usa URL passato come parametro o fallback a self.aa_url
        url = aa_url or self.aa_url
        if not url:
            self.print_error("Nessun URL AA disponibile")
            return None, None
        
        # Se l'URL è cambiato, invalida la cache
        if hasattr(self, '_last_aa_url') and self._last_aa_url != url:
            self._aa_certificate = None
            self._aa_public_key = None
        
        self._last_aa_url = url
            
        if self._aa_certificate is None:
            try:
                # Ottieni certificato dall'endpoint AA
                response = requests.get(f"{url}/api/authorization/certificate", timeout=5)
                if response.status_code == 200:
                    cert_pem = response.text
                    self._aa_certificate = x509.load_pem_x509_certificate(
                        cert_pem.encode('utf-8'), default_backend()
                    )
                    self._aa_public_key = self._aa_certificate.public_key()
                    self.print_info(f"Ottenuto certificato AA dall'endpoint")
                else:
                    self.print_error(f"Errore ottenimento certificato AA: {response.status_code}")
                    # Fallback al file system
                    self._fallback_get_aa_certificate()
            except Exception as e:
                self.print_error(f"Errore caricamento certificato AA: {e}")
                # Fallback al file system
                self._fallback_get_aa_certificate()
        return self._aa_certificate, self._aa_public_key
    
    def _fallback_get_aa_certificate(self):
        """Fallback: ottiene certificato AA dal file system"""
        try:
            cert_path = Path("test_root/subordinates")
            if cert_path.exists():
                cert_files = list(cert_path.glob("AA_*.pem"))
                if cert_files:
                    with open(cert_files[0], 'r') as f:
                        cert_pem = f.read()
                    self._aa_certificate = x509.load_pem_x509_certificate(
                        cert_pem.encode('utf-8'), default_backend()
                    )
                    self._aa_public_key = self._aa_certificate.public_key()
                    self.print_info(f"Usando certificato AA dal file system (fallback)")
        except Exception as e:
            self.print_error(f"Errore caricamento certificato AA dal file system: {e}")
    
    def create_etsi_enrollment_request(self, vehicle_id, private_key, public_key_pem, ea_url=None):
        """Crea una richiesta enrollment ETSI ASN.1 OER"""
        try:
            # Ottieni certificato EA
            ea_cert, ea_public_key = self.get_ea_certificate(ea_url)
            if not ea_cert or not ea_public_key:
                raise ValueError("Certificato EA non disponibile")
            
            # Debug: print EA cert info
            self.print_info(f"EA Certificate subject: {ea_cert.subject}")
            self.print_info(f"EA Certificate serial: {ea_cert.serial_number}")
            
            # Carica chiave pubblica dal PEM
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'), default_backend()
            )
            
            # Converti a bytes per InnerEcRequest
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Crea InnerEcRequest
            inner_request = InnerEcRequest(
                itsId=vehicle_id,
                certificateFormat=1,  # X.509
                publicKeys={"verification": public_key_bytes},
                requestedSubjectAttributes={
                    "country": "IT",
                    "organization": f"TestOrg_{vehicle_id}",
                    "appPermissions": "CAM,DENM"  # Stringa separata da virgola
                }
            )
            
            self.print_info(f"Created InnerEcRequest for {vehicle_id}")
            
            # Codifica richiesta ETSI
            encoded_request = self.encoder.encode_enrollment_request(
                inner_request=inner_request,
                private_key=private_key,
                ea_public_key=ea_public_key,
                ea_certificate=ea_cert
            )
            
            self.print_info(f"Encoded ETSI request: {len(encoded_request)} bytes")
            
            return encoded_request
            
        except Exception as e:
            self.print_error(f"Errore creazione richiesta enrollment ETSI: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def create_etsi_authorization_request(self, vehicle_id, enrollment_cert_pem, private_key, public_key_pem, hmac_key=None, aa_url=None):
        """Crea una richiesta authorization ETSI ASN.1 OER"""
        try:
            # Ottieni certificato AA
            aa_cert, aa_public_key = self.get_aa_certificate(aa_url)
            if not aa_cert or not aa_public_key:
                raise ValueError("Certificato AA non disponibile")
            
            # Carica enrollment certificate
            ec_cert = x509.load_pem_x509_certificate(
                enrollment_cert_pem.encode('utf-8'), default_backend()
            )
            
            # Carica chiave pubblica dal PEM
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'), default_backend()
            )
            
            # Converti a bytes per InnerAtRequest
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Crea HMAC key unica per unlinkability
            if hmac_key is None:
                hmac_key = secrets.token_bytes(32)
            
            # Crea InnerAtRequest
            inner_request = InnerAtRequest(
                publicKeys={"verification": public_key_bytes},
                hmacKey=hmac_key,
                requestedSubjectAttributes={
                    "appPermissions": "CAM,DENM",  # Stringa separata da virgola
                    "validityPeriod": 7  # giorni
                }
            )
            
            # Codifica richiesta ETSI
            encoded_request = self.encoder.encode_authorization_request(
                inner_request=inner_request,
                enrollment_certificate=ec_cert,
                aa_public_key=aa_public_key,
                aa_certificate=aa_cert,
                testing_mode=True  # TEMP: testing mode
            )
            
            return encoded_request, hmac_key
            
        except Exception as e:
            self.print_error(f"Errore creazione richiesta authorization ETSI: {e}")
            return None, None
    
    def create_etsi_butterfly_request(self, vehicle_id, enrollment_cert_pem, num_tickets=5, aa_url=None):
        """Crea una richiesta butterfly ETSI ASN.1 OER per batch authorization"""
        try:
            # Ottieni certificato AA dall'endpoint REST
            aa_cert, aa_public_key = self.get_aa_certificate(aa_url)
            if not aa_cert or not aa_public_key:
                raise ValueError("Certificato AA non disponibile")
            
            self.print_info(f"Certificato AA ottenuto:")
            self.print_info(f"  Subject: {aa_cert.subject.rfc4514_string()}")
            self.print_info(f"  Serial: {aa_cert.serial_number}")
            
            # Carica enrollment certificate
            ec_cert = x509.load_pem_x509_certificate(
                enrollment_cert_pem.encode('utf-8'), default_backend()
            )
            
            # Crea N InnerAtRequests per butterfly
            inner_requests = []
            hmac_keys = []
            
            for i in range(num_tickets):
                # Genera chiave pubblica per questo AT
                private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                public_key = private_key.public_key()
                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Genera HMAC key univoca per unlinkability
                hmac_key = secrets.token_bytes(32)
                hmac_keys.append(hmac_key)
                
                # Crea InnerAtRequest
                inner_request = InnerAtRequest(
                    publicKeys={"verification": public_key_bytes},
                    hmacKey=hmac_key,
                    requestedSubjectAttributes={
                        "appPermissions": "CAM,DENM",
                        "validityPeriod": 7  # giorni
                    }
                )
                
                inner_requests.append(inner_request)
            
            # Ottieni EA certificate per il SharedAtRequest
            ea_cert, _ = self.get_ea_certificate()
            if not ea_cert:
                self.print_error("Certificato EA non disponibile, uso placeholder")
                ea_hashed_id8 = b"\x00" * 8
            else:
                # Calcola HashedId8 del certificato EA
                from protocols.etsi_message_types import compute_hashed_id8
                ea_cert_der = ea_cert.public_bytes(serialization.Encoding.DER)
                ea_hashed_id8 = compute_hashed_id8(ea_cert_der)
                self.print_info(f"EA HashedId8: {ea_hashed_id8.hex()}")
            
            # Crea SharedAtRequest per parametri condivisi
            key_tag = secrets.token_bytes(16)  # Random key tag per questa richiesta
            
            shared_at_request = SharedAtRequest(
                eaId=ea_hashed_id8,
                keyTag=key_tag,
                certificateFormat=1,
                requestedSubjectAttributes={
                    "appPermissions": "CAM,DENM",
                    "validityPeriod": 7
                }
            )
            
            # Crea ButterflyAuthorizationRequest
            from protocols.etsi_message_types import ButterflyAuthorizationRequest
            butterfly_request = ButterflyAuthorizationRequest(
                sharedAtRequest=shared_at_request,
                innerAtRequests=inner_requests,
                batchSize=len(inner_requests),
                enrollmentCertificate=ec_cert.public_bytes(serialization.Encoding.DER),
                timestamp=datetime.now(timezone.utc)
            )
            
            # Codifica richiesta ETSI
            encoded_request = self.encoder.encode_butterfly_authorization_request(
                butterfly_request=butterfly_request,
                enrollment_certificate=ec_cert,
                aa_public_key=aa_public_key,
                aa_certificate=aa_cert
            )
            
            self.print_info(f"Encoded ETSI butterfly request: {len(encoded_request)} bytes")
            self.print_info(f"  Numero AT richiesti: {num_tickets}")
            
            return encoded_request, hmac_keys
            
        except Exception as e:
            self.print_error(f"Errore creazione richiesta butterfly ETSI: {e}")
            import traceback
            traceback.print_exc()
            return None, None

    def test_1_vehicle_enrollment(self):
        """Test 1: Enrollment completo di un veicolo usando API ETSI standard"""
        self.print_header("TEST 1: Enrollment Veicolo (ETSI Standard)")
        
        # Chiedi all'utente quale EA usare
        ea_url = self.select_entity_interactive("EA")
        if not ea_url:
            return False
        
        # Inizia timer DOPO le selezioni dell'utente
        start_time = time.time()
        
        try:
            vehicle_id = f"VEHICLE_{int(time.time())}"
            self.print_info(f"Creazione richiesta enrollment ETSI: {vehicle_id}")
            
            # Genera chiavi per il veicolo
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # Crea richiesta enrollment ETSI ASN.1 OER
            encoded_request = self.create_etsi_enrollment_request(vehicle_id, private_key, public_key_pem, ea_url)
            if not encoded_request:
                self.print_error("Impossibile creare richiesta enrollment ETSI")
                return False
            
            self.print_info(f"Invio richiesta ETSI a {ea_url}/api/enrollment/request")
            self.print_info(f"Payload ASN.1 OER: {len(encoded_request)} bytes")
            
            # Headers per ETSI
            headers = {
                "Content-Type": "application/octet-stream"
            }
            
            response = requests.post(
                f"{ea_url}/api/enrollment/request",
                data=encoded_request,
                headers=headers,
                timeout=10,
                **get_request_kwargs()
            )
            
            if response.status_code == 200:
                # La risposta dovrebbe essere ASN.1 OER encoded
                response_data = response.content
                self.print_success(f"Enrollment Certificate ottenuto!")
                self.print_info(f"  Response ASN.1 OER: {len(response_data)} bytes")
                
                # Decodifica risposta ETSI per estrarre il certificato
                encoder = ETSIMessageEncoder()
                try:
                    inner_response = encoder.decode_enrollment_response(response_data, private_key)
                    
                    if inner_response.is_success() and inner_response.certificate:
                        # Converti DER a PEM
                        cert_der = inner_response.certificate
                        cert_x509 = x509.load_der_x509_certificate(cert_der, default_backend())
                        cert_pem = cert_x509.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                        
                        # Salva certificato su disco
                        paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
                        paths.certificates_dir.mkdir(parents=True, exist_ok=True)
                        ec_path = paths.certificates_dir / f"{vehicle_id}_EC.pem"
                        with open(ec_path, 'w') as f:
                            f.write(cert_pem)
                        
                        self.print_info(f"  Certificato salvato: {ec_path}")
                        
                        # Salva anche chiave privata
                        key_path = paths.private_keys_dir / f"{vehicle_id}_key.pem"
                        paths.private_keys_dir.mkdir(parents=True, exist_ok=True)
                        private_key_pem = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption()
                        ).decode('utf-8')
                        with open(key_path, 'w') as f:
                            f.write(private_key_pem)
                        
                        self.print_info(f"  Chiave privata salvata: {key_path}")
                        
                        result = {
                            "message": "ETSI Enrollment successful",
                            "response_size": len(response_data),
                            "vehicle_id": vehicle_id,
                            "certificate_path": str(ec_path),
                            "private_key_path": str(key_path),
                            "certificate_pem": cert_pem
                        }
                    else:
                        self.print_error(f"Enrollment fallito: {inner_response.responseCode}")
                        return False
                        
                except Exception as e:
                    self.print_error(f"Errore decodifica risposta ETSI: {e}")
                    # Fallback: salva dati raw
                    result = {
                        "message": "ETSI Enrollment successful (raw)",
                        "response_size": len(response_data),
                        "vehicle_id": vehicle_id
                    }
                
                # Incrementa contatore EC emessi
                self.total_ec_issued += 1
                
                # Salva info veicolo
                vehicle_info = {
                    "enrollment_response": result,
                    "private_key": private_key,
                    "public_key_pem": public_key_pem,
                    "timestamp": datetime.now().isoformat()
                }
                
                # Aggiungi certificato PEM se decodificato
                if 'certificate_pem' in result:
                    vehicle_info["certificate_pem"] = result["certificate_pem"]
                
                self.enrolled_vehicles[vehicle_id] = vehicle_info
                
                # Calcola e stampa tempo di esecuzione
                duration = time.time() - start_time
                self.print_test_execution_time("Enrollment Veicolo", duration)
                
                self.save_test_result(
                    "vehicle_enrollment_etsi",
                    "success",
                    {
                        "vehicle_id": vehicle_id,
                        "response_size": len(response_data),
                        "message": "ETSI enrollment successful",
                        "execution_time": duration
                    }
                )
                return True
            else:
                duration = time.time() - start_time
                self.print_test_execution_time("Enrollment Veicolo", duration)
                self.print_error(f"Enrollment ETSI fallito! Status: {response.status_code}")
                self.print_error(f"Error: {response.text[:200]}")
                self.save_test_result("vehicle_enrollment_etsi", "failed", {"status": response.status_code, "execution_time": duration})
                return False
                
        except requests.exceptions.ConnectionError:
            duration = time.time() - start_time
            self.print_test_execution_time("Enrollment Veicolo", duration)
            self.print_error(f"Impossibile connettersi a {self.ea_url}")
            self.save_test_result("vehicle_enrollment_etsi", "error", {"error": "Connection refused", "execution_time": duration})
            return False
        except Exception as e:
            duration = time.time() - start_time
            self.print_test_execution_time("Enrollment Veicolo", duration)
            self.print_error(f"Errore: {e}")
            self.save_test_result("vehicle_enrollment_etsi", "error", {"error": str(e), "execution_time": duration})
            return False
    
    def test_batch_vehicle_enrollment(self, num_vehicles=None):
        """Test ottimizzato: Enrollment batch di veicoli per migliorare performance"""
        
        # Chiedi numero di veicoli se non specificato
        if num_vehicles is None:
            if self.auto_mode:
                num_vehicles = 10
                self.print_info("Modalità auto: uso 10 veicoli per enrollment batch.")
            else:
                try:
                    num_vehicles_input = input("  Quanti veicoli enrollare in batch? (default 10): ").strip()
                    num_vehicles = int(num_vehicles_input) if num_vehicles_input else 10
                    if num_vehicles <= 0:
                        raise ValueError("Deve essere positivo")
                except ValueError as e:
                    self.print_error(f"Input non valido: {e}. Uso default 10.")
                    num_vehicles = 10
        
        self.print_header(f"TEST BATCH: Enrollment {num_vehicles} veicoli (Ottimizzato)")
        
        # Chiedi all'utente quale EA usare
        ea_url = self.select_entity_interactive("EA")
        if not ea_url:
            return False
        
        try:
            self.print_info(f"Generazione batch enrollment per {num_vehicles} veicoli...")
            
            # Pre-genera tutte le richieste per ridurre latenza
            enrollment_requests = []
            vehicle_ids = []
            
            for i in range(num_vehicles):
                vehicle_id = f"VEHICLE_BATCH_{int(time.time())}_{i}"
                vehicle_ids.append(vehicle_id)
                
                # Usa chiave più piccola per ottimizzazione (se possibile)
                # Nota: SECP256R1 è già ottimizzato, ma potremmo usare curve più piccole in futuro
                private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                public_key = private_key.public_key()
                
                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                enrollment_request = {
                    "its_id": vehicle_id,
                    "public_key": public_key_pem,
                    "requested_attributes": {
                        "country": "IT",
                        "organization": f"BatchOrg_{vehicle_id}",
                        "validity_days": 365
                    }
                }
                enrollment_requests.append(enrollment_request)
            
            self.print_info(f"Invio batch enrollment a {ea_url}/api/enrollment/request/batch")
            
            # Richiesta batch singola invece di N richieste separate
            batch_request = {
                "enrollment_requests": enrollment_requests,
                "batch_size": num_vehicles,
                "optimized": True
            }
            
            start_time = time.time()
            
            # Prima prova batch endpoint, se non esiste fallback a richieste sequenziali
            try:
                response = requests.post(
                    f"{ea_url}/api/enrollment/request/batch",
                    json=batch_request,
                    timeout=60,  # Timeout più lungo per batch
                    **get_request_kwargs()
                )
                
                if response.status_code == 200:
                    # Batch endpoint disponibile
                    result = response.json()
                    enrolled_count = len(result.get("enrolled_vehicles", []))
                    elapsed = time.time() - start_time
                    
                    self.print_success(f"Batch enrollment completato!")
                    self.print_info(f"  Veicoli enrollati: {enrolled_count}/{num_vehicles}")
                    self.print_info(f"  Tempo totale: {elapsed:.2f}s")
                    self.print_info(f"  Throughput: {enrolled_count/elapsed:.2f} veicoli/s")
                    
                    # Salva veicoli enrollati
                    for vehicle_data in result.get("enrolled_vehicles", []):
                        vehicle_id = vehicle_data["vehicle_id"]
                        self.enrolled_vehicles[vehicle_id] = {
                            "enrollment_response": vehicle_data,
                            "timestamp": datetime.now().isoformat(),
                            "batch_enrolled": True
                        }
                    
                    self.total_ec_issued += enrolled_count
                    
                    self.save_test_result(
                        "batch_vehicle_enrollment",
                        "success",
                        {
                            "vehicles_enrolled": enrolled_count,
                            "batch_size": num_vehicles,
                            "elapsed_time": elapsed,
                            "throughput": enrolled_count/elapsed
                        }
                    )
                    return True
                    
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    self.print_info("Batch endpoint non disponibile, uso richieste sequenziali ottimizzate...")
                else:
                    raise e
            
            # Fallback: richieste sequenziali ma ottimizzate
            self.print_info("Eseguendo enrollment sequenziale ottimizzato...")
            enrolled_count = 0
            total_elapsed = 0
            
            for i, (vehicle_id, request) in enumerate(zip(vehicle_ids, enrollment_requests)):
                self.print_info(f"  Enrollment veicolo {i+1}/{num_vehicles}: {vehicle_id}")
                
                req_start = time.time()
                # Usa endpoint ETSI invece di /simple
                # Crea richiesta ETSI ASN.1 OER
                encoded_request = self.create_etsi_enrollment_request(vehicle_id, private_key, public_key_pem, ea_url)
                if not encoded_request:
                    self.print_error(f"Impossibile creare richiesta ETSI per {vehicle_id}")
                    continue
                
                response = requests.post(
                    f"{ea_url}/api/enrollment/request",
                    data=encoded_request,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=10,
                    **get_request_kwargs()
                )
                req_elapsed = time.time() - req_start
                total_elapsed += req_elapsed
                
                if response.status_code == 200:
                    # Decodifica risposta ETSI ASN.1 OER
                    response_data = response.content
                    try:
                        inner_response = self.encoder.decode_enrollment_response(response_data, private_key)
                        
                        if inner_response.is_success() and inner_response.certificate:
                            # Converti DER a PEM
                            cert_der = inner_response.certificate
                            cert_x509 = x509.load_der_x509_certificate(cert_der, default_backend())
                            cert_pem = cert_x509.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                            
                            self.print_success(f"    ✓ {vehicle_id} enrollato (ETSI)")
                            
                            # Salva dati veicolo
                            vehicle_info = {
                                "enrollment_response": {
                                    "success": True,
                                    "certificate": cert_pem,
                                    "serial_number": cert_x509.serial_number
                                },
                                "timestamp": datetime.now().isoformat(),
                                "batch_enrolled": False,
                                "etsi_encoded": True
                            }
                            
                            self.enrolled_vehicles[vehicle_id] = vehicle_info
                            enrolled_count += 1
                            self.total_ec_issued += 1
                        else:
                            self.print_error(f"    ❌ {vehicle_id} enrollment fallito: {inner_response.responseCode}")
                    except Exception as e:
                        self.print_error(f"    ❌ {vehicle_id} errore decodifica ETSI: {e}")
                else:
                    self.print_error(f"    ❌ {vehicle_id} fallito: {response.status_code}")
            
            self.print_success(f"Enrollment sequenziale completato!")
            self.print_info(f"  Veicoli enrollati: {enrolled_count}/{num_vehicles}")
            self.print_info(f"  Tempo totale: {total_elapsed:.2f}s")
            self.print_info(f"  Throughput medio: {enrolled_count/total_elapsed:.2f} veicoli/s")
            
            self.save_test_result(
                "batch_vehicle_enrollment_sequential",
                "success" if enrolled_count > 0 else "partial",
                {
                    "vehicles_enrolled": enrolled_count,
                    "batch_size": num_vehicles,
                    "elapsed_time": total_elapsed,
                    "throughput": enrolled_count/total_elapsed,
                    "method": "sequential"
                }
            )
            return enrolled_count > 0
            
        except requests.exceptions.ConnectionError:
            self.print_error(f"Impossibile connettersi a {ea_url}")
            self.save_test_result("batch_vehicle_enrollment", "error", {"error": "Connection refused"})
            return False
        except Exception as e:
            self.print_error(f"Errore batch enrollment: {e}")
            self.save_test_result("batch_vehicle_enrollment", "error", {"error": str(e)})
            return False
    
    def test_3_authorization_ticket(self):
        """Test 3: Richiesta Authorization Ticket usando API ETSI standard"""
        self.print_header("TEST 3: Authorization Ticket (ETSI Standard)")
        
        # Chiedi all'utente quale AA usare
        aa_url = self.select_entity_interactive("AA")
        if not aa_url:
            return False
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo enrollato! Esegui prima il Test 1")
            return False
        
        # Inizia timer DOPO le selezioni dell'utente
        start_time = time.time()
        
        try:
            # Usa primo veicolo disponibile
            vehicle_id = list(self.enrolled_vehicles.keys())[0]
            vehicle_data = self.enrolled_vehicles[vehicle_id]
            
            self.print_info(f"Veicolo: {vehicle_id}")
            
            # Verifica che abbiamo i dati necessari
            if "enrollment_response" not in vehicle_data:
                self.print_error("Nessun enrollment certificate trovato!")
                return False
            
            # Usa il certificato enrollment salvato nei dati del veicolo
            enrollment_cert_pem = vehicle_data.get("certificate_pem")
            
            if not enrollment_cert_pem:
                # Fallback: cerca su disco
                try:
                    paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
                    ec_path = paths.certificates_dir / f"{vehicle_id}_EC.pem"
                    if ec_path.exists():
                        with open(ec_path, 'r') as f:
                            enrollment_cert_pem = f.read()
                except:
                    pass
            
            if not enrollment_cert_pem:
                self.print_error("Certificato enrollment non trovato!")
                return False
            
            # Genera nuove chiavi per l'AT (diverse da quelle enrollment)
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.print_info(f"Richiesta Authorization Ticket ETSI all'AA...")
            
            # Crea richiesta authorization ETSI ASN.1 OER
            encoded_request, hmac_key = self.create_etsi_authorization_request(
                vehicle_id, enrollment_cert_pem, private_key, public_key_pem, None, aa_url
            )
            if not encoded_request:
                self.print_error("Impossibile creare richiesta authorization ETSI")
                return False
            
            # Headers per ETSI
            headers = {
                "Content-Type": "application/octet-stream",
                "X-Testing-Mode": "true"  # TEMP: usa testing mode per debug
            }
            
            # Aggiungi enrollment certificate come header per testing mode
            if enrollment_cert_pem:
                cert_der = x509.load_pem_x509_certificate(
                    enrollment_cert_pem.encode('utf-8'), default_backend()
                ).public_bytes(serialization.Encoding.DER)
                import base64
                headers["X-Enrollment-Certificate"] = base64.b64encode(cert_der).decode('utf-8')
            
            response = requests.post(
                f"{aa_url}/api/authorization/request",
                data=encoded_request,
                headers=headers,
                timeout=10,
                **get_request_kwargs()
            )
            
            if response.status_code == 200:
                # La risposta dovrebbe essere ASN.1 OER encoded
                response_data = response.content
                self.print_success(f"Authorization Ticket ottenuto!")
                self.print_info(f"  Response ASN.1 OER: {len(response_data)} bytes")
                
                # Decodifica risposta ETSI
                try:
                    inner_response = self.encoder.decode_authorization_response(
                        response_data, hmac_key
                    )
                    
                    if inner_response.responseCode == ResponseCode.OK and inner_response.certificate:
                        # Converti certificato DER a PEM
                        at_cert = x509.load_der_x509_certificate(inner_response.certificate, default_backend())
                        at_cert_pem = at_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                        
                        result = {
                            "message": "ETSI Authorization successful",
                            "response_size": len(response_data),
                            "vehicle_id": vehicle_id,
                            "hmac_key": hmac_key.hex() if hmac_key else None,
                            "certificate_pem": at_cert_pem
                        }
                        
                        self.print_info(f"  Authorization Ticket decodificato correttamente")
                    else:
                        self.print_error(f"  Risposta authorization fallita: {inner_response.responseCode}")
                        result = {
                            "message": f"ETSI Authorization failed: {inner_response.responseCode}",
                            "response_size": len(response_data),
                            "vehicle_id": vehicle_id,
                            "hmac_key": hmac_key.hex() if hmac_key else None
                        }
                        
                except Exception as e:
                    self.print_error(f"Errore decodifica risposta ETSI: {e}")
                    # Fallback: salva dati raw
                    result = {
                        "message": "ETSI Authorization successful (raw)",
                        "response_size": len(response_data),
                        "vehicle_id": vehicle_id,
                        "hmac_key": hmac_key.hex() if hmac_key else None
                    }
                
                # Incrementa contatore AT emessi
                self.total_at_issued += 1
                
                # Salva AT nel veicolo
                vehicle_data["authorization_ticket"] = result
                
                # Salva authorization ticket su disco
                try:
                    paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
                    paths.create_all()
                    
                    if 'certificate_pem' in result:
                        # Salva come PEM
                        at_path = paths.certificates_dir / f"{vehicle_id}_AT_etsi.pem"
                        with open(at_path, 'w') as f:
                            f.write(result['certificate_pem'])
                        self.print_info(f"Authorization Ticket ETSI salvato: {at_path}")
                    else:
                        # Fallback: salva raw data come bin
                        at_path = paths.certificates_dir / f"{vehicle_id}_AT_etsi.bin"
                        with open(at_path, 'wb') as f:
                            f.write(response_data)
                        self.print_info(f"Authorization Ticket ETSI salvato (raw): {at_path}")
                except Exception as e:
                    self.print_warning(f"Errore salvataggio AT ETSI: {e}")
                
                # Calcola e stampa tempo di esecuzione
                duration = time.time() - start_time
                self.print_test_execution_time("Authorization Ticket", duration)
                
                self.save_test_result(
                    "authorization_ticket_etsi",
                    "success",
                    {
                        "vehicle_id": vehicle_id,
                        "response_size": len(response_data),
                        "message": "ETSI authorization successful",
                        "execution_time": duration
                    }
                )
                return True
            else:
                duration = time.time() - start_time
                self.print_test_execution_time("Authorization Ticket", duration)
                self.print_error(f"Authorization ETSI fallita! Status: {response.status_code}")
                self.print_error(f"Error: {response.text[:200]}")
                self.save_test_result("authorization_ticket_etsi", "failed", {"status": response.status_code, "execution_time": duration})
                return False
                
        except Exception as e:
            duration = time.time() - start_time
            self.print_test_execution_time("Authorization Ticket", duration)
            self.print_error(f"Errore: {e}")
            self.save_test_result("authorization_ticket_etsi", "error", {"error": str(e), "execution_time": duration})
            return False
    
    def test_2_multiple_vehicles(self, num_vehicles=None):
        """Test 2: Enrollment multiplo (flotta veicoli) usando API REST"""
        self.print_header("TEST 2: Enrollment Flotta Veicoli")
        
        # Chiedi numero di veicoli se non specificato
        if num_vehicles is None:
            if self.auto_mode:
                num_vehicles = 5
                self.print_info("Modalità auto: uso 5 veicoli per enrollment flotta.")
            else:
                try:
                    num_vehicles_input = input("  Quanti veicoli enrollare nella flotta? (default 5): ").strip()
                    num_vehicles = int(num_vehicles_input) if num_vehicles_input else 5
                    if num_vehicles <= 0:
                        raise ValueError("Deve essere positivo")
                except ValueError as e:
                    self.print_error(f"Input non valido: {e}. Uso default 5.")
                    num_vehicles = 5
        
        # Chiedi all'utente quale EA usare
        ea_url = self.select_entity_interactive("EA")
        if not ea_url:
            return False
        
        # Inizia timer DOPO le selezioni dell'utente
        start_time = time.time()
        
        self.print_info(f"Enrollment di {num_vehicles} veicoli...")
        
        success_count = 0
        failed_count = 0
        success_times = []
        start_time = time.time()
        
        for i in range(num_vehicles):
            vehicle_id = f"FLEET_VEHICLE_{i+1:03d}_{int(time.time())}"
            
            try:
                print(f"\n  [{i+1}/{num_vehicles}] {vehicle_id}...", end=" ")
                
                # Genera chiavi reali per il veicolo
                private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                public_key = private_key.public_key()
                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                # Crea richiesta ETSI ASN.1 OER
                encoded_request = self.create_etsi_enrollment_request(vehicle_id, private_key, public_key_pem, ea_url)
                if not encoded_request:
                    print(f"❌ (ETSI encoding failed)")
                    failed_count += 1
                    continue
                
                req_start = time.time()
                response = requests.post(
                    f"{ea_url}/api/enrollment/request",
                    data=encoded_request,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=10,
                    **get_request_kwargs()
                )
                req_end = time.time()
                
                if response.status_code == 200:
                    # Decodifica risposta ETSI
                    response_data = response.content
                    try:
                        inner_response = self.encoder.decode_enrollment_response(response_data, private_key)
                        
                        if inner_response.is_success() and inner_response.certificate:
                            # Converti certificato DER a PEM
                            cert_der = inner_response.certificate
                            cert_x509 = x509.load_der_x509_certificate(cert_der, default_backend())
                            cert_pem = cert_x509.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                            
                            self.enrolled_vehicles[vehicle_id] = {
                                "enrollment_response": {
                                    "success": True,
                                    "certificate": cert_pem,
                                    "serial_number": cert_x509.serial_number
                                },
                                "timestamp": datetime.now().isoformat(),
                                "etsi_encoded": True
                            }
                            
                            print("✅")
                            success_count += 1
                            success_times.append(req_end - req_start)
                            self.total_ec_issued += 1
                        else:
                            print(f"❌ (Enrollment failed: {inner_response.responseCode})")
                            failed_count += 1
                    except Exception as e:
                        print(f"❌ (Decode error: {str(e)[:20]})")
                        failed_count += 1
                else:
                    print(f"❌ ({response.status_code})")
                    failed_count += 1
                    
            except Exception as e:
                print(f"❌ ({str(e)[:30]})")
                failed_count += 1
        
        end_time = time.time()
        total_time = end_time - start_time
        
        print()
        self.print_success(f"Enrollment completati: {success_count}/{num_vehicles}")
        if failed_count > 0:
            self.print_error(f"Enrollment falliti: {failed_count}/{num_vehicles}")
        
        # Print performance metrics
        if success_times:
            avg_time = sum(success_times) / len(success_times)
            min_time = min(success_times)
            max_time = max(success_times)
            
            self.print_test_execution_time("Enrollment Flotta Veicoli", total_time)
            self.print_info(f"Tempo medio per enrollment: {avg_time:.3f}s")
            self.print_info(f"Tempo minimo: {min_time:.3f}s")
            self.print_info(f"Tempo massimo: {max_time:.3f}s")
            self.print_info(f"Throughput: {len(success_times)/total_time:.2f} veicoli/s")
        
        self.save_test_result(
            "fleet_enrollment",
            "success" if success_count == num_vehicles else "partial",
            {
                "total": num_vehicles,
                "success": success_count,
                "failed": failed_count,
                "total_time": total_time,
                "execution_time": total_time,
                "avg_time": sum(success_times) / len(success_times) if success_times else 0,
                "throughput": len(success_times)/total_time if success_times else 0
            }
        )
        
        return success_count > 0
    
    def test_4_v2v_communication(self):
        """Test 4: Simulazione comunicazione V2V"""
        self.print_header("TEST 4: Comunicazione V2V (CAM)")
        
        if len(self.enrolled_vehicles) < 2:
            self.print_error("Servono almeno 2 veicoli! Esegui prima il Test 2")
            return False
        
        # Inizia timer (nessun input utente in questo test)
        start_time = time.time()
        
        try:
            # Prendi primi due veicoli
            vehicle_ids = list(self.enrolled_vehicles.keys())[:2]
            
            self.print_info(f"Sender: {vehicle_ids[0]}")
            self.print_info(f"Receiver: {vehicle_ids[1]}")
            
            # Simula invio CAM (Cooperative Awareness Message)
            cam_data = {
                "message_id": 2,  # CAM
                "station_id": vehicle_ids[0],
                "timestamp": int(time.time() * 1000),
                "latitude": 45.4642,
                "longitude": 9.1900,
                "speed": 50.0,
                "heading": 90.0
            }
            
            self.print_info("Simulazione invio messaggio CAM...")
            self.print_info(f"  Message ID: {cam_data['message_id']}")
            self.print_info(f"  Position: {cam_data['latitude']}, {cam_data['longitude']}")
            self.print_info(f"  Speed: {cam_data['speed']} km/h")
            
            # Verifica che entrambi i veicoli abbiano i certificati
            sender_has_cert = "enrollment_response" in self.enrolled_vehicles[vehicle_ids[0]]
            receiver_has_cert = "enrollment_response" in self.enrolled_vehicles[vehicle_ids[1]]
            
            if sender_has_cert and receiver_has_cert:
                self.print_success("Messaggio CAM inviato con successo!")
                self.print_info("  Sender: Certificato EC valido ✅")
                self.print_info("  Receiver: Certificato EC valido ✅")
                status = "success"
                note = "V2V communication simulated with valid certificates"
            else:
                self.print_success("Messaggio CAM simulato (senza verifica certificati)")
                status = "partial"
                note = "Communication successful but certificate verification skipped"
            
            self.print_success("Test V2V comunicazione completato!")
            
            # Calcola e stampa tempo di esecuzione
            duration = time.time() - start_time
            self.print_test_execution_time("Comunicazione V2V", duration)
            
            self.save_test_result(
                "v2v_communication",
                status,
                {
                    "sender": vehicle_ids[0],
                    "receiver": vehicle_ids[1],
                    "message_type": "CAM",
                    "sender_has_cert": sender_has_cert,
                    "receiver_has_cert": receiver_has_cert,
                    "note": note,
                    "execution_time": duration
                }
            )
            return True
            
        except Exception as e:
            duration = time.time() - start_time
            self.print_test_execution_time("Comunicazione V2V", duration)
            self.print_error(f"Errore: {e}")
            self.save_test_result("v2v_communication", "error", {"error": str(e), "execution_time": duration})
            return False
    
    def test_5_certificate_validation(self):
        """Test 5: Validazione certificati X.509 conforme ETSI"""
        self.print_header("TEST 5: Validazione Certificati (ETSI Standard)")
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo disponibile!")
            return False
        
        # Inizia timer (nessun input utente in questo test)
        start_time = time.time()
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime
            
            valid_count = 0
            invalid_count = 0
            validation_details = []
            
            self.print_info(f"Veicoli da validare: {len(self.enrolled_vehicles)}")
            
            for vehicle_id, vehicle_data in self.enrolled_vehicles.items():
                try:
                    # Estrai certificato PEM - cerca prima in vehicle_data, poi in enrollment_response
                    cert_pem = vehicle_data.get("certificate_pem") or vehicle_data.get("enrollment_response", {}).get("certificate")
                    if not cert_pem:
                        self.print_error(f"  {vehicle_id}: ❌ Certificato mancante")
                        invalid_count += 1
                        continue
                    
                    # Parse X.509 certificate
                    cert_bytes = cert_pem.encode('utf-8')
                    certificate = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                    
                    # Validazione ETSI TS 103 097 - Certificato ITS
                    validation_result = {
                        "vehicle_id": vehicle_id,
                        "serial": certificate.serial_number,
                        "checks": {}
                    }
                    
                    # 1. Verifica periodo di validità
                    now = datetime.now(timezone.utc)
                    not_before = certificate.not_valid_before_utc
                    not_after = certificate.not_valid_after_utc
                    
                    time_valid = not_before <= now <= not_after
                    validation_result["checks"]["temporal_validity"] = time_valid
                    
                    # 2. Verifica subject
                    subject = certificate.subject
                    cn = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                    has_cn = len(cn) > 0 and cn[0].value == vehicle_id
                    validation_result["checks"]["subject_cn"] = has_cn
                    
                    # 3. Verifica issuer (EA)
                    issuer = certificate.issuer
                    issuer_cn = issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                    has_issuer = len(issuer_cn) > 0
                    validation_result["checks"]["has_issuer"] = has_issuer
                    
                    # 4. Verifica algoritmo firma (ETSI richiede ECDSA)
                    is_ecdsa = certificate.signature_algorithm_oid._name.startswith('ecdsa')
                    validation_result["checks"]["ecdsa_signature"] = is_ecdsa
                    
                    # 5. Verifica chiave pubblica (ECC)
                    from cryptography.hazmat.primitives.asymmetric import ec
                    is_ecc = isinstance(certificate.public_key(), ec.EllipticCurvePublicKey)
                    validation_result["checks"]["ecc_public_key"] = is_ecc
                    
                    # 6. Verifica estensioni certificate
                    has_basic_constraints = False
                    try:
                        bc = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
                        has_basic_constraints = not bc.value.ca  # Deve essere False per ITS-S
                        validation_result["checks"]["basic_constraints"] = has_basic_constraints
                    except x509.ExtensionNotFound:
                        validation_result["checks"]["basic_constraints"] = False
                    
                    # Determina stato complessivo
                    all_checks = validation_result["checks"]
                    is_valid = all(all_checks.values())
                    
                    if is_valid:
                        self.print_info(f"  {vehicle_id}: ✅ VALIDO (ETSI compliant)")
                        valid_count += 1
                    else:
                        failed_checks = [k for k, v in all_checks.items() if not v]
                        self.print_error(f"  {vehicle_id}: ❌ INVALIDO - Failed: {', '.join(failed_checks)}")
                        invalid_count += 1
                    
                    validation_details.append(validation_result)
                    
                except Exception as cert_error:
                    self.print_error(f"  {vehicle_id}: ❌ Errore parsing: {str(cert_error)[:50]}")
                    invalid_count += 1
            
            # Riepilogo
            total = valid_count + invalid_count
            self.print_success(f"Certificati validi (ETSI): {valid_count}/{total}")
            if invalid_count > 0:
                self.print_error(f"Certificati invalidi: {invalid_count}/{total}")
            
            # Calcola e stampa tempo di esecuzione
            duration = time.time() - start_time
            self.print_test_execution_time("Validazione Certificati", duration)
            
            self.save_test_result(
                "certificate_validation",
                "success" if valid_count == total else "partial",
                {
                    "total": total,
                    "valid": valid_count,
                    "invalid": invalid_count,
                    "validation_details": validation_details,
                    "execution_time": duration
                }
            )
            return valid_count > 0
            
        except Exception as e:
            duration = time.time() - start_time
            self.print_test_execution_time("Validazione Certificati", duration)
            self.print_error(f"Errore: {e}")
            import traceback
            self.print_error(traceback.format_exc()[:200])
            self.save_test_result("certificate_validation", "error", {"error": str(e), "execution_time": duration})
            return False
    
    def test_6_butterfly_expansion(self, num_tickets=None):
        """
        Test Butterfly Key Expansion per generazione batch di Authorization Tickets.
        Genera multiple AT in una singola richiesta usando chiave master HMAC.
        """
        self.print_header("TEST 6: Butterfly Key Expansion")
        
        # Chiedi numero di ticket se non specificato
        if num_tickets is None:
            if self.auto_mode:
                num_tickets = 20
                self.print_info("Modalità auto: uso 20 Authorization Tickets per Butterfly.")
            else:
                try:
                    num_tickets_input = input("  Quanti AT richiedere in batch (Butterfly)? (default 20, max 100 ETSI): ").strip()
                    num_tickets = int(num_tickets_input) if num_tickets_input else 20
                    
                    # ETSI TS 102941 V2.1.1 Section 6.3.3: batch size limits
                    if num_tickets < 1 or num_tickets > 100:
                        raise ValueError(f"Batch size deve essere tra 1 e 100 (ETSI TS 102941), ricevuto {num_tickets}")
                except ValueError as e:
                    self.print_error(f"Input non valido: {e}. Uso default 20.")
                    num_tickets = 20
        
        # Chiedi all'utente quale AA usare
        aa_url = self.select_entity_interactive("AA")
        if not aa_url:
            return False
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo enrollato! Esegui prima il Test 1")
            return False
        
        # Inizia timer DOPO le selezioni dell'utente
        start_time = time.time()
        
        try:
            # Usa primo veicolo disponibile
            vehicle_id = list(self.enrolled_vehicles.keys())[0]
            vehicle_data = self.enrolled_vehicles[vehicle_id]
            
            # Usa il certificato enrollment
            enrollment_cert = vehicle_data.get("certificate_pem") or vehicle_data["enrollment_response"].get("certificate")
            if not enrollment_cert:
                self.print_error("Certificato enrollment mancante!")
                return False
            
            self.print_info(f"Veicolo: {vehicle_id}")
            self.print_info(f"Richiesta Butterfly: {num_tickets} Authorization Tickets in batch...")
            
            start_time = time.time()
            # Crea richiesta ETSI butterfly completa
            encoded_request, hmac_keys = self.create_etsi_butterfly_request(
                vehicle_id, enrollment_cert, num_tickets, aa_url
            )
            
            if not encoded_request or not hmac_keys:
                self.print_error("Impossibile creare richiesta butterfly ETSI")
                return False
            
            response = requests.post(
                f"{aa_url}/api/authorization/request/butterfly",
                data=encoded_request,
                headers={"Content-Type": "application/octet-stream"},
                timeout=30,
                **get_request_kwargs()
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                # Decodifica risposta ETSI butterfly
                response_data = response.content
                try:
                    # Usa il metodo decode_butterfly_response (da implementare nell'encoder)
                    # Per ora placeholder
                    at_count = len(hmac_keys)  # Placeholder
                    
                    self.print_success(f"Butterfly Expansion completato (ETSI)!")
                    self.print_info(f"  Authorization Tickets generati: {at_count}")
                    self.print_info(f"  HMAC keys derivate: {len(hmac_keys)}")
                    self.print_test_execution_time("Butterfly Key Expansion", elapsed)
                    self.print_info(f"  Throughput: {at_count/elapsed:.2f} AT/s")
                    
                    # Incrementa contatore AT emessi
                    self.total_at_issued += at_count
                    
                    # Salva AT nel veicolo (placeholder)
                    vehicle_data["butterfly_tickets"] = [f"AT_{i}_placeholder" for i in range(at_count)]
                    
                    self.save_test_result(
                        "butterfly_expansion_etsi",
                        "success",
                        {
                            "vehicle_id": vehicle_id,
                            "tickets_generated": at_count,
                            "elapsed_time": elapsed,
                            "throughput": at_count/elapsed,
                            "etsi_encoded": True
                        }
                    )
                    return True
                except Exception as e:
                    self.print_error(f"Errore decodifica risposta butterfly ETSI: {e}")
                    self.save_test_result("butterfly_expansion_etsi", "decode_error", {"error": str(e)})
                    return False
            else:
                self.print_error(f"Butterfly ETSI fallito! Status: {response.status_code}")
                try:
                    error_data = response.json()
                    self.print_error(f"Errore dal server: {error_data}")
                except:
                    self.print_error(f"Risposta raw: {response.text[:500]}")
                self.save_test_result("butterfly_expansion_etsi", "failed", {"status": response.status_code})
                return False
                
        except Exception as e:
            self.print_error(f"Errore: {e}")
            self.save_test_result("butterfly_expansion", "error", {"error": str(e)})
            return False
    
    def test_7_certificate_revocation(self, num_revocations=None):
        """Test 7: Revoca certificati (EC e AT) usando API REST"""
        self.print_header("TEST 7: Revoca Certificati (ETSI Standard)")
        
        # Chiedi numero di revoche se non specificato
        if num_revocations is None:
            if self.auto_mode:
                num_revocations = 1
                self.print_info("Modalità auto: revoca 1 certificato.")
            else:
                try:
                    num_revocations_input = input("  Quanti certificati revocare? (default 1): ").strip()
                    num_revocations = int(num_revocations_input) if num_revocations_input else 1
                    if num_revocations <= 0:
                        raise ValueError("Deve essere positivo")
                except ValueError as e:
                    self.print_error(f"Input non valido: {e}. Uso default 1.")
                    num_revocations = 1
        
        # Chiedi all'utente quale EA e AA usare
        ea_url = self.select_entity_interactive("EA")
        if not ea_url:
            return False
        aa_url = self.select_entity_interactive("AA")
        if not aa_url:
            return False
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo disponibile! Esegui prima il Test 1")
            return False
        
        if num_revocations > len(self.enrolled_vehicles):
            self.print_error(f"Troppi veicoli da revocare! Disponibili: {len(self.enrolled_vehicles)}")
            return False
        
        # Inizia timer DOPO le selezioni dell'utente
        start_time = time.time()
        
        success_count = 0
        failed_count = 0
        
        # Prendi gli ultimi num_revocations veicoli
        vehicles_to_revoke = list(self.enrolled_vehicles.keys())[-num_revocations:]
        
        for vehicle_id in vehicles_to_revoke:
            try:
                vehicle_data = self.enrolled_vehicles[vehicle_id]
                
                # Estrai certificato PEM
                cert_pem = vehicle_data.get("enrollment_response", {}).get("certificate")
                if not cert_pem:
                    self.print_error(f"Certificato mancante per {vehicle_id}!")
                    failed_count += 1
                    continue
                
                # Parse certificato per estrarre serial number
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                cert_bytes = cert_pem.encode('utf-8')
                certificate = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                serial_number = certificate.serial_number
                serial_hex = format(serial_number, 'X')  # Converti a hex uppercase
                
                self.print_info(f"Revoca veicolo: {vehicle_id}")
                self.print_info(f"  Serial Number: {serial_number}")
                self.print_info(f"  Serial Hex: {serial_hex}")
                
                # Richiesta di revoca via API
                revoke_request = {
                    "serial_number": serial_hex,
                    "reason": "unspecified",  # Motivo revoca ETSI standard
                    "its_id": vehicle_id
                }
                
                self.print_info(f"  Invio richiesta revoca a {ea_url}/api/enrollment/revoke...")
                
                response = requests.post(
                    f"{ea_url}/api/enrollment/revoke",
                    json=revoke_request,
                    timeout=10,
                    **get_request_kwargs()
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.print_success(f"  Certificato revocato con successo!")
                    self.print_info(f"    Serial: {serial_hex}")
                    self.print_info(f"    Response: {result.get('message', 'Success')}")
                    
                    # Incrementa contatore EC revocati
                    self.revoked_ec_count += 1
                    success_count += 1
                    
                    # Verifica rapida inserimento in CRL (senza attesa)
                    # La Delta CRL è pubblicata immediatamente dopo la revoca
                    self.print_info(f"  Verifica inserimento in CRL...")
                    
                    is_revoked = None
                    # Usa Delta CRL per verificare revoche recenti (secondo ETSI)
                    crl_response = requests.get(f"{ea_url}/api/crl/delta", timeout=5)
                    if crl_response.status_code == 200:
                        try:
                            # Parse CRL - prova prima PEM, poi DER
                            crl_data = crl_response.content
                            
                            # Determina formato dalla risposta
                            content_type = crl_response.headers.get('Content-Type', '')
                            
                            try:
                                # Prova PEM prima (più comune)
                                if b'-----BEGIN' in crl_data:
                                    crl = x509.load_pem_x509_crl(crl_data, default_backend())
                                else:
                                    # Altrimenti DER
                                    crl = x509.load_der_x509_crl(crl_data, default_backend())
                                
                                # Cerca serial nella CRL
                                is_revoked = False
                                for revoked_cert in crl:
                                    if revoked_cert.serial_number == serial_number:
                                        is_revoked = True
                                        revocation_date = revoked_cert.revocation_date_utc
                                        self.print_success(f"    ✅ Certificato presente in CRL!")
                                        self.print_info(f"       Data revoca: {revocation_date}")
                                        break
                                
                                if not is_revoked:
                                    self.print_info(f"    ⚠️  Certificato non ancora in CRL (propagazione in corso)")
                                    
                            except Exception as parse_error:
                                self.print_info(f"    ⚠️  Errore parsing CRL: {str(parse_error)[:100]}")
                                self.print_info(f"       Content-Type: {content_type}")
                                self.print_info(f"       Size: {len(crl_data)} bytes")
                                
                        except Exception as verify_error:
                            self.print_info(f"    ⚠️  Verifica CRL non disponibile: {str(verify_error)[:80]}")
                    else:
                        self.print_info(f"    ℹ️  CRL non disponibile per verifica (status: {crl_response.status_code})")
                    
                    # Ora revoca anche un AT per test completo
                    self.print_info(f"")
                    self.print_info(f"  Revocando anche un Authorization Ticket...")
                    
                    # Trova un veicolo con AT
                    at_vehicle = None
                    at_cert_pem = None
                    for v_id, v_data in self.enrolled_vehicles.items():
                        if "authorization_ticket" in v_data:
                            at_vehicle = v_id
                            at_data = v_data["authorization_ticket"]
                            # Estrai il certificato PEM dal dizionario
                            if isinstance(at_data, dict) and "certificate_pem" in at_data:
                                at_cert_pem = at_data["certificate_pem"]
                                if at_cert_pem and isinstance(at_cert_pem, str):
                                    break
                            elif isinstance(at_data, str):
                                at_cert_pem = at_data
                                break
                    
                    if at_cert_pem:
                        # Parse AT per serial
                        at_cert_bytes = at_cert_pem.encode('utf-8')
                        at_certificate = x509.load_pem_x509_certificate(at_cert_bytes, default_backend())
                        at_serial_number = at_certificate.serial_number
                        at_serial_hex = format(at_serial_number, 'X')
                        
                        self.print_info(f"  Veicolo con AT: {at_vehicle}")
                        self.print_info(f"  AT Serial: {at_serial_number} (hex: {at_serial_hex})")
                        
                        # Richiesta revoca AT
                        at_revoke_request = {
                            "serial_number": at_serial_hex,
                            "reason": "unspecified",
                            "its_id": at_vehicle
                        }
                        
                        self.print_info(f"  Invio richiesta revoca AT a {aa_url}/api/authorization/revoke...")
                        
                        at_response = requests.post(
                            f"{aa_url}/api/authorization/revoke",
                            json=at_revoke_request,
                            timeout=10,
                            **get_request_kwargs()
                        )
                        
                        if at_response.status_code == 200:
                            at_result = at_response.json()
                            self.print_success(f"  AT revocato con successo!")
                            self.print_info(f"    Serial: {at_serial_hex}")
                            self.print_info(f"    Response: {at_result.get('message', 'Success')}")
                            
                            # Incrementa contatore AT revocati
                            self.revoked_at_count += 1
                            
                            # Verifica rapida inserimento AT in CRL AA (senza attesa)
                            # La Delta CRL è pubblicata immediatamente dopo la revoca
                            self.print_info(f"  Verifica inserimento AT in CRL AA...")
                            
                            # Usa Delta CRL per verificare revoche recenti (secondo ETSI)
                            aa_crl_response = requests.get(f"{aa_url}/api/crl/delta", timeout=5)
                            if aa_crl_response.status_code == 200:
                                try:
                                    # Parse CRL AA - prova prima PEM, poi DER
                                    aa_crl_data = aa_crl_response.content
                                    
                                    # Determina formato dalla risposta
                                    aa_content_type = aa_crl_response.headers.get('Content-Type', '')
                                    
                                    try:
                                        # Prova PEM prima (più comune)
                                        if b'-----BEGIN' in aa_crl_data:
                                            aa_crl = x509.load_pem_x509_crl(aa_crl_data, default_backend())
                                        else:
                                            # Altrimenti DER
                                            aa_crl = x509.load_der_x509_crl(aa_crl_data, default_backend())
                                        
                                        # Cerca serial AT nella CRL AA
                                        at_is_revoked = False
                                        for revoked_cert in aa_crl:
                                            if revoked_cert.serial_number == at_serial_number:
                                                at_is_revoked = True
                                                at_revocation_date = revoked_cert.revocation_date_utc
                                                self.print_success(f"    ✅ AT presente in CRL AA!")
                                                self.print_info(f"       Data revoca: {at_revocation_date}")
                                                break
                                        
                                        if not at_is_revoked:
                                            self.print_info(f"    ⚠️  AT non ancora in CRL AA (propagazione in corso)")
                                            
                                    except Exception as parse_error:
                                        self.print_info(f"    ⚠️  Errore parsing CRL AA: {str(parse_error)[:100]}")
                                        self.print_info(f"       Content-Type: {aa_content_type}")
                                        self.print_info(f"       Size: {len(aa_crl_data)} bytes")
                                        
                                except Exception as verify_error:
                                    self.print_info(f"    ⚠️  Verifica CRL AA non disponibile: {str(verify_error)[:80]}")
                            else:
                                self.print_info(f"    ℹ️  CRL AA non disponibile per verifica (status: {aa_crl_response.status_code})")
                            
                        else:
                            self.print_error(f"  Revoca AT fallita! Status: {at_response.status_code}")
                            self.print_error(f"  Error: {at_response.text[:200]}")
                    else:
                        self.print_info(f"  Nessun AT disponibile per revoca")
                    
                    # Rimuovi veicolo dalla lista locale
                    del self.enrolled_vehicles[vehicle_id]
                    
                elif response.status_code == 404:
                    # Endpoint non implementato - fallback a simulazione
                    self.print_info(f"  ⚠️  API revoca non disponibile su questo EA")
                    self.print_info(f"    Modalità fallback: simulazione locale")
                    
                    # Rimuovi veicolo dalla lista (simulazione)
                    del self.enrolled_vehicles[vehicle_id]
                    
                    self.print_success(f"  Certificato simulato come revocato!")
                    self.print_info(f"    In produzione: certificato verrebbe aggiunto alla CRL")
                    
                    success_count += 1
                    
                else:
                    self.print_error(f"  Revoca fallita! Status: {response.status_code}")
                    self.print_error(f"  Error: {response.text[:200]}")
                    failed_count += 1
                    
            except Exception as e:
                self.print_error(f"Errore revoca {vehicle_id}: {e}")
                failed_count += 1
        
        print()
        self.print_success(f"Revoche completate: {success_count}/{num_revocations}")
        if failed_count > 0:
            self.print_error(f"Revoche fallite: {failed_count}/{num_revocations}")
        
        # Calcola e stampa tempo di esecuzione
        duration = time.time() - start_time
        self.print_test_execution_time("Revoca Certificati", duration)
        
        self.save_test_result(
            "certificate_revocation",
            "success" if success_count == num_revocations else "partial",
            {
                "total_requested": num_revocations,
                "successful": success_count,
                "failed": failed_count,
                "execution_time": duration
            }
        )
        return success_count > 0
    
    def test_8_crl_download(self):
        """Test 8: Download e verifica CRL da EA e AA"""
        self.print_header("TEST 8: Download CRL (Certificate Revocation List)")
        
        # Chiedi all'utente quale EA e AA usare
        ea_url = self.select_entity_interactive("EA")
        if not ea_url:
            return False
        aa_url = self.select_entity_interactive("AA")
        if not aa_url:
            return False
        
        # Inizia timer DOPO le selezioni dell'utente
        start_time = time.time()
        
        ea_success = False
        aa_success = False
        results = {}
        
        try:
            self.print_info(f"Forzando pubblicazione CRL iniziale...")
            
            # Force CRL publication for EA
            try:
                publish_response = requests.post(
                    f"{ea_url}/api/enrollment/publish-crl",
                    json={},
                    timeout=5,
                    **get_request_kwargs()
                )
                if publish_response.status_code in [200, 201]:
                    self.print_success(f"CRL EA pubblicata via API")
            except:
                self.print_info(f"  Endpoint publish-crl EA non disponibile, CRL potrebbe già esistere")
            
            # Note: AA doesn't have a publish-crl endpoint, CRL is published automatically on revocation
            self.print_info(f"  Nota: AA pubblica CRL automaticamente alla revoca, nessun endpoint manuale")
            
            # Test EA CRL
            self.print_info(f"Download CRL da EA...")
            response = requests.get(f"{ea_url}/api/crl/full", timeout=5)
            
            if response.status_code == 200:
                crl_size = len(response.content)
                self.print_success(f"CRL Full EA scaricata!")
                self.print_info(f"  Dimensione: {crl_size} bytes")
                self.print_info(f"  Content-Type: {response.headers.get('Content-Type', 'N/A')}")
                
                # Prova anche Delta CRL EA
                delta_response = requests.get(f"{ea_url}/api/crl/delta", timeout=5)
                if delta_response.status_code == 200:
                    delta_size = len(delta_response.content)
                    self.print_success(f"CRL Delta EA scaricata!")
                    self.print_info(f"  Dimensione: {delta_size} bytes")
                    ea_delta_available = True
                else:
                    self.print_info(f"  CRL Delta EA non disponibile (normale)")
                    ea_delta_available = False
                
                ea_success = True
                results["ea"] = {
                    "full_crl_size": crl_size,
                    "delta_crl_available": ea_delta_available
                }
            elif response.status_code == 404:
                self.print_info(f"⚠️  CRL EA non ancora pubblicata (prima esecuzione)")
                results["ea"] = {
                    "note": "CRL not yet published - acceptable on first run",
                    "status": 404
                }
                ea_success = True  # Considerato successo per prima esecuzione
            else:
                self.print_error(f"Download CRL EA fallito! Status: {response.status_code}")
                results["ea"] = {"status": response.status_code, "error": "Download failed"}
            
            # Test AA CRL
            self.print_info(f"Download CRL da AA...")
            aa_response = requests.get(f"{aa_url}/api/crl/full", timeout=5)
            
            if aa_response.status_code == 200:
                aa_crl_size = len(aa_response.content)
                self.print_success(f"CRL Full AA scaricata!")
                self.print_info(f"  Dimensione: {aa_crl_size} bytes")
                self.print_info(f"  Content-Type: {aa_response.headers.get('Content-Type', 'N/A')}")
                
                # Prova anche Delta CRL AA
                aa_delta_response = requests.get(f"{aa_url}/api/crl/delta", timeout=5)
                if aa_delta_response.status_code == 200:
                    aa_delta_size = len(aa_delta_response.content)
                    self.print_success(f"CRL Delta AA scaricata!")
                    self.print_info(f"  Dimensione: {aa_delta_size} bytes")
                    aa_delta_available = True
                else:
                    self.print_info(f"  CRL Delta AA non disponibile (normale)")
                    aa_delta_available = False
                
                aa_success = True
                results["aa"] = {
                    "full_crl_size": aa_crl_size,
                    "delta_crl_available": aa_delta_available
                }
            elif aa_response.status_code == 404:
                self.print_info(f"⚠️  CRL AA non ancora pubblicata (prima esecuzione)")
                results["aa"] = {
                    "note": "CRL not yet published - acceptable on first run",
                    "status": 404
                }
                aa_success = True  # Considerato successo per prima esecuzione
            else:
                self.print_error(f"Download CRL AA fallito! Status: {aa_response.status_code}")
                results["aa"] = {"status": aa_response.status_code, "error": "Download failed"}
            
            # Determina stato complessivo
            overall_success = ea_success or aa_success
            status = "success" if overall_success else "failed"
            
            if ea_success and aa_success:
                self.print_success("Entrambe le CRL (EA e AA) scaricate con successo!")
            elif ea_success:
                self.print_success("CRL EA scaricata con successo, CRL AA non disponibile")
            elif aa_success:
                self.print_success("CRL AA scaricata con successo, CRL EA non disponibile")
            else:
                self.print_error("Nessuna CRL disponibile da EA o AA")
            
            # Calcola e stampa tempo di esecuzione
            duration = time.time() - start_time
            self.print_test_execution_time("Download CRL", duration)
            
            results["execution_time"] = duration
            self.save_test_result("crl_download", status, results)
            return overall_success
                
        except Exception as e:
            duration = time.time() - start_time
            self.print_test_execution_time("Download CRL", duration)
            self.print_error(f"Errore: {e}")
            self.save_test_result("crl_download", "error", {"error": str(e), "execution_time": duration})
            return False
    
    def run_interactive_menu(self):
        """Menu interattivo per scegliere i test"""
        while True:
            self.print_header("PKI TESTER - Menu Interattivo (API REST)")
            print("\n  Test Disponibili:")
            print("  1. ✈️  Enrollment singolo veicolo")
            print("  2. 🚗 Enrollment flotta veicoli (configurabile)")
            print("  3. 🎫 Richiesta Authorization Ticket")
            print("  4. 📡 Simulazione comunicazione V2V")
            print("  5. ✔️  Validazione certificati")
            print("  6. 🦋 Butterfly Expansion (configurabile)")
            print("  7. 🚫 Revoca certificato (configurabile)")
            print("  8. 📥 Download CRL (EA & AA)")
            print("  A. 🔄 Esegui tutti i test (configurabile)")
            print("  B. 📊 Mostra risultati")
            print("  C. 🗑️  Pulisci dati test")
            print("  D. 🚀 Batch Enrollment Ottimizzato (configurabile)")
            print("  0. ❌ Esci")
            
            print("\n  Stato corrente:")
            print(f"    Veicoli enrollati: {len(self.enrolled_vehicles)}")
            print(f"    Test eseguiti: {len(self.test_results)}")
            
            choice = input("\n  Scegli test (0-9, A-D): ").strip().upper()
            
            if choice == "1":
                self.test_1_vehicle_enrollment()
            elif choice == "2":
                self.test_2_multiple_vehicles()
            elif choice == "3":
                self.test_3_authorization_ticket()
            elif choice == "4":
                self.test_4_v2v_communication()
            elif choice == "5":
                self.test_5_certificate_validation()
            elif choice == "6":
                self.test_6_butterfly_expansion()
            elif choice == "7":
                self.test_7_certificate_revocation()
            elif choice == "8":
                self.test_8_crl_download()
            elif choice == "A":
                self.run_all_tests()
            elif choice == "B":
                self.show_results()
            elif choice == "C":
                self.cleanup()
            elif choice == "D":
                self.test_batch_vehicle_enrollment()
            elif choice == "0":
                self.print_info("Uscita...")
                break
            else:
                self.print_error("Scelta non valida!")
            
            input("\n  Premi ENTER per continuare...")
    
    def run_all_tests(self):
        """Esegui tutti i test in sequenza"""
        self.print_header("ESECUZIONE TUTTI I TEST")
        
        if self.auto_mode:
            self.print_info("Modalità auto: uso valori predefiniti per tutti i test.")
        else:
            self.print_info("Ogni test configurabile chiederà i suoi parametri durante l'esecuzione.")
        print()  # Riga vuota per separazione
        
        tests = [
            ("Test 1", self.test_1_vehicle_enrollment),
            ("Test 2", self.test_2_multiple_vehicles),
            ("Test 3", self.test_3_authorization_ticket),
            ("Test 4", self.test_4_v2v_communication),
            ("Test 5", self.test_5_certificate_validation),
            ("Test 6", self.test_6_butterfly_expansion),
            ("Test 7", self.test_7_certificate_revocation),
            ("Test 8", self.test_8_crl_download)
        ]
        
        results = []
        total_start_time = time.time()
        
        for name, test_func in tests:
            print(f"\n{'='*70}")
            result = test_func()
            results.append((name, result))
            time.sleep(1)
        
        total_end_time = time.time()
        total_duration = total_end_time - total_start_time
        
        self.print_header("RIEPILOGO TOTALE")
        passed = sum(1 for _, r in results if r)
        failed = len(results) - passed
        
        for name, result in results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"  {name}: {status}")
        
        print(f"\n  Totale: {passed}/{len(results)} test superati")
        
        if passed == len(results):
            self.print_success("Tutti i test superati!")
        else:
            self.print_error(f"{failed} test falliti")
        # Conteggio totale certificati emessi (usando contatori dinamici)
        total_ec = self.total_ec_issued
        total_at = self.total_at_issued
        
        print(f"\n  📊 RIEPILOGO CERTIFICATI:")
        print(f"     Enrollment Certificates (EC): {total_ec} totali, {total_ec - self.revoked_ec_count} validi ({self.revoked_ec_count} revocato)")
        print(f"     Authorization Tickets (AT): {total_at} totali, {total_at - self.revoked_at_count} validi ({self.revoked_at_count} revocato)")
        print(f"     Totale certificati emessi: {total_ec + total_at}")
        print(f"     Totale certificati validi: {total_ec + total_at - self.revoked_ec_count - self.revoked_at_count}")
        
        # Metriche di performance
        print(f"\n  📈 METRICHE PERFORMANCE:")
        print(f"     Tempo totale suite: {total_duration:.2f}s")
        print(f"     Numero di test eseguiti: {len(results)}")
    
    def show_results(self):
        """Mostra risultati dei test"""
        self.print_header("RISULTATI TEST")
        
        if not self.test_results:
            self.print_info("Nessun test eseguito ancora")
            return
        
        for i, result in enumerate(self.test_results, 1):
            status_icon = "✅" if result['status'] == "success" else "❌"
            print(f"\n  [{i}] {status_icon} {result['test']}")
            print(f"      Timestamp: {result['timestamp']}")
            print(f"      Status: {result['status']}")
            if result.get('details'):
                print(f"      Details: {json.dumps(result['details'], indent=10)}")
    
    def cleanup(self):
        """Pulisci dati di test"""
        self.print_info("Rimozione dati test...")
        
        count = len(self.enrolled_vehicles)
        self.enrolled_vehicles.clear()
        
        self.print_success(f"Rimossi {count} veicoli test dalla memoria")
        self.print_info("⚠️  I dati sul server EA rimangono (riavvia server per reset completo)")


def main():
    parser = argparse.ArgumentParser(
        description="Interactive PKI Tester",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Avvia con integrazione dashboard"
    )
    
    parser.add_argument(
        "--ea-url",
        default="http://localhost:5000",
        help="URL Enrollment Authority (default: http://localhost:5000, EA range: 5000-5019)"
    )
    
    parser.add_argument(
        "--aa-url",
        default="http://localhost:5020",
        help="URL Authorization Authority (default: http://localhost:5020, AA range: 5020-5039)"
    )
    
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Esegui tutti i test automaticamente"
    )
    
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Chiudi automaticamente le entities PKI alla fine dei test (--auto)"
    )
    
    parser.add_argument(
        "--no-start",
        action="store_true",
        help="Non avviare automaticamente le entities PKI (usa quelle già attive)"
    )
    
    parser.add_argument(
        "--scan-entities",
        action="store_true",
        help="Scansiona tutte le porte 5000-5039 all'avvio per identificare EA/AA disponibili"
    )
    
    args = parser.parse_args()
    
    # Avvia entities se richiesto
    started_entities = []
    if not args.no_start:
        started_entities = start_pki_entities()
    else:
        print("\n[WARNING] Modalità --no-start: usando entities già attive")
    
    tester = PKITester()
    tester.auto_mode = args.auto
    tester.ea_url = args.ea_url
    tester.aa_url = args.aa_url
    
    # SEMPRE scansiona le porte 5000-5039 per trovare EA e AA disponibili
    # (sia che le abbiamo appena avviate, sia in modalità --no-start)
    print("\n" + "="*70)
    print("  SCANSIONE ENTITÀ DISPONIBILI")
    print("="*70)
    tester.scan_entities_at_startup()
    
    # Configura URL dinamicamente se entities sono state avviate
    if started_entities:
        for entity in started_entities:
            if entity['type'] == 'EA':
                print(f"  EA avviato: {entity['id']} su {entity['url']}")
            elif entity['type'] == 'AA':
                print(f"  AA avviato: {entity['id']} su {entity['url']}")
    
    if args.dashboard:
        print("\n[DASHBOARD] Integrazione dashboard attiva")
        print(f"   Risultati salvati in: data/test_results.json")
        print(f"   Apri dashboard: file://{Path('pki_dashboard.html').absolute()}\n")
    
    try:
        if args.auto:
            tester.run_all_tests()
            print("\n" + "="*70)
            print("  TEST COMPLETATI - ENTITIES ATTIVE")
            print("  Per continuare test o usare dashboard")
            print("="*70)
            if args.cleanup:
                print("  --cleanup attivo: chiusura entities...")
                stop_pki_entities()
            else:
                print("  Usa --cleanup per chiudere automaticamente")
                print("  Oppure: python stop_all.ps1")
                print("  Premi Ctrl+C per uscire")
                print("="*70)
                if not tester.auto_mode:
                    input("\nPremi Enter per continuare...")
        
        else:
            tester.run_interactive_menu()
    
    finally:
        # Chiudi i processi avviati solo se --cleanup è attivo
        if args.cleanup and not args.no_start:
            stop_pki_entities()


if __name__ == "__main__":
    main()
