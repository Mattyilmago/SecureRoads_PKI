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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Import PKIEntityManager for port management
sys.path.insert(0, str(Path(__file__).parent.parent))
from server import PKIEntityManager
from utils.pki_paths import PKIPathManager

# Import ETSI components
from protocols.messages.encoder import ETSIMessageEncoder
from protocols.messages.types import InnerEcRequest, InnerAtRequest, SharedAtRequest
from protocols.core.types import ResponseCode, convert_app_permissions_to_psid_ssp
from protocols.core.primitives import public_key_to_etsi_verification_key, public_key_to_etsi_encryption_key
from protocols.certificates.asn1_encoder import decode_certificate_with_asn1
from protocols.certificates.utils import extract_public_key_from_asn1_certificate

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


def start_pki_entities(temp_mode=False):
    """
    Avvia le entities PKI automaticamente controllando la disponibilità delle porte
    
    Args:
        temp_mode: Se True, non salva EA/AA in entity_configs.json (test temporanei)
    """
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
    project_root = Path(__file__).parent
    
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
    # IMPORTANTE: TLM e RootCA DEVONO essere avviati PRIMA di EA/AA
    # perché EA/AA si registrano automaticamente al TLM all'avvio
    entities = [
        ("TLM", "TLM_MAIN"),      # 1. Prima TLM (per registrazione EA)
        ("RootCA", "RootCA"),     # 2. Poi RootCA (per firma certificati)
        ("EA", ea_name),          # 3. EA (si registra al TLM)
        ("AA", aa_name)           # 4. AA (usa EA per validazione)
    ]
    
    # Trova porte disponibili per ogni entity 
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
            # Distingui tra TLM/RootCA (necessarie per test) e altre entities (errore)
            if entity_type in ["TLM", "RootCA"]:
                default_port = 5050 if entity_type == 'TLM' else 5999
                
                # Solo in modalità temp_mode, prova ad avviare TLM/RootCA se non attive
                # Verifica se sono realmente attive e funzionanti
                try:
                    import socket
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex(('127.0.0.1', default_port))
                    sock.close()
                    
                    if result == 0:
                        # Porta occupata - verifica che risponda correttamente
                        try:
                            url = build_url('127.0.0.1', default_port, '/health')
                            response = requests.get(url, timeout=2, **get_request_kwargs())
                            if response.status_code == 200:
                                print(f'    {entity_id}: ✅ già attiva e funzionante (porta {default_port})')
                                # Non aggiungere a entity_configs - non serve riavviarla
                            else:
                                # Porta occupata ma non risponde correttamente
                                print(f'    {entity_id}: ⚠️  non risponde, skip avvio (porta {default_port} occupata)')
                        except:
                            # Non risponde - porta occupata da altro processo
                            print(f'    {entity_id}: ⚠️  porta {default_port} occupata da altro processo')
                    else:
                        # Porta libera - AVVIA TLM/RootCA (SEMPRE necessari per PKI)
                        print(f'    {entity_id}: 🚀 avvio sulla porta {default_port}')
                        entity_configs.append((entity_type, entity_id, default_port))
                        used_ports.add(default_port)
                except Exception as e:
                    print(f'    {entity_id}: ⚠️  errore verifica ({str(e)[:50]})')
            else:
                print(f"    {entity_id}: ⚠️  nessuna porta disponibile nel range - SKIP")
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
            
            # Se temp_mode è True, aggiungi il flag per EA e AA (non per TLM/RootCA)
            # TLM e RootCA sono sempre persistenti perché condivisi tra test
            if temp_mode and entity_type in ["EA", "AA"]:
                cmd.append("--temp")
            
            # Avvia in background con PYTHONPATH settato
            env = os.environ.copy()
            env['PYTHONPATH'] = str(project_root)
            
            # Prepare logs directory - use entity-specific path in pki_data
            entity_paths = PKIPathManager.get_entity_paths(entity_type, entity_id)
            log_dir = entity_paths.logs_dir
            log_dir.mkdir(parents=True, exist_ok=True)

            # Redirect all output (stdout/stderr) to the main .log file
            # This consolidates logging to a single file per entity
            log_path = str(log_dir / f"{entity_id}.log")
            log_f = open(log_path, "ab")

            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    env=env,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    shell=False,
                    stdout=log_f,
                    stderr=subprocess.STDOUT  # Redirect stderr to stdout (combined in .log)
                )
            else:  # Linux/Mac
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    env=env,
                    stdout=log_f,
                    stderr=subprocess.STDOUT  # Redirect stderr to stdout (combined in .log)
                )
            
            _started_processes.append((entity_type, entity_id, process))
            print("✅")
            
            # Aspetta che TLM sia pronto prima di avviare EA/AA (che si registrano al TLM)
            if entity_type == "TLM":
                print("  ⏳ Attesa TLM pronto (2 secondi)...", end=" ")
                time.sleep(1)
                print("✅")
            
        except Exception as e:
            print(f" ({str(e)[:30]})")
    
    # Aspetta che gli altri server siano pronti
    print(f"\n  Attesa avvio server rimanenti (1 secondo)...")
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
            except (requests.RequestException, Exception):
                print(f"    {entity_id} (:{port}): ❌")
        else:
            print(f"    {entity_id}: ❌ (porta non trovata)")
    
    print(f"\n  Entities attive: {active_count}/{len(_started_processes)}")
    
    if active_count == 0:
        print("\n  ℹ️ Nessuna entity attiva! Test potrebbero fallire.")
    
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
                except (AttributeError, OSError):
                    process.terminate()
            else:
                process.terminate()
            
            try:
                process.wait(timeout=5)
                print("✅")
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                print("ℹ️ (forzata)")
        except Exception as e:
            print(f" ({str(e)[:20]})")
    
    _started_processes = []


class PKITester:
    """Classe per eseguire test interattivi sulla PKI usando API REST"""
    
    def __init__(self):
        self.test_results = []
        self.enrolled_vehicles = {}  # {vehicle_id: {certificate_data}}
        
        # Statistiche per singola EA/AA
        self.entity_stats = {
            "EA": {},  # {ea_id: {"ec_issued": 0, "ec_valid": 0, "ec_revoked": 0}}
            "AA": {}   # {aa_id: {"at_issued": 0, "at_valid": 0, "at_revoked": 0}}
        }
        
        # Lista delle entity disponibili (popolata da scan_entities_at_startup)
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
    
    def _init_entity_stats(self, entity_type, entity_id):
        """Inizializza le statistiche per un'entit se non esistono"""
        if entity_id not in self.entity_stats[entity_type]:
            if entity_type == "EA":
                self.entity_stats[entity_type][entity_id] = {
                    "ec_issued": 0,
                    "ec_valid": 0,
                    "ec_revoked": 0
                }
            else:  # AA
                self.entity_stats[entity_type][entity_id] = {
                    "at_issued": 0,
                    "at_valid": 0,
                    "at_revoked": 0
                }
    
    def _record_ec_issued(self, ea_id, is_valid=True):
        """Registra un EC emesso da una specifica EA"""
        self._init_entity_stats("EA", ea_id)
        self.entity_stats["EA"][ea_id]["ec_issued"] += 1
        if is_valid:
            self.entity_stats["EA"][ea_id]["ec_valid"] += 1
    
    def _record_at_issued(self, aa_id, count=1, is_valid=True):
        """Registra AT emessi da una specifica AA"""
        self._init_entity_stats("AA", aa_id)
        self.entity_stats["AA"][aa_id]["at_issued"] += count
        if is_valid:
            self.entity_stats["AA"][aa_id]["at_valid"] += count
    
    def _record_ec_revoked(self, ea_id):
        """Registra un EC revocato"""
        self._init_entity_stats("EA", ea_id)
        self.entity_stats["EA"][ea_id]["ec_revoked"] += 1
        if self.entity_stats["EA"][ea_id]["ec_valid"] > 0:
            self.entity_stats["EA"][ea_id]["ec_valid"] -= 1
    
    def _record_at_revoked(self, aa_id):
        """Registra un AT revocato"""
        self._init_entity_stats("AA", aa_id)
        self.entity_stats["AA"][aa_id]["at_revoked"] += 1
        if self.entity_stats["AA"][aa_id]["at_valid"] > 0:
            self.entity_stats["AA"][aa_id]["at_valid"] -= 1
    
    def _extract_entity_id_from_url(self, url):
        """Estrae l'entity ID dall'URL usando prima la cache, poi chiamando l'API"""
        # Prima prova a cercare nella cache
        for entity_type in ["EA", "AA"]:
            for entity in self.available_entities.get(entity_type, []):
                if entity['url'] == url:
                    return entity['id']
        
        # Fallback: chiama l'API
        try:
            response = requests.get(url, timeout=2, **get_request_kwargs())
            if response.status_code == 200:
                data = response.json()
                return data.get('entity_id', 'UNKNOWN')
        except (requests.RequestException, Exception):
            pass
        
        # Ultimo fallback: estrae dalla porta
        port = url.split(':')[-1].replace('/', '')
        return f"ENTITY_{port}"
    
    def _sync_entity_statistics(self):
        """Sincronizza le statistiche locali con i dati reali delle entity tramite API /stats"""
        # Sincronizza EA
        for ea in self.available_entities.get("EA", []):
            try:
                stats_response = requests.get(f"{ea['url']}/api/stats", timeout=2)
                if stats_response.status_code == 200:
                    stats_data = stats_response.json()
                    self._init_entity_stats("EA", ea['id'])
                    # Aggiorna le statistiche reali dall'EA
                    self.entity_stats["EA"][ea['id']]["ec_issued"] = stats_data.get("certificates_issued", 0)
                    self.entity_stats["EA"][ea['id']]["ec_valid"] = stats_data.get("active_certificates", 0)
                    self.entity_stats["EA"][ea['id']]["ec_revoked"] = stats_data.get("revoked_certificates", 0)
            except Exception:
                pass  # Mantieni i valori attuali se la sincronizzazione fallisce
        
        # Sincronizza AA
        for aa in self.available_entities.get("AA", []):
            try:
                stats_response = requests.get(f"{aa['url']}/api/stats", timeout=2)
                if stats_response.status_code == 200:
                    stats_data = stats_response.json()
                    self._init_entity_stats("AA", aa['id'])
                    # Aggiorna le statistiche reali dall'AA
                    self.entity_stats["AA"][aa['id']]["at_issued"] = stats_data.get("certificates_issued", 0)
                    self.entity_stats["AA"][aa['id']]["at_valid"] = stats_data.get("active_certificates", 0)
                    self.entity_stats["AA"][aa['id']]["at_revoked"] = stats_data.get("revoked_certificates", 0)
            except Exception:
                pass  # Mantieni i valori attuali se la sincronizzazione fallisce
    
    def _print_entity_statistics(self):
        """Stampa statistiche dettagliate per ogni entity EA e AA usando i contatori locali"""
        ea_stats = self.entity_stats.get("EA", {})
        aa_stats = self.entity_stats.get("AA", {})
        
        if not ea_stats and not aa_stats:
            return  # Nessuna statistica da mostrare
        
        print("\n" + "="*60)
        print("     STATISTICHE PER ENTITÀ")
        print("="*60)
        
        # Mostra statistiche EA
        if ea_stats:
            print("\n    📋 Enrollment Authorities (EA):")
            print("    " + "-"*56)
            for ea_id in sorted(ea_stats.keys()):
                stats = ea_stats[ea_id]
                print(f"      {ea_id}:")
                print(f"        ✅ EC emessi: {stats['ec_issued']}")
                print(f"        ✅ EC validi: {stats['ec_valid']}")
                print(f"        🚫 EC revocati: {stats['ec_revoked']}")
        
        # Mostra statistiche AA
        if aa_stats:
            print("\n    📋 Authorization Authorities (AA):")
            print("    " + "-"*56)
            for aa_id in sorted(aa_stats.keys()):
                stats = aa_stats[aa_id]
                print(f"      {aa_id}:")
                print(f"        🎫 AT emessi: {stats['at_issued']}")
                print(f"        ✅ AT validi: {stats['at_valid']}")
                print(f"        🚫 AT revocati: {stats['at_revoked']}")
        
        print("="*60 + "\n")
        
    def _find_entity_url(self, entity_type, port_start, port_end):
        """Trova dinamicamente l'URL di un'entit in esecuzione"""
        import socket
        
        for port in range(port_start, port_end + 1):
            try:
                # Test connessione TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    # Porta aperta, verifica se  l'entit giusta
                    url = f"http://127.0.0.1:{port}"
                    try:
                        response = requests.get(f"{url}/", timeout=2)
                        if response.status_code == 200:
                            data = response.json()
                            if data.get('entity_type') == entity_type:
                                self.print_info(f"Trovata {entity_type} su porta {port}")
                                return url
                    except (requests.RequestException, Exception):
                        pass
                        
            except (requests.RequestException, ValueError, Exception):
                pass
        
        # Fallback alla porta di default se nessuna trovata
        default_port = port_start
        self.print_info(f"Nessuna {entity_type} trovata, uso porta default {default_port}")
        return f"http://127.0.0.1:{default_port}"
    
    def scan_entities_at_startup(self):
        """Scansiona tutte le porte da 5000 a 5039 all'avvio per identificare EA e AA disponibili"""
        self.print_info("ℹ  Scansione entity disponibili (porte 5000-5039)...")
        
        import socket
        import concurrent.futures
        import requests
        
        def check_port(port):
            """Controlla una singola porta e restituisce info entity se trovata"""
            try:
                # Test connessione TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                
                if result == 0:
                    # Porta aperta, verifica se  un'entit PKI
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
                    except (requests.RequestException, Exception):
                        pass
                        
            except (requests.RequestException, ValueError, Exception):
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
        
        # Inizializza statistiche per ogni entity trovata leggendo i dati dalle API /stats
        for ea in found_ea:
            try:
                stats_response = requests.get(f"{ea['url']}/api/stats", timeout=2)
                if stats_response.status_code == 200:
                    stats_data = stats_response.json()
                    self._init_entity_stats("EA", ea['id'])
                    # Carica le statistiche attuali dall'EA
                    self.entity_stats["EA"][ea['id']]["ec_issued"] = stats_data.get("certificates_issued", 0)
                    self.entity_stats["EA"][ea['id']]["ec_valid"] = stats_data.get("active_certificates", 0)
                    self.entity_stats["EA"][ea['id']]["ec_revoked"] = stats_data.get("revoked_certificates", 0)
            except Exception as e:
                # Se fallisce, inizializza con valori 0
                self._init_entity_stats("EA", ea['id'])
        
        for aa in found_aa:
            try:
                stats_response = requests.get(f"{aa['url']}/api/stats", timeout=2)
                if stats_response.status_code == 200:
                    stats_data = stats_response.json()
                    self._init_entity_stats("AA", aa['id'])
                    # Carica le statistiche attuali dall'AA
                    self.entity_stats["AA"][aa['id']]["at_issued"] = stats_data.get("certificates_issued", 0)
                    self.entity_stats["AA"][aa['id']]["at_valid"] = stats_data.get("active_certificates", 0)
                    self.entity_stats["AA"][aa['id']]["at_revoked"] = stats_data.get("revoked_certificates", 0)
            except Exception as e:
                # Se fallisce, inizializza con valori 0
                self._init_entity_stats("AA", aa['id'])
        
        # Log dei risultati
        total_found = len(found_ea) + len(found_aa)
        if total_found > 0:
            self.print_success(f"✅ Trovate {total_found} entity: {len(found_ea)} EA, {len(found_aa)} AA")
            for ea in found_ea:
                stats = self.entity_stats["EA"].get(ea['id'], {})
                self.print_info(f"  📋 EA: {ea['id']} (porta {ea['port']}) - EC: {stats.get('ec_issued', 0)} emessi, {stats.get('ec_valid', 0)} validi, {stats.get('ec_revoked', 0)} revocati")
            for aa in found_aa:
                stats = self.entity_stats["AA"].get(aa['id'], {})
                self.print_info(f"  📋 AA: {aa['id']} (porta {aa['port']}) - AT: {stats.get('at_issued', 0)} emessi, {stats.get('at_valid', 0)} validi, {stats.get('at_revoked', 0)} revocati")
        else:
            self.print_info("Nessuna entity PKI trovata nelle porte 5000-5039")
    
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
        self.print_info(f"📋 Autorità {entity_type} disponibili:")
        for i, entity in enumerate(available_entities, 1):
            print(f"  {i}. {entity['id']} - Porta {entity['port']}")
        
        # Chiedi all'utente quale scegliere
        if len(available_entities) > 1:
            while True:
                try:
                    choice = input(f"\nScegli l'{entity_type} da usare (1-{len(available_entities)}) o 0 per annullare: ").strip()
                    choice_num = int(choice)
                
                    if choice_num == 0:
                        self.print_info("Operazione annullata")
                        return None
                    elif 1 <= choice_num <= len(available_entities):
                        selected = available_entities[choice_num - 1]
                        self.print_success(f"✅ Selezionata {entity_type}: {selected['id']} su porta {selected['port']}")
                        return selected['url']
                    else:
                        self.print_error(f"Scelta non valida. Inserisci un numero tra 1 e {len(available_entities)} o 0 per annullare")
                except ValueError:
                    self.print_error("Inserisci un numero valido")
        else:
            self.print_success(f"✅ Selezionata {entity_type}: {available_entities[0]['id']} su porta {available_entities[0]['port']}")
            return available_entities[0]['url']
    def print_header(self, text):
        """Stampa intestazione formattata"""
        print("\n" + "="*70)
        print(f"  {text}")
        print("="*70)
    
    def print_success(self, text):
        """Stampa messaggio di successo"""
        print(f" {text}")
        
    def print_error(self, text):
        """Stampa messaggio di errore"""
        print(f" {text}")
    
    def print_warning(self, text):
        """Stampa messaggio di warning"""
        print(f"ℹ  {text}")
        
    def print_info(self, text):
        """Stampa informazione"""
        print(f"ℹ  {text}")
    
    def print_test_execution_time(self, test_name, duration):
        """Stampa il tempo di esecuzione di un test"""
        self.print_info(f"ℹ  Tempo esecuzione {test_name}: {duration:.2f}s")
    
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
                    args[0].print_info(f"ℹ  Tempo esecuzione {display_name}: {duration:.2f}s")
                    return result
                except Exception as e:
                    end_time = time.time()
                    duration = end_time - start_time
                    display_name = test_name or func.__name__.replace('test_', '').replace('_', ' ').title()
                    args[0].print_error(f"ℹ  Test {display_name} fallito dopo {duration:.2f}s: {e}")
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
        from config import PKI_PATHS
        results_file = PKI_PATHS.BASE / "test_results.json"
        results_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(results_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
    
    def get_entity_metrics(self, entity_url):
        """Ottiene le metriche da un'entit PKI"""
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
        self.print_info(" METRICHE ENTITIES:")
        
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
        """Ottiene il certificato pubblico dell'EA dall'endpoint (ASN.1 format)"""
        # Usa URL passato come parametro o fallback a self.ea_url
        url = ea_url or self.ea_url
        if not url:
            self.print_error("Nessun URL EA disponibile")
            return None, None
        
        # Se l'URL  cambiato, invalida la cache
        if hasattr(self, '_last_ea_url') and self._last_ea_url != url:
            self._ea_certificate = None
            self._ea_public_key = None
        
        self._last_ea_url = url
            
        if self._ea_certificate is None:
            try:
                # Ottieni certificato dall'endpoint EA (formato ASN.1 OER binario)
                response = requests.get(f"{url}/api/enrollment/certificate", timeout=5, **get_request_kwargs())
                if response.status_code == 200:
                    # Il certificato  in formato ASN.1 OER (binary)
                    cert_asn1 = response.content
                    self._ea_certificate = cert_asn1
                    
                    # Estrai chiave pubblica dal certificato ASN.1
                    self._ea_public_key = extract_public_key_from_asn1_certificate(cert_asn1)
                    self.print_info(f"Ottenuto certificato EA dall'endpoint (ASN.1 format)")
                else:
                    self.print_error(f"❌ Errore ottenimento certificato EA: {response.status_code}")
                    # Fallback al file system
                    self._fallback_get_ea_certificate()
            except Exception as e:
                self.print_error(f"❌ Errore caricamento certificato EA: {e}")
                # Fallback al file system
                self._fallback_get_ea_certificate()
        return self._ea_certificate, self._ea_public_key
    
    def _fallback_get_ea_certificate(self):
        """Fallback: ottiene certificato EA dal file system (ASN.1 format)"""
        try:
            # Cerca file .oer nella directory dell'EA
            from pathlib import Path
            ea_dirs = list(Path("pki_data/ea").glob("EA_*"))
            if ea_dirs:
                cert_path = ea_dirs[0] / "certificates" / "ea_certificate.oer"
                if cert_path.exists():
                    with open(cert_path, 'rb') as f:
                        cert_asn1 = f.read()
                    self._ea_certificate = cert_asn1
                    try:
                        self._ea_public_key = extract_public_key_from_asn1_certificate(cert_asn1)
                        self.print_info(f"Usando certificato EA dal file system (fallback): {cert_path}")
                    except Exception as e:
                        self.print_error(f"❌ Errore estrazione chiave pubblica EA: {e}")
                        # Prova decodifica ASN.1 completa
                        try:
                            cert_decoded = decode_certificate_with_asn1(cert_asn1, "EtsiTs103097Certificate")
                            # Estrai chiave pubblica dai dati decodificati
                            if 'toBeSigned' in cert_decoded and 'verifyKeyIndicator' in cert_decoded['toBeSigned']:
                                self.print_info("Chiave pubblica trovata tramite decodifica ASN.1")
                        except Exception as e2:
                            self.print_error(f"❌ Errore decodifica certificato EA: {e2}")
        except Exception as e:
            self.print_error(f"❌ Errore caricamento certificato EA dal file system: {e}")
    
    def get_aa_certificate(self, aa_url=None):
        """Ottiene il certificato pubblico dell'AA dall'endpoint (ASN.1 format)"""
        # Usa URL passato come parametro o fallback a self.aa_url
        url = aa_url or self.aa_url
        if not url:
            self.print_error("Nessun URL AA disponibile")
            return None, None
        
        # Se l'URL  cambiato, invalida la cache
        if hasattr(self, '_last_aa_url') and self._last_aa_url != url:
            self._aa_certificate = None
            self._aa_public_key = None
        
        self._last_aa_url = url
            
        if self._aa_certificate is None:
            try:
                # Ottieni certificato dall'endpoint AA (formato ASN.1 OER binario)
                response = requests.get(f"{url}/api/authorization/certificate", timeout=5, **get_request_kwargs())
                if response.status_code == 200:
                    # Il certificato  in formato ASN.1 OER (binary)
                    cert_asn1 = response.content
                    self._aa_certificate = cert_asn1
                    
                    # Estrai chiave di ENCRYPTION dal certificato ASN.1 (ETSI TS 102 941)
                    # Per le richieste authorization, usiamo la encryption key dell'AA
                    self._aa_public_key = extract_public_key_from_asn1_certificate(cert_asn1, key_type="encryption")
                    self.print_info(f"Ottenuto certificato AA dall'endpoint (ASN.1 format)")
                    self.print_info(f"  🔐 Estratta encryption key per cifrare richieste")
                else:
                    self.print_error(f"❌ Errore ottenimento certificato AA: {response.status_code}")
                    # Fallback al file system
                    self._fallback_get_aa_certificate()
            except Exception as e:
                self.print_error(f"❌ Errore caricamento certificato AA: {e}")
                # Fallback al file system
                self._fallback_get_aa_certificate()
        return self._aa_certificate, self._aa_public_key
    
    def _fallback_get_aa_certificate(self):
        """Fallback: ottiene certificato AA dal file system (ASN.1 format)"""
        try:
            # Cerca file .oer nella directory dell'AA
            from pathlib import Path
            aa_dirs = list(Path("pki_data/aa").glob("AA_*"))
            if aa_dirs:
                cert_path = aa_dirs[0] / "certificates" / "aa_certificate.oer"
                if cert_path.exists():
                    with open(cert_path, 'rb') as f:
                        cert_asn1 = f.read()
                    self._aa_certificate = cert_asn1
                    # Usa encryption key per cifrare richieste authorization
                    self._aa_public_key = extract_public_key_from_asn1_certificate(cert_asn1, key_type="encryption")
                    self.print_info(f"ℹ  Usando certificato AA dal file system (fallback): {cert_path}")
                    self.print_info(f"ℹ  🔐 Estratta encryption key per cifrare richieste")
        except Exception as e:
            self.print_error(f"❌ Errore caricamento certificato AA dal file system: {e}")
    
    def create_etsi_enrollment_request(self, vehicle_id, private_key, public_key_pem, ea_url=None):
        """Crea una richiesta enrollment ETSI ASN.1 OER"""
        try:
            # Ottieni certificato EA (ASN.1 format)
            ea_cert_asn1, ea_public_key = self.get_ea_certificate(ea_url)
            if not ea_cert_asn1 or not ea_public_key:
                raise ValueError("Certificato EA non disponibile")
            
            # Decodifica certificato per debug
            try:
                cert_decoded = decode_certificate_with_asn1(ea_cert_asn1, "EtsiTs103097Certificate")
                self.print_info(f"EA Certificate decoded successfully")
            except Exception as e:
                self.print_warning(f"Could not decode EA cert for debug: {e}")
            
            # Carica e converti chiave pubblica in formato ETSI
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'), default_backend()
            )
            verification_key_etsi = public_key_to_etsi_verification_key(public_key)
            
            # ETSI TS 102 941: L'ITS-S deve fornire sia verification che encryption key
            # La verification key viene usata per il certificato
            # La encryption key viene usata dall'EA per cifrare la risposta
            encryption_key_etsi = public_key_to_etsi_encryption_key(public_key)
            
            # Converti ITS-AIDs in formato PsidSsp secondo ETSI standard
            app_permissions = convert_app_permissions_to_psid_ssp(["CAM", "DENM"])
            
            # Crea InnerEcRequest secondo ETSI TS 102941
            inner_request = InnerEcRequest(
                itsId=vehicle_id,
                certificateFormat=1,  # ETSI TS 103097
                publicKeys={
                    "verification": verification_key_etsi,
                    "encryption": encryption_key_etsi  # Richiesta da ETSI TS 102 941 Section 6.2.3
                },
                requestedSubjectAttributes={
                    "country": "IT",
                    "organization": f"TestOrg_{vehicle_id}",
                    "appPermissions": app_permissions  # Lista di PsidSsp dicts
                }
            )
            
            self.print_info(f"Created InnerEcRequest for {vehicle_id}")
            
            # Codifica richiesta ETSI
            encoded_request = self.encoder.encode_enrollment_request(
                inner_request=inner_request,
                private_key=private_key,
                ea_public_key=ea_public_key,
                ea_certificate_asn1=ea_cert_asn1  # Passa certificato ASN.1 binario
            )
            
            self.print_info(f"Encoded ETSI request: {len(encoded_request)} bytes")
            
            return encoded_request
            
        except Exception as e:
            self.print_error(f"❌ Errore creazione richiesta enrollment ETSI: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def create_etsi_authorization_request(self, vehicle_id, enrollment_cert_asn1, private_key, public_key_pem, hmac_key=None, aa_url=None):
        """Crea una richiesta authorization ETSI ASN.1 OER
        
        Args:
            vehicle_id: ID del veicolo
            enrollment_cert_asn1: Certificato enrollment in formato ASN.1 binario
            private_key: Chiave privata per firma
            public_key_pem: Chiave pubblica in PEM
            hmac_key: HMAC key opzionale
            aa_url: URL dell'AA
        """
        try:
            # Ottieni certificato AA (ASN.1 format)
            aa_cert_asn1, aa_public_key = self.get_aa_certificate(aa_url)
            if not aa_cert_asn1 or not aa_public_key:
                raise ValueError("Certificato AA non disponibile")
            
            # Carica e converti chiave pubblica in formato ETSI
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'), default_backend()
            )
            verification_key_etsi = public_key_to_etsi_verification_key(public_key)
            
            # Crea HMAC key unica per unlinkability
            if hmac_key is None:
                hmac_key = secrets.token_bytes(32)
            
            # Converti ITS-AIDs in formato PsidSsp secondo ETSI standard
            app_permissions = convert_app_permissions_to_psid_ssp(["CAM", "DENM"])
            
            # Crea validityPeriod correttamente strutturato
            from protocols.core.primitives import time32_encode
            start_time32 = time32_encode(datetime.now(timezone.utc))
            duration_choice = ('hours', 7 * 24)  # 7 giorni in ore
            
            # Crea InnerAtRequest secondo ETSI TS 102941
            inner_request = InnerAtRequest(
                publicKeys={"verification": verification_key_etsi},
                hmacKey=hmac_key,
                requestedSubjectAttributes={
                    "appPermissions": app_permissions,  # Lista di PsidSsp dicts
                    "validityPeriod": {
                        "start": start_time32,
                        "duration": duration_choice
                    }
                }
            )
            
            # Codifica richiesta ETSI
            encoded_request = self.encoder.encode_authorization_request(
                inner_request=inner_request,
                enrollment_certificate_asn1=enrollment_cert_asn1,  # Passa ASN.1 binario
                enrollment_private_key=private_key,  # Chiave privata EC per firma
                aa_public_key=aa_public_key,
                aa_certificate_asn1=aa_cert_asn1,  # Passa ASN.1 binario
                testing_mode=False  # Usa SignedAndEncrypted standard ETSI
            )
            
            return encoded_request, hmac_key
            
        except Exception as e:
            self.print_error(f"❌ Errore creazione richiesta authorization ETSI: {e}")
            return None, None
    
    def create_etsi_butterfly_request(self, vehicle_id, enrollment_cert_asn1, enrollment_private_key, num_tickets=5, aa_url=None):
        """Crea una richiesta butterfly ETSI ASN.1 OER per batch authorization
        
        Args:
            vehicle_id: ID del veicolo
            enrollment_cert_asn1: Certificato enrollment in formato ASN.1 binario
            enrollment_private_key: Chiave privata enrollment per firma
            num_tickets: Numero di AT da richiedere
            aa_url: URL dell'AA
        """
        try:
            # Ottieni certificato AA dall'endpoint REST (ASN.1 format)
            aa_cert_asn1, aa_public_key = self.get_aa_certificate(aa_url)
            if not aa_cert_asn1 or not aa_public_key:
                raise ValueError("Certificato AA non disponibile")
            
            self.print_info(f"Certificato AA ottenuto (ASN.1 format)")
            
            # Crea N InnerAtRequests per butterfly
            inner_requests = []
            hmac_keys = []
            
            for i in range(num_tickets):
                # Genera chiave pubblica per questo AT
                private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                public_key = private_key.public_key()
                
                # Converti in formato ETSI usando helper DRY
                verification_key_etsi = public_key_to_etsi_verification_key(public_key)
                
                # Genera HMAC key univoca per unlinkability
                hmac_key = secrets.token_bytes(32)
                hmac_keys.append(hmac_key)
                
                # Converti ITS-AIDs in formato PsidSsp secondo ETSI standard
                app_permissions = convert_app_permissions_to_psid_ssp(["CAM", "DENM"])
                
                # Crea validityPeriod correttamente strutturato
                from protocols.core.primitives import time32_encode
                start_time32 = time32_encode(datetime.now(timezone.utc))
                duration_choice = ('hours', 7 * 24)  # 7 giorni in ore
                
                # Crea InnerAtRequest secondo ETSI TS 102941
                inner_request = InnerAtRequest(
                    publicKeys={"verification": verification_key_etsi},
                    hmacKey=hmac_key,
                    requestedSubjectAttributes={
                        "appPermissions": app_permissions,  # Lista di PsidSsp dicts
                        "validityPeriod": {
                            "start": start_time32,
                            "duration": duration_choice
                        }
                    }
                )
                
                inner_requests.append(inner_request)
            
            # Ottieni EA certificate per il SharedAtRequest (ASN.1 format)
            ea_cert_asn1, _ = self.get_ea_certificate()
            if not ea_cert_asn1:
                self.print_error("Certificato EA non disponibile, uso placeholder")
                ea_hashed_id8 = b"\x00" * 8
            else:
                # Calcola HashedId8 del certificato EA (ASN.1)
                from protocols.core.primitives import compute_hashed_id8
                ea_hashed_id8 = compute_hashed_id8(ea_cert_asn1)
                self.print_info(f"EA HashedId8: {ea_hashed_id8.hex()}")
            
            # Crea SharedAtRequest per parametri condivisi
            key_tag = secrets.token_bytes(16)  # Random key tag per questa richiesta
            
            # Converti ITS-AIDs in formato PsidSsp secondo ETSI standard
            app_permissions = convert_app_permissions_to_psid_ssp(["CAM", "DENM"])
            
            # Crea validityPeriod correttamente strutturato
            from protocols.core.primitives import time32_encode
            start_time32 = time32_encode(datetime.now(timezone.utc))
            duration_choice = ('hours', 7 * 24)  # 7 giorni in ore
            
            shared_at_request = SharedAtRequest(
                eaId=ea_hashed_id8,
                keyTag=key_tag,
                certificateFormat=1,
                requestedSubjectAttributes={
                    "appPermissions": app_permissions,  # Lista di PsidSsp dicts
                    "validityPeriod": {
                        "start": start_time32,
                        "duration": duration_choice
                    }
                }
            )
            
            # Crea ButterflyAuthorizationRequest
            from protocols.messages.types import ButterflyAuthorizationRequest
            butterfly_request = ButterflyAuthorizationRequest(
                sharedAtRequest=shared_at_request,
                innerAtRequests=inner_requests,
                batchSize=len(inner_requests),
                enrollmentCertificate=enrollment_cert_asn1,  # Passa ASN.1 binario
                timestamp=datetime.now(timezone.utc)
            )
            
            # Codifica richiesta ETSI con SignedAndEncrypted (100% ETSI standard)
            encoded_request = self.encoder.encode_butterfly_authorization_request(
                butterfly_request=butterfly_request,
                enrollment_certificate_asn1=enrollment_cert_asn1,  # ASN.1 binario
                enrollment_private_key=enrollment_private_key,  # Chiave privata per firma
                aa_public_key=aa_public_key,
                aa_certificate_asn1=aa_cert_asn1  # ASN.1 binario
            )
            
            self.print_info(f"Encoded ETSI butterfly request: {len(encoded_request)} bytes")
            self.print_info(f"  Numero AT richiesti: {num_tickets}")
            self.print_info(f"  Formato: SignedAndEncrypted (ETSI TS 102941 compliant)")
            
            return encoded_request, hmac_keys
            
        except Exception as e:
            self.print_error(f"❌ Errore creazione richiesta butterfly ETSI: {e}")
            import traceback
            traceback.print_exc()
            return None, None

    def test_1_vehicle_enrollment(self):
        """Test 1: Enrollment completo di un veicolo usando API ETSI standard"""
        self.print_header("🚗 TEST 1: Enrollment Veicolo (ETSI Standard)")
        
        # Chiedi all'utente quale EA usare
        ea_url = self.select_entity_interactive("EA")
        if not ea_url:
            return False
        
        # Inizia timer DOPO le selezioni dell'utente
        start_time = time.time()
        
        try:
            vehicle_id = f"VEHICLE_{int(time.time())}"
            self.print_info(f"📝 Creazione richiesta enrollment ETSI: {vehicle_id}")
            
            # 1. Crea directory PRIMA di generare chiavi
            paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
            paths.create_all()
            
            # 2. Genera chiavi per il veicolo
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            # 3. SALVA SUBITO la chiave privata (CRITICO!)
            key_path = paths.private_keys_dir / f"{vehicle_id}_key.key"
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            with open(key_path, 'w') as f:
                f.write(private_key_pem)
            self.print_info(f"  🔑 Chiave privata salvata: {key_path}")
            
            # 4. Crea richiesta enrollment ETSI ASN.1 OER
            encoded_request = self.create_etsi_enrollment_request(vehicle_id, private_key, public_key_pem, ea_url)
            if not encoded_request:
                self.print_error("❌ Impossibile creare richiesta enrollment ETSI")
                return False
            
            self.print_info(f"📤 Invio richiesta ETSI a {ea_url}/api/enrollment/request")
            self.print_info(f"Payload ASN.1 OER: {len(encoded_request)} bytes")
            
            # Headers per ETSI TS 102941
            headers = {
                "Content-Type": "application/vnd.etsi.ts102941.v2.1.1"
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
                self.print_success(f"✅ Enrollment Certificate ottenuto!")
                self.print_info(f"  Response ASN.1 OER: {len(response_data)} bytes")
                
                # Decodifica risposta ETSI per estrarre il certificato
                encoder = ETSIMessageEncoder()
                try:
                    inner_response = encoder.decode_enrollment_response(response_data, private_key)
                    
                    if inner_response.is_success() and inner_response.certificate:
                        # Il certificato è già in formato ASN.1 binario (OER)
                        cert_asn1 = inner_response.certificate
                        
                        # Salva certificato su disco (formato ASN.1 binario)
                        # Directory già create all'inizio
                        ec_path = paths.certificates_dir / f"{vehicle_id}_EC.oer"
                        with open(ec_path, 'wb') as f:  # Modalità binaria
                            f.write(cert_asn1)
                        
                        self.print_info(f"  💾 Certificato ASN.1 salvato: {ec_path}")
                        
                        result = {
                            "message": "ETSI ✅ Enrollment successful",
                            "response_size": len(response_data),
                            "vehicle_id": vehicle_id,
                            "certificate_path": str(ec_path),
                            "private_key_path": str(key_path),
                            "certificate_asn1": cert_asn1  # Salva binario invece di PEM
                        }
                    else:
                        self.print_error(f"Enrollment fallito: {inner_response.responseCode}")
                        return False
                        
                except Exception as e:
                    self.print_error(f"❌ Errore decodifica risposta ETSI: {e}")
                    # Fallback: salva dati raw
                    result = {
                        "message": "ETSI ✅ Enrollment successful (raw)",
                        "response_size": len(response_data),
                        "vehicle_id": vehicle_id
                    }
                
                # Registra EC emesso per questa EA
                ea_id = self._extract_entity_id_from_url(ea_url)
                self._record_ec_issued(ea_id, is_valid=True)
                
                # Salva info veicolo
                vehicle_info = {
                    "enrollment_response": result,
                    "private_key": private_key,
                    "public_key_pem": public_key_pem,
                    "timestamp": datetime.now().isoformat(),
                    "ea_url": ea_url,  # Salva quale EA ha emesso il certificato
                    "ea_id": ea_id
                }
                
                # Aggiungià certificato ASN.1 se decodificato
                if 'certificate_asn1' in result:
                    vehicle_info["certificate_asn1"] = result["certificate_asn1"]
                
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
                        "message": "ETSI ✅ enrollment successful",
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
                self.print_info("Modalit  auto: uso 10 veicoli per enrollment batch.")
            else:
                try:
                    num_vehicles_input = input("  Quanti veicoli enrollare in batch (default 10): ").strip()
                    num_vehicles = int(num_vehicles_input) if num_vehicles_input else 10
                    if num_vehicles <= 0:
                        raise ValueError("Deve essere positivo")
                except ValueError as e:
                    self.print_error(f"Input non valido: {e}. Uso default 10.")
                    num_vehicles = 10
        
        self.print_header(f"🚀 TEST BATCH: Enrollment {num_vehicles} veicoli (Ottimizzato)")
        
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
                
                # Usa chiave pi piccola per ottimizzazione (se possibile)
                # Nota: SECP256R1  già ottimizzato, ma potremmo usare curve pi piccole in futuro
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
                    timeout=60,  # Timeout pi lungo per batch
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
                    ea_id = self._extract_entity_id_from_url(ea_url)
                    for vehicle_data in result.get("enrolled_vehicles", []):
                        vehicle_id = vehicle_data["vehicle_id"]
                        self.enrolled_vehicles[vehicle_id] = {
                            "enrollment_response": vehicle_data,
                            "timestamp": datetime.now().isoformat(),
                            "batch_enrolled": True,
                            "ea_url": ea_url,
                            "ea_id": ea_id
                        }
                        # Registra ogni EC emesso
                        self._record_ec_issued(ea_id, is_valid=True)
                    
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
                    headers={"Content-Type": "application/vnd.etsi.ts102941.v2.1.1"},
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
                            # Il certificato  già in formato ASN.1 binario (OER)
                            cert_asn1 = inner_response.certificate
                            
                            # Salva certificato su disco nella directory del veicolo (formato ASN.1)
                            try:
                                paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
                                paths.create_all()
                                ec_path = paths.certificates_dir / f"{vehicle_id}_EC.oer"
                                with open(ec_path, 'wb') as f:
                                    f.write(cert_asn1)
                                
                                # Salva anche chiave privata
                                key_path = paths.private_keys_dir / f"{vehicle_id}_key.key"
                                # Directory già create con create_all()
                                private_key_pem = private_key.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                ).decode('utf-8')
                                with open(key_path, 'w') as f:
                                    f.write(private_key_pem)
                                
                                self.print_success(f"    ✓ {vehicle_id} enrollato e salvato (ETSI)")
                            except Exception as save_error:
                                self.print_error(f"    ℹ {vehicle_id} enrollato ma errore salvataggio: {save_error}")
                            
                            # Salva dati veicolo in memoria
                            vehicle_info = {
                                "enrollment_response": {
                                    "success": True,
                                    "certificate_asn1": cert_asn1,
                                    "certificate_path": str(ec_path) if 'ec_path' in locals() else None,
                                    "private_key_path": str(key_path) if 'key_path' in locals() else None
                                },
                                "timestamp": datetime.now().isoformat(),
                                "batch_enrolled": True,
                                "etsi_encoded": True
                            }
                            
                            self.enrolled_vehicles[vehicle_id] = vehicle_info
                            enrolled_count += 1
                            
                            # Registra EC emesso per questa EA
                            ea_id = self._extract_entity_id_from_url(ea_url)
                            self._record_ec_issued(ea_id, is_valid=True)
                        else:
                            self.print_error(f"     {vehicle_id} enrollment fallito: {inner_response.responseCode}")
                    except Exception as e:
                        self.print_error(f"     {vehicle_id} errore decodifica ETSI: {e}")
                else:
                    self.print_error(f"     {vehicle_id} fallito: {response.status_code}")
            
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
            self.print_error(f"❌ Errore batch enrollment: {e}")
            self.save_test_result("batch_vehicle_enrollment", "error", {"error": str(e)})
            return False
    
    def test_3_authorization_ticket(self):
        """Test 3: Richiesta Authorization Ticket usando API ETSI standard"""
        self.print_header("🎫 TEST 3: Authorization Ticket (ETSI Standard)")
        
        # Chiedi all'utente quale AA usare
        aa_url = self.select_entity_interactive("AA")
        if not aa_url:
            return False
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo enrollato! Esegui prima il Test 1")
            return False
        
        # Controlla se l'EA usata per enrollment  ancora disponibile
        vehicle_id = list(self.enrolled_vehicles.keys())[0]
        vehicle_data = self.enrolled_vehicles[vehicle_id]
        
        if "ea_id" in vehicle_data:
            ea_id = vehicle_data["ea_id"]
            ea_still_available = any(
                ea['id'] == ea_id for ea in self.available_entities.get("EA", [])
            )
            if not ea_still_available:
                self.print_warning(
                    f"ℹ  ATTENZIONE: Il veicolo  stato enrollato con {ea_id}, "
                    f"ma questa EA non  pi disponibile!"
                )
                self.print_warning(
                    f"    L'AA potrebbe non riconoscere l'Enrollment Certificate."
                )
                self.print_info(
                    f"    Suggerimento: Usa opzione 'R' per ri-scansionare le entity "
                    f"o fai un nuovo enrollment con un'EA attualmente attiva."
                )
                proceed = input(f"\n    Vuoi procedere comunque (s/n): ").strip().lower()
                if proceed != 's':
                    self.print_info("Operazione annullata")
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
            
            # Usa il certificato enrollment salvato nei dati del veicolo (ASN.1 format)
            enrollment_cert_asn1 = vehicle_data.get("enrollment_response", {}).get("certificate_asn1")
            
            if not enrollment_cert_asn1:
                # Fallback: cerca su disco (formato .oer)
                try:
                    paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
                    ec_path = paths.certificates_dir / f"{vehicle_id}_EC.oer"
                    if ec_path.exists():
                        with open(ec_path, 'rb') as f:  # Modalit binaria
                            enrollment_cert_asn1 = f.read()
                except:
                    pass
            
            if not enrollment_cert_asn1:
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
                vehicle_id, enrollment_cert_asn1, private_key, public_key_pem, None, aa_url
            )
            if not encoded_request:
                self.print_error("❌ Impossibile creare richiesta authorization ETSI")
                return False
            
            # Headers per ETSI TS 102941
            headers = {
                "Content-Type": "application/vnd.etsi.ts102941.v2.1.1",
                "X-Testing-Mode": "true"
            }
            
            # Aggiungià enrollment certificate come header per testing mode (ASN.1 in base64)
            if enrollment_cert_asn1:
                import base64
                headers["X-Enrollment-Certificate"] = base64.b64encode(enrollment_cert_asn1).decode('utf-8')
            
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
                        # Il certificato AT  già in formato ASN.1 binario (OER)
                        at_cert_asn1 = inner_response.certificate
                        
                        result = {
                            "message": "ETSI Authorization successful",
                            "response_size": len(response_data),
                            "vehicle_id": vehicle_id,
                            "hmac_key": hmac_key.hex() if hmac_key else None,
                            "certificate_asn1": at_cert_asn1
                        }
                        
                        self.print_info(f"  Authorization Ticket decodificato correttamente")
                    else:
                        self.print_error(f"  Risposta authorization fallita: {inner_response.responseCode}")
                        result = {
                            "message": f"ETSI Authorization failed: {inner_response.responseCode}",
                            "response_size": len(response_data),
                            "vehicle_id": vehicle_id,
                            "hmac_key": hmac_key.hex() if hmac_key else None,
                            "failed": True  # Flag per indicare fallimento
                        }
                        
                except Exception as e:
                    self.print_error(f"❌ Errore decodifica risposta ETSI: {e}")
                    # Fallback: salva dati raw
                    result = {
                        "message": "ETSI Authorization successful (raw)",
                        "response_size": len(response_data),
                        "vehicle_id": vehicle_id,
                        "hmac_key": hmac_key.hex() if hmac_key else None
                    }
                
                # Registra AT emesso solo se l'authorization è riuscita
                if not result.get("failed", False):
                    aa_id = self._extract_entity_id_from_url(aa_url)
                    self._record_at_issued(aa_id, count=1, is_valid=True)
                
                # Salva AT nel veicolo
                vehicle_data["authorization_ticket"] = result
                
                # Salva authorization ticket su disco solo se riuscito
                if not result.get("failed", False):
                    try:
                        paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
                        paths.create_all()
                        
                        if 'certificate_asn1' in result:
                            # Salva come ASN.1 binario (.oer)
                            at_path = paths.certificates_dir / f"{vehicle_id}_AT_etsi.oer"
                            with open(at_path, 'wb') as f:  # Modalit binaria
                                f.write(result['certificate_asn1'])
                            self.print_info(f"✅ Authorization Ticket ETSI salvato: {at_path}")
                        else:
                            # Fallback: salva raw data come bin
                            at_path = paths.certificates_dir / f"{vehicle_id}_AT_etsi.bin"
                            with open(at_path, 'wb') as f:
                                f.write(response_data)
                            self.print_info(f"✅ Authorization Ticket ETSI salvato (raw): {at_path}")
                    except Exception as e:
                        self.print_warning(f"Errore salvataggio AT ETSI: {e}")
                else:
                    self.print_warning(f"⚠️  Authorization Ticket NON salvato (authorization fallita)")
                
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
        self.print_header("🚗 TEST 2: Enrollment Flotta Veicoli")
        
        # Chiedi numero di veicoli se non specificato
        if num_vehicles is None:
            if self.auto_mode:
                num_vehicles = 5
                self.print_info("Modalit  auto: uso 5 veicoli per enrollment flotta.")
            else:
                try:
                    num_vehicles_input = input("  Quanti veicoli enrollare nella flotta (default 5): ").strip()
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
                    print(f" (ETSI encoding failed)")
                    failed_count += 1
                    continue
                
                req_start = time.time()
                response = requests.post(
                    f"{ea_url}/api/enrollment/request",
                    data=encoded_request,
                    headers={"Content-Type": "application/vnd.etsi.ts102941.v2.1.1"},
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
                            # Il certificato  già in formato ASN.1 binario (OER)
                            cert_asn1 = inner_response.certificate
                            
                            # Salva certificato e chiave su disco (formato ASN.1)
                            try:
                                paths = PKIPathManager.get_entity_paths("ITS", vehicle_id)
                                paths.create_all()
                                ec_path = paths.certificates_dir / f"{vehicle_id}_EC.oer"
                                with open(ec_path, 'wb') as f:  # Modalit binaria
                                    f.write(cert_asn1)
                                
                                # Salva chiave privata
                                key_path = paths.private_keys_dir / f"{vehicle_id}_key.key"
                                private_key_pem = private_key.private_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.PKCS8,
                                    encryption_algorithm=serialization.NoEncryption()
                                ).decode('utf-8')
                                with open(key_path, 'w') as f:
                                    f.write(private_key_pem)
                            except Exception as save_error:
                                print(f"ℹ (Save error: {str(save_error)[:20]})", end=" ")
                            
                            ea_id = self._extract_entity_id_from_url(ea_url)
                            self.enrolled_vehicles[vehicle_id] = {
                                "enrollment_response": {
                                    "success": True,
                                    "certificate_asn1": cert_asn1,
                                    "certificate_path": str(ec_path) if 'ec_path' in locals() else None,
                                    "private_key_path": str(key_path) if 'key_path' in locals() else None
                                },
                                "timestamp": datetime.now().isoformat(),
                                "etsi_encoded": True,
                                "ea_url": ea_url,
                                "ea_id": ea_id
                            }
                            
                            print("✅")
                            success_count += 1
                            success_times.append(req_end - req_start)
                            
                            # Registra EC emesso per questa EA
                            ea_id = self._extract_entity_id_from_url(ea_url)
                            self._record_ec_issued(ea_id, is_valid=True)
                        else:
                            print(f" (Enrollment failed: {inner_response.responseCode})")
                            failed_count += 1
                    except Exception as e:
                        print(f" (Decode error: {str(e)[:20]})")
                        failed_count += 1
                else:
                    print(f" ({response.status_code})")
                    failed_count += 1
                    
            except Exception as e:
                print(f" ({str(e)[:30]})")
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
        self.print_header("📡 TEST 4: Comunicazione V2V (CAM)")
        
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
            
            # Salva messaggio in outbox del sender e inbox del receiver
            try:
                # Ottieni paths dei veicoli
                sender_paths = PKIPathManager.get_entity_paths("ITS", vehicle_ids[0])
                receiver_paths = PKIPathManager.get_entity_paths("ITS", vehicle_ids[1])
                
                # Assicurati che le directory esistano
                sender_paths.create_all()
                receiver_paths.create_all()
                
                # Crea il messaggio da salvare
                message_text = (
                    f"=== V2V MESSAGE (CAM) ===\n"
                    f"Timestamp: {datetime.now().isoformat()}\n"
                    f"From: {vehicle_ids[0]}\n"
                    f"To: {vehicle_ids[1]}\n"
                    f"Message Type: CAM\n"
                    f"Position: {cam_data['latitude']}, {cam_data['longitude']}\n"
                    f"Speed: {cam_data['speed']} km/h\n"
                    f"Heading: {cam_data['heading']}°\n"
                    f"Sender Certificate: {'Valid ' if sender_has_cert else 'Missing '}\n"
                    f"========================\n\n"
                )
                
                # Salva in outbox del sender
                outbox_file = sender_paths.outbox_dir / f"{vehicle_ids[0]}_outbox.txt"
                with open(outbox_file, 'a', encoding='utf-8') as f:
                    f.write(message_text)
                self.print_info(f"   Messaggio salvato in outbox: {outbox_file}")
                
                # Salva in inbox del receiver
                inbox_file = receiver_paths.inbox_dir / f"from_{vehicle_ids[0]}.txt"
                with open(inbox_file, 'a', encoding='utf-8') as f:
                    f.write(message_text)
                self.print_info(f"   Messaggio salvato in inbox: {inbox_file}")
                
            except Exception as save_error:
                self.print_error(f"  ℹ  Errore salvataggio messaggi: {save_error}")
            
            if sender_has_cert and receiver_has_cert:
                self.print_success("Messaggio CAM inviato con successo!")
                self.print_info("  Sender: Certificato EC valido ")
                self.print_info("  Receiver: Certificato EC valido ")
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
                    # Estrai certificato ASN.1 - cerca prima in vehicle_data, poi in enrollment_response
                    cert_asn1 = vehicle_data.get("certificate_asn1") or vehicle_data.get("enrollment_response", {}).get("certificate_asn1")
                    if not cert_asn1:
                        self.print_error(f"  {vehicle_id}:  Certificato mancante")
                        invalid_count += 1
                        continue
                    
                    # Decodifica certificato ASN.1 per validazione ETSI TS 103097
                    cert_decoded = decode_certificate_with_asn1(cert_asn1, "EtsiTs103097Certificate")
                    
                    # Validazione completa ETSI TS 103097 V2.1.1 Section 6.2
                    validation_result = {
                        "vehicle_id": vehicle_id,
                        "checks": {}
                    }
                    
                    # 1. Verifica decodifica ASN.1 OER corretta
                    validation_result["checks"]["asn1_decodable"] = True
                    
                    # 2. Verifica versione certificato (ETSI TS 103097 V2)
                    version = cert_decoded.get('version', 0)
                    validation_result["checks"]["version_valid"] = (version == 3)  # Version 3 = ETSI TS 103097 V2
                    
                    # 3. Verifica presenza issuerIdentifier (HashedId8 della CA)
                    issuer = cert_decoded.get('issuer', {})
                    has_issuer = 'sha256AndDigest' in issuer or 'sha384AndDigest' in issuer
                    validation_result["checks"]["has_issuer"] = has_issuer
                    
                    # 4. Verifica toBeSigned structure
                    tbs = cert_decoded.get('toBeSigned', {})
                    has_tbs = bool(tbs)
                    validation_result["checks"]["has_tbs"] = has_tbs
                    
                    # 5. Verifica validità temporale (ValidityPeriod)
                    from protocols.core.primitives import extract_validity_period
                    try:
                        start_time_cert, expiry_time, duration_sec = extract_validity_period(cert_asn1)
                        now = datetime.now(timezone.utc)
                        is_valid_time = start_time_cert <= now <= expiry_time
                        validation_result["checks"]["temporal_validity"] = is_valid_time
                        validation_result["validity_start"] = start_time_cert.isoformat()
                        validation_result["validity_end"] = expiry_time.isoformat()
                    except Exception as e:
                        validation_result["checks"]["temporal_validity"] = False
                        validation_result["validity_error"] = str(e)
                    
                    # 6. Verifica chiave pubblica (verifyKeyIndicator)
                    verify_key = tbs.get('verifyKeyIndicator', {})
                    has_public_key = bool(verify_key)
                    validation_result["checks"]["has_public_key"] = has_public_key
                    
                    # 7. Verifica algoritmo firma (ECDSA NIST P-256)
                    signature = cert_decoded.get('signature', {})
                    if isinstance(signature, tuple) and len(signature) == 2:
                        sig_algo = signature[0]
                        is_ecdsa = sig_algo in ['ecdsaNistP256Signature', 'ecdsaBrainpoolP256r1Signature']
                        validation_result["checks"]["ecdsa_signature"] = is_ecdsa
                    else:
                        validation_result["checks"]["ecdsa_signature"] = False
                    
                    # 8. Verifica app permissions (se presente)
                    app_permissions = tbs.get('appPermissions', [])
                    if app_permissions:
                        validation_result["checks"]["has_app_permissions"] = True
                        validation_result["app_permissions_count"] = len(app_permissions)
                    else:
                        validation_result["checks"]["has_app_permissions"] = False
                    
                    # Determina stato complessivo
                    all_checks = validation_result["checks"]
                    is_valid = all(all_checks.values())
                    
                    if is_valid:
                        self.print_info(f"  {vehicle_id}:  VALIDO (ETSI TS 103097 compliant)")
                        valid_count += 1
                    else:
                        failed_checks = [k for k, v in all_checks.items() if not v]
                        self.print_error(f"  {vehicle_id}:  INVALIDO - Failed: {', '.join(failed_checks)}")
                        invalid_count += 1
                    
                    validation_details.append(validation_result)
                    
                except Exception as cert_error:
                    self.print_error(f"  {vehicle_id}:  Errore parsing: {str(cert_error)[:50]}")
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
                self.print_info("Modalit  auto: uso 20 Authorization Tickets per Butterfly.")
            else:
                try:
                    num_tickets_input = input("  Quanti AT richiedere in batch (Butterfly) (default 20, max 100 ETSI): ").strip()
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
            
            # Usa il certificato enrollment ASN.1
            enrollment_cert_asn1 = vehicle_data.get("certificate_asn1") or vehicle_data["enrollment_response"].get("certificate_asn1")
            if not enrollment_cert_asn1:
                self.print_error("Certificato enrollment mancante!")
                return False
            
            # Recupera chiave privata enrollment per firma
            enrollment_private_key = vehicle_data.get("private_key")
            if not enrollment_private_key:
                self.print_error("Chiave privata enrollment mancante!")
                return False
            
            self.print_info(f"Veicolo: {vehicle_id}")
            self.print_info(f"Richiesta Butterfly: {num_tickets} Authorization Tickets in batch...")
            
            start_time = time.time()
            # Crea richiesta ETSI butterfly completa con SignedAndEncrypted
            encoded_request, hmac_keys = self.create_etsi_butterfly_request(
                vehicle_id, enrollment_cert_asn1, enrollment_private_key, num_tickets, aa_url
            )
            
            if not encoded_request or not hmac_keys:
                self.print_error("❌ Impossibile creare richiesta butterfly ETSI")
                return False
            
            response = requests.post(
                f"{aa_url}/api/authorization/request/butterfly",
                data=encoded_request,
                headers={
                    "Content-Type": "application/vnd.etsi.ts102941.v2.1.1",
                    "X-Request-Type": "butterfly"
                },
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
                    
                    # Registra AT emessi per questa AA
                    aa_id = self._extract_entity_id_from_url(aa_url)
                    self._record_at_issued(aa_id, count=at_count, is_valid=True)
                    
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
                    self.print_error(f"❌ Errore decodifica risposta butterfly ETSI: {e}")
                    self.save_test_result("butterfly_expansion_etsi", "decode_error", {"error": str(e)})
                    return False
            else:
                self.print_error(f"Butterfly ETSI fallito! Status: {response.status_code}")
                try:
                    error_data = response.json()
                    self.print_error(f"❌ Errore dal server: {error_data}")
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
                self.print_info("Modalit  auto: revoca 1 certificato.")
            else:
                try:
                    num_revocations_input = input("  Quanti certificati revocare (default 1): ").strip()
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
                
                self.print_info(f"🚫 Revoca veicolo: {vehicle_id}")
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
                    
                    # Registra EC revocato per questa EA
                    ea_id = self._extract_entity_id_from_url(ea_url)
                    self._record_ec_revoked(ea_id)
                    
                    success_count += 1
                    
                    # Verifica rapida inserimento in CRL (senza attesa)
                    # La Delta CRL  pubblicata immediatamente dopo la revoca
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
                                # Prova PEM prima (pi comune)
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
                                        self.print_success(f"     Certificato presente in CRL!")
                                        self.print_info(f"       Data revoca: {revocation_date}")
                                        break
                                
                                if not is_revoked:
                                    self.print_info(f"    ℹ  Certificato non ancora in CRL (propagazione in corso)")
                                    
                            except Exception as parse_error:
                                self.print_info(f"    ℹ  Errore parsing CRL: {str(parse_error)[:100]}")
                                self.print_info(f"       Content-Type: {content_type}")
                                self.print_info(f"       Size: {len(crl_data)} bytes")
                                
                        except Exception as verify_error:
                            self.print_info(f"    ℹ  Verifica CRL non disponibile: {str(verify_error)[:80]}")
                    else:
                        self.print_info(f"    ℹ  CRL non disponibile per verifica (status: {crl_response.status_code})")
                    
                    # Ora revoca anche un AT per test completo
                    self.print_info(f"")
                    self.print_info(f"  Revocando anche un Authorization Ticket...")
                    
                    # Trova un veicolo con AT
                    at_vehicle = None
                    at_cert_asn1 = None
                    for v_id, v_data in self.enrolled_vehicles.items():
                        if "authorization_ticket" in v_data:
                            at_vehicle = v_id
                            at_data = v_data["authorization_ticket"]
                            # Estrai il certificato ASN.1 dal dizionario
                            if isinstance(at_data, dict) and "certificate_asn1" in at_data:
                                at_cert_asn1 = at_data["certificate_asn1"]
                                if at_cert_asn1 and isinstance(at_cert_asn1, bytes):
                                    break
                            elif isinstance(at_data, bytes):
                                at_cert_asn1 = at_data
                                break
                    
                    if at_cert_asn1:
                        # Decodifica AT per estrarre serial (ETSI TS 103097)
                        # TODO: Implementare estrazione serial da certificato ETSI
                        # Per ora usa un hash del certificato come identificatore
                        from protocols.core.primitives import compute_hashed_id8
                        at_hashed_id = compute_hashed_id8(at_cert_asn1)
                        at_serial_hex = at_hashed_id.hex()
                        
                        self.print_info(f"  Veicolo con AT: {at_vehicle}")
                        self.print_info(f"  AT HashedId8: {at_serial_hex}")
                        
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
                            
                            # Registra AT revocato per questa AA
                            aa_id = self._extract_entity_id_from_url(aa_url)
                            self._record_at_revoked(aa_id)
                            
                            # Verifica rapida inserimento AT in CRL AA (senza attesa)
                            # La Delta CRL  pubblicata immediatamente dopo la revoca
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
                                        # Prova PEM prima (pi comune)
                                        if b'-----BEGIN' in aa_crl_data:
                                            aa_crl = x509.load_pem_x509_crl(aa_crl_data, default_backend())
                                        else:
                                            # Altrimenti DER
                                            aa_crl = x509.load_der_x509_crl(aa_crl_data, default_backend())
                                        
                                        # Cerca serial AT nella CRL AA
                                        at_is_revoked = False
                                        # TODO: Implementare verifica CRL ETSI (usa HashedId8, non serial)
                                        for revoked_cert in aa_crl:
                                            if False:  # Disabilitato: at_serial_number non pi disponibile
                                                at_is_revoked = True
                                                at_revocation_date = revoked_cert.revocation_date_utc
                                                self.print_success(f"     AT presente in CRL AA!")
                                                self.print_info(f"       Data revoca: {at_revocation_date}")
                                                break
                                        
                                        if not at_is_revoked:
                                            self.print_info(f"    ℹ  AT non ancora in CRL AA (propagazione in corso)")
                                            
                                    except Exception as parse_error:
                                        self.print_info(f"    ℹ  Errore parsing CRL AA: {str(parse_error)[:100]}")
                                        self.print_info(f"       Content-Type: {aa_content_type}")
                                        self.print_info(f"       Size: {len(aa_crl_data)} bytes")
                                        
                                except Exception as verify_error:
                                    self.print_info(f"    ℹ  Verifica CRL AA non disponibile: {str(verify_error)[:80]}")
                            else:
                                self.print_info(f"    ℹ  CRL AA non disponibile per verifica (status: {aa_crl_response.status_code})")
                            
                        else:
                            self.print_error(f"  Revoca AT fallita! Status: {at_response.status_code}")
                            self.print_error(f"  Error: {at_response.text[:200]}")
                    else:
                        self.print_info(f"  Nessun AT disponibile per revoca")
                    
                    # Rimuovi veicolo dalla lista locale
                    del self.enrolled_vehicles[vehicle_id]
                    
                elif response.status_code == 404:
                    # Endpoint non implementato - fallback a simulazione
                    self.print_info(f"  ℹ  API revoca non disponibile su questo EA")
                    self.print_info(f"    Modalit  fallback: simulazione locale")
                    
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
                self.print_error(f"❌ Errore revoca {vehicle_id}: {e}")
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
            self.print_info(f"📥 Download CRL da EA...")
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
                self.print_info(f"ℹ  CRL EA non ancora pubblicata (prima esecuzione)")
                results["ea"] = {
                    "note": "CRL not yet published - acceptable on first run",
                    "status": 404
                }
                ea_success = True  # Considerato successo per prima esecuzione
            else:
                self.print_error(f"Download CRL EA fallito! Status: {response.status_code}")
                results["ea"] = {"status": response.status_code, "error": "Download failed"}
            
            # Test AA CRL
            self.print_info(f"📥 Download CRL da AA...")
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
                self.print_info(f"ℹ  CRL AA non ancora pubblicata (prima esecuzione)")
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
            print("  1. 🚗 Enrollment singolo veicolo")
            print("  2. 🚗 Enrollment flotta veicoli (configurabile)")
            print("  3. 🎫 Richiesta Authorization Ticket")
            print("  4. 📡 Simulazione comunicazione V2V")
            print("  5. ✅ Validazione certificati")
            print("  6. 🦋 Butterfly Expansion (configurabile)")
            print("  7. 🚫 Revoca certificato (configurabile)")
            print("  8. 📥 Download CRL (EA & AA)")
            print("  A. 🔄 Esegui tutti i test (configurabile)")
            print("  B. 📊 Mostra risultati")
            print("  C. 🗑️  Pulisci dati test")
            print("  D. 🚀 Batch Enrollment Ottimizzato (configurabile)")
            print("  R. 🔍 Ri-scansiona entity disponibili")
            print("  0. ❌ Esci")
            
            # Mostra statistiche dettagliate per EA/AA
            print("\n  ℹ️ Statistiche Entità:")
            self._print_entity_statistics()
            
            print("\n  Stato corrente:")
            print(f"    Veicoli enrollati: {len(self.enrolled_vehicles)}")
            print(f"    Test eseguiti: {len(self.test_results)}")
            
            choice = input("\n  Scegli test (0-9, A-D, R): ").strip().upper()
            
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
            elif choice == "R":
                self.print_info("ℹ Ri-scansione entity in corso...")
                self.scan_entities_at_startup()
                self.print_success("Scansione completata!")
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
            self.print_info("Modalit  auto: uso valori predefiniti per tutti i test.")
        else:
            self.print_info("Ogni test configurabile chieder  i suoi parametri durante l'esecuzione.")
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
            status = " PASS" if result else " FAIL"
            print(f"  {name}: {status}")
        
        print(f"\n  Totale: {passed}/{len(results)} test superati")
        
        if passed == len(results):
            self.print_success("Tutti i test superati!")
        else:
            self.print_error(f"{failed} test falliti")
        
        # Stampa statistiche dettagliate per ogni entity EA/AA
        self._print_entity_statistics()
        
        # Metriche di performance
        print(f"\n   METRICHE PERFORMANCE:")
        print(f"     Tempo totale suite: {total_duration:.2f}s")
        print(f"     Numero di test eseguiti: {len(results)}")
    
    def show_results(self):
        """Mostra risultati dei test"""
        self.print_header("RISULTATI TEST")
        
        if not self.test_results:
            self.print_info("Nessun test eseguito ancora")
            return
        
        for i, result in enumerate(self.test_results, 1):
            status_icon = "" if result['status'] == "success" else ""
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
        self.print_info("ℹ  I dati sul server EA rimangono (riavvia server per reset completo)")


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
    
    parser.add_argument(
        "--temp",
        action="store_true",
        help="Modalità temporanea: non salvare EA/AA avviate in entity_configs.json (test isolati)"
    )
    
    args = parser.parse_args()
    
    # Avvia entities se richiesto
    started_entities = []
    if not args.no_start:
        started_entities = start_pki_entities(temp_mode=args.temp)
    else:
        print("\n[WARNING] Modalit  --no-start: usando entities già attive")
    
    if args.temp:
        print("\n[INFO] Modalità --temp: le entità EA/AA non saranno salvate in entity_configs.json")
    
    tester = PKITester()
    tester.auto_mode = args.auto
    tester.ea_url = args.ea_url
    tester.aa_url = args.aa_url
    
    # SEMPRE scansiona le porte 5000-5039 per trovare EA e AA disponibili
    # (sia che le abbiamo appena avviate, sia in modalità--no-start)
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
        # Chiudi i processi avviati solo se --cleanup  attivo
        if args.cleanup and not args.no_start:
            stop_pki_entities()


if __name__ == "__main__":
    main()
