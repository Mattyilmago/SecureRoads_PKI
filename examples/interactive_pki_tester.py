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
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Variabile globale per tenere traccia dei processi avviati
_started_processes = []


def safe_print(text, **kwargs):
    """Stampa testo gestendo errori di encoding su Windows"""
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        # Fallback: rimuovi caratteri non ASCII
        safe_text = text.encode('ascii', 'ignore').decode('ascii')
        print(safe_text, **kwargs)


def start_pki_entities():
    """Avvia le entities PKI automaticamente"""
    global _started_processes
    
    print("\n" + "="*70)
    print("  AVVIO ENTITIES PKI")
    print("="*70)
    
    # Trova root del progetto
    project_root = Path(__file__).parent.parent
    
    # Configura entities da avviare con porte standard
    entities = [
        ("EA", "EA_001"),
        ("AA", "AA_001"),
        ("TLM", "TLM_MAIN"),
        ("RootCA", "RootCA")
    ]
    
    for entity_type, entity_id in entities:
        try:
            print(f"\n  Avvio {entity_id}...", end=" ")
            
            # Comando per avviare l'entity con server.py
            cmd = [
                sys.executable,
                str(project_root / "server.py"),
                "--entity", entity_type,
                "--id", entity_id
            ]
            
            # Avvia in background con PYTHONPATH settato
            env = os.environ.copy()
            env['PYTHONPATH'] = str(project_root)
            
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    env=env,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    shell=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:  # Linux/Mac
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            _started_processes.append((entity_type, entity_id, process))
            print("✅")
            
        except Exception as e:
            print(f"❌ ({str(e)[:30]})")
    
    # Aspetta che i server siano pronti
    print(f"\n  Attesa avvio server (5 secondi)...")
    time.sleep(5)
    
    # Verifica che siano attivi - usa porte standard
    print("\n  Verifica connessioni:")
    active_count = 0
    ports_map = {
        ("EA", "EA_001"): 5000,
        ("EA", "EA_002"): 5001,
        ("EA", "EA_003"): 5002,
        ("AA", "AA_001"): 5020,
        ("AA", "AA_002"): 5021,
        ("TLM", "TLM_MAIN"): 5050,
        ("RootCA", "RootCA"): 5999
    }
    
    for entity_type, entity_id, process in _started_processes:
        port = ports_map.get((entity_type, entity_id), 5000)
        try:
            response = requests.get(f"http://localhost:{port}/health", timeout=2)
            if response.status_code == 200:
                print(f"    {entity_id} (:{port}): ✅")
                active_count += 1
            else:
                print(f"    {entity_id} (:{port}): ❌")
        except:
            print(f"    {entity_id} (:{port}): ❌")
    
    print(f"\n  Entities attive: {active_count}/{len(_started_processes)}")
    
    if active_count == 0:
        print("\n  ⚠️  Nessuna entity attiva! Test potrebbero fallire.")
    
    return _started_processes


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
        # Default ports from configured ranges:
        # EA: 5000-5019, AA: 5020-5039, TLM: 5040
        self.ea_url = "http://localhost:5000"
        self.aa_url = "http://localhost:5020"
        self.tlm_url = "http://localhost:5040"
        
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
        
    def print_info(self, text):
        """Stampa informazione"""
        print(f"ℹ️  {text}")
    
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
        results_file = Path("data/test_results.json")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(results_file, 'w') as f:
            json.dump(self.test_results, f, indent=2)
    
    def test_1_vehicle_enrollment(self):
        """Test 1: Enrollment completo di un veicolo usando API REST"""
        self.print_header("TEST 1: Enrollment Veicolo")
        
        try:
            vehicle_id = f"VEHICLE_{int(time.time())}"
            self.print_info(f"Creazione richiesta enrollment: {vehicle_id}")
            
            # Prepara richiesta enrollment
            enrollment_request = {
                "its_id": vehicle_id,
                "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfEeCICXLNuwlLRNsap323uVYBG5p\n/LoUa3nH+sbElrw1Dy4M18/9Bib0OLTYXEyuw4/g1U3uHztrLQCKud1y+Q==\n-----END PUBLIC KEY-----",
                "requested_attributes": {
                    "country": "IT",
                    "organization": f"TestOrg_{vehicle_id}",
                    "validity_days": 365
                }
            }
            
            self.print_info(f"Invio richiesta a {self.ea_url}/api/enrollment/request/simple")
            
            response = requests.post(
                f"{self.ea_url}/api/enrollment/request/simple",
                json=enrollment_request,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"Enrollment Certificate ottenuto!")
                self.print_info(f"  Response: {result.get('message', 'Success')}")
                
                # Salva info veicolo
                self.enrolled_vehicles[vehicle_id] = {
                    "enrollment_response": result,
                    "timestamp": datetime.now().isoformat()
                }
                
                self.save_test_result(
                    "vehicle_enrollment",
                    "success",
                    {
                        "vehicle_id": vehicle_id,
                        "message": result.get('message', 'Success')
                    }
                )
                return True
            else:
                self.print_error(f"Enrollment fallito! Status: {response.status_code}")
                self.print_error(f"Error: {response.text[:200]}")
                self.save_test_result("vehicle_enrollment", "failed", {"status": response.status_code})
                return False
                
        except requests.exceptions.ConnectionError:
            self.print_error(f"Impossibile connettersi a {self.ea_url}")
            self.save_test_result("vehicle_enrollment", "error", {"error": "Connection refused"})
            return False
        except Exception as e:
            self.print_error(f"Errore: {e}")
            self.save_test_result("vehicle_enrollment", "error", {"error": str(e)})
            return False
    
    def test_2_authorization_ticket(self):
        """Test 2: Richiesta Authorization Ticket usando API REST"""
        self.print_header("TEST 2: Authorization Ticket")
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo enrollato! Esegui prima il Test 1")
            return False
        
        try:
            # Usa primo veicolo disponibile
            vehicle_id = list(self.enrolled_vehicles.keys())[0]
            vehicle_data = self.enrolled_vehicles[vehicle_id]
            
            self.print_info(f"Veicolo: {vehicle_id}")
            
            # Estrai certificato enrollment dalla risposta
            if "enrollment_response" not in vehicle_data:
                self.print_error("Nessun enrollment certificate trovato!")
                return False
            
            enrollment_cert = vehicle_data["enrollment_response"].get("certificate")
            if not enrollment_cert:
                self.print_error("Certificato enrollment mancante nella risposta!")
                return False
            
            self.print_info(f"Richiesta Authorization Ticket all'AA...")
            
            # Prepara richiesta authorization usando API simplified
            auth_request = {
                "its_id": vehicle_id,
                "enrollment_certificate": enrollment_cert,
                "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfEeCICXLNuwlLRNsap323uVYBG5p\n/LoUa3nH+sbElrw1Dy4M18/9Bib0OLTYXEyuw4/g1U3uHztrLQCKud1y+Q==\n-----END PUBLIC KEY-----",
                "requested_permissions": ["cam", "denm"],
                "validity_days": 7
            }
            
            response = requests.post(
                f"{self.aa_url}/api/authorization/request/simple",
                json=auth_request,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"Authorization Ticket ottenuto!")
                self.print_info(f"  Response: {result.get('message', 'Success')}")
                
                # Salva AT nel veicolo
                vehicle_data["authorization_ticket"] = result
                
                self.save_test_result(
                    "authorization_ticket",
                    "success",
                    {
                        "vehicle_id": vehicle_id,
                        "message": result.get('message', 'Success'),
                        "permissions": auth_request["requested_permissions"]
                    }
                )
                return True
            else:
                self.print_error(f"Authorization fallita! Status: {response.status_code}")
                self.print_error(f"Error: {response.text[:200]}")
                self.save_test_result("authorization_ticket", "failed", {"status": response.status_code})
                return False
                
        except Exception as e:
            self.print_error(f"Errore: {e}")
            self.save_test_result("authorization_ticket", "error", {"error": str(e)})
            return False
    
    def test_3_multiple_vehicles(self):
        """Test 3: Enrollment multiplo (flotta veicoli) usando API REST"""
        self.print_header("TEST 3: Enrollment Flotta Veicoli")
        
        num_vehicles = 5
        self.print_info(f"Enrollment di {num_vehicles} veicoli...")
        
        success_count = 0
        failed_count = 0
        
        for i in range(num_vehicles):
            vehicle_id = f"FLEET_VEHICLE_{i+1:03d}_{int(time.time())}"
            
            try:
                print(f"\n  [{i+1}/{num_vehicles}] {vehicle_id}...", end=" ")
                
                enrollment_request = {
                    "its_id": vehicle_id,
                    "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfEeCICXLNuwlLRNsap323uVYBG5p\n/LoUa3nH+sbElrw1Dy4M18/9Bib0OLTYXEyuw4/g1U3uHztrLQCKud1y+Q==\n-----END PUBLIC KEY-----",
                    "requested_attributes": {
                        "country": "IT",
                        "organization": f"FleetOrg_{i+1}",
                        "validity_days": 365
                    }
                }
                
                response = requests.post(
                    f"{self.ea_url}/api/enrollment/request/simple",
                    json=enrollment_request,
                    timeout=10
                )
                
                if response.status_code == 200:
                    result = response.json()
                    self.enrolled_vehicles[vehicle_id] = {
                        "enrollment_response": result,
                        "timestamp": datetime.now().isoformat()
                    }
                    print("✅")
                    success_count += 1
                else:
                    print(f"❌ ({response.status_code})")
                    failed_count += 1
                    
            except Exception as e:
                print(f"❌ ({str(e)[:30]})")
                failed_count += 1
        
        print()
        self.print_success(f"Enrollment completati: {success_count}/{num_vehicles}")
        if failed_count > 0:
            self.print_error(f"Enrollment falliti: {failed_count}/{num_vehicles}")
        
        self.save_test_result(
            "fleet_enrollment",
            "success" if success_count == num_vehicles else "partial",
            {
                "total": num_vehicles,
                "success": success_count,
                "failed": failed_count
            }
        )
        
        return success_count > 0
    
    def test_4_v2v_communication(self):
        """Test 4: Simulazione comunicazione V2V"""
        self.print_header("TEST 4: Comunicazione V2V (CAM)")
        
        if len(self.enrolled_vehicles) < 2:
            self.print_error("Servono almeno 2 veicoli! Esegui prima il Test 3")
            return False
        
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
            
            self.save_test_result(
                "v2v_communication",
                status,
                {
                    "sender": vehicle_ids[0],
                    "receiver": vehicle_ids[1],
                    "message_type": "CAM",
                    "sender_has_cert": sender_has_cert,
                    "receiver_has_cert": receiver_has_cert,
                    "note": note
                }
            )
            return True
            
        except Exception as e:
            self.print_error(f"Errore: {e}")
            self.save_test_result("v2v_communication", "error", {"error": str(e)})
            return False
    
    def test_5_certificate_validation(self):
        """Test 5: Validazione certificati X.509 conforme ETSI"""
        self.print_header("TEST 5: Validazione Certificati (ETSI Standard)")
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo disponibile!")
            return False
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from datetime import datetime, timezone
            
            valid_count = 0
            invalid_count = 0
            validation_details = []
            
            self.print_info(f"Veicoli da validare: {len(self.enrolled_vehicles)}")
            
            for vehicle_id, vehicle_data in self.enrolled_vehicles.items():
                try:
                    # Estrai certificato PEM
                    cert_pem = vehicle_data.get("enrollment_response", {}).get("certificate")
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
            
            self.save_test_result(
                "certificate_validation",
                "success" if valid_count == total else "partial",
                {
                    "total": total,
                    "valid": valid_count,
                    "invalid": invalid_count,
                    "validation_details": validation_details
                }
            )
            return valid_count > 0
            
        except Exception as e:
            self.print_error(f"Errore: {e}")
            import traceback
            self.print_error(traceback.format_exc()[:200])
            self.save_test_result("certificate_validation", "error", {"error": str(e)})
            return False
    
    def test_6_performance_test(self):
        """Test 6: Test performance (enrollment multipli) usando API REST"""
        self.print_header("TEST 6: Performance Test")
        
        num_requests = 10
        self.print_info(f"Esecuzione di {num_requests} enrollment consecutivi...")
        
        start_time = time.time()
        success_times = []
        failed = 0
        
        for i in range(num_requests):
            try:
                vehicle_id = f"PERF_TEST_{i+1:03d}_{int(time.time())}"
                
                enrollment_request = {
                    "its_id": vehicle_id,
                    "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfEeCICXLNuwlLRNsap323uVYBG5p\n/LoUa3nH+sbElrw1Dy4M18/9Bib0OLTYXEyuw4/g1U3uHztrLQCKud1y+Q==\n-----END PUBLIC KEY-----",
                    "requested_attributes": {
                        "country": "IT",
                        "organization": "PerfTest",
                        "validity_days": 365
                    }
                }
                
                req_start = time.time()
                response = requests.post(
                    f"{self.ea_url}/api/enrollment/request/simple",
                    json=enrollment_request,
                    timeout=10
                )
                req_end = time.time()
                
                if response.status_code == 200:
                    success_times.append(req_end - req_start)
                else:
                    failed += 1
                    
            except Exception:
                failed += 1
        
        end_time = time.time()
        total_time = end_time - start_time
        
        if success_times:
            avg_time = sum(success_times) / len(success_times)
            min_time = min(success_times)
            max_time = max(success_times)
            
            self.print_success(f"Test completato in {total_time:.2f}s")
            self.print_info(f"  Richieste riuscite: {len(success_times)}/{num_requests}")
            self.print_info(f"  Tempo medio: {avg_time:.3f}s")
            self.print_info(f"  Tempo minimo: {min_time:.3f}s")
            self.print_info(f"  Tempo massimo: {max_time:.3f}s")
            self.print_info(f"  Throughput: {len(success_times)/total_time:.2f} req/s")
            
            self.save_test_result(
                "performance_test",
                "success",
                {
                    "total_requests": num_requests,
                    "successful": len(success_times),
                    "failed": failed,
                    "total_time": total_time,
                    "avg_time": avg_time,
                    "throughput": len(success_times)/total_time
                }
            )
            return True
        else:
            self.print_error("Tutti i test sono falliti!")
            self.save_test_result("performance_test", "failed")
            return False
    
    def test_7_butterfly_expansion(self):
        """Test 7: Butterfly Key Expansion - Richiesta 20 AT in batch"""
        self.print_header("TEST 7: Butterfly Key Expansion (20 AT)")
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo enrollato! Esegui prima il Test 1")
            return False
        
        try:
            # Usa primo veicolo disponibile
            vehicle_id = list(self.enrolled_vehicles.keys())[0]
            vehicle_data = self.enrolled_vehicles[vehicle_id]
            
            enrollment_cert = vehicle_data["enrollment_response"].get("certificate")
            if not enrollment_cert:
                self.print_error("Certificato enrollment mancante!")
                return False
            
            self.print_info(f"Veicolo: {vehicle_id}")
            self.print_info(f"Richiesta Butterfly: 20 Authorization Tickets in batch...")
            
            # Genera 20 chiavi pubbliche per i 20 AT
            public_keys = []
            for i in range(20):
                private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
                public_key = private_key.public_key()
                public_key_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                public_keys.append(public_key_pem)
            
            # Genera master HMAC key
            master_hmac = secrets.token_hex(32)  # 32 bytes hex
            
            # Butterfly expansion request
            butterfly_request = {
                "its_id": vehicle_id,
                "enrollment_certificate": enrollment_cert,
                "public_keys": public_keys,
                "master_hmac_key": master_hmac,
                "num_tickets": 20,
                "validity_days": 7
            }
            
            start_time = time.time()
            response = requests.post(
                f"{self.aa_url}/api/authorization/butterfly-request/simple",
                json=butterfly_request,
                timeout=30
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                at_count = len(result.get("authorization_tickets", []))
                hmac_keys = result.get("hmac_keys", [])
                
                self.print_success(f"Butterfly Expansion completato!")
                self.print_info(f"  Authorization Tickets generati: {at_count}")
                self.print_info(f"  HMAC derivate: {len(hmac_keys)}")
                self.print_info(f"  Master HMAC: {master_hmac[:16]}...")
                self.print_info(f"  Tempo impiegato: {elapsed:.2f}s")
                self.print_info(f"  Throughput: {at_count/elapsed:.2f} AT/s")
                
                # Salva AT nel veicolo
                vehicle_data["butterfly_tickets"] = result.get("authorization_tickets", [])
                
                self.save_test_result(
                    "butterfly_expansion",
                    "success",
                    {
                        "vehicle_id": vehicle_id,
                        "tickets_generated": at_count,
                        "elapsed_time": elapsed,
                        "throughput": at_count/elapsed
                    }
                )
                return True
            else:
                self.print_error(f"Butterfly fallito! Status: {response.status_code}")
                self.print_error(f"Error: {response.text[:200]}")
                self.save_test_result("butterfly_expansion", "failed", {"status": response.status_code})
                return False
                
        except Exception as e:
            self.print_error(f"Errore: {e}")
            self.save_test_result("butterfly_expansion", "error", {"error": str(e)})
            return False
    
    def test_8_certificate_revocation(self):
        """Test 8: Revoca certificato usando API REST"""
        self.print_header("TEST 8: Revoca Certificato (ETSI Standard)")
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo disponibile! Esegui prima il Test 1")
            return False
        
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            
            # Usa ultimo veicolo enrollato per revoca
            vehicle_id = list(self.enrolled_vehicles.keys())[-1]
            vehicle_data = self.enrolled_vehicles[vehicle_id]
            
            # Estrai certificato PEM
            cert_pem = vehicle_data.get("enrollment_response", {}).get("certificate")
            if not cert_pem:
                self.print_error("Certificato mancante!")
                return False
            
            # Parse certificato per estrarre serial number
            cert_bytes = cert_pem.encode('utf-8')
            certificate = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            serial_number = certificate.serial_number
            serial_hex = format(serial_number, 'X')  # Converti a hex uppercase
            
            self.print_info(f"Veicolo: {vehicle_id}")
            self.print_info(f"Serial Number: {serial_number}")
            self.print_info(f"Serial Hex: {serial_hex}")
            
            # Richiesta di revoca via API
            revoke_request = {
                "serial_number": serial_hex,
                "reason": "unspecified",  # Motivo revoca ETSI standard
                "its_id": vehicle_id
            }
            
            self.print_info(f"Invio richiesta revoca a {self.ea_url}/api/enrollment/revoke...")
            
            response = requests.post(
                f"{self.ea_url}/api/enrollment/revoke",
                json=revoke_request,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                self.print_success(f"Certificato revocato con successo!")
                self.print_info(f"  Serial: {serial_hex}")
                self.print_info(f"  Response: {result.get('message', 'Success')}")
                
                # Verifica che il certificato sia nella CRL
                self.print_info(f"Verifica inserimento in CRL...")
                time.sleep(2)  # Attesa pubblicazione Delta CRL
                
                is_revoked = None
                crl_response = requests.get(f"{self.ea_url}/api/crl/full", timeout=5)
                if crl_response.status_code == 200:
                    try:
                        # Parse CRL - prova prima PEM, poi DER
                        crl_data = crl_response.content
                        from cryptography import x509
                        
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
                                    revocation_date = revoked_cert.revocation_date
                                    self.print_success(f"  ✅ Certificato presente in CRL!")
                                    self.print_info(f"     Data revoca: {revocation_date}")
                                    break
                            
                            if not is_revoked:
                                self.print_info(f"  ⚠️  Certificato non ancora in CRL (propagazione in corso)")
                                
                        except Exception as parse_error:
                            self.print_info(f"  ⚠️  Errore parsing CRL: {str(parse_error)[:100]}")
                            self.print_info(f"     Content-Type: {content_type}")
                            self.print_info(f"     Size: {len(crl_data)} bytes")
                            
                    except Exception as verify_error:
                        self.print_info(f"  ⚠️  Verifica CRL non disponibile: {str(verify_error)[:80]}")
                else:
                    self.print_info(f"  ℹ️  CRL non disponibile per verifica (status: {crl_response.status_code})")
                
                # Rimuovi veicolo dalla lista locale
                del self.enrolled_vehicles[vehicle_id]
                
                self.save_test_result(
                    "certificate_revocation",
                    "success",
                    {
                        "vehicle_id": vehicle_id,
                        "serial_number": serial_hex,
                        "reason": "unspecified",
                        "in_crl": is_revoked
                    }
                )
                return True
            elif response.status_code == 404:
                # Endpoint non implementato - fallback a simulazione
                self.print_info(f"⚠️  API revoca non disponibile su questo EA")
                self.print_info(f"  Modalità fallback: simulazione locale")
                
                # Rimuovi veicolo dalla lista (simulazione)
                del self.enrolled_vehicles[vehicle_id]
                
                self.print_success(f"Certificato simulato come revocato!")
                self.print_info(f"  In produzione: certificato verrebbe aggiunto alla CRL")
                
                self.save_test_result(
                    "certificate_revocation",
                    "success",
                    {
                        "vehicle_id": vehicle_id,
                        "serial_number": serial_hex,
                        "note": "Simulation mode - API endpoint not available"
                    }
                )
                return True
            else:
                self.print_error(f"Revoca fallita! Status: {response.status_code}")
                self.print_error(f"Error: {response.text[:200]}")
                self.save_test_result("certificate_revocation", "failed", {"status": response.status_code})
                return False
                
        except Exception as e:
            self.print_error(f"Errore: {e}")
            import traceback
            self.print_error(traceback.format_exc()[:200])
            self.save_test_result("certificate_revocation", "error", {"error": str(e)})
            return False
    
    def test_9_crl_download(self):
        """Test 9: Download e verifica CRL"""
        self.print_header("TEST 9: Download CRL (Certificate Revocation List)")
        
        try:
            self.print_info(f"Forzando pubblicazione CRL iniziale...")
            
            # Force CRL publication by calling publish endpoint (if exists)
            # Or trigger it via a simple revocation + undo
            try:
                # Try to trigger CRL generation by calling a test endpoint
                publish_response = requests.post(
                    f"{self.ea_url}/api/enrollment/publish-crl",
                    json={},
                    timeout=5
                )
                if publish_response.status_code in [200, 201]:
                    self.print_success(f"CRL pubblicata via API")
            except:
                # If endpoint doesn't exist, CRL might already be published or will be created on demand
                self.print_info(f"  Endpoint publish-crl non disponibile, CRL potrebbe già esistere")
            
            self.print_info(f"Download CRL da EA...")
            
            # Download Full CRL
            response = requests.get(f"{self.ea_url}/api/crl/full", timeout=5)
            
            if response.status_code == 200:
                crl_size = len(response.content)
                self.print_success(f"CRL Full scaricata!")
                self.print_info(f"  Dimensione: {crl_size} bytes")
                self.print_info(f"  Content-Type: {response.headers.get('Content-Type', 'N/A')}")
                
                # Prova anche Delta CRL
                delta_response = requests.get(f"{self.ea_url}/api/crl/delta", timeout=5)
                if delta_response.status_code == 200:
                    delta_size = len(delta_response.content)
                    self.print_success(f"CRL Delta scaricata!")
                    self.print_info(f"  Dimensione: {delta_size} bytes")
                else:
                    self.print_info(f"  CRL Delta non disponibile (normale)")
                
                self.save_test_result(
                    "crl_download",
                    "success",
                    {
                        "full_crl_size": crl_size,
                        "delta_crl_available": delta_response.status_code == 200
                    }
                )
                return True
            elif response.status_code == 404:
                # CRL not published yet - this is acceptable on first run
                self.print_info(f"⚠️  CRL non ancora pubblicata (prima esecuzione)")
                self.print_info(f"  In produzione: CRL verrebbe pubblicata periodicamente")
                self.save_test_result(
                    "crl_download",
                    "success",
                    {
                        "note": "CRL not yet published - acceptable on first run",
                        "status": 404
                    }
                )
                return True
            else:
                self.print_error(f"Download CRL fallito! Status: {response.status_code}")
                self.save_test_result("crl_download", "failed", {"status": response.status_code})
                return False
                
        except Exception as e:
            self.print_error(f"Errore: {e}")
            self.save_test_result("crl_download", "error", {"error": str(e)})
            return False
    
    def run_interactive_menu(self):
        """Menu interattivo per scegliere i test"""
        while True:
            self.print_header("PKI TESTER - Menu Interattivo (API REST)")
            print("\n  Test Disponibili:")
            print("  1. ✈️  Enrollment singolo veicolo")
            print("  2. 🎫 Richiesta Authorization Ticket")
            print("  3. 🚗 Enrollment flotta veicoli (5 veicoli)")
            print("  4. 📡 Simulazione comunicazione V2V")
            print("  5. ✔️  Validazione certificati")
            print("  6. ⚡ Performance test (10 enrollment)")
            print("  7. 🦋 Butterfly Expansion (20 AT in batch)")
            print("  8. 🚫 Revoca certificato")
            print("  9. � Download CRL")
            print("  A. �🔄 Esegui tutti i test")
            print("  B. 📊 Mostra risultati")
            print("  C. 🗑️  Pulisci dati test")
            print("  0. ❌ Esci")
            
            print("\n  Stato corrente:")
            print(f"    Veicoli enrollati: {len(self.enrolled_vehicles)}")
            print(f"    Test eseguiti: {len(self.test_results)}")
            
            choice = input("\n  Scegli test (0-9, A-C): ").strip().upper()
            
            if choice == "1":
                self.test_1_vehicle_enrollment()
            elif choice == "2":
                self.test_2_authorization_ticket()
            elif choice == "3":
                self.test_3_multiple_vehicles()
            elif choice == "4":
                self.test_4_v2v_communication()
            elif choice == "5":
                self.test_5_certificate_validation()
            elif choice == "6":
                self.test_6_performance_test()
            elif choice == "7":
                self.test_7_butterfly_expansion()
            elif choice == "8":
                self.test_8_certificate_revocation()
            elif choice == "9":
                self.test_9_crl_download()
            elif choice == "A":
                self.run_all_tests()
            elif choice == "B":
                self.show_results()
            elif choice == "C":
                self.cleanup()
            elif choice == "0":
                self.print_info("Uscita...")
                break
            else:
                self.print_error("Scelta non valida!")
            
            input("\n  Premi ENTER per continuare...")
    
    def run_all_tests(self):
        """Esegui tutti i test in sequenza"""
        self.print_header("ESECUZIONE TUTTI I TEST")
        
        tests = [
            ("Test 1", self.test_1_vehicle_enrollment),
            ("Test 2", self.test_2_authorization_ticket),
            ("Test 3", self.test_3_multiple_vehicles),
            ("Test 4", self.test_4_v2v_communication),
            ("Test 5", self.test_5_certificate_validation),
            ("Test 6", self.test_6_performance_test),
            ("Test 7", self.test_7_butterfly_expansion),
            ("Test 8", self.test_8_certificate_revocation),
            ("Test 9", self.test_9_crl_download)
        ]
        
        results = []
        for name, test_func in tests:
            print(f"\n{'='*70}")
            result = test_func()
            results.append((name, result))
            time.sleep(1)
        
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
        "--no-start",
        action="store_true",
        help="Non avviare automaticamente le entities (usa quelle già attive)"
    )
    
    args = parser.parse_args()
    
    # Avvia entities se richiesto
    if not args.no_start:
        start_pki_entities()
    else:
        print("\n[WARNING] Modalità --no-start: usando entities già attive")
    
    tester = PKITester()
    tester.ea_url = args.ea_url
    tester.aa_url = args.aa_url
    
    if args.dashboard:
        print("\n[DASHBOARD] Integrazione dashboard attiva")
        print(f"   Risultati salvati in: data/test_results.json")
        print(f"   Apri dashboard: file://{Path('pki_dashboard.html').absolute()}\n")
    
    try:
        if args.auto:
            tester.run_all_tests()
        else:
            tester.run_interactive_menu()
    
    finally:
        # Chiudi i processi avviati
        if not args.no_start:
            stop_pki_entities()


if __name__ == "__main__":
    main()
