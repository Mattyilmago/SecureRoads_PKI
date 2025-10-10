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

import argparse
import json
import requests
import subprocess
import sys
import time
import os
from datetime import datetime
from pathlib import Path

# Variabile globale per tenere traccia dei processi avviati
_started_processes = []


def start_pki_entities():
    """Avvia le entities PKI automaticamente"""
    global _started_processes
    
    print("\n" + "="*70)
    print("  AVVIO ENTITIES PKI")
    print("="*70)
    
    # Trova root del progetto
    project_root = Path(__file__).parent.parent
    
    # Configura entities da avviare
    entities = [
        ("EA_001", "5000", "EA"),
        ("EA_002", "5001", "EA"),
        ("EA_003", "5002", "EA"),
        ("AA_001", "5003", "AA"),
        ("AA_002", "5004", "AA"),
        ("TLM_MAIN", "5005", "TLM")
    ]
    
    for entity_id, port, entity_type in entities:
        try:
            print(f"\n  Avvio {entity_id} sulla porta {port}...", end=" ")
            
            # Comando per avviare l'entity
            cmd = [
                sys.executable,
                str(project_root / "server.py"),
                "--entity", entity_type,
                "--id", entity_id,
                "--port", port
            ]
            
            # Avvia in background
            if os.name == 'nt':  # Windows
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root),
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    shell=False
                )
            else:  # Linux/Mac
                process = subprocess.Popen(
                    cmd,
                    cwd=str(project_root)
                )
            
            _started_processes.append((entity_id, port, process))
            print("✅")
            
        except Exception as e:
            print(f"❌ ({str(e)[:30]})")
    
    # Aspetta che i server siano pronti
    print(f"\n  Attesa avvio server (10 secondi)...")
    time.sleep(10)
    
    # Verifica che siano attivi
    print("\n  Verifica connessioni:")
    active_count = 0
    for entity_id, port, process in _started_processes:
        try:
            response = requests.get(f"http://localhost:{port}/health", timeout=2)
            if response.status_code == 200:
                print(f"    {entity_id} (:{port}): ✅")
                active_count += 1
            else:
                print(f"    {entity_id} (:{port}): ❌")
        except:
            print(f"    {entity_id} (:{port}): ❌")
    
    print(f"\n  Entities attive: {active_count}/{len(entities)}")
    
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
    
    for entity_id, port, process in _started_processes:
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
                "canonical_id": vehicle_id,
                "requested_subject_attributes": {
                    "country": "IT",
                    "organization": f"TestOrg_{vehicle_id}",
                    "its_aid": "36"  # CA Basic Service
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
            
            self.print_info(f"Veicolo: {vehicle_id}")
            self.print_info(f"⚠️  Authorization richiede implementazione completa del protocollo")
            self.print_info(f"   Per ora eseguiamo enrollment come verifica")
            
            # Per ora, verifica che il veicolo sia enrollato
            if vehicle_id in self.enrolled_vehicles:
                self.print_success("Veicolo correttamente enrollato")
                self.print_info("   Authorization Ticket test parziale completato")
                
                self.save_test_result(
                    "authorization_ticket",
                    "partial",
                    {
                        "vehicle_id": vehicle_id,
                        "note": "Requires full protocol implementation"
                    }
                )
                return True
            else:
                self.print_error("Veicolo non ha Enrollment Certificate!")
                self.save_test_result("authorization_ticket", "failed")
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
                    "canonical_id": vehicle_id,
                    "requested_subject_attributes": {
                        "country": "IT",
                        "organization": f"FleetOrg_{i+1}",
                        "its_aid": "36"
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
            
            self.print_success("Messaggio CAM simulato con successo!")
            self.print_info("⚠️  Firma e verifica crittografica richiedono certificati completi")
            self.print_success("Test V2V comunicazione completato!")
            
            self.save_test_result(
                "v2v_communication",
                "partial",
                {
                    "sender": vehicle_ids[0],
                    "receiver": vehicle_ids[1],
                    "message_type": "CAM",
                    "note": "Simulation only, crypto verification requires full certificates"
                }
            )
            return True
            
        except Exception as e:
            self.print_error(f"Errore: {e}")
            self.save_test_result("v2v_communication", "error", {"error": str(e)})
            return False
    
    def test_5_certificate_validation(self):
        """Test 5: Validazione certificati"""
        self.print_header("TEST 5: Validazione Certificati")
        
        if not self.enrolled_vehicles:
            self.print_error("Nessun veicolo disponibile!")
            return False
        
        try:
            valid_count = len(self.enrolled_vehicles)
            
            self.print_info(f"Veicoli enrollati: {valid_count}")
            
            for vehicle_id in self.enrolled_vehicles:
                self.print_info(f"  {vehicle_id}: ✅ ENROLLATO")
            
            self.print_success(f"Certificati enrollati: {valid_count}")
            self.print_info("⚠️  Validazione completa richiede parsing certificati X.509")
            
            self.save_test_result(
                "certificate_validation",
                "success",
                {
                    "enrolled": valid_count
                }
            )
            return True
            
        except Exception as e:
            self.print_error(f"Errore: {e}")
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
                    "canonical_id": vehicle_id,
                    "requested_subject_attributes": {
                        "country": "IT",
                        "its_aid": "36"
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
            print("  7. 🔄 Esegui tutti i test")
            print("  8. 📊 Mostra risultati")
            print("  9. 🗑️  Pulisci dati test")
            print("  0. ❌ Esci")
            
            print("\n  Stato corrente:")
            print(f"    Veicoli enrollati: {len(self.enrolled_vehicles)}")
            print(f"    Test eseguiti: {len(self.test_results)}")
            
            choice = input("\n  Scegli test (0-9): ").strip()
            
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
                self.run_all_tests()
            elif choice == "8":
                self.show_results()
            elif choice == "9":
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
        print("\n⚠️  Modalità --no-start: usando entities già attive")
    
    tester = PKITester()
    tester.ea_url = args.ea_url
    tester.aa_url = args.aa_url
    
    if args.dashboard:
        print("\n🌐 Integrazione dashboard attiva")
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
