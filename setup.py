"""
Script per generare configurazioni multiple di entità PKI.

Genera file di configurazione JSON per avviare facilmente multiple istanze di:
- Enrollment Authority (EA)
- Authorization Authority (AA)
- Trust List Manager (TLM)

Usage:
    python setup.py --ea 3 --aa 2 --tlm 2
    python setup.py --config dashboard_request.json
"""

import argparse
import json
import os
import sys
import subprocess
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from managers.trust_list_manager import TrustListManager


def find_existing_entities(entity_type, base_dir="./data"):
    """Trova entità esistenti di un tipo"""
    entity_type_lower = entity_type.lower()
    entity_dir = os.path.join(base_dir, entity_type_lower)
    
    if not os.path.exists(entity_dir):
        return []
    
    existing = []
    for item in os.listdir(entity_dir):
        item_path = os.path.join(entity_dir, item)
        if os.path.isdir(item_path) and item.startswith(entity_type):
            existing.append(item)
    
    return existing


def ensure_root_ca_exists(base_dir="./data/root_ca"):
    """
    Verifica che esista una RootCA. Se non esiste, la crea.
    
    Returns:
        tuple: (root_ca_instance, was_created)
    """
    root_ca_path = Path(base_dir)
    root_ca_cert_path = root_ca_path / "root_ca_certificate.pem"
    
    if root_ca_cert_path.exists():
        print(f"✅ RootCA esistente trovata in: {base_dir}")
        try:
            root_ca = RootCA(base_dir=str(root_ca_path))
            return root_ca, False
        except Exception as e:
            print(f"⚠️  Errore caricamento RootCA esistente: {e}")
            print(f"   Creazione nuova RootCA...")
    
    # Crea nuova RootCA
    print(f"\n🆕 Creazione nuova Root CA...")
    print(f"   Directory: {base_dir}")
    
    try:
        root_ca = RootCA(base_dir=str(root_ca_path))
        print(f"✅ Root CA creata con successo!")
        print(f"   Certificato: {root_ca.ca_certificate_path}")
        return root_ca, True
    except Exception as e:
        print(f"❌ Errore nella creazione della RootCA: {e}")
        raise


def generate_entity_configs(num_ea=0, num_aa=0, num_tlm=0, ea_names=None, aa_names=None, ensure_root_ca=True):
    """
    Genera configurazioni per multiple entità.
    
    Args:
        num_ea: Numero di EA da generare
        num_aa: Numero di AA da generare
        num_tlm: Numero di TLM da generare (sempre 0 o 1)
        ea_names: Lista di nomi custom per le EA (opzionale)
        aa_names: Lista di nomi custom per le AA (opzionale)
        ensure_root_ca: Se True, verifica/crea RootCA prima di generare le entità
        
    Returns:
        Dict con configurazioni generate
    """
    config = {
        "port_ranges": {
            "RootCA": {
                "start": 5999,
                "end": 5999,
                "description": "Root CA port (1 instance)"
            },
            "EA": {
                "start": 5000,
                "end": 5019,
                "description": "Enrollment Authority ports (20 instances)"
            },
            "AA": {
                "start": 5020,
                "end": 5039,
                "description": "Authorization Authority ports (20 instances)"
            },
            "TLM": {
                "start": 5050,
                "end": 5050,
                "description": "Trust List Manager port (1 instance)"
            },
            "RootCA": {
                "start": 5999,
                "end": 5999,
                "description": "Root CA port (1 instance)"
            }
        },
        "entities": [],
        "start_commands": []
    }
    
    print("\n" + "="*70)
    print("🏗️  GENERAZIONE CONFIGURAZIONI ENTITÀ PKI")
    print("="*70 + "\n")
    print("📌 Port Ranges:")
    print("   - RootCA: 5999 (1 istanza)")
    print("   - EA: 5000-5019 (fino a 20 istanze)")
    print("   - AA: 5020-5039 (fino a 20 istanze)")
    print("   - TLM: 5050 (1 istanza)\n")
    
    # STEP 1: Verifica/Crea RootCA se richiesto
    root_ca_created = False
    if ensure_root_ca:
        print("🔐 Verifica Root CA...")
        try:
            root_ca, root_ca_created = ensure_root_ca_exists()
            
            # Comando per avviare RootCA
            start_cmd = f"python server.py --entity RootCA --id ROOT_CA"
            config["start_commands"].append({
                "entity": "ROOT_CA",
                "command": start_cmd,
                "description": f"Start Root CA (auto port 5999, PKI trust anchor)"
            })
            
            if root_ca_created:
                print(f"  🆕 Nuova Root CA creata e aggiunta alla configurazione")
            else:
                print(f"  ✅ Root CA esistente aggiunta alla configurazione")
            print(f"  📜 Certificato: {root_ca.ca_certificate_path}\n")
        except Exception as e:
            print(f"  ❌ Errore con Root CA: {e}")
            print(f"  ⚠️  Continuo senza Root CA...\n")
    
    # Verifica limiti
    if num_ea > 20:
        print(f"⚠️  ATTENZIONE: Richieste {num_ea} EA, ma il massimo è 20. Limito a 20.")
        num_ea = 20
    if num_aa > 20:
        print(f"⚠️  ATTENZIONE: Richieste {num_aa} AA, ma il massimo è 20. Limito a 20.")
        num_aa = 20
    
    # Genera configurazioni EA
    if num_ea > 0:
        print(f"📝 Generazione configurazioni per {num_ea} Enrollment Authorities...")
        existing_eas = find_existing_entities("EA")
        
        for i in range(num_ea):
            # Usa nome custom se fornito, altrimenti auto-genera
            if ea_names and i < len(ea_names) and ea_names[i]:
                ea_id = ea_names[i]
                # Verifica che non esista già
                if ea_id in existing_eas:
                    print(f"  ⚠️  EA '{ea_id}' già esistente, verrà riutilizzato")
            else:
                # Trova prossimo numero disponibile
                ea_num = 1
                while True:
                    ea_id = f"EA_{ea_num:03d}"
                    if ea_id not in existing_eas:
                        break
                    ea_num += 1
            
            # Comando per avviare (senza --port, usa auto-selezione)
            start_cmd = f"python server.py --entity EA --id {ea_id}"
            config["start_commands"].append({
                "entity": ea_id,
                "command": start_cmd,
                "description": f"Start Enrollment Authority {ea_id} (auto port 5000-5019)"
            })
            
            existing_eas.append(ea_id)
            print(f"  ✅ {ea_id} configurato (porta auto-assegnata dal range 5000-5019)")
    
    # Genera configurazioni AA
    if num_aa > 0:
        print(f"\n🎫 Generazione configurazioni per {num_aa} Authorization Authorities...")
        existing_aas = find_existing_entities("AA")
        
        for i in range(num_aa):
            # Usa nome custom se fornito, altrimenti auto-genera
            if aa_names and i < len(aa_names) and aa_names[i]:
                aa_id = aa_names[i]
                # Verifica che non esista già
                if aa_id in existing_aas:
                    print(f"  ⚠️  AA '{aa_id}' già esistente, verrà riutilizzato")
            else:
                # Trova prossimo numero disponibile
                aa_num = 1
                while True:
                    aa_id = f"AA_{aa_num:03d}"
                    if aa_id not in existing_aas:
                        break
                    aa_num += 1
            
            # Comando per avviare (senza --port, usa auto-selezione)
            start_cmd = f"python server.py --entity AA --id {aa_id}"
            config["start_commands"].append({
                "entity": aa_id,
                "command": start_cmd,
                "description": f"Start Authorization Authority {aa_id} (auto port 5020-5039, creates EA_FOR_{aa_id})"
            })
            
            existing_aas.append(aa_id)
            print(f"  ✅ {aa_id} configurato (porta auto-assegnata dal range 5020-5039)")
    
    # Genera configurazione TLM (sempre singolo, centralizzato)
    if num_tlm > 0:
        print(f"\n📋 Configurazione Trust List Manager (TLM unico)...")
        
        # TLM è sempre singolo e centralizzato
        tlm_id = "TLM_MAIN"
        
        # Verifica se esiste già
        existing_tlms = find_existing_entities("TLM")
        if tlm_id in existing_tlms:
            print(f"  ⚠️  TLM '{tlm_id}' già esistente, verrà riutilizzato")
        else:
            print(f"  🆕 Creazione nuovo TLM '{tlm_id}'")
        
        # Comando per avviare (senza --port, usa auto-selezione)
        start_cmd = f"python server.py --entity TLM --id {tlm_id}"
        config["start_commands"].append({
            "entity": tlm_id,
            "command": start_cmd,
            "description": f"Start Trust List Manager (auto port 5050, central trust anchor repository)"
        })
        
        print(f"  ✅ {tlm_id} configurato (porta 5050)")
        print(f"  ℹ️  NOTA: TLM è unico e centralizzato per tutta la PKI")
    
    print("\n" + "="*70)
    print(f"✅ Generazione completata! Totale comandi: {len(config['start_commands'])}")
    print("="*70 + "\n")
    
    return config


def save_config(config, output_file="entity_configs.json"):
    """Salva configurazione su file JSON"""
    with open(output_file, 'w') as f:
        json.dump(config, f, indent=2)
    print(f"💾 Configurazione salvata in: {output_file}\n")


def print_start_commands(config):
    """Stampa i comandi per avviare le entità"""
    print("\n" + "="*70)
    print("🚀 COMANDI PER AVVIARE LE ENTITÀ")
    print("="*70 + "\n")
    
    for i, cmd_info in enumerate(config["start_commands"], 1):
        print(f"{i}. {cmd_info['description']}")
        print(f"   {cmd_info['command']}\n")
    
    print("💡 Suggerimento: Apri un terminale separato per ogni entità\n")


def generate_batch_script(config, output_file="start_all_entities.bat"):
    """Genera script batch per Windows per avviare tutte le entità"""
    with open(output_file, 'w') as f:
        f.write("@echo off\n")
        f.write("REM Script generato automaticamente per avviare tutte le entità PKI\n")
        f.write("REM Ogni entità viene avviata in una nuova finestra\n\n")
        
        for cmd_info in config["start_commands"]:
            entity_id = cmd_info["entity"]
            command = cmd_info["command"]
            f.write(f'start "PKI - {entity_id}" cmd /k "{command}"\n')
        
        f.write("\necho Tutte le entità sono state avviate in finestre separate!\n")
        f.write("pause\n")
    
    print(f"📜 Script batch Windows salvato in: {output_file}")


def generate_powershell_script(config, output_file="start_all_entities.ps1"):
    """Genera script PowerShell per avviare tutte le entità"""
    with open(output_file, 'w') as f:
        f.write("# Script generato automaticamente per avviare tutte le entità PKI\n")
        f.write("# Ogni entità viene avviata in una nuova finestra PowerShell\n\n")
        
        for cmd_info in config["start_commands"]:
            entity_id = cmd_info["entity"]
            command = cmd_info["command"]
            f.write(f'Start-Process powershell -ArgumentList "-NoExit", "-Command", "{command}"\n')
        
        f.write('\nWrite-Host "Tutte le entità sono state avviate in finestre separate!" -ForegroundColor Green\n')
    
    print(f"📜 Script PowerShell salvato in: {output_file}\n")


def start_entities_in_vscode_terminals(config):
    """
    Avvia automaticamente ogni entità come processi background SENZA finestre.
    Usa pythonw.exe (Python headless) per evitare completamente le finestre.
    """
    print("\n" + "="*70)
    print("🚀 AVVIO AUTOMATICO ENTITÀ IN BACKGROUND (NO WINDOWS)")
    print("="*70 + "\n")
    
    import time
    import sys
    started_count = 0
    failed_count = 0
    processes = []
    
    # Crea directory per i log
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Determina l'eseguibile Python senza finestra
    # pythonw.exe è la versione di Python senza console window
    python_exe = sys.executable
    if python_exe.endswith('python.exe'):
        pythonw_exe = python_exe.replace('python.exe', 'pythonw.exe')
        if not os.path.exists(pythonw_exe):
            print(f"  ⚠️  pythonw.exe not found, using python.exe with hidden window flag")
            pythonw_exe = python_exe
    else:
        pythonw_exe = python_exe
    
    print(f"  📌 Using: {pythonw_exe}")
    print()
    
    for idx, cmd_info in enumerate(config["start_commands"]):
        entity_id = cmd_info["entity"]
        command = cmd_info["command"]
        
        try:
            print(f"  ⏳ Starting {entity_id}...")
            
            # Crea file di log per questa entità
            log_file = log_dir / f"{entity_id}.log"
            
            # Estrai il comando Python dal command string
            # Formato: "python server.py --entity EA --id EA_001"
            if command.startswith("python "):
                cmd_parts = command.split(" ", 1)  # ["python", "server.py --entity EA --id EA_001"]
                python_args = cmd_parts[1] if len(cmd_parts) > 1 else ""
            else:
                python_args = command
            
            # Apri file di log
            log_f = open(log_file, 'a', encoding='utf-8')
            log_f.write(f"\n{'='*70}\n")
            log_f.write(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            log_f.write(f"Command: {command}\n")
            log_f.write(f"{'='*70}\n\n")
            log_f.flush()
            
            # Crea il processo usando pythonw.exe (senza finestra)
            # oppure usa CREATE_NO_WINDOW flag se pythonw non disponibile
            startup_info = None
            creation_flags = 0
            
            if os.name == 'nt':  # Windows
                startup_info = subprocess.STARTUPINFO()
                startup_info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startup_info.wShowWindow = subprocess.SW_HIDE
                creation_flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
            
            # Avvia il processo
            result = subprocess.Popen(
                [pythonw_exe] + python_args.split(),
                stdout=log_f,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                creationflags=creation_flags,
                startupinfo=startup_info,
                cwd=os.getcwd()
            )
            
            # Attendi un momento per verificare che il processo sia partito
            time.sleep(0.8)
            
            # Verifica se il processo è ancora in esecuzione
            if result.poll() is None:
                processes.append({
                    'entity': entity_id,
                    'pid': result.pid,
                    'process': result,
                    'log': str(log_file),
                    'log_handle': log_f
                })
                print(f"  ✅ {entity_id} started (PID: {result.pid}) → Log: {log_file}")
                started_count += 1
                
                # Delay tra entità per evitare conflitti di porta
                if idx < len(config["start_commands"]) - 1:
                    time.sleep(1.5)
            else:
                print(f"  ⚠️  {entity_id} process terminated immediately (check log: {log_file})")
                log_f.close()
                failed_count += 1
                
        except Exception as e:
            print(f"  ❌ Error starting {entity_id}: {e}")
            failed_count += 1
    
    print(f"\n{'='*70}")
    print(f"📊 Summary: {started_count} entities started, {failed_count} errors")
    print(f"{'='*70}\n")
    
    if started_count > 0:
        print("💡 Entities are running as HIDDEN background processes (NO WINDOWS!).")
        print(f"   📁 Logs are in: ./{log_dir}/")
        print("   📊 Check dashboard or use: Get-Process pythonw*\n")
        print("   🛑 To stop all: Get-Process pythonw* | Stop-Process -Force\n")
        
        # Salva i PID in un file per riferimento
        pids_file = "running_entities_pids.txt"
        with open(pids_file, 'w', encoding='utf-8') as f:
            f.write(f"# PKI Entities PIDs - Started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# All running as pythonw.exe (no windows)\n")
            f.write(f"# To stop: Get-Process pythonw* | Stop-Process -Force\n\n")
            for p in processes:
                f.write(f"{p['entity']}: PID {p['pid']} -> {p['log']}\n")
        print(f"   📋 PIDs saved to: {pids_file}")
    
    return started_count > 0


def main():
    parser = argparse.ArgumentParser(
        description="Genera configurazioni per multiple entità PKI e le avvia automaticamente",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Genera 3 EA, 2 AA + TLM con RootCA (default)
  python setup.py --ea 3 --aa 2 --tlm
  
  # Genera 5 EA con nomi custom e li avvia
  python setup.py --ea 5 --ea-names "EA_SEMAFORO_02,EA_SEMAFORO_04,EA_SEMAFORO_03"
  
  # Genera 2 AA con nomi custom (senza RootCA)
  python setup.py --aa 2 --aa-names "AA_HIGHWAY,AA_CITY" --no-root-ca
  
  # Genera solo configurazioni senza avviare
  python setup.py --ea 3 --aa 2 --tlm --no-auto-start
  
  # Carica da file JSON e avvia
  python setup.py --config dashboard_request.json

Note:
  - RootCA viene verificata/creata automaticamente (disabilita con --no-root-ca)
  - TLM viene incluso automaticamente (disabilita con --no-tlm)
  - Le entità vengono avviate automaticamente in terminali separati
  - Usa --no-auto-start per generare solo le configurazioni
        """
    )
    
    parser.add_argument("--ea", type=int, default=0, help="Numero di Enrollment Authorities da generare")
    parser.add_argument("--aa", type=int, default=0, help="Numero di Authorization Authorities da generare")
    parser.add_argument("--tlm", action="store_true", default=True, help="Includi Trust List Manager (default: True, sempre singolo e centralizzato)")
    parser.add_argument("--no-tlm", action="store_true", help="NON includere Trust List Manager")
    parser.add_argument("--root-ca", action="store_true", default=True, help="Verifica/crea Root CA (default: True)")
    parser.add_argument("--no-root-ca", action="store_true", help="NON verificare/creare Root CA")
    parser.add_argument("--ea-names", type=str, help="Nomi custom per le EA, separati da virgola (es: EA_HIGHWAY_01,EA_CITY_01)")
    parser.add_argument("--aa-names", type=str, help="Nomi custom per le AA, separati da virgola (es: AA_TRAFFIC,AA_PARKING)")
    parser.add_argument("--config", type=str, help="Carica configurazione da file JSON")
    parser.add_argument("--output", type=str, default="entity_configs.json", help="File di output (default: entity_configs.json)")
    parser.add_argument("--no-scripts", action="store_true", help="Non generare script di avvio automatici")
    parser.add_argument("--no-auto-start", action="store_true", help="NON avviare automaticamente le entità (default: avvio automatico)")
    
    args = parser.parse_args()
    
    # Parse custom names if provided
    ea_names = []
    aa_names = []
    
    if args.ea_names:
        ea_names = [name.strip() for name in args.ea_names.split(',') if name.strip()]
        print(f"\n📝 Nomi custom per EA: {ea_names}")
    
    if args.aa_names:
        aa_names = [name.strip() for name in args.aa_names.split(',') if name.strip()]
        print(f"📝 Nomi custom per AA: {aa_names}")
    
    # Carica da file se specificato
    if args.config:
        if not os.path.exists(args.config):
            print(f"❌ Errore: File {args.config} non trovato!")
            sys.exit(1)
        
        with open(args.config, 'r') as f:
            request_config = json.load(f)
        
        num_ea = request_config.get("num_ea", 0)
        num_aa = request_config.get("num_aa", 0)
        # TLM dal file: 0 o 1 (qualsiasi valore > 0 diventa 1)
        num_tlm = 1 if request_config.get("num_tlm", 0) > 0 else 0
    else:
        num_ea = args.ea
        num_aa = args.aa
        # TLM da argomenti: default True, disabilitato con --no-tlm
        num_tlm = 0 if args.no_tlm else 1
    
    # Determina se creare/verificare RootCA
    ensure_root_ca = not args.no_root_ca
    
    # Valida input (almeno un'entità o la RootCA)
    if num_ea == 0 and num_aa == 0 and num_tlm == 0 and not ensure_root_ca:
        print("❌ Errore: Specifica almeno un'entità da generare!")
        print("\nEsempi:")
        print("  python setup.py --ea 3 --aa 2 --tlm")
        print("  python setup.py --ea 5")
        print("  python setup.py --config entity_request.json")
        parser.print_help()
        sys.exit(1)
    
    # Genera configurazioni (con RootCA se richiesta)
    config = generate_entity_configs(num_ea, num_aa, num_tlm, ea_names, aa_names, ensure_root_ca)
    
    # Salva configurazione
    save_config(config, args.output)
    
    # Stampa comandi
    print_start_commands(config)
    
    # Genera script di avvio
    if not args.no_scripts:
        generate_batch_script(config)
        generate_powershell_script(config)
    
    # Avvia automaticamente (comportamento predefinito, disabilitabile con --no-auto-start)
    if not args.no_auto_start:
        start_entities_in_vscode_terminals(config)
    else:
        print("✅ Configurazione completata (avvio automatico disabilitato)!\n")
        print("  Puoi avviare le entità con:\n")
        print("  1. Comandi manuali (vedi sopra)")
        print("  2. Script batch:      start_all_entities.bat")
        print("  3. Script PowerShell: .\\start_all_entities.ps1")
        print("  4. Rilanciare senza --no-auto-start per avvio automatico\n")


if __name__ == "__main__":
    main()
