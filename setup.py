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
import re
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Singleton instance cache
_root_ca_instance = None

def get_or_create_root_ca(base_dir="./data/root_ca"):
    """Get or create RootCA singleton instance."""
    global _root_ca_instance
    if _root_ca_instance is None:
        from entities.root_ca import RootCA
        _root_ca_instance = RootCA(base_dir=base_dir)
    return _root_ca_instance
from entities.authorization_authority import AuthorizationAuthority
from managers.trust_list_manager import TrustListManager


def find_existing_entities(entity_type, base_dir="./data"):
    """
    Trova entità esistenti di un tipo, controllando sia le directory che entity_configs.json.
    Questo previene il riutilizzo di nomi di entità che sono state cancellate ma potrebbero
    avere ancora configurazioni o dati residui.
    """
    existing = []
    
    # 1. Controlla le directory esistenti in data/
    entity_type_lower = entity_type.lower()
    entity_dir = os.path.join(base_dir, entity_type_lower)
    
    if os.path.exists(entity_dir):
        for item in os.listdir(entity_dir):
            item_path = os.path.join(entity_dir, item)
            if os.path.isdir(item_path) and item.startswith(entity_type):
                existing.append(item)
    
    # 2. Controlla entity_configs.json per entità già configurate
    config_file = Path("entity_configs.json")
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Estrai nomi entità dai start_commands
            for cmd_entry in config.get('start_commands', []):
                entity_name = cmd_entry.get('entity', '')
                if entity_name.startswith(f"{entity_type}_") and entity_name not in existing:
                    existing.append(entity_name)
        except Exception as e:
            # Se non riusciamo a leggere il config, continua con le directory
            pass
    
    return existing


def find_used_ports():
    """
    Controllo semplice delle porte con netstat.
    
    Returns:
        set: Insieme delle porte già in uso
    """
    used_ports = set()
    
    try:
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            for line in lines:
                if 'LISTENING' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr_part = parts[1]
                        if ':' in addr_part:
                            port_str = addr_part.split(':')[-1]
                            try:
                                port = int(port_str)
                                if 5000 <= port <= 5999:  # Solo porte PKI
                                    used_ports.add(port)
                            except ValueError:
                                pass
    except Exception as e:
        print(f"⚠️  Errore controllo porte: {e}")
    
    # Aggiungi anche le porte configurate in entity_configs.json
    config_file = Path("entity_configs.json")
    if config_file.exists():
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            
            # Estrai porte dai comandi di avvio
            for cmd_entry in config.get('start_commands', []):
                command = cmd_entry.get('command', '')
                # Cerca pattern --port PORTA
                port_match = re.search(r'--port\s+(\d+)', command)
                if port_match:
                    try:
                        port = int(port_match.group(1))
                        used_ports.add(port)
                    except ValueError:
                        pass
        except Exception as e:
            print(f"⚠️  Errore leggendo configurazione porte: {e}")
    
    return used_ports


def check_entity_active(port, entity_type, timeout=3):
    """
    Controlla se un'entità è già attiva sulla porta specificata controllando se la porta è in uso.
    
    Args:
        port: Porta da controllare
        entity_type: Tipo di entità ('RootCA', 'TLM', 'EA', 'AA')
        timeout: Timeout in secondi (non usato per socket)
        
    Returns:
        bool: True se la porta è in uso (entità probabilmente attiva), False se libera
    """
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        return result == 0  # 0 means connection successful, port is in use
    except Exception:
        return False


def generate_entity_name_with_suffix(desired_name, existing_entities):
    """
    Genera un nome entità con suffisso numerico se il nome base già esiste.
    Supporta sia il nuovo formato con underscore che il vecchio con parentesi.
    
    Esempi:
    - Se "EA_001" non esiste, restituisce "EA_001"
    - Se "EA_001" esiste, cerca "EA_001_2", "EA_001_3", etc.
    - Se esistono "EA_001" e "EA_001_2", restituisce "EA_001_3"
    - Riconosce anche vecchi formati come "EA_001 (2)" per backward compatibility
    
    Args:
        desired_name: Nome desiderato per l'entità
        existing_entities: Lista delle entità esistenti
        
    Returns:
        String: Nome con suffisso se necessario (sempre nuovo formato)
    """
    if desired_name not in existing_entities:
        return desired_name
    
    # Trova tutti i nomi che iniziano con desired_name (supporta sia vecchio che nuovo formato)
    base_pattern = re.escape(desired_name)
    # Pattern per nuovo formato: EA_001_2, EA_001_3, etc.
    new_suffix_pattern = re.compile(rf'^{base_pattern}_(\d+)$')
    # Pattern per vecchio formato: EA_001 (2), EA_001 (3), etc.
    old_suffix_pattern = re.compile(rf'^{base_pattern}\s*\((\d+)\)$')
    
    max_suffix = 1
    for entity in existing_entities:
        # Controlla nuovo formato
        match = new_suffix_pattern.match(entity)
        if match:
            suffix_num = int(match.group(1))
            max_suffix = max(max_suffix, suffix_num)
        else:
            # Controlla vecchio formato per backward compatibility
            match = old_suffix_pattern.match(entity)
            if match:
                suffix_num = int(match.group(1))
                max_suffix = max(max_suffix, suffix_num)
    
    # Il prossimo suffisso è max_suffix + 1
    return f"{desired_name}_{max_suffix + 1}"


def cleanup_obsolete_entities(requested_entities, entity_type):
    """
    Rimuove dalla configurazione entity_configs.json le entità che non sono più richieste.
    
    Args:
        requested_entities: Lista delle entità che dovrebbero rimanere
        entity_type: Tipo di entità ('EA', 'AA', 'TLM')
    """
    config_file = Path("entity_configs.json")
    if not config_file.exists():
        return
    
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        
        original_commands = config.get('start_commands', [])
        updated_commands = []
        
        for cmd in original_commands:
            entity_name = cmd.get('entity', '')
            # Mantieni RootCA e TLM sempre
            if entity_name in ['ROOT_CA', 'TLM_MAIN']:
                updated_commands.append(cmd)
            # Mantieni entità del tipo richiesto che sono nella lista
            elif entity_name.startswith(f"{entity_type}_") and entity_name in requested_entities:
                updated_commands.append(cmd)
            # Rimuovi entità obsolete
            elif entity_name.startswith(f"{entity_type}_"):
                print(f"🗑️  Rimozione entità obsoleta dalla configurazione: {entity_name}")
            else:
                updated_commands.append(cmd)
        
        config['start_commands'] = updated_commands
        
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
            
    except Exception as e:
        print(f"⚠️  Errore durante la pulizia delle entità obsolete: {e}")


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
            root_ca = get_or_create_root_ca(base_dir=str(root_ca_path))
            return root_ca, False
        except Exception as e:
            print(f"⚠️  Errore caricamento RootCA esistente: {e}")
            print(f"   Creazione nuova RootCA...")
    
    # Crea nuova RootCA
    print(f"\n🆕 Creazione nuova Root CA...")
    print(f"   Directory: {base_dir}")
    
    try:
        root_ca = get_or_create_root_ca(base_dir=str(root_ca_path))
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
            start_cmd = f"python server.py --entity RootCA --id ROOT_CA --port 5999"
            config["start_commands"].append({
                "entity": "ROOT_CA",
                "command": start_cmd,
                "description": f"Start Root CA (port 5999, PKI trust anchor)"
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
    
    # STEP 2: Prepara lista delle entità che saranno create
    entities_to_keep = []
    
    # Aggiungi RootCA e TLM sempre
    entities_to_keep.extend(["ROOT_CA", "TLM_MAIN"])
    
    # Ottieni lista delle entità esistenti
    existing_eas = find_existing_entities("EA")
    existing_aas = find_existing_entities("AA")
    
    print(f"📊 Entità esistenti rilevate: {len(existing_eas)} EA, {len(existing_aas)} AA")
    if existing_eas:
        print(f"   EA esistenti: {', '.join(existing_eas)}")
    if existing_aas:
        print(f"   AA esistenti: {', '.join(existing_aas)}")
    print()
    
    # Determina quali EA saranno create
    created_eas = []
    for i in range(num_ea):
        if ea_names and i < len(ea_names) and ea_names[i]:
            desired_ea_name = ea_names[i]
            ea_id = generate_entity_name_with_suffix(desired_ea_name, existing_eas)
            if ea_id != desired_ea_name:
                print(f"🆕 EA '{desired_ea_name}' già esistente, verrà creata come '{ea_id}'")
            else:
                print(f"🆕 EA '{ea_id}' sarà creata")
            entities_to_keep.append(ea_id)
            created_eas.append(ea_id)
        else:
            # Trova prossimo numero disponibile (saltando quelli esistenti)
            ea_num = 1
            while True:
                ea_id = f"EA_{ea_num:03d}"
                if ea_id not in entities_to_keep and ea_id not in existing_eas:
                    entities_to_keep.append(ea_id)
                    created_eas.append(ea_id)
                    break
                ea_num += 1
    
    # Determina quali AA saranno create
    created_aas = []
    for i in range(num_aa):
        if aa_names and i < len(aa_names) and aa_names[i]:
            desired_aa_name = aa_names[i]
            aa_id = generate_entity_name_with_suffix(desired_aa_name, existing_aas)
            if aa_id != desired_aa_name:
                print(f"🆕 AA '{desired_aa_name}' già esistente, verrà creata come '{aa_id}'")
            else:
                print(f"🆕 AA '{aa_id}' sarà creata")
            entities_to_keep.append(aa_id)
            created_aas.append(aa_id)
        else:
            # Trova prossimo numero disponibile (saltando quelli esistenti)
            aa_num = 1
            while True:
                aa_id = f"AA_{aa_num:03d}"
                if aa_id not in entities_to_keep and aa_id not in existing_aas:
                    entities_to_keep.append(aa_id)
                    created_aas.append(aa_id)
                    break
                aa_num += 1
    
    # Pulisci entità obsolete dalla configurazione
    print("🧹 Pulizia entità obsolete...")
    cleanup_obsolete_entities(entities_to_keep, "EA")
    cleanup_obsolete_entities(entities_to_keep, "AA")
    print("✅ Pulizia completata\n")
    
    # Controlla porte già in uso
    print("🔍 Controllo porte già in uso...")
    used_ports = find_used_ports()
    if used_ports:
        print(f"   Porte già in uso: {sorted(used_ports)}")
    else:
        print("   Nessuna porta in uso rilevata")
    print()
    
    # Genera configurazioni EA
    if num_ea > 0:
        print(f"📝 Generazione configurazioni per {num_ea} Enrollment Authorities...")
        print(f"   Verranno create/riutilizzate: {', '.join(created_eas)}")
        
        for ea_id in created_eas:
            # Trova prossima porta disponibile per EA (5000-5019)
            ea_port = 5000
            while ea_port in used_ports and ea_port <= 5019:
                ea_port += 1
            
            if ea_port > 5019:
                print(f"  ❌ ERRORE: Non ci sono porte disponibili per {ea_id} (range EA esaurito)")
                continue
                
            used_ports.add(ea_port)  # Marca come usata
            start_cmd = f"python server.py --entity EA --id {ea_id} --port {ea_port}"
            config["start_commands"].append({
                "entity": ea_id,
                "command": start_cmd,
                "description": f"Start Enrollment Authority {ea_id} (port {ea_port})"
            })
            
            if ea_id in existing_eas:
                print(f"  🔄 {ea_id} esistente riutilizzato (porta {ea_port})")
            else:
                print(f"  ✅ {ea_id} configurato (porta {ea_port})")
    
    # Genera configurazioni AA
    if num_aa > 0:
        print(f"\n🎫 Generazione configurazioni per {num_aa} Authorization Authorities...")
        print(f"   Verranno create/riutilizzate: {', '.join(created_aas)}")
        
        for aa_id in created_aas:
            # Trova prossima porta disponibile per AA (5020-5039)
            aa_port = 5020
            while aa_port in used_ports and aa_port <= 5039:
                aa_port += 1
            
            if aa_port > 5039:
                print(f"  ❌ ERRORE: Non ci sono porte disponibili per {aa_id} (range AA esaurito)")
                continue
                
            used_ports.add(aa_port)  # Marca come usata
            start_cmd = f"python server.py --entity AA --id {aa_id} --port {aa_port}"
            config["start_commands"].append({
                "entity": aa_id,
                "command": start_cmd,
                "description": f"Start Authorization Authority {aa_id} (port {aa_port}, creates EA_FOR_{aa_id})"
            })
            
            if aa_id in existing_aas:
                print(f"  🔄 {aa_id} esistente riutilizzato (porta {aa_port})")
            else:
                print(f"  ✅ {aa_id} configurato (porta {aa_port})")
    
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
        
        # Comando per avviare (con porta esplicita)
        start_cmd = f"python server.py --entity TLM --id {tlm_id} --port 5050"
        config["start_commands"].append({
            "entity": tlm_id,
            "command": start_cmd,
            "description": f"Start Trust List Manager (port 5050, central trust anchor repository)"
        })
        
        print(f"  ✅ {tlm_id} configurato (porta 5050)")
        print(f"  ℹ️  NOTA: TLM è unico e centralizzato per tutta la PKI")
    
    print("\n" + "="*70)
    print(f"✅ Generazione completata! Totale comandi: {len(config['start_commands'])}")
    print("="*70 + "\n")
    
    return config


def save_config(config, output_file="entity_configs.json"):
    """
    Salva/Aggiorna configurazione su file JSON.
    Se il file esiste, AGGIORNA la lista start_commands invece di sovrascriverla.
    """
    existing_config = None
    
    # Leggi configurazione esistente se presente
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                existing_config = json.load(f)
            print(f"📄 File {output_file} esistente trovato, verrà aggiornato...")
        except Exception as e:
            print(f"⚠️  Errore leggendo {output_file}: {e}")
            print(f"   Creerò un nuovo file...")
            existing_config = None
    
    if existing_config:
        # MODALITÀ AGGIORNAMENTO: Merge dei start_commands
        # Mantieni port_ranges esistenti
        config["port_ranges"] = existing_config.get("port_ranges", config["port_ranges"])
        
        # Crea set di entity_id esistenti per evitare duplicati
        existing_entities = {cmd.get("entity") for cmd in existing_config.get("start_commands", [])}
        new_entities = {cmd.get("entity") for cmd in config.get("start_commands", [])}
        
        # Merge: mantieni esistenti + aggiungi nuovi (no duplicati)
        merged_commands = existing_config.get("start_commands", [])
        
        for new_cmd in config["start_commands"]:
            new_entity_id = new_cmd.get("entity")
            if new_entity_id not in existing_entities:
                merged_commands.append(new_cmd)
                print(f"  ➕ Aggiunta entità: {new_entity_id}")
            else:
                # Aggiorna comando esistente (caso in cui l'entità esiste ma il comando è cambiato)
                for i, existing_cmd in enumerate(merged_commands):
                    if existing_cmd.get("entity") == new_entity_id:
                        merged_commands[i] = new_cmd
                        print(f"  🔄 Aggiornata entità: {new_entity_id}")
                        break
        
        config["start_commands"] = merged_commands
        print(f"  ✅ Totale entità configurate: {len(merged_commands)}")
    else:
        # MODALITÀ CREAZIONE: Nuovo file
        print(f"  🆕 Creazione nuovo file di configurazione...")
    
    # Salva configurazione (sovrascrittura completa con dati merged)
    # Use ensure_ascii=False to preserve non-ASCII characters in descriptions
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
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
    
    # Filtra le entità da avviare: salta RootCA e TLM se già attivi
    entities_to_start = []
    for cmd_info in config["start_commands"]:
        entity_id = cmd_info["entity"]
        command = cmd_info["command"]
        
        # Controlla se RootCA è già attivo sulla porta 5999
        if entity_id == "ROOT_CA":
            if check_entity_active(5999, "RootCA"):
                print(f"  ⏭️  ROOT_CA already active on port 5999, skipping...")
                continue
        
        # Controlla se TLM è già attivo sulla porta 5050
        elif entity_id == "TLM_MAIN":
            if check_entity_active(5050, "TLM"):
                print(f"  ⏭️  TLM_MAIN already active on port 5050, skipping...")
                continue
        
        entities_to_start.append(cmd_info)
    
    print(f"  📊 Will start {len(entities_to_start)} out of {len(config['start_commands'])} entities")
    print()
    
    for idx, cmd_info in enumerate(entities_to_start):
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

    # Recommended: crea un file JSON (UTF-8) e passa --config to avoid quoting/encoding issues
    # Esempio file `my_entities.json`:
    # {
    #   "num_ea": 5,
    #   "ea_names": ["EA_SEMAFORO_02","EA_SEMAFORO_04","EA_SEMAFORO_03"]
    # }
    python setup.py --config my_entities.json

    # Genera solo configurazioni senza avviare
    python setup.py --ea 3 --aa 2 --tlm --no-auto-start

    # Nota: --ea-names/--aa-names rimangono supportati come modalità legacy,
    # ma l'approccio con --config è raccomandato per sicurezza e compatibilità.

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
    
    # Helper: sanitize entity id to avoid shells / file injection
    def sanitize_entity_id(name, max_len=64):
        if not isinstance(name, str):
            name = str(name)
        # Trim
        n = name.strip()
        # Replace spaces with underscore
        n = re.sub(r"\s+", "_", n)
        # Remove problematic chars, allow letters, digits, underscore, hyphen and dot
        n = re.sub(r"[^A-Za-z0-9_\-\.]+", "_", n)
        # Collapse multiple underscores
        n = re.sub(r"_+", "_", n)
        # Trim leading/trailing underscores/dots/hyphens
        n = n.strip('._-')
        if not n:
            n = 'entity'
        # Limit length
        if len(n) > max_len:
            n = n[:max_len]
        return n
    
    # Carica da file se specificato
    if args.config:
        if not os.path.exists(args.config):
            print(f"❌ Errore: File {args.config} non trovato!")
            sys.exit(1)
        
        with open(args.config, 'r', encoding='utf-8') as f:
            request_config = json.load(f)
        
        num_ea = request_config.get("num_ea", 0)
        num_aa = request_config.get("num_aa", 0)
        # TLM dal file: 0 o 1 (qualsiasi valore > 0 diventa 1)
        num_tlm = 1 if request_config.get("num_tlm", 0) > 0 else 0

        # Read custom names from config (prefer lists, but accept comma strings)
        rc_ea_names = request_config.get('ea_names')
        if rc_ea_names:
            if isinstance(rc_ea_names, str):
                ea_names = [n.strip() for n in rc_ea_names.split(',') if n.strip()]
            elif isinstance(rc_ea_names, list):
                ea_names = [str(n).strip() for n in rc_ea_names if str(n).strip()]

        rc_aa_names = request_config.get('aa_names')
        if rc_aa_names:
            if isinstance(rc_aa_names, str):
                aa_names = [n.strip() for n in rc_aa_names.split(',') if n.strip()]
            elif isinstance(rc_aa_names, list):
                aa_names = [str(n).strip() for n in rc_aa_names if str(n).strip()]

        # Sanitize names to produce safe entity IDs used in filenames/commands
        ea_names = [sanitize_entity_id(n) for n in ea_names]
        aa_names = [sanitize_entity_id(n) for n in aa_names]
        if ea_names:
            print(f"\n📝 Nomi custom per EA (da config): {ea_names}")
        if aa_names:
            print(f"📝 Nomi custom per AA (da config): {aa_names}")
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
    #if not args.no_scripts:
       # generate_batch_script(config)
        # generate_powershell_script(config)  # RIMOSSO - ora start_all_entities.ps1 è fisso
    
    # Avvia automaticamente (comportamento predefinito, disabilitabile con --no-auto-start)
    if not args.no_auto_start:
        start_entities_in_vscode_terminals(config)
    else:
        print("✅ Configurazione completata (avvio automatico disabilitato)!\n")
        print("  Puoi avviare le entità con:\n")
        print("  1. Comandi manuali (vedi sopra)")
        print("  2. Script batch:      start_all_entities.bat")
        print("  3. Script PowerShell: .\\start_all_entities.ps1 (fisso - non rigenerato)")
        print("  4. Rilanciare senza --no-auto-start per avvio automatico\n")


if __name__ == "__main__":
    main()
