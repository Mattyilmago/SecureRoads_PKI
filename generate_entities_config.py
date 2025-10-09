"""
Script per generare configurazioni multiple di entità PKI.

Genera file di configurazione JSON per avviare facilmente multiple istanze di:
- Enrollment Authority (EA)
- Authorization Authority (AA)
- Trust List Manager (TLM)

Usage:
    python generate_entities_config.py --ea 3 --aa 2 --tlm 2
    python generate_entities_config.py --config dashboard_request.json
"""

import argparse
import json
import os
import sys
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


def generate_entity_configs(num_ea=0, num_aa=0, num_tlm=0, start_port=5000):
    """
    Genera configurazioni per multiple entità.
    
    Args:
        num_ea: Numero di EA da generare
        num_aa: Numero di AA da generare
        num_tlm: Numero di TLM da generare
        start_port: Porta iniziale (incrementa automaticamente)
        
    Returns:
        Dict con configurazioni generate
    """
    config = {
        "entities": [],
        "start_commands": []
    }
    
    current_port = start_port
    
    print("\n" + "="*70)
    print("🏗️  GENERAZIONE CONFIGURAZIONI ENTITÀ PKI")
    print("="*70 + "\n")
    
    # Genera configurazioni EA
    if num_ea > 0:
        print(f"📝 Generazione configurazioni per {num_ea} Enrollment Authorities...")
        existing_eas = find_existing_entities("EA")
        
        for i in range(num_ea):
            # Trova prossimo numero disponibile
            ea_num = 1
            while True:
                ea_id = f"EA_{ea_num:03d}"
                if ea_id not in existing_eas:
                    break
                ea_num += 1
            
            entity_config = {
                "type": "EA",
                "id": ea_id,
                "port": current_port,
                "host": "0.0.0.0"
            }
            config["entities"].append(entity_config)
            
            # Comando per avviare
            start_cmd = f"python start_production_server.py --entity EA --id {ea_id} --port {current_port}"
            config["start_commands"].append({
                "entity": ea_id,
                "command": start_cmd,
                "description": f"Start Enrollment Authority {ea_id} on port {current_port}"
            })
            
            existing_eas.append(ea_id)
            current_port += 1
            print(f"  ✅ {ea_id} configurato su porta {current_port - 1}")
    
    # Genera configurazioni AA
    if num_aa > 0:
        print(f"\n🎫 Generazione configurazioni per {num_aa} Authorization Authorities...")
        existing_aas = find_existing_entities("AA")
        
        for i in range(num_aa):
            # Trova prossimo numero disponibile
            aa_num = 1
            while True:
                aa_id = f"AA_{aa_num:03d}"
                if aa_id not in existing_aas:
                    break
                aa_num += 1
            
            entity_config = {
                "type": "AA",
                "id": aa_id,
                "port": current_port,
                "host": "0.0.0.0"
            }
            config["entities"].append(entity_config)
            
            # Comando per avviare (creerà automaticamente EA_FOR_AA_XXX)
            start_cmd = f"python start_production_server.py --entity AA --id {aa_id} --port {current_port}"
            config["start_commands"].append({
                "entity": aa_id,
                "command": start_cmd,
                "description": f"Start Authorization Authority {aa_id} on port {current_port} (creates EA_FOR_{aa_id})"
            })
            
            existing_aas.append(aa_id)
            current_port += 1
            print(f"  ✅ {aa_id} configurato su porta {current_port - 1}")
    
    # Genera configurazioni TLM
    if num_tlm > 0:
        print(f"\n📋 Generazione configurazioni per {num_tlm} Trust List Managers...")
        existing_tlms = find_existing_entities("TLM")
        
        for i in range(num_tlm):
            # Trova prossimo numero disponibile
            tlm_num = 1
            while True:
                tlm_id = f"TLM_{tlm_num:03d}"
                if tlm_id not in existing_tlms:
                    break
                tlm_num += 1
            
            entity_config = {
                "type": "TLM",
                "id": tlm_id,
                "port": current_port,
                "host": "0.0.0.0"
            }
            config["entities"].append(entity_config)
            
            # Comando per avviare
            start_cmd = f"python start_production_server.py --entity TLM --id {tlm_id} --port {current_port}"
            config["start_commands"].append({
                "entity": tlm_id,
                "command": start_cmd,
                "description": f"Start Trust List Manager {tlm_id} on port {current_port}"
            })
            
            existing_tlms.append(tlm_id)
            current_port += 1
            print(f"  ✅ {tlm_id} configurato su porta {current_port - 1}")
    
    print("\n" + "="*70)
    print(f"✅ Generazione completata! Totale entità: {len(config['entities'])}")
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


def main():
    parser = argparse.ArgumentParser(
        description="Genera configurazioni per multiple entità PKI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Genera 3 EA, 2 AA, 1 TLM
  python generate_entities_config.py --ea 3 --aa 2 --tlm 1
  
  # Genera solo EA
  python generate_entities_config.py --ea 5
  
  # Specifica porta iniziale
  python generate_entities_config.py --ea 3 --aa 2 --start-port 6000
  
  # Carica da file JSON
  python generate_entities_config.py --config dashboard_request.json
        """
    )
    
    parser.add_argument("--ea", type=int, default=0, help="Numero di Enrollment Authorities da generare")
    parser.add_argument("--aa", type=int, default=0, help="Numero di Authorization Authorities da generare")
    parser.add_argument("--tlm", type=int, default=0, help="Numero di Trust List Managers da generare")
    parser.add_argument("--start-port", type=int, default=5000, help="Porta iniziale (default: 5000)")
    parser.add_argument("--config", type=str, help="Carica configurazione da file JSON")
    parser.add_argument("--output", type=str, default="entity_configs.json", help="File di output (default: entity_configs.json)")
    parser.add_argument("--no-scripts", action="store_true", help="Non generare script di avvio automatici")
    
    args = parser.parse_args()
    
    # Carica da file se specificato
    if args.config:
        if not os.path.exists(args.config):
            print(f"❌ Errore: File {args.config} non trovato!")
            sys.exit(1)
        
        with open(args.config, 'r') as f:
            request_config = json.load(f)
        
        num_ea = request_config.get("num_ea", 0)
        num_aa = request_config.get("num_aa", 0)
        num_tlm = request_config.get("num_tlm", 0)
        start_port = request_config.get("start_port", 5000)
    else:
        num_ea = args.ea
        num_aa = args.aa
        num_tlm = args.tlm
        start_port = args.start_port
    
    # Valida input
    if num_ea == 0 and num_aa == 0 and num_tlm == 0:
        print("❌ Errore: Specifica almeno un'entità da generare!")
        parser.print_help()
        sys.exit(1)
    
    # Genera configurazioni
    config = generate_entity_configs(num_ea, num_aa, num_tlm, start_port)
    
    # Salva configurazione
    save_config(config, args.output)
    
    # Stampa comandi
    print_start_commands(config)
    
    # Genera script di avvio
    if not args.no_scripts:
        generate_batch_script(config)
        generate_powershell_script(config)
    
    print("✅ Completato! Ora puoi:\n")
    print("  1. Avviare manualmente ogni entità con i comandi sopra")
    print("  2. Usare lo script batch:      start_all_entities.bat")
    print("  3. Usare lo script PowerShell: .\\start_all_entities.ps1")
    print("  4. Usare la dashboard per monitorare le istanze\n")


if __name__ == "__main__":
    main()
