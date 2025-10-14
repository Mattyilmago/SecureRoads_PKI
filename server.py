"""
Production Server Launcher for SecureRoad PKI.

ETSI TS 102941 compliant REST API server supporting EA, AA, TLM, and RootCA entities.

Usage:
    python server.py --entity EA --config config.json  # Single entity
    python server.py --ea 3 --aa 2 --tlm 2              # Multi-entity setup
    python server.py --config dashboard_request.json   # Multi-entity from config
"""

import sys
import os

# Fix Windows console encoding BEFORE any other imports
if sys.platform == "win32":
    try:
        # Force UTF-8 encoding for Windows console
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
        # Set environment variable for child processes
        os.environ['PYTHONIOENCODING'] = 'utf-8'
    except AttributeError:
        # Python < 3.7 fallback
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')
    except Exception:
        pass

import argparse
import json
import re
import secrets
import socket
import subprocess
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from api.flask_app_factory import create_app
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from managers.trust_list_manager import TrustListManager
from utils.cert_utils import get_certificate_ski


class PKIEntityManager:
    """Unified manager for PKI entities - handles both single launch and multi-entity setup."""

    def __init__(self):
        # Global RootCA instance (singleton pattern)
        self._root_ca_instance = None
        # Global TLM_MAIN instance (singleton pattern - shared across all AA)
        self._tlm_main_instance = None

    def get_or_create_root_ca(self, base_dir="./data/root_ca"):
        """Get or create RootCA singleton instance."""
        if self._root_ca_instance is None:
            self._root_ca_instance = RootCA(base_dir=base_dir)
        return self._root_ca_instance

    def get_or_create_tlm_main(self, base_dir="./data/tlm"):
        """Get or create TLM_MAIN singleton instance."""
        if self._tlm_main_instance is None:
            root_ca = self.get_or_create_root_ca()
            self._tlm_main_instance = TrustListManager(root_ca, base_dir=base_dir)
        return self._tlm_main_instance

    def generate_entity_name_with_suffix(self, desired_name, existing_entities):
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

    def get_port_range_for_entity(self, entity_type):
        """
        Ottiene il range di porte per un tipo di entità dal file entity_configs.json.

        Args:
            entity_type: 'EA', 'AA', 'TLM', 'RootCA'

        Returns:
            Tuple (start_port, end_port) o None se non trovato
        """
        try:
            config_path = Path(__file__).parent / "entity_configs.json"
            if config_path.exists():
                with open(config_path, "r") as f:
                    config = json.load(f)
                    if "port_ranges" in config and entity_type in config["port_ranges"]:
                        range_info = config["port_ranges"][entity_type]
                        return (range_info["start"], range_info["end"])
        except Exception as e:
            print(f"  Errore nel leggere port_ranges da entity_configs.json: {e}")

        # Fallback ai range di default
        default_ranges = {
            "EA": (5000, 5019),
            "AA": (5020, 5039),
            "TLM": (5050, 5059),  # Range più ampio per TLM se 5050 occupata
            "RootCA": (5999, 6009)  # Range più ampio per RootCA se 5999 occupata
        }
        return default_ranges.get(entity_type, (5000, 5000))

    def find_available_port_in_range(self, entity_type, host="0.0.0.0", used_ports=None):
        """
        Trova la prima porta disponibile nel range dedicato per il tipo di entità.

        Args:
            entity_type: 'EA', 'AA', 'TLM', 'RootCA'
            host: Host su cui verificare
            used_ports: Set di porte già usate (opzionale)

        Returns:
            Porta disponibile trovata, o None se nessuna porta disponibile
        """
        if used_ports is None:
            used_ports = set()

        start_port, end_port = self.get_port_range_for_entity(entity_type)

        print(f"🔍 Cerco porta disponibile per {entity_type} nel range {start_port}-{end_port}...")

        for port in range(start_port, end_port + 1):
            if not self.is_port_in_use(host, port) and port not in used_ports:
                print(f"✅ Porta {port} disponibile per {entity_type}")
                return port

        print(f"❌ ERRORE: Nessuna porta disponibile nel range {start_port}-{end_port} per {entity_type}!")
        print(f"   Tutte le {end_port - start_port + 1} porte sono occupate.")
        return None

    def is_port_in_use(self, host, port):
        """
        Verifica se una porta è già in uso.

        Args:
            host: Host da testare
            port: Porta da testare

        Returns:
            bool: True se in uso, False altrimenti
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def find_used_ports(self):
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
            print(f"  Errore controllo porte: {e}")

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
                print(f"  Errore leggendo configurazione porte: {e}")

        return used_ports

    def check_entity_active(self, port, entity_type, timeout=3):
        """
        Controlla se un'entità è già attiva sulla porta specificata controllando se la porta è in uso.

        Args:
            port: Porta da controllare
            entity_type: Tipo di entità ('RootCA', 'TLM', 'EA', 'AA')
            timeout: Timeout in secondi (non usato per socket)

        Returns:
            bool: True se la porta è in uso (entità probabilmente attiva), False se libera
        """
        return self.is_port_in_use('localhost', port)

    def find_existing_entities(self, entity_type, base_dir="./data"):
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

        # 2. Controlla entity_configs.json per entità già configurate,
        #    ma solo se la directory corrispondente esiste ancora
        config_file = Path("entity_configs.json")
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)

                # Estrai nomi entità dai start_commands
                for cmd_entry in config.get('start_commands', []):
                    entity_name = cmd_entry.get('entity', '')
                    if entity_name.startswith(f"{entity_type}_"):
                        # Verifica se la directory esiste ancora
                        entity_dir_path = os.path.join(base_dir, entity_type_lower, entity_name)
                        if os.path.exists(entity_dir_path) and entity_name not in existing:
                            existing.append(entity_name)
            except Exception as e:
                # Se non riusciamo a leggere il config, continua con le directory
                pass

        return existing

    def load_config(self, config_path=None):
        """Load configuration from JSON file"""
        config = DEFAULT_CONFIG.copy()

        if config_path and Path(config_path).exists():
            with open(config_path, "r") as f:
                user_config = json.load(f)
                config.update(user_config)
            print(f" Configuration loaded from: {config_path}")
        else:
            print("  No config file provided, using defaults")

            # Generate API key if none provided
            if not config["api_keys"]:
                api_key = secrets.token_urlsafe(32)
                config["api_keys"] = [api_key]
                print(f"  Generated API key: {api_key}")
                print("   Save this key! You'll need it for authentication.")

        return config

    def launch_single_entity(self, entity_type, entity_id=None, config_path=None, config=None):
        """Launch a single PKI entity server (from server.py logic).

        Accept either a path to a config (config_path) or a pre-built config dict
        (config). If both are provided, the explicit `config` dict takes precedence.
        This ensures callers that parse CLI args can pass overridden host/port values
        and they will be respected when starting the server.
        """
        print(f" Launching single {entity_type} entity...")

        # Prefer an explicit config dict if provided (caller may override port/host)
        if config is None:
            config = self.load_config(config_path)

        # Determine entity ID
        if entity_id:
            entity_name = entity_id
        else:
            # Generate default name
            existing = self.find_existing_entities(entity_type)
            entity_name = self.generate_entity_name_with_suffix(f"{entity_type}_001", existing)

        # If a port was explicitly provided in the config (CLI --port or caller), respect it
        if not config.get("port"):
            # Find available port only when no port provided
            port = self.find_available_port_in_range(entity_type, config.get("host", "0.0.0.0"))
            if port is None:
                print(f" No available port for {entity_type}")
                return False
            config["port"] = port
        else:
            # If caller provided a port, verify it's free (warn/abort if already in use)
            requested_port = int(config.get("port"))
            if self.is_port_in_use(config.get("host", "localhost"), requested_port):
                print(f" ERRORE: Porta richiesta {requested_port} già in uso!")
                return False

        print(f" Entity: {entity_name}")
        print(f" Host: {config.get('host')}:{config.get('port')}")

        # Create entity instance based on type
        if entity_type == "RootCA":
            entity = self.get_or_create_root_ca()
        elif entity_type == "EA":
            root_ca = self.get_or_create_root_ca()
            entity = EnrollmentAuthority(root_ca, ea_id=entity_name)
        elif entity_type == "AA":
            root_ca = self.get_or_create_root_ca()
            tlm = self.get_or_create_tlm_main()
            entity = AuthorizationAuthority(root_ca, tlm, aa_id=entity_name)
        elif entity_type == "TLM":
            entity = self.get_or_create_tlm_main()
        else:
            print(f"❌ Unknown entity type: {entity_type}")
            return False

        # Create Flask app
        app = create_app(entity_type, entity, config)

        # Start server with TLS if configured
        if config.get("tls_enabled"):
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            if not config.get("tls_cert") or not config.get("tls_key"):
                print(" TLS enabled but cert/key not provided!")
                return False

            context.load_cert_chain(config["tls_cert"], config["tls_key"])

            if config.get("tls_ca_cert"):
                context.load_verify_locations(cafile=config["tls_ca_cert"])
                context.verify_mode = ssl.CERT_REQUIRED
                print(f" mTLS enabled with CA: {config['tls_ca_cert']}")
            else:
                context.verify_mode = ssl.CERT_NONE
                print(" TLS enabled (server cert only)")

            print(" Starting HTTPS server...")
            app.run(host=config.get("host"), port=config.get("port"), debug=config.get("debug"), ssl_context=context)
        else:
            print(" Starting HTTP server...")
            app.run(host=config.get("host"), port=config.get("port"), debug=config.get("debug"))

        return True

    def setup_multi_entities(self, num_ea=0, num_aa=0, config_file=None, ea_names=None, aa_names=None):
        """Setup multiple entities with automatic TLM and RootCA creation if ports available"""
        print(" Setting up multiple PKI entities...")

        # Load from config file if provided
        if config_file:
            with open(config_file, 'r', encoding='utf-8') as f:
                request_config = json.load(f)
            num_ea = request_config.get("num_ea", 0)
            num_aa = request_config.get("num_aa", 0)
            ea_names = request_config.get('ea_names', [])
            aa_names = request_config.get('aa_names', [])

        config = {
            "start_commands": [],
            "port_ranges": {
                "EA": {"start": 5000, "end": 5019},
                "AA": {"start": 5020, "end": 5039},
                "TLM": {"start": 5050, "end": 5050},
                "RootCA": {"start": 5999, "end": 5999}
            }
        }

        used_ports = self.find_used_ports()

        # Generate EA configs
        for i in range(num_ea):
            existing = self.find_existing_entities("EA")
            name = ea_names[i] if ea_names and i < len(ea_names) else f"EA_{i+1:03d}"
            name = self.generate_entity_name_with_suffix(name, existing)
            port = self.find_available_port_in_range("EA", used_ports=used_ports)
            if port and port not in used_ports:
                config["start_commands"].append({
                    "entity": name,
                    "command": f"python server.py --entity EA --id {name} --port {port}"
                })
                used_ports.add(port)

        # Generate AA configs
        for i in range(num_aa):
            existing = self.find_existing_entities("AA")
            name = aa_names[i] if aa_names and i < len(aa_names) else f"AA_{i+1:03d}"
            name = self.generate_entity_name_with_suffix(name, existing)
            port = self.find_available_port_in_range("AA", used_ports=used_ports)
            if port and port not in used_ports:
                config["start_commands"].append({
                    "entity": name,
                    "command": f"python server.py --entity AA --id {name} --port {port}"
                })
                used_ports.add(port)

        # Always try to create TLM (always include system entity)
        port = 5050  # Fixed port for TLM
        config["start_commands"].append({
            "entity": "TLM_MAIN",
            "command": f"python server.py --entity TLM --port {port}"
        })
        print("✅ TLM will be created (system entity)")

        # Always try to create RootCA (always include critical entity)
        port = 5999  # Fixed port for RootCA
        config["start_commands"].append({
            "entity": "ROOT_CA",
            "command": f"python server.py --entity RootCA --id ROOT_CA --port {port}"
        })
        print("✅ RootCA will be created (critical entity)")

        # Save config
        with open("entity_configs.json", "w") as f:
            json.dump(config, f, indent=2)

        print("✅ Multi-entity config generated!")
        print("\n🚀 Start commands:")
        for cmd in config["start_commands"]:
            print(f"  {cmd['command']}")

        return config

    def start_entities_in_vscode_terminals(self, config):
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
                print("⚠️  pythonw.exe not found, using python.exe with hidden window flag")
                pythonw_exe = python_exe
        else:
            pythonw_exe = python_exe

        print(f"📌 Using: {pythonw_exe}")
        print()

        # Filtra le entità da avviare: salta RootCA e TLM se già attivi
        entities_to_start = []

        for cmd_info in config["start_commands"]:
            entity_id = cmd_info["entity"]
            command = cmd_info["command"]

            # Estrai il tipo di entità dal nome
            if entity_id.startswith("EA_"):
                entity_type = "EA"
            elif entity_id.startswith("AA_"):
                entity_type = "AA"
            elif entity_id == "TLM_MAIN":
                entity_type = "TLM"
            elif entity_id == "ROOT_CA":
                entity_type = "RootCA"
            else:
                continue

            # Controlla se l'entità è già attiva
            port_match = re.search(r'--port\s+(\d+)', command)
            if port_match:
                port = int(port_match.group(1))
                if not self.check_entity_active(port, entity_type):
                    entities_to_start.append((entity_id, command, port))
                else:
                    print(f"⏭️  {entity_id} già attivo sulla porta {port}, saltato")

        if not entities_to_start:
            print("✅ Tutte le entità sono già attive!")
            return

        print(f"🚀 Avvio di {len(entities_to_start)} entità...")
        print()

        # Avvia ogni entità
        for entity_id, command, port in entities_to_start:
            try:
                print(f"🔄 Avvio {entity_id} sulla porta {port}...")

                # Crea file di log per l'entità
                log_file = log_dir / f"{entity_id.lower()}.log"

                # Avvia il processo in background
                # Parse command string into arguments list
                import shlex
                cmd_parts = shlex.split(command)
                # Replace 'python' with pythonw_exe path
                if cmd_parts[0] == 'python':
                    cmd_parts[0] = pythonw_exe

                process = subprocess.Popen(
                    cmd_parts,
                    stdout=open(log_file, 'w'),
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )

                processes.append((entity_id, process, port))
                started_count += 1

                # Aspetta un momento per evitare sovraccarico
                time.sleep(1)

            except Exception as e:
                print(f"❌ Errore avvio {entity_id}: {e}")
                failed_count += 1

        print()
        print("="*70)
        print("📊 RISULTATI AVVIO:")
        print(f"✅ Avviate: {started_count}")
        print(f"❌ Fallite: {failed_count}")
        print("="*70)

        if started_count > 0:
            print("\n🔍 Controllo stato entità...")
            time.sleep(5)  # Aspetta che si avviino completamente

            active_count = 0
            for entity_id, process, port in processes:
                if process.poll() is None:  # Processo ancora attivo
                    if self.check_entity_active(port, "EA"):  # Controllo generico
                        print(f"✅ {entity_id}: ATTIVO (porta {port})")
                        active_count += 1
                    else:
                        print(f"⚠️  {entity_id}: PROCESSO ATTIVO ma porta {port} non risponde ancora")
                        active_count += 1  # Considera attivo se il processo è vivo
                else:
                    print(f"❌ {entity_id}: PROCESSO TERMINATO")

            print(f"\n🎯 Totale entità attive: {active_count}/{started_count}")

        print("\n💡 Puoi monitorare i log in: logs/")
        print("💡 Usa 'python stop_all.ps1' per fermare tutto")


DEFAULT_CONFIG = {
    "host": "0.0.0.0",
    "port": 5000,
    "debug": False,
    "api_keys": [],
    "rate_limit_per_second": 100,
    "rate_limit_burst": 500,
    "log_level": "INFO",
    "tls_enabled": False,
    "tls_cert": None,
    "tls_key": None,
}


def main():
    parser = argparse.ArgumentParser(
        description="SecureRoad PKI Entity Manager - Single launch or Multi-entity setup",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single entity launch
  python server.py --entity EA --config config.json
  python server.py --entity AA --id AA_001 --port 5020

  # Multi-entity setup (automatically creates TLM and RootCA if ports available)
  python server.py --ea 3 --aa 2
  python server.py --ea 1 --aa 1 --ea-names "EA_Prod,EA_Test"
  python server.py --config entity_request.json

  # Generate API key
  python server.py --generate-key
        """
    )

    # Single entity options
    parser.add_argument("--entity", choices=["EA", "AA", "TLM", "RootCA"],
                       help="Launch single entity of specified type")
    parser.add_argument("--id", help="Entity ID (auto-generated if not provided)")
    parser.add_argument("--port", type=int, help="Port to use (auto-assigned if not provided)")
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--host", help="Host to bind (overrides config)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    # Multi-entity setup options
    parser.add_argument("--ea", type=int, default=0, help="Number of Enrollment Authorities to create")
    parser.add_argument("--aa", type=int, default=0, help="Number of Authorization Authorities to create")
    parser.add_argument("--ea-names", help="Comma-separated list of EA names")
    parser.add_argument("--aa-names", help="Comma-separated list of AA names")
    parser.add_argument("--output", default="entity_configs.json", help="Output config file")

    # Utility options
    parser.add_argument("--generate-key", action="store_true", help="Generate a secure API key and exit")

    args = parser.parse_args()

    # Handle --generate-key flag
    if args.generate_key:
        generate_api_key()
        sys.exit(0)

    # Create manager instance
    manager = PKIEntityManager()

    # Determine mode
    if args.entity:
        # Single entity mode
        config = manager.load_config(args.config)

        # Apply CLI overrides
        if args.host:
            config["host"] = args.host
        if args.port:
            config["port"] = args.port
        elif not config.get("port"):
            # Auto-assign port if not specified
            auto_port = manager.find_available_port_in_range(args.entity, config.get("host", "0.0.0.0"))
            if auto_port:
                config["port"] = auto_port
                print(f" Porta selezionata automaticamente: {config['port']}")
            else:
                print(f" ERRORE: Impossibile trovare una porta disponibile per {args.entity}!")
                sys.exit(1)

        if args.debug:
            config["debug"] = True

        # Pass the constructed config so CLI --port/--host override are respected
        success = manager.launch_single_entity(args.entity, args.id, None, config)
        if not success:
            sys.exit(1)

    elif args.ea > 0 or args.aa > 0:
        # Multi-entity setup mode - always create TLM and RootCA if ports available
        ea_names = [n.strip() for n in args.ea_names.split(',')] if args.ea_names else None
        aa_names = [n.strip() for n in args.aa_names.split(',')] if args.aa_names else None

        config = manager.setup_multi_entities(
            num_ea=args.ea,
            num_aa=args.aa,
            ea_names=ea_names,
            aa_names=aa_names
        )

        # Always auto-start entities
        print("\n🚀 Starting entities automatically...")
        manager.start_entities_in_vscode_terminals(config)

    else:
        parser.print_help()
        sys.exit(1)


def generate_api_key():
    """Generate a secure API key and print it"""
    api_key = secrets.token_urlsafe(32)
    print("\n" + "="*70)
    print(" SECURE API KEY GENERATED")
    print("="*70)
    print(f"\n{api_key}\n")
    print("  SAVE THIS KEY SECURELY!")
    print("   Add it to your config.json:")
    print('   {"api_keys": ["' + api_key + '"]}\n')
    print("="*70 + "\n")
    return api_key


if __name__ == "__main__":
    main()
