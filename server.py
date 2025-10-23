"""
Production Server Launcher for SecureRoad PKI.

ETSI TS 102941 compliant REST API server supporting EA, AA, TLM, and RootCA entities.

Usage:
    python server.py --entity EA --config config.json  # Single entity
    python server.py --ea 3 --aa 2                      # Update config only (no auto-start)
    python server.py --config dashboard_request.json   # Multi-entity from config
    .\\start_all_entities.ps1                           # Start all entities from config
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
from utils.config_utils import write_atomic_json, read_json

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
        # Cache for batching writes to entity_configs.json to avoid many small writes
        self._entity_config_cache = None

    def get_or_create_root_ca(self, ca_id="ROOT_CA_01", base_dir=None):
        """Get or create RootCA singleton instance with ETSI-compliant ca_id."""
        if self._root_ca_instance is None:
            self._root_ca_instance = RootCA(ca_id=ca_id, base_dir=base_dir)
        return self._root_ca_instance

    def get_or_create_tlm_main(self, base_dir=None):
        """Get or create TLM_MAIN singleton instance."""
        if self._tlm_main_instance is None:
            root_ca = self.get_or_create_root_ca()
            self._tlm_main_instance = TrustListManager(root_ca, tlm_id="TLM_MAIN", base_dir=base_dir)
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

        # For small ranges it's efficient to probe ports in parallel to reduce wall-clock time.
        candidates = [p for p in range(start_port, end_port + 1) if p not in used_ports]
        if not candidates:
            # Per TLM e RootCA, messaggio neutro (sono tipicamente già attive)
            if entity_type in ["TLM", "RootCA"]:
                print(f"ℹ️  Nessuna porta disponibile nel range {start_port}-{end_port} per {entity_type} (probabilmente già attiva)")
            else:
                print(f"❌ ERRORE: Nessuna porta disponibile nel range {start_port}-{end_port} per {entity_type}!")
            return None

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def probe(port):
            try:
                # Use is_port_in_use which probes localhost/127.0.0.1 as well for reliability
                return (port, self.is_port_in_use(host, port))
            except Exception:
                return (port, True)

        free_ports = []
        max_workers = min(32, len(candidates))
        with ThreadPoolExecutor(max_workers=max_workers) as exc:
            futures = {exc.submit(probe, p): p for p in candidates}
            for fut in as_completed(futures):
                port, in_use = fut.result()
                if not in_use:
                    free_ports.append(port)

        if free_ports:
            selected = min(free_ports)
            print(f"✅ Porta {selected} disponibile per {entity_type}")
            return selected

        # Per TLM e RootCA, messaggio neutro (sono tipicamente già attive)
        if entity_type in ["TLM", "RootCA"]:
            print(f"ℹ️  Nessuna porta disponibile nel range {start_port}-{end_port} per {entity_type} (probabilmente già attiva)")
        else:
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
        # Try connecting to multiple local addresses to reliably detect listeners
        # on Windows where binding to 0.0.0.0 may not be reachable via that address.
        try:
            hosts_to_try = []
            if host:
                hosts_to_try.append(host)

            # Always try localhost and 127.0.0.1 as they are the most reliable for detection
            hosts_to_try.extend(['127.0.0.1', 'localhost'])

            seen = set()
            for h in hosts_to_try:
                if h in seen:
                    continue
                seen.add(h)
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.2)  # Ridotto da 0.5
                    result = sock.connect_ex((h, port))
                    sock.close()
                    if result == 0:
                        return True
                except Exception:
                    # ignore and try the next address
                    try:
                        sock.close()
                    except Exception:
                        pass

            return False
        except Exception:
            return False

    def find_used_ports(self):
        """
        Controllo semplice delle porte con netstat.

        Returns:
            set: Insieme delle porte già in uso
        """
        used_ports = set()
        # If available, prefer using the bundled PowerShell script which already
        # performs a parallel check of PKI ports. This is faster and more reliable
        # on Windows. Otherwise fall back to netstat with a shorter timeout.
        ps_script = Path(__file__).parent / 'scripts' / 'check_ports.ps1'
        if sys.platform == 'win32' and ps_script.exists():
            try:
                # Run the PowerShell script and parse lines like: "  [X] Porta 5000 (EA) IN USO"
                pwsh_cmd = [
                    'powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', str(ps_script)
                ]
                result = subprocess.run(pwsh_cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        m = re.search(r'\[X\]\s*Porta\s+(\d+)', line)
                        if m:
                            try:
                                port = int(m.group(1))
                                if 5000 <= port <= 5999:
                                    used_ports.add(port)
                            except ValueError:
                                pass
            except Exception as e:
                print(f"  Errore eseguendo check_ports.ps1: {e}")
        else:
            try:
                # Shorter timeout to avoid long delays
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True, timeout=3)
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

    def _cache_register_entity(self, entity_name, start_cmd_str):
        """Register an entity start command in an in-memory cache to batch writes.

        Call `flush_entity_config_cache` to persist to disk.
        """
        if self._entity_config_cache is None:
            # Initialize from existing file if present
            cfg_path = Path('entity_configs.json')
            try:
                existing = read_json(cfg_path) or {"start_commands": [], "port_ranges": {}}
            except Exception:
                existing = {"start_commands": [], "port_ranges": {}}

            self._entity_config_cache = existing

        # Avoid duplicates
        found = False
        for cmd in self._entity_config_cache.get('start_commands', []):
            if cmd.get('entity') == entity_name:
                found = True
                break

        if not found:
            self._entity_config_cache.setdefault('start_commands', []).append({
                'entity': entity_name,
                'command': start_cmd_str
            })

    def flush_entity_config_cache(self, path='entity_configs.json'):
        """Persist the in-memory entity_configs cache to disk (atomic where possible)."""
        if not self._entity_config_cache:
            return

        success = False
        try:
            write_atomic_json(path, self._entity_config_cache, indent=2)
            print(f"✅ Flushed {len(self._entity_config_cache.get('start_commands', []))} entries to {path}")
            success = True
        except Exception as e:
            # Try a simple fallback and log details if it fails
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self._entity_config_cache, f, indent=2)
                print(f"✅ Flushed (fallback) {len(self._entity_config_cache.get('start_commands', []))} entries to {path}")
                success = True
            except Exception as e2:
                import traceback
                print(f"⚠️ Failed to write entity config to {path}: {e} / {e2}")
                traceback.print_exc()
                success = False

        # Only clear cache if we successfully persisted the content
        if success:
            self._entity_config_cache = None

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

    def find_existing_entities(self, entity_type, base_dir=None):
        """
        Trova entità esistenti di un tipo, controllando sia le directory che entity_configs.json.
        Questo previene il riutilizzo di nomi di entità che sono state cancellate ma potrebbero
        avere ancora configurazioni o dati residui.
        """
        # Usa percorso centralizzato se non specificato
        if base_dir is None:
            from config import PKI_PATHS
            base_dir = str(PKI_PATHS.BASE)
        
        existing = []

        # 1. Controlla le directory esistenti in pki_data/
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

    def load_config(self, config_path=None, entity_type=None, entity_id=None):
        """
        Load configuration from JSON file.
        
        Also loads TLS configuration from entity_configs.json if available.
        
        Args:
            config_path: Optional path to config file
            entity_type: Entity type (EA, AA, RootCA, TLM) for TLS config
            entity_id: Entity ID for TLS cert path resolution
        """
        config = DEFAULT_CONFIG.copy()

        def _env_flag_enabled(value):
            """Return True if the provided environment flag string is truthy."""
            return str(value).strip().lower() in {"1", "true", "yes", "on"}

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

        # Load TLS configuration from entity_configs.json
        if entity_type:
            entity_configs_path = Path(__file__).parent / "entity_configs.json"
            if entity_configs_path.exists():
                try:
                    with open(entity_configs_path, "r") as f:
                        entity_configs = json.load(f)
                    
                    tls_config = entity_configs.get("tls_config", {})
                    
                    # Check global enabled flag
                    global_tls_enabled = tls_config.get("enabled", False)
                    
                    # Check entity-specific config
                    entity_tls_config = tls_config.get("entities", {}).get(entity_type, {})
                    entity_tls_enabled = entity_tls_config.get("tls_enabled", False)
                    
                    # TLS is enabled if either global OR entity-specific is true
                    if global_tls_enabled or entity_tls_enabled:
                        config["tls_enabled"] = True
                        
                        # Resolve certificate paths with {id} placeholder
                        cert_path = entity_tls_config.get("tls_cert", "")
                        key_path = entity_tls_config.get("tls_key", "")
                        ca_cert_path = entity_tls_config.get("tls_ca_cert", "")
                        
                        # Replace {id} placeholder with entity_id (lowercase, without entity type prefix)
                        if entity_id and "{id}" in cert_path:
                            # EA_001 -> 001, AA_002 -> 002
                            # Split on underscore and take everything after first part
                            parts = entity_id.split('_', 1)
                            if len(parts) > 1:
                                id_suffix = parts[1].lower()  # "001"
                            else:
                                id_suffix = entity_id.lower()
                            
                            cert_path = cert_path.replace("{id}", id_suffix)
                            key_path = key_path.replace("{id}", id_suffix)
                        
                        config["tls_cert"] = cert_path
                        config["tls_key"] = key_path
                        config["tls_ca_cert"] = ca_cert_path
                        
                        # Auto-generate TLS certificates if missing
                        if cert_path and key_path:
                            cert_exists = Path(cert_path).exists()
                            key_exists = Path(key_path).exists()
                            
                            if not cert_exists or not key_exists:
                                print(f"  ⚠️  Certificati TLS mancanti per {entity_id}")
                                print(f"  🔧 Generazione automatica in corso...")
                                
                                try:
                                    # Import auto-generation function
                                    from scripts.setup_tls_certificates import ensure_tls_certificate_for_entity
                                    
                                    # Get port from config (use default if not set yet)
                                    port_to_use = config.get("port")
                                    
                                    # Generate certificates
                                    generated_cert, generated_key = ensure_tls_certificate_for_entity(
                                        entity_id, port=port_to_use
                                    )
                                    
                                    if generated_cert and generated_key:
                                        print(f"  ✅ Certificati TLS generati automaticamente")
                                        config["tls_cert"] = generated_cert
                                        config["tls_key"] = generated_key
                                    else:
                                        print(f"  ❌ Errore nella generazione automatica certificati TLS")
                                        print(f"  💡 Esegui manualmente: python scripts/setup_tls_certificates.py")
                                        # Disable TLS if cert generation failed
                                        config["tls_enabled"] = False
                                        
                                except ImportError as e:
                                    print(f"  ⚠️  Impossibile importare setup_tls_certificates: {e}")
                                    print(f"  💡 Esegui manualmente: python scripts/setup_tls_certificates.py")
                                    config["tls_enabled"] = False
                                except Exception as e:
                                    print(f"  ⚠️  Errore generazione certificati: {e}")
                                    print(f"  💡 Esegui manualmente: python scripts/setup_tls_certificates.py")
                                    config["tls_enabled"] = False
                        
                        print(f"  TLS configuration loaded:")
                        print(f"    Enabled: {config['tls_enabled']}")
                        print(f"    Cert: {config['tls_cert']}")
                        print(f"    Key: {config['tls_key']}")
                        print(f"    CA: {config.get('tls_ca_cert', 'N/A')}")
                    
                except Exception as e:
                    print(f"  Warning: Could not load TLS config from entity_configs.json: {e}")

        # Environment overrides (force HTTP for local tooling)
        allow_tls_override = _env_flag_enabled(os.environ.get("PKI_ALLOW_TLS"))
        disable_tls_override = (
            _env_flag_enabled(os.environ.get("PKI_DISABLE_TLS"))
            or _env_flag_enabled(os.environ.get("PKI_FORCE_HTTP"))
        )

        if disable_tls_override and not allow_tls_override:
            if config.get("tls_enabled"):
                print("  TLS disabled via environment override (PKI_DISABLE_TLS/PKI_FORCE_HTTP)")
            else:
                print("  Environment override forces HTTP mode")
            config["tls_enabled"] = False
            config["tls_cert"] = None
            config["tls_key"] = None
            if "tls_ca_cert" in config:
                config["tls_ca_cert"] = None

        return config

    def launch_single_entity(self, entity_type, entity_id=None, config_path=None, config=None, temp_mode=False):
        """Launch a single PKI entity server (from server.py logic).

        Accept either a path to a config (config_path) or a pre-built config dict
        (config). If both are provided, the explicit `config` dict takes precedence.
        This ensures callers that parse CLI args can pass overridden host/port values
        and they will be respected when starting the server.
        
        Args:
            temp_mode: If True, do not save entity to entity_configs.json (temporary test mode)
        """
        print(f" Launching single {entity_type} entity...")

        # Determine entity ID first (needed for TLS config loading)
        if entity_id:
            entity_name = entity_id
        else:
            # Generate default name
            existing = self.find_existing_entities(entity_type)
            entity_name = self.generate_entity_name_with_suffix(f"{entity_type}_001", existing)

        # Prefer an explicit config dict if provided (caller may override port/host)
        if config is None:
            config = self.load_config(config_path, entity_type=entity_type, entity_id=entity_name)

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

        # Ensure entity is recorded in entity_configs.json so tooling can discover it
        # Skip saving if temp_mode is True (temporary test mode)
        if temp_mode:
            print(f"  [TEMP] Entity {entity_name} will NOT be saved to entity_configs.json")
        
        if not temp_mode:
            try:
                cfg_path = Path("entity_configs.json")
                existing_cfg = read_json(cfg_path) or {"start_commands": [], "port_ranges": {}}

                # Build start command string to match format used elsewhere
                start_cmd_str = f"python server.py --entity {entity_type} --id {entity_name} --port {config.get('port')}"

                # Avoid duplicates: skip if same entity exists or if we're registering a TLM/RootCA
                # and a TLM/RootCA already exists for the same port or entity
                found = False
                for cmd in existing_cfg.get('start_commands', []):
                    if cmd.get('entity') == entity_name:
                        found = True
                        break
                    # If registering a TLM, avoid creating another TLM on same port or another system TLM
                    if entity_type == 'TLM':
                        existing_entity = cmd.get('entity', '')
                        existing_cmd = cmd.get('command', '')
                        if existing_entity.startswith('TLM') or 'TLM_MAIN' in existing_entity:
                            # If port matches, treat as duplicate
                            if f"--port {config.get('port')}" in existing_cmd:
                                found = True
                                break
                            # If an existing system TLM exists, skip adding another
                            if existing_entity == 'TLM_MAIN':
                                found = True
                                break
                    # Similarly for RootCA avoid duplicates
                    if entity_type == 'RootCA':
                        if cmd.get('entity') == 'ROOT_CA' or cmd.get('entity', '').startswith('ROOT_CA'):
                            found = True
                            break

                if not found:
                    # Use in-memory cache to batch writes and persist immediately for single-entity launches
                    self._cache_register_entity(entity_name, start_cmd_str)
                    try:
                        # Persist to disk so tooling and scripts (like start_all_entities) see the new entity
                        self.flush_entity_config_cache('entity_configs.json')
                        print(f"✅ Registered {entity_name} and flushed to entity_configs.json")
                    except Exception:
                        # Keep the entry in-memory if flush fails; outer except will also log a warning
                        print(f"⚠️ Registered {entity_name} in in-memory config cache (flush failed)")
            except Exception as e:
                print(f"⚠️ Warning: failed to update entity_configs.json for {entity_name}: {e}")

        # Create entity instance based on type
        if entity_type == "RootCA":
            entity = self.get_or_create_root_ca()
        elif entity_type == "EA":
            root_ca = self.get_or_create_root_ca()
            # EA needs TLM reference only for initialization
            # After init, EA registers itself to remote TLM via HTTP API
            tlm = self.get_or_create_tlm_main()
            entity = EnrollmentAuthority(root_ca, tlm, ea_id=entity_name)
                
        elif entity_type == "AA":
            root_ca = self.get_or_create_root_ca()
            # AA needs TLM reference for EC validation
            # If TLM is already running as separate service, create local instance
            # (it will be kept in sync via file-based storage)
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

        # Load existing config or create new one
        existing_config = read_json('entity_configs.json') or {"start_commands": []}
        
        config = {
            "start_commands": existing_config.get("start_commands", []),
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
            else:
                print(f"❌ Nessuna porta disponibile per {name}, interrompo creazione EA")
                break

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
            else:
                print(f"❌ Nessuna porta disponibile per {name}, interrompo creazione AA")
                break

        # Always try to create TLM (always include system entity) - only if not already present
        tlm_exists = any(cmd.get('entity') == 'TLM_MAIN' for cmd in config["start_commands"])
        if not tlm_exists:
            port = 5050  # Fixed port for TLM
            config["start_commands"].append({
                "entity": "TLM_MAIN",
                "command": f"python server.py --entity TLM --port {port}"
            })
            print("✅ TLM will be created (system entity)")
        else:
            print("⏭️ TLM already configured, skipped")

        # Always try to create RootCA (always include critical entity) - only if not already present
        rootca_exists = any(cmd.get('entity') == 'ROOT_CA' for cmd in config["start_commands"])
        if not rootca_exists:
            port = 5999  # Fixed port for RootCA
            config["start_commands"].append({
                "entity": "ROOT_CA",
                "command": f"python server.py --entity RootCA --id ROOT_CA --port {port}"
            })
            print("✅ RootCA will be created (critical entity)")
        else:
            print("⏭️ RootCA already configured, skipped")

        # Save config atomically
        # Persist the generated multi-entity config via cache flush to avoid many
        # small writes when also starting entities immediately after.
        try:
            self._entity_config_cache = config
            self.flush_entity_config_cache('entity_configs.json')
        except Exception as e:
            print(f"❌ Failed to persist multi-entity config: {e}")

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

        # Avvia ogni entità in parallelo usando ThreadPoolExecutor per velocizzare l'avvio
        from concurrent.futures import ThreadPoolExecutor, as_completed
        import shlex

        def start_one_entity(entry):
            entity_id, command, port = entry
            try:
                print(f"🔄 Avvio {entity_id} sulla porta {port}...")

                # Determina il tipo di entità dall'ID
                if entity_id.startswith("EA_"):
                    entity_type = "EA"
                elif entity_id.startswith("AA_"):
                    entity_type = "AA"
                elif entity_id == "TLM_MAIN":
                    entity_type = "TLM"
                elif entity_id.startswith("ROOT_CA"):
                    entity_type = "RootCA"
                else:
                    entity_type = "EA"  # default fallback
                
                # Usa PKIPathManager per ottenere la cartella log corretta
                from utils.pki_paths import PKIPathManager
                entity_paths = PKIPathManager.get_entity_paths(entity_type, entity_id)
                entity_log_dir = entity_paths.logs_dir
                entity_log_dir.mkdir(parents=True, exist_ok=True)
                
                # Crea file di log per l'entità nella sua cartella specifica
                log_file = entity_log_dir / f"{entity_id.lower()}.log"

                # Parse command string into arguments list
                cmd_parts = shlex.split(command)
                # Replace 'python' with pythonw_exe path
                if cmd_parts[0] == 'python':
                    cmd_parts[0] = pythonw_exe

                proc = subprocess.Popen(
                    cmd_parts,
                    stdout=open(log_file, 'w'),
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
                )

                return (entity_id, proc, port, None)

            except Exception as e:
                return (entity_id, None, port, e)

        max_workers = min(8, len(entities_to_start)) or 1
        futures = []
        with ThreadPoolExecutor(max_workers=max_workers) as exc:
            for entry in entities_to_start:
                futures.append(exc.submit(start_one_entity, entry))

            for fut in as_completed(futures):
                entity_id, proc, port, err = fut.result()
                if err:
                    print(f"❌ Errore avvio {entity_id}: {err}")
                    failed_count += 1
                else:
                    processes.append((entity_id, proc, port))
                    started_count += 1

        print()
        print("="*70)
        print("📊 RISULTATI AVVIO:")
        print(f"✅ Avviate: {started_count}")
        print(f"❌ Fallite: {failed_count}")
        print("="*70)

        if started_count > 0:
            print("\n🔍 Controllo stato entità...")

            # Controllo parallelo dello stato delle entità per velocizzare
            from concurrent.futures import ThreadPoolExecutor, as_completed

            def check_entity_status(entry):
                entity_id, process, port = entry
                if process.poll() is None:  # Processo ancora attivo
                    elapsed = 0.0
                    ready = False
                    max_wait_per_entity = 2.0  # Ridotto da 3.0
                    poll_interval = 0.2  # Ridotto da 0.5
                    while elapsed < max_wait_per_entity:
                        if self.check_entity_active(port, 'EA'):
                            ready = True
                            break
                        time.sleep(poll_interval)
                        elapsed += poll_interval

                    if ready:
                        return (entity_id, port, elapsed, "ATTIVO")
                    else:
                        return (entity_id, port, max_wait_per_entity, "PROCESSO_ATTIVO_MA_PORTA_NON_RISPONDE")
                else:
                    return (entity_id, port, 0.0, "PROCESSO_TERMINATO")

            active_count = 0
            max_workers_check = min(8, len(processes)) or 1
            with ThreadPoolExecutor(max_workers=max_workers_check) as exc:
                futures = {exc.submit(check_entity_status, entry): entry for entry in processes}
                for fut in as_completed(futures):
                    entity_id, port, elapsed, status = fut.result()
                    if status == "ATTIVO":
                        print(f"✅ {entity_id}: ATTIVO (porta {port}) dopo {elapsed:.1f}s")
                        active_count += 1
                    elif status == "PROCESSO_ATTIVO_MA_PORTA_NON_RISPONDE":
                        print(f"⚠️  {entity_id}: PROCESSO ATTIVO ma porta {port} non risponde dopo {elapsed:.1f}s")
                        active_count += 1  # Considera attivo se il processo è vivo ma porta non pronta
                    else:
                        print(f"❌ {entity_id}: PROCESSO TERMINATO")

            print(f"\n🎯 Totale entità attive (o con processo vivo): {active_count}/{started_count}")

        print("\n💡 Puoi monitorare i log in: pki_data/<entity_type>/<entity_id>/logs/")
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
        description="SecureRoad PKI Entity Manager - Single launch or Multi-entity config update",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single entity launch
  python server.py --entity EA --config config.json
  python server.py --entity AA --id AA_001 --port 5020

  # Multi-entity config update (doesn't start entities)
  python server.py --ea 3 --aa 2
  python server.py --ea 1 --aa 1 --ea-names "EA_Prod,EA_Test"
  python server.py --config entity_request.json

  # Start all entities from config
  .\\start_all_entities.ps1

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
    parser.add_argument("--no-auto-start", action="store_true", help="When running multi-entity setup from --config, do not auto-start entities")
    parser.add_argument("--temp", action="store_true", help="Temporary mode: do not save entity to entity_configs.json (isolated test)")

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
        config = manager.load_config(args.config, entity_type=args.entity, entity_id=args.id)

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
        success = manager.launch_single_entity(args.entity, args.id, None, config, temp_mode=args.temp)
        if not success:
            sys.exit(1)

    elif args.ea > 0 or args.aa > 0:
        # Launch mode - start only specified entities + TLM/RootCA if needed
        ea_names = [n.strip() for n in args.ea_names.split(',')] if args.ea_names else None
        aa_names = [n.strip() for n in args.aa_names.split(',')] if args.aa_names else None

        # Create temp config with only the specified entities
        temp_config = {"start_commands": []}
        used_ports = manager.find_used_ports()

        # Add EA entities
        for i in range(args.ea):
            existing = manager.find_existing_entities("EA")
            name = ea_names[i] if ea_names and i < len(ea_names) else f"EA_{i+1:03d}"
            name = manager.generate_entity_name_with_suffix(name, existing)
            port = manager.find_available_port_in_range("EA", used_ports=used_ports)
            if port and port not in used_ports:
                temp_config["start_commands"].append({
                    "entity": name,
                    "command": f"python server.py --entity EA --id {name} --port {port}"
                })
                used_ports.add(port)
            else:
                print(f"❌ Nessuna porta disponibile per {name}, interrompo creazione EA")
                break

        # Add AA entities
        for i in range(args.aa):
            existing = manager.find_existing_entities("AA")
            name = aa_names[i] if aa_names and i < len(aa_names) else f"AA_{i+1:03d}"
            name = manager.generate_entity_name_with_suffix(name, existing)
            port = manager.find_available_port_in_range("AA", used_ports=used_ports)
            if port and port not in used_ports:
                temp_config["start_commands"].append({
                    "entity": name,
                    "command": f"python server.py --entity AA --id {name} --port {port}"
                })
                used_ports.add(port)
            else:
                print(f"❌ Nessuna porta disponibile per {name}, interrompo creazione AA")
                break

        # Check if TLM is active, if not add it
        if not manager.check_entity_active(5050, "TLM"):
            temp_config["start_commands"].append({
                "entity": "TLM_MAIN",
                "command": "python server.py --entity TLM --port 5050"
            })

        # Check if RootCA is active, if not add it
        if not manager.check_entity_active(5999, "RootCA"):
            temp_config["start_commands"].append({
                "entity": "ROOT_CA",
                "command": "python server.py --entity RootCA --id ROOT_CA --port 5999"
            })

        # Update persistent config with new entities
        existing_config = read_json('entity_configs.json') or {"start_commands": []}
        existing_config["start_commands"].extend(temp_config["start_commands"])
        write_atomic_json('entity_configs.json', existing_config)

        print("\n✅ Config updated with new entities in entity_configs.json")
        print("🚀 Starting only the specified entities + TLM/RootCA if needed...")

        # Start only the new entities
        manager.start_entities_in_vscode_terminals(temp_config)

    elif args.config and not args.entity and args.ea == 0 and args.aa == 0:
        # Interpret config file as a multi-entity request (contains num_ea/num_aa)
        try:
            with open(args.config, 'r', encoding='utf-8') as f:
                request_config = json.load(f)

            num_ea = int(request_config.get('num_ea', 0))
            num_aa = int(request_config.get('num_aa', 0))
            ea_names = request_config.get('ea_names', [])
            aa_names = request_config.get('aa_names', [])

            config = manager.setup_multi_entities(num_ea=num_ea, num_aa=num_aa, ea_names=ea_names, aa_names=aa_names)

            if not args.no_auto_start:
                print("\n🚀 Starting entities automatically...")
                manager.start_entities_in_vscode_terminals(config)
            else:
                print("--no-auto-start specified; skipping automatic start. Config written to entity_configs.json")

        except Exception as e:
            print(f"Error processing --config for multi-entity setup: {e}")
            sys.exit(1)

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
