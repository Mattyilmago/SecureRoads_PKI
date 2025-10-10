"""
Production Server Launcher for SecureRoad PKI.

ETSI TS 102941 compliant REST API server supporting EA, AA, TLM, and RootCA entities.

Usage:
    python server.py --entity EA --config config.json
    python server.py --entity AA --id AA_001
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
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from api.flask_app_factory import create_app
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from managers.trust_list_manager import TrustListManager
from utils.cert_utils import get_certificate_ski


# Global RootCA instance (singleton pattern)
_root_ca_instance = None

# Global TLM_MAIN instance (singleton pattern - shared across all AA)
_tlm_main_instance = None


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


def load_config(config_path=None):
    """Load configuration from JSON file"""
    config = DEFAULT_CONFIG.copy()

    if config_path and Path(config_path).exists():
        with open(config_path, "r") as f:
            user_config = json.load(f)
            config.update(user_config)
        print(f"✅ Configuration loaded from: {config_path}")
    else:
        print("⚠️  No config file provided, using defaults")

        # Generate API key if none provided
        if not config["api_keys"]:
            api_key = secrets.token_urlsafe(32)
            config["api_keys"] = [api_key]
            print(f"⚠️  Generated API key: {api_key}")
            print("   Save this key! You'll need it for authentication.")

    return config


def get_port_range_for_entity(entity_type):
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
        print(f"⚠️  Errore nel leggere port_ranges da entity_configs.json: {e}")
    
    # Fallback ai range di default
    default_ranges = {
        "EA": (5000, 5019),
        "AA": (5020, 5039),
        "TLM": (5050, 5050),
        "RootCA": (5999, 5999)
    }
    return default_ranges.get(entity_type, (5000, 5000))


def find_available_port_in_range(entity_type, host="0.0.0.0"):
    """
    Trova la prima porta disponibile nel range dedicato per il tipo di entità.
    
    Args:
        entity_type: 'EA', 'AA', 'TLM', 'RootCA'
        host: Host su cui verificare
        
    Returns:
        Porta disponibile trovata, o None se nessuna porta disponibile
    """
    start_port, end_port = get_port_range_for_entity(entity_type)
    
    print(f"🔍 Cerco porta disponibile per {entity_type} nel range {start_port}-{end_port}...")
    
    for port in range(start_port, end_port + 1):
        if not is_port_in_use(host, port):
            print(f"✅ Porta {port} disponibile per {entity_type}")
            return port
    
    print(f"❌ ERRORE: Nessuna porta disponibile nel range {start_port}-{end_port} per {entity_type}!")
    print(f"   Tutte le {end_port - start_port + 1} porte sono occupate.")
    return None


def is_port_in_use(host, port):
    """
    Verifica se una porta è già in uso.
    
    Args:
        host: Host da testare
        port: Porta da testare
        
    Returns:
        True se la porta è in uso, False altrimenti
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def find_available_port(start_port, host="0.0.0.0", max_attempts=100):
    """
    Trova la prima porta disponibile a partire da start_port.
    
    Args:
        start_port: Porta iniziale da cui partire
        host: Host su cui verificare
        max_attempts: Numero massimo di tentativi
        
    Returns:
        Porta disponibile trovata, o None se non trovata
    """
    for port in range(start_port, start_port + max_attempts):
        if not is_port_in_use(host, port):
            return port
    return None


def check_port_conflicts(host, port, entity_type, entity_id):
    """
    Controlla se c'è un conflitto di porta e suggerisce alternative.
    
    Args:
        host: Host da verificare
        port: Porta richiesta
        entity_type: Tipo di entità
        entity_id: ID dell'entità
        
    Returns:
        Tuple (is_available, suggested_port)
    """
    if is_port_in_use(host, port):
        print(f"\n⚠️  ATTENZIONE: Porta {port} già in uso su {host}!")
        print(f"   Impossibile avviare {entity_type} '{entity_id}' su questa porta.")
        
        # Cerca porta alternativa
        alternative = find_available_port(port + 1, host)
        if alternative:
            print(f"   💡 Porta alternativa disponibile: {alternative}")
            return False, alternative
        else:
            print(f"   ❌ Nessuna porta alternativa trovata!")
            return False, None
    
    return True, port


def find_existing_entities(entity_type, base_dir="./data"):
    """
    Trova tutte le entità esistenti di un determinato tipo scansionando la directory.
    
    Args:
        entity_type: 'EA', 'AA', 'TLM', 'RootCA'
        base_dir: Directory base dove cercare
        
    Returns:
        List di ID esistenti (es. ['EA_001', 'EA_002', 'EA_FOR_AA_001'])
    """
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


def find_next_available_id(entity_type, base_dir="./data"):
    """
    Trova il prossimo ID numerico disponibile per un'entità.
    
    Args:
        entity_type: 'EA', 'AA', 'TLM'
        base_dir: Directory base dove cercare
        
    Returns:
        String con il prossimo ID disponibile (es. 'EA_003')
    """
    existing = find_existing_entities(entity_type, base_dir)
    
    # Estrai i numeri dalle entità esistenti (solo quelle con pattern TIPO_NNN)
    numbers = []
    pattern = re.compile(rf'^{entity_type}_(\d{{3}})$')
    
    for entity_id in existing:
        match = pattern.match(entity_id)
        if match:
            numbers.append(int(match.group(1)))
    
    # Trova il prossimo numero disponibile
    if not numbers:
        next_num = 1
    else:
        # Trova il primo buco nella sequenza, o usa max+1
        numbers.sort()
        next_num = None
        for i in range(1, numbers[-1] + 2):
            if i not in numbers:
                next_num = i
                break
    
    return f"{entity_type}_{next_num:03d}"


def get_or_create_root_ca():
    """
    Singleton pattern per RootCA - evita re-inizializzazioni multiple.
    
    Problema risolto: Ogni entità (EA, AA, TLM) creava la propria istanza RootCA,
    causando log duplicati "Nessun metadata Full CRL esistente" e spreco risorse.
    
    Returns:
        Istanza condivisa di RootCA
    """
    global _root_ca_instance
    
    if '_root_ca_instance' not in globals() or _root_ca_instance is None:
        print("📦 Creating shared RootCA instance...")
        _root_ca_instance = RootCA(base_dir="data/root_ca")
        print("✅ RootCA instance created and cached")
    else:
        print("♻️  Reusing cached RootCA instance")
    
    return _root_ca_instance


def get_or_create_tlm_main():
    """
    Singleton pattern per TLM_MAIN - evita re-inizializzazioni multiple.
    
    Tutte le AA condividono la stessa istanza TLM_MAIN per validare EC.
    Questo è conforme allo standard ETSI TS 102941 che raccomanda un
    Trust List Manager centralizzato.
    
    Returns:
        Istanza condivisa di TLM_MAIN
    """
    global _tlm_main_instance
    
    if '_tlm_main_instance' not in globals() or _tlm_main_instance is None:
        print("📦 Creating shared TLM_MAIN instance...")
        root_ca = get_or_create_root_ca()
        tlm_path = "./data/tlm/TLM_MAIN/"
        _tlm_main_instance = TrustListManager(root_ca, base_dir=tlm_path)
        print("✅ TLM_MAIN instance created and cached")
        print(f"   Trust anchors: {len(_tlm_main_instance.trust_anchors)}")
    else:
        print("♻️  Reusing cached TLM_MAIN instance")
        print(f"   Trust anchors: {len(_tlm_main_instance.trust_anchors)}")
    
    return _tlm_main_instance


def create_entity(entity_type, entity_id=None, ea_id=None):
    """
    Create PKI entity instance

    Args:
        entity_type: 'EA', 'AA', 'TLM', or 'RootCA'
        entity_id: Optional entity identifier
        ea_id: Optional EA identifier (only for AA type)

    Returns:
        Entity instance
    """
    print(f"\n{'='*70}")
    print(f"  Initializing {entity_type}")
    print(f"{'='*70}\n")

    if entity_type == "RootCA":
        entity_id = entity_id or "RootCA"
        # Usa singleton invece di creare nuova istanza
        entity = get_or_create_root_ca()

    elif entity_type == "EA":
        # Se non specificato, trova automaticamente il prossimo ID disponibile
        if not entity_id:
            entity_id = find_next_available_id("EA")
            print(f"📝 Auto-assigned ID: {entity_id}")
            existing = find_existing_entities("EA")
            if existing:
                print(f"ℹ️  Existing EA instances: {', '.join(sorted(existing))}")
        
        # Usa RootCA condivisa
        root_ca = get_or_create_root_ca()
        entity = EnrollmentAuthority(root_ca, ea_id=entity_id)
        
        # ===================================================================
        # REGISTRAZIONE AUTOMATICA IN TLM_MAIN
        # ===================================================================
        # Ogni EA creata viene automaticamente registrata nel TLM_MAIN
        # centralizzato in modo che tutte le AA possano validare i suoi EC
        # ===================================================================
        
        print(f"\n🔗 Auto-registering EA in central TLM...")
        tlm_main = get_or_create_tlm_main()
        
        # Verifica se EA è già registrata
        ea_ski = get_certificate_ski(entity.certificate)
        already_registered = any(anchor.get("ski") == ea_ski for anchor in tlm_main.trust_anchors)
        
        if already_registered:
            print(f"   ℹ️  EA '{entity_id}' already registered in TLM_MAIN")
        else:
            # Registra EA come trust anchor
            tlm_main.add_trust_anchor(entity.certificate, authority_type="EA")
            print(f"   ✅ EA '{entity_id}' registered in TLM_MAIN")
            
            # Pubblica Full CTL
            tlm_main.publish_full_ctl()
            print(f"   ✅ Full CTL published")
        
        print(f"   📊 Total trust anchors in TLM: {len(tlm_main.trust_anchors)}")

    elif entity_type == "AA":
        # Se non specificato, trova automaticamente il prossimo ID disponibile
        if not entity_id:
            entity_id = find_next_available_id("AA")
            print(f"📝 Auto-assigned ID: {entity_id}")
            existing = find_existing_entities("AA")
            if existing:
                print(f"ℹ️  Existing AA instances: {', '.join(sorted(existing))}")
        
        # Usa RootCA condivisa
        root_ca = get_or_create_root_ca()

        # ===================================================================
        # MODALITÀ TLM CENTRALIZZATA (ETSI-Compliant)
        # ===================================================================
        # Tutte le AA condividono lo stesso TLM_MAIN che contiene i trust
        # anchors di TUTTE le EA attive nel sistema.
        # Usa singleton per evitare re-inizializzazioni multiple.
        # ===================================================================
        
        print(f"\n🔗 Connecting to central TLM (ETSI-Compliant mode)...")
        tlm = get_or_create_tlm_main()
        
        # Mostra trust anchors disponibili
        if tlm.trust_anchors:
            print(f"\n✅ Central TLM has {len(tlm.trust_anchors)} trust anchor(s):")
            for anchor in tlm.trust_anchors:
                auth_type = anchor.get('authority_type', 'UNKNOWN')
                subject = anchor.get('subject_name', 'Unknown')
                print(f"   - {auth_type}: {subject}")
        else:
            print(f"\n⚠️  WARNING: TLM has no trust anchors!")
            print(f"   AA will reject all EC validation requests until EA are added to TLM.")
            print(f"   Add EA to TLM:")
            print(f"   1. Start EA: python server.py --entity EA --id EA_001")
            print(f"   2. Register: python scripts/register_ea_to_tlm.py EA_001")

        entity = AuthorizationAuthority(root_ca, tlm, aa_id=entity_id)

    elif entity_type == "TLM":
        # Se non specificato, trova automaticamente il prossimo ID disponibile
        if not entity_id:
            entity_id = find_next_available_id("TLM")
            print(f"📝 Auto-assigned ID: {entity_id}")
            existing = find_existing_entities("TLM")
            if existing:
                print(f"ℹ️  Existing TLM instances: {', '.join(sorted(existing))}")
        
        # Usa RootCA condivisa
        root_ca = get_or_create_root_ca()
        entity = TrustListManager(root_ca, base_dir=f"./data/tlm/{entity_id}/")

    else:
        raise ValueError(f"Unknown entity type: {entity_type}")

    print(f"\n✅ {entity_type} initialized successfully!")
    return entity


def print_startup_info(entity_type, config, entity):
    """Print server startup information"""
    print(f"\n{'='*70}")
    print(f"  SecureRoad PKI Server - {entity_type}")
    print(f"{'='*70}")
    print(f"  Entity ID: {getattr(entity, entity_type.lower() + '_id', 'N/A')}")
    print(f"  Host: {config['host']}")
    print(f"  Port: {config['port']}")
    print(f"  TLS: {'Enabled' if config['tls_enabled'] else 'Disabled ⚠️'}")
    print(f"  API Keys: {len(config['api_keys'])} configured")
    print(
        f"  Rate Limit: {config['rate_limit_per_second']} req/s (burst: {config['rate_limit_burst']})"
    )
    print(f"  Log Level: {config['log_level']}")
    print(f"{'='*70}\n")

    if entity_type == "EA":
        print("📋 Available Endpoints:")
        print("  POST   /enrollment/request     - Issue enrollment certificate")
        print("  POST   /enrollment/validation  - Validate EC for AA")
        print("  GET    /crl/full               - Full CRL")
        print("  GET    /crl/delta              - Delta CRL")

    elif entity_type == "AA":
        print("📋 Available Endpoints:")
        print("  POST   /authorization/request            - Issue authorization ticket")
        print("  POST   /authorization/request/butterfly  - Batch AT issuance")
        print("  GET    /crl/full                         - Full CRL")
        print("  GET    /crl/delta                        - Delta CRL")

    elif entity_type == "TLM":
        print("📋 Available Endpoints:")
        print("  GET    /ctl/full               - Full CTL")
        print("  GET    /ctl/delta              - Delta CTL")
        print("  POST   /ctl/update             - Update trust list")

    print("\n📊 Common Endpoints:")
    print("  GET    /                         - API information")
    print("  GET    /health                   - Health check")

    print(
        f"\n🔗 Base URL: http{'s' if config['tls_enabled'] else ''}://{config['host']}:{config['port']}"
    )

    if not config["tls_enabled"]:
        print("\n⚠️  WARNING: TLS is DISABLED!")
        print("   ETSI TS 102941 requires TLS for production!")
        print("   Enable TLS in config: 'tls_enabled': true")

    print(f"\n{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecureRoad PKI Production Server (ETSI TS 102941 Compliant)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start servers (ports auto-assigned from configured ranges)
  python server.py --entity EA --id EA_001
  python server.py --entity AA --id AA_001 --config prod.json
  python server.py --entity TLM --id TLM_MAIN --host 0.0.0.0
  
  # Generate secure API key
  python server.py --generate-key
        """,
    )

    parser.add_argument(
        "--entity",
        choices=["EA", "AA", "TLM", "RootCA"],
        help="Entity type to run (EA, AA, TLM, RootCA)",
    )
    
    parser.add_argument(
        "--generate-key",
        action="store_true",
        help="Generate a secure API key and exit",
    )

    parser.add_argument("--id", type=str, help="Entity identifier (default: auto-generated)")

    parser.add_argument(
        "--ea-id", 
        type=str, 
        help="EA identifier to use for AA initialization (default: creates dedicated EA_FOR_{AA_ID})"
    )

    parser.add_argument("--config", type=str, help="Path to JSON configuration file")

    parser.add_argument("--host", type=str, help="Host to bind (overrides config)")

    parser.add_argument("--port", type=int, help="Port to bind (overrides config)")

    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode (NOT for production!)"
    )

    args = parser.parse_args()

    # Handle --generate-key flag
    if args.generate_key:
        generate_api_key()
        sys.exit(0)
    
    # Validate --entity is required if not generating key
    if not args.entity:
        parser.error("--entity is required unless using --generate-key")

    # Load configuration
    config = load_config(args.config)

    # Apply CLI overrides
    if args.host:
        config["host"] = args.host
    
    # AUTO-SELEZIONE PORTA se non specificata
    if args.port:
        # Porta esplicitamente specificata dall'utente
        config["port"] = args.port
        print(f"🎯 Porta specificata manualmente: {config['port']}")
    else:
        # Trova automaticamente una porta libera nel range per questo tipo di entità
        auto_port = find_available_port_in_range(args.entity, config.get("host", "0.0.0.0"))
        if auto_port:
            config["port"] = auto_port
            print(f"✅ Porta selezionata automaticamente: {config['port']}")
        else:
            print(f"❌ ERRORE: Impossibile trovare una porta disponibile per {args.entity}!")
            sys.exit(1)
    
    if args.debug:
        config["debug"] = True
        print("⚠️  DEBUG MODE ENABLED - Not for production!")

    # VERIFICA CONFLITTI DI PORTA (solo se specificata manualmente)
    port_available = True
    suggested_port = None
    
    if args.port:
        print(f"\n🔍 Verifica disponibilità porta {config['port']} su {config['host']}...")
        port_available, suggested_port = check_port_conflicts(
            config["host"], 
            config["port"], 
            args.entity, 
            args.id or "auto"
        )
        
        if not port_available:
            if suggested_port:
                print(f"\n❓ Vuoi usare la porta alternativa {suggested_port}? (non implementato)")
                print(f"   Riavvia con: --port {suggested_port}")
            print(f"\n❌ ERRORE: Impossibile avviare il server sulla porta {config['port']}")
            print(f"   La porta è già occupata da un altro processo.")
            print(f"\n💡 SOLUZIONI:")
            print(f"   1. Ferma il processo che sta usando la porta {config['port']}")
            print(f"   2. Usa una porta diversa con --port {suggested_port or 'XXXX'}")
            print(f"   3. Controlla i processi attivi con: netstat -ano | findstr :{config['port']}")
            sys.exit(1)
        
        print(f"✅ Porta {config['port']} disponibile!\n")
    else:
        # Porta auto-assegnata, assumiamo sia disponibile (verrà verificata al bind)
        print(f"✅ Porta {config['port']} auto-assegnata dal range!\n")

    try:
        # Create entity
        entity = create_entity(args.entity, args.id, ea_id=args.ea_id)

        # Create Flask app
        app = create_app(args.entity, entity, config)

        # Print startup information
        print_startup_info(args.entity, config, entity)

        # Start server
        if config["tls_enabled"]:
            if not config["tls_cert"] or not config["tls_key"]:
                print("❌ TLS enabled but certificate/key not provided!")
                print("   Set 'tls_cert' and 'tls_key' in config")
                sys.exit(1)

            import ssl

            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(config["tls_cert"], config["tls_key"])
            
            # Configurazione mTLS (ETSI TS 102941 requirement)
            if config.get("mtls_required", False):
                print("🔐 mTLS enabled (client certificate required)")
                context.verify_mode = ssl.CERT_REQUIRED
                
                # Carica CA per verificare certificati client
                if config.get("tls_ca_cert"):
                    context.load_verify_locations(cafile=config["tls_ca_cert"])
                    print(f"   CA cert loaded: {config['tls_ca_cert']}")
                else:
                    print("⚠️  mTLS enabled but no CA cert provided!")
                    print("   Set 'tls_ca_cert' in config")
                    sys.exit(1)
            else:
                # TLS normale senza verifica client
                context.verify_mode = ssl.CERT_NONE

            print("🔒 Starting HTTPS server...")
            app.run(
                host=config["host"], port=config["port"], debug=config["debug"], ssl_context=context
            )
        else:
            print("🚀 Starting HTTP server...")
            app.run(host=config["host"], port=config["port"], debug=config["debug"])

    except KeyboardInterrupt:
        print("\n\n⚠️  Server stopped by user (Ctrl+C)")
        sys.exit(0)

    except Exception as e:
        print(f"\n\n❌ Server error: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


def generate_api_key():
    """Generate a secure API key and print it"""
    api_key = secrets.token_urlsafe(32)
    print("\n" + "="*70)
    print("🔑 SECURE API KEY GENERATED")
    print("="*70)
    print(f"\n{api_key}\n")
    print("⚠️  SAVE THIS KEY SECURELY!")
    print("   Add it to your config.json:")
    print('   {"api_keys": ["' + api_key + '"]}\n')
    print("="*70 + "\n")
    return api_key


if __name__ == "__main__":
    main()
