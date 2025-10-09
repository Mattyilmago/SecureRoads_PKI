"""
Production Server Launcher for SecureRoad PKI.

ETSI TS 102941 compliant REST API server supporting EA, AA, TLM, and RootCA entities.

Usage:
    python start_production_server.py --entity EA --config config.json
    python start_production_server.py --entity AA --port 5002
"""

import argparse
import json
import os
import re
import secrets
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from api.flask_app_factory import create_app
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from managers.trust_list_manager import TrustListManager


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
        entity = RootCA(base_dir="data/root_ca")

    elif entity_type == "EA":
        # Se non specificato, trova automaticamente il prossimo ID disponibile
        if not entity_id:
            entity_id = find_next_available_id("EA")
            print(f"📝 Auto-assigned ID: {entity_id}")
            existing = find_existing_entities("EA")
            if existing:
                print(f"ℹ️  Existing EA instances: {', '.join(sorted(existing))}")
        
        root_ca = RootCA(base_dir="data/root_ca")
        entity = EnrollmentAuthority(root_ca, ea_id=entity_id)

    elif entity_type == "AA":
        # Se non specificato, trova automaticamente il prossimo ID disponibile
        if not entity_id:
            entity_id = find_next_available_id("AA")
            print(f"📝 Auto-assigned ID: {entity_id}")
            existing = find_existing_entities("AA")
            if existing:
                print(f"ℹ️  Existing AA instances: {', '.join(sorted(existing))}")
        
        root_ca = RootCA(base_dir="data/root_ca")

        # Initialize TLM with EA trust anchor
        if ea_id:
            # Usa EA esistente specificata
            print(f"🔗 Using existing EA '{ea_id}' for {entity_id}...")
            ea = EnrollmentAuthority(root_ca, ea_id=ea_id)
            print(f"✅ EA '{ea_id}' loaded")
        else:
            # Trova automaticamente un'EA libera o creane una nuova
            print(f"🔍 Looking for available EA for {entity_id}...")
            
            # Cerca EA standalone già esistenti (non usate da altre AA)
            existing_eas = find_existing_entities("EA")
            existing_aas = find_existing_entities("AA")
            
            # Filtra EA che non sono già associate ad altre AA
            used_ea_ids = set()
            for aa_id in existing_aas:
                if aa_id != entity_id:  # Esclude l'AA corrente se sta reinizializzando
                    # Pattern: EA_FOR_AA_XXX
                    potential_ea = f"EA_FOR_{aa_id}"
                    if potential_ea in existing_eas:
                        used_ea_ids.add(potential_ea)
            
            # Cerca EA standalone disponibili (pattern EA_NNN)
            available_standalone = [ea for ea in existing_eas 
                                   if re.match(r'^EA_\d{3}$', ea) and ea not in used_ea_ids]
            
            if available_standalone:
                # Usa la prima EA standalone disponibile
                ea_id_to_use = sorted(available_standalone)[0]
                print(f"♻️  Reusing standalone EA '{ea_id_to_use}'")
                ea = EnrollmentAuthority(root_ca, ea_id=ea_id_to_use)
            else:
                # Crea una nuova EA dedicata
                ea_id_for_aa = f"EA_FOR_{entity_id}"
                print(f"🆕 Creating dedicated EA '{ea_id_for_aa}'...")
                ea = EnrollmentAuthority(root_ca, ea_id=ea_id_for_aa)
                print(f"✅ Dedicated EA '{ea_id_for_aa}' created")

        print("Initializing TLM for AA...")
        tlm_id = f"TLM_FOR_{entity_id}"
        tlm = TrustListManager(root_ca, base_dir=f"./data/tlm/{tlm_id}/")
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")
        print(f"✅ TLM '{tlm_id}' initialized with {len(tlm.trust_anchors)} trust anchor(s)")

        entity = AuthorizationAuthority(root_ca, tlm, aa_id=entity_id)

    elif entity_type == "TLM":
        # Se non specificato, trova automaticamente il prossimo ID disponibile
        if not entity_id:
            entity_id = find_next_available_id("TLM")
            print(f"📝 Auto-assigned ID: {entity_id}")
            existing = find_existing_entities("TLM")
            if existing:
                print(f"ℹ️  Existing TLM instances: {', '.join(sorted(existing))}")
        
        root_ca = RootCA(base_dir="data/root_ca")
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
  # Start servers
  python start_production_server.py --entity EA
  python start_production_server.py --entity AA --port 5002 --config prod.json
  python start_production_server.py --entity TLM --id TLM_MAIN --host 0.0.0.0
  
  # Generate secure API key
  python start_production_server.py --generate-key
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
    if args.port:
        config["port"] = args.port
    if args.debug:
        config["debug"] = True
        print("⚠️  DEBUG MODE ENABLED - Not for production!")

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
