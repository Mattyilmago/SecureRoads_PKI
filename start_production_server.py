"""
Production Server Launcher for SecureRoad PKI.

ETSI TS 102941 compliant REST API server supporting EA, AA, TLM, and RootCA entities.

Usage:
    python start_production_server.py --entity EA --config config.json
    python start_production_server.py --entity AA --port 5002
"""

import argparse
import json
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


def create_entity(entity_type, entity_id=None):
    """
    Create PKI entity instance

    Args:
        entity_type: 'EA', 'AA', 'TLM', or 'RootCA'
        entity_id: Optional entity identifier

    Returns:
        Entity instance
    """
    print(f"\n{'='*70}")
    print(f"  Initializing {entity_type}")
    print(f"{'='*70}\n")

    if entity_type == "RootCA":
        entity_id = entity_id or "RootCA"
        entity = RootCA(entity_id, base_dir="data/root_ca")

    elif entity_type == "EA":
        entity_id = entity_id or "EA_001"
        root_ca = RootCA("RootCA", base_dir="data/root_ca")
        entity = EnrollmentAuthority(root_ca, ea_id=entity_id)

    elif entity_type == "AA":
        entity_id = entity_id or "AA_001"
        root_ca = RootCA("RootCA", base_dir="data/root_ca")

        # Initialize TLM with EA trust anchor
        print("Initializing TLM for AA...")
        ea = EnrollmentAuthority(root_ca, ea_id="EA_001")

        tlm = TrustListManager("TLM_001")
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")
        print(f"✅ TLM initialized with {len(tlm.trust_anchors)} trust anchor(s)")

        entity = AuthorizationAuthority(root_ca, tlm, aa_id=entity_id)

    elif entity_type == "TLM":
        entity_id = entity_id or "TLM_001"
        entity = TrustListManager(entity_id)

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
  python start_production_server.py --entity EA
  python start_production_server.py --entity AA --port 5002 --config prod.json
  python start_production_server.py --entity TLM --id TLM_MAIN --host 0.0.0.0
        """,
    )

    parser.add_argument(
        "--entity",
        required=True,
        choices=["EA", "AA", "TLM", "RootCA"],
        help="Entity type to run (EA, AA, TLM, RootCA)",
    )

    parser.add_argument("--id", type=str, help="Entity identifier (default: auto-generated)")

    parser.add_argument("--config", type=str, help="Path to JSON configuration file")

    parser.add_argument("--host", type=str, help="Host to bind (overrides config)")

    parser.add_argument("--port", type=int, help="Port to bind (overrides config)")

    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode (NOT for production!)"
    )

    args = parser.parse_args()

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
        entity = create_entity(args.entity, args.id)

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


if __name__ == "__main__":
    main()
