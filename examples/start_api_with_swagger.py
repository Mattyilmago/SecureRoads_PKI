"""
Script di esempio per avviare l'API REST con Swagger UI

Questo script:
1. Crea un'infrastruttura PKI di test (Root CA, EA, AA)
2. Avvia il server Flask con documentazione Swagger UI
3. Permette di esplorare e testare gli endpoint API interattivamente

Accesso Swagger UI:
    http://localhost:5000/api/docs

Endpoints disponibili:
    GET  /                           - Info API
    GET  /health                     - Health check
    GET  /api/docs                   - Swagger UI (documentazione interattiva)
    GET  /api/openapi.yaml           - Specifica OpenAPI
    
    POST /enrollment/request         - Richiesta EC
    POST /enrollment/validation      - Validazione (mTLS)
    POST /authorization/request      - Richiesta AT
    POST /authorization/request/butterfly - Richiesta AT batch
    
    GET  /crl/full                   - Download Full CRL
    GET  /crl/delta                  - Download Delta CRL
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from api.flask_app_factory import create_app


def main():
    print("=" * 80)
    print("🚀 SecureRoad PKI - API Server with Swagger UI")
    print("=" * 80)
    print()
    
    # 1. Crea infrastruttura PKI
    print("📦 Creando infrastruttura PKI di test...")
    
    root_ca = RootCA(base_dir="./data/root_ca/")
    print("✅ Root CA creata")
    
    ea = EnrollmentAuthority(
        root_ca=root_ca,
        ea_id="EA_DEMO",
        base_dir="./data/ea/"
    )
    print("✅ Enrollment Authority creata")
    
    aa = AuthorizationAuthority(
        root_ca=root_ca,
        aa_id="AA_DEMO",
        base_dir="./data/aa/"
    )
    print("✅ Authorization Authority creata")
    
    print()
    print("=" * 80)
    print("🌐 Avviando server API...")
    print("=" * 80)
    print()
    
    # 2. Crea app Flask per EA (puoi scegliere EA o AA)
    app = create_app(
        entity_type="EA",
        entity_instance=ea,
        config={
            "api_keys": ["demo-api-key-123"],  # API key per test
            "cors_origins": "*",  # Consente tutte le origini per Swagger UI
            "log_level": "INFO"
        }
    )
    
    print("📚 Documentazione API disponibile:")
    print()
    print("   🔗 Swagger UI:    http://localhost:5000/api/docs")
    print("   📄 OpenAPI Spec:  http://localhost:5000/api/openapi.yaml")
    print("   ℹ️  API Info:      http://localhost:5000/")
    print("   💚 Health Check:  http://localhost:5000/health")
    print()
    print("=" * 80)
    print("🔑 API Key per test: demo-api-key-123")
    print("   (Aggiungi header: X-API-Key: demo-api-key-123)")
    print("=" * 80)
    print()
    print("⚡ Server in esecuzione su http://localhost:5000")
    print("   Premi Ctrl+C per fermare")
    print()
    
    # 3. Avvia server
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )


if __name__ == "__main__":
    main()
