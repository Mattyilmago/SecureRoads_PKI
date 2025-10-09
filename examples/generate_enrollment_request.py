#!/usr/bin/env python3
"""
Script per generare una richiesta di enrollment valida
da usare con Swagger UI o altri client API
"""

import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_enrollment_request():
    """Genera una richiesta di enrollment con chiave pubblica valida"""
    
    # 1. Genera coppia di chiavi ECC (NIST P-256)
    print("🔐 Generando coppia di chiavi ECC...")
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    # 2. Serializza chiave pubblica in formato PEM
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # 3. Serializza chiave privata (per uso successivo)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # 4. Crea richiesta enrollment
    enrollment_request = {
        "its_id": "VEHICLE_001",
        "public_key": public_key_pem,
        "requested_attributes": {
            "country": "IT",
            "organization": "SecureRoad"
        }
    }
    
    # 5. Stampa risultati
    print("\n" + "="*80)
    print("✅ RICHIESTA ENROLLMENT GENERATA")
    print("="*80)
    
    print("\n📋 COPIA QUESTO JSON IN SWAGGER UI:\n")
    print(json.dumps(enrollment_request, indent=2))
    
    print("\n" + "="*80)
    print("🔑 CHIAVE PRIVATA (salvala per dopo!):")
    print("="*80)
    print(private_key_pem)
    
    # 6. Salva su file per backup
    with open("enrollment_request.json", "w") as f:
        json.dump(enrollment_request, f, indent=2)
    
    with open("vehicle_001_private_key.pem", "w") as f:
        f.write(private_key_pem)
    
    print("\n💾 File salvati:")
    print("   - enrollment_request.json")
    print("   - vehicle_001_private_key.pem")
    
    print("\n" + "="*80)
    print("🚀 COME USARLO IN SWAGGER UI:")
    print("="*80)
    print("1. Vai a http://localhost:5000/api/docs")
    print("2. Clicca su 'POST /enrollment/request'")
    print("3. Clicca 'Try it out'")
    print("4. Aggiungi header: X-API-Key: demo-api-key-123")
    print("5. Incolla il JSON sopra nel campo 'Request body'")
    print("6. Clicca 'Execute'")
    print("="*80 + "\n")
    
    return enrollment_request, private_key_pem


if __name__ == "__main__":
    generate_enrollment_request()
