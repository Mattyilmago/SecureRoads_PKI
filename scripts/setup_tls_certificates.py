#!/usr/bin/env python3
"""
Script per generare certificati TLS per tutti i server PKI
Conforme a ETSI TS 102941 requirements
"""

import os
import ipaddress
from pathlib import Path
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def create_tls_ca():
    """Crea Certificate Authority per TLS"""
    print("\n=== Creazione TLS CA ===")
    
    # Directory per certificati
    certs_dir = Path("certs")
    certs_dir.mkdir(exist_ok=True)
    
    ca_key_path = certs_dir / "tls_ca_key.pem"
    ca_cert_path = certs_dir / "tls_ca_cert.pem"
    
    # Genera chiave CA
    ca_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Crea certificato CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureRoad PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureRoad TLS CA"),
    ])
    
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 anni
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    # Salva chiave CA
    with open(ca_key_path, "wb") as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"✅ CA Key salvata: {ca_key_path}")
    
    # Salva certificato CA
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print(f"✅ CA Cert salvato: {ca_cert_path}")
    
    return ca_key, ca_cert


def create_server_certificate(entity_id, port, ca_key, ca_cert):
    """Crea certificato TLS per un server"""
    print(f"\n=== Creazione certificato per {entity_id} (:{port}) ===")
    
    certs_dir = Path("certs")
    key_path = certs_dir / f"{entity_id.lower()}_key.pem"
    cert_path = certs_dir / f"{entity_id.lower()}_cert.pem"
    
    # Genera chiave server
    server_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Subject con Common Name = entity ID
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureRoad PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, entity_id),
    ])
    
    # SANs (Subject Alternative Names) - richiesto per TLS moderno
    san_list = [
        x509.DNSName("localhost"),
        x509.DNSName("127.0.0.1"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]
    
    # Crea certificato server
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 anno
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,  # Per mTLS
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    # Salva chiave server
    with open(key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"  ✅ Key: {key_path}")
    
    # Salva certificato server
    with open(cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  ✅ Cert: {cert_path}")
    
    return key_path, cert_path


def create_client_certificate(client_id, ca_key, ca_cert):
    """Crea certificato client per mTLS"""
    print(f"\n=== Creazione certificato client per {client_id} ===")
    
    certs_dir = Path("certs/clients")
    certs_dir.mkdir(exist_ok=True, parents=True)
    
    key_path = certs_dir / f"{client_id.lower()}_key.pem"
    cert_path = certs_dir / f"{client_id.lower()}_cert.pem"
    
    # Genera chiave client
    client_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    
    # Subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureRoad PKI"),
        x509.NameAttribute(NameOID.COMMON_NAME, client_id),
    ])
    
    # Crea certificato client
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    
    # Salva chiave client
    with open(key_path, "wb") as f:
        f.write(client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"  ✅ Key: {key_path}")
    
    # Salva certificato client
    with open(cert_path, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))
    print(f"  ✅ Cert: {cert_path}")
    
    return key_path, cert_path


def main():
    """Main function"""
    import ipaddress
    
    print("\n" + "="*70)
    print("  SETUP CERTIFICATI TLS - ETSI TS 102941 Compliant")
    print("="*70)
    
    # Crea CA
    ca_key, ca_cert = create_tls_ca()
    
    # Entities da configurare
    entities = [
        ("EA_001", 5000),
        ("EA_002", 5001),
        ("EA_003", 5002),
        ("AA_001", 5003),
        ("AA_002", 5004),
        ("TLM_MAIN", 5005),
    ]
    
    # Crea certificati server
    for entity_id, port in entities:
        create_server_certificate(entity_id, port, ca_key, ca_cert)
    
    # Crea certificati client per test
    print("\n=== Certificati Client per Testing ===")
    create_client_certificate("TEST_CLIENT", ca_key, ca_cert)
    create_client_certificate("DASHBOARD_CLIENT", ca_key, ca_cert)
    
    print("\n" + "="*70)
    print("  ✅ SETUP COMPLETATO")
    print("="*70)
    print("\nProssimi passi:")
    print("1. Configura server.py per usare i certificati TLS")
    print("2. Aggiorna config files con tls_enabled: true")
    print("3. Aggiorna test per usare HTTPS con certificati client")
    print("\nFile generati:")
    print("  - certs/tls_ca_cert.pem (CA pubblico)")
    print("  - certs/tls_ca_key.pem (CA privato)")
    print("  - certs/{entity}_cert.pem (certificati server)")
    print("  - certs/{entity}_key.pem (chiavi private server)")
    print("  - certs/clients/*_cert.pem (certificati client per mTLS)")
    print()


if __name__ == "__main__":
    main()
