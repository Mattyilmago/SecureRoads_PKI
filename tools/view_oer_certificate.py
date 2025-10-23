"""
OER Certificate Viewer

Visualizza certificati ASN.1 OER in formato leggibile.
I file .oer sono binari e non possono essere visualizzati direttamente in VS Code.

Usage:
    python tools/view_oer_certificate.py <path_to_certificate.oer>
    python tools/view_oer_certificate.py pki_data/aa/AA_001/certificates/aa_certificate.oer

Author: SecureRoad PKI Project
Date: October 2025
"""

import sys
import asn1tools
from pathlib import Path
from binascii import hexlify

# Aggiungi la directory root al path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import degli schema ASN.1
PROTOCOLS_DIR = Path(__file__).parent.parent / "protocols"
IEEE1609DOT2_SCHEMA = PROTOCOLS_DIR / "ieee1609dot2.asn"
ETSI_TS_103097_SCHEMA = PROTOCOLS_DIR / "etsi_ts_103097.asn"
ETSI_TS_102941_SCHEMA = PROTOCOLS_DIR / "etsi_ts_102941.asn"

# Compila gli schema ASN.1
try:
    asn1_compiler = asn1tools.compile_files(
        [
            str(IEEE1609DOT2_SCHEMA),
            str(ETSI_TS_103097_SCHEMA),
            str(ETSI_TS_102941_SCHEMA)
        ],
        codec="oer"
    )
except Exception as e:
    print(f"❌ Errore durante la compilazione degli schema ASN.1: {e}")
    sys.exit(1)


def format_bytes(data: bytes, max_length: int = 32) -> str:
    """Formatta bytes in esadecimale con troncamento"""
    if len(data) <= max_length:
        return hexlify(data).decode('ascii')
    else:
        return hexlify(data[:max_length]).decode('ascii') + f"... ({len(data)} bytes total)"


def print_certificate(cert_data: dict, indent: int = 0) -> None:
    """Stampa ricorsivamente i dati del certificato in formato leggibile"""
    prefix = "  " * indent
    
    for key, value in cert_data.items():
        if isinstance(value, dict):
            print(f"{prefix}{key}:")
            print_certificate(value, indent + 1)
        elif isinstance(value, bytes):
            print(f"{prefix}{key}: {format_bytes(value)}")
        elif isinstance(value, list):
            print(f"{prefix}{key}:")
            for i, item in enumerate(value):
                if isinstance(item, dict):
                    print(f"{prefix}  [{i}]:")
                    print_certificate(item, indent + 2)
                elif isinstance(item, bytes):
                    print(f"{prefix}  [{i}]: {format_bytes(item)}")
                else:
                    print(f"{prefix}  [{i}]: {item}")
        else:
            print(f"{prefix}{key}: {value}")


def view_oer_certificate(file_path: str) -> None:
    """
    Visualizza un certificato OER
    
    Args:
        file_path: Percorso al file .oer
    """
    path = Path(file_path)
    
    if not path.exists():
        print(f"❌ File non trovato: {file_path}")
        sys.exit(1)
    
    if not path.suffix == '.oer':
        print(f"⚠️  Attenzione: Il file non ha estensione .oer")
    
    # Leggi il file binario
    try:
        with open(path, 'rb') as f:
            oer_data = f.read()
    except Exception as e:
        print(f"❌ Errore nella lettura del file: {e}")
        sys.exit(1)
    
    print(f"\n{'='*70}")
    print(f"  CERTIFICATO OER: {path.name}")
    print(f"{'='*70}")
    print(f"Percorso: {path.absolute()}")
    print(f"Dimensione: {len(oer_data)} bytes")
    print(f"\nDati RAW (primi 64 bytes):")
    print(f"  {format_bytes(oer_data, 64)}")
    print(f"\n{'='*70}")
    
    # Prova a decodificare come EtsiTs103097Certificate
    try:
        cert_decoded = asn1_compiler.decode('EtsiTs103097Certificate', oer_data)
        print(f"  DECODIFICA ASN.1 (EtsiTs103097Certificate)")
        print(f"{'='*70}\n")
        print_certificate(cert_decoded)
        print(f"\n{'='*70}")
        print(f"✅ Certificato decodificato con successo!")
        print(f"{'='*70}\n")
    except Exception as e:
        print(f"\n❌ Errore nella decodifica ASN.1: {e}")
        print(f"\nIl file potrebbe essere:")
        print(f"  - Un certificato in formato diverso")
        print(f"  - Un messaggio ETSI (EnrollmentResponse, etc.)")
        print(f"  - Corrotto o non valido")
        print(f"\nProva a usare altri decoder o contatta il supporto.")
        sys.exit(1)


def main():
    """Entry point"""
    if len(sys.argv) < 2:
        print("Usage: python tools/view_oer_certificate.py <path_to_certificate.oer>")
        print("\nEsempio:")
        print("  python tools/view_oer_certificate.py pki_data/aa/AA_001/certificates/aa_certificate.oer")
        print("  python tools/view_oer_certificate.py pki_data/ea/EA_001/certificates/ea_certificate.oer")
        sys.exit(1)
    
    certificate_path = sys.argv[1]
    view_oer_certificate(certificate_path)


if __name__ == "__main__":
    main()
