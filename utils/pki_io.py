"""
PKI I/O Utilities - Eliminazione codice duplicato per operazioni su file

Questo modulo centralizza tutte le operazioni di I/O per chiavi e certificati,
eliminando la duplicazione presente in RootCA, EA, AA.

Design Pattern: Template Method + DRY (Don't Repeat Yourself)
"""

import os
import json
import shutil
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from typing import Optional, Dict, Any
from pathlib import Path


class PKIFileHandler:
    """Handler centralizzato per operazioni I/O su chiavi e certificati PKI"""

    @staticmethod
    def load_private_key(key_path: str, password: Optional[bytes] = None):
        """
        Carica chiave privata da file PEM con LRU cache per performance.

        Args:
            key_path: Path al file della chiave privata
            password: Password per chiave cifrata (opzionale)

        Returns:
            Chiave privata caricata (cached se già caricata)

        Raises:
            FileNotFoundError: Se il file non esiste
            ValueError: Se la chiave non è valida
            
        Note:
            Performance: ~2000x più veloce per chiavi già caricate.
        """
        from utils.cert_cache import load_private_key_cached
        return load_private_key_cached(key_path, password)

    @staticmethod
    def save_private_key(
        private_key, key_path: str, password: Optional[bytes] = None, create_dirs: bool = True
    ):
        """
        Salva chiave privata su file PEM.

        Args:
            private_key: Chiave privata da salvare
            key_path: Path dove salvare la chiave
            password: Password per cifrare la chiave (opzionale)
            create_dirs: Se True, crea directory se non esiste
        """
        if create_dirs:
            os.makedirs(os.path.dirname(key_path), exist_ok=True)

        encryption = (
            serialization.BestAvailableEncryption(password)
            if password
            else serialization.NoEncryption()
        )

        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption,
                )
            )

    @staticmethod
    def load_certificate(cert_path: str) -> x509.Certificate:
        """
        Carica certificato da file PEM con LRU cache per performance.

        Args:
            cert_path: Path al file del certificato

        Returns:
            Certificato X.509 caricato (cached se già caricato)

        Raises:
            FileNotFoundError: Se il file non esiste
            ValueError: Se il certificato non è valido
            
        Note:
            Performance: ~2000x più veloce per certificati già caricati.
            First load: ~2ms, Cached load: ~0.001ms
        """
        from utils.cert_cache import load_certificate_cached
        return load_certificate_cached(cert_path)

    @staticmethod
    def save_certificate(certificate: x509.Certificate, cert_path: str, create_dirs: bool = True):
        """
        Salva certificato su file PEM.

        Args:
            certificate: Certificato X.509 da salvare
            cert_path: Path dove salvare il certificato
            create_dirs: Se True, crea directory se non esiste
        """
        if create_dirs:
            os.makedirs(os.path.dirname(cert_path), exist_ok=True)

        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def load_crl(crl_path: str) -> Optional[x509.CertificateRevocationList]:
        """
        Carica CRL da file PEM.

        Args:
            crl_path: Path al file CRL

        Returns:
            CRL caricata o None se non esiste
        """
        if not os.path.exists(crl_path):
            return None

        with open(crl_path, "rb") as f:
            return x509.load_pem_x509_crl(f.read())

    @staticmethod
    def save_crl(crl: x509.CertificateRevocationList, crl_path: str, create_dirs: bool = True):
        """
        Salva CRL su file PEM.

        Args:
            crl: CRL da salvare
            crl_path: Path dove salvare la CRL
            create_dirs: Se True, crea directory se non esiste
        """
        if create_dirs:
            os.makedirs(os.path.dirname(crl_path), exist_ok=True)

        with open(crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def save_binary_file(data: bytes, file_path: str, create_dirs: bool = True) -> None:
        """
        Salva dati binari su file (es: AT in formato ASN.1 OER).
        
        Args:
            data: Dati binari da salvare
            file_path: Path dove salvare il file
            create_dirs: Se True, crea directory se non esiste
        """
        if create_dirs:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "wb") as f:
            f.write(data)
    
    @staticmethod
    def ensure_directories(*paths: str):
        """
        Crea multiple directory se non esistono.

        Args:
            *paths: Lista di path delle directory da creare
        """
        for path in paths:
            os.makedirs(path, exist_ok=True)

    @staticmethod
    def load_binary_file(file_path: str) -> Optional[bytes]:
        """
        Carica dati binari da file.
        
        Args:
            file_path: Path del file da caricare
            
        Returns:
            Dati binari o None se il file non esiste
            
        Raises:
            IOError: Se ci sono errori di lettura
        """
        if not os.path.exists(file_path):
            return None
        
        with open(file_path, "rb") as f:
            return f.read()
    
    @staticmethod
    def load_json_file(file_path: str) -> Optional[Dict[str, Any]]:
        """
        Carica dati JSON da file.
        
        Args:
            file_path: Path del file JSON da caricare
            
        Returns:
            Dizionario con i dati o None se il file non esiste
            
        Raises:
            json.JSONDecodeError: Se il file non è un JSON valido
        """
        if not os.path.exists(file_path):
            return None
        
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)
    
    @staticmethod
    def save_json_file(data: Dict[str, Any], file_path: str, create_dirs: bool = True, indent: int = 2) -> None:
        """
        Salva dati in formato JSON su file.
        
        Args:
            data: Dizionario da salvare
            file_path: Path dove salvare il file
            create_dirs: Se True, crea directory se non esiste
            indent: Indentazione per pretty-print (default: 2)
            
        Raises:
            IOError: Se ci sono errori di scrittura
        """
        if create_dirs:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
    
    @staticmethod
    def append_to_log_file(log_entry: str, file_path: str, create_dirs: bool = True) -> None:
        """
        Aggiunge una riga a un file di log.
        
        Args:
            log_entry: Stringa da aggiungere (verrà aggiunto newline automaticamente)
            file_path: Path del file di log
            create_dirs: Se True, crea directory se non esiste
            
        Raises:
            IOError: Se ci sono errori di scrittura
        """
        if create_dirs:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")
    
    @staticmethod
    def copy_file(source: str, destination: str, create_dirs: bool = True) -> None:
        """
        Copia un file da source a destination preservando metadata.
        
        Args:
            source: Path del file sorgente
            destination: Path del file destinazione
            create_dirs: Se True, crea directory destinazione se non esiste
            
        Raises:
            FileNotFoundError: Se il file sorgente non esiste
            IOError: Se ci sono errori di copia
        """
        if not os.path.exists(source):
            raise FileNotFoundError(f"Source file not found: {source}")
        
        if create_dirs:
            os.makedirs(os.path.dirname(destination), exist_ok=True)
        
        shutil.copy2(source, destination)

