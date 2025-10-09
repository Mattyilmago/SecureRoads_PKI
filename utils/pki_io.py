"""
PKI I/O Utilities - Eliminazione codice duplicato per operazioni su file

Questo modulo centralizza tutte le operazioni di I/O per chiavi e certificati,
eliminando la duplicazione presente in RootCA, EA, AA.

Design Pattern: Template Method + DRY (Don't Repeat Yourself)
"""

import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from typing import Optional


class PKIFileHandler:
    """Handler centralizzato per operazioni I/O su chiavi e certificati PKI"""

    @staticmethod
    def load_private_key(key_path: str, password: Optional[bytes] = None):
        """
        Carica chiave privata da file PEM.

        Args:
            key_path: Path al file della chiave privata
            password: Password per chiave cifrata (opzionale)

        Returns:
            Chiave privata caricata

        Raises:
            FileNotFoundError: Se il file non esiste
            ValueError: Se la chiave non è valida
        """
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Chiave privata non trovata: {key_path}")

        with open(key_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=password)

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
        Carica certificato da file PEM.

        Args:
            cert_path: Path al file del certificato

        Returns:
            Certificato X.509 caricato

        Raises:
            FileNotFoundError: Se il file non esiste
            ValueError: Se il certificato non è valido
        """
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Certificato non trovato: {cert_path}")

        with open(cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

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
    def ensure_directories(*paths: str):
        """
        Crea multiple directory se non esistono.

        Args:
            *paths: Lista di path delle directory da creare
        """
        for path in paths:
            os.makedirs(path, exist_ok=True)
