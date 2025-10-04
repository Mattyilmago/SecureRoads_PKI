from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags
from datetime import datetime, timedelta, timezone
import os

from managers.crl_manager import CRLManager
from utils.cert_utils import get_certificate_identifier, get_short_identifier, get_certificate_ski


class RootCA:
    def __init__(self, base_dir="./data/root_ca/"):
        self.ca_certificate_path = os.path.join(base_dir, "certificates/root_ca_certificate.pem")
        self.ca_key_path = os.path.join(base_dir, "private_keys/root_ca_key.pem")
        self.crl_path = os.path.join(base_dir, "crl/root_ca_crl.pem")
        print(f"[RootCA] Inizializzando Root CA...")
        print(f"[RootCA] Percorso certificato: {self.ca_certificate_path}")
        print(f"[RootCA] Percorso chiave privata: {self.ca_key_path}")
        print(f"[RootCA] Percorso CRL: {self.crl_path}")

        self.private_key = None
        self.certificate = None

        # Assicura che le directory esistano
        print(f"[RootCA] Creando directory necessarie...")
        for d in [
            os.path.dirname(self.ca_certificate_path),
            os.path.dirname(self.ca_key_path),
            os.path.dirname(self.crl_path),
        ]:
            os.makedirs(d, exist_ok=True)

        # Prova a caricare chiave/cert
        print(f"[RootCA] Caricando o generando chiave e certificato...")
        self.load_or_generate_ca()

        # Inizializza CRLManager dopo aver caricato certificato e chiave privata
        print(f"[RootCA] Inizializzando CRLManager per RootCA...")
        self.crl_manager = CRLManager(
            authority_id="RootCA",
            base_dir=base_dir,
            issuer_certificate=self.certificate,
            issuer_private_key=self.private_key,
        )
        print(f"[RootCA] CRLManager inizializzato con successo!")

        print(f"[RootCA] Inizializzazione completata!")

    # Carica chiave/cert se esistono, altrimenti li genera
    def load_or_generate_ca(self):
        print(f"[RootCA] Verificando esistenza chiave e certificato...")
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_certificate_path):
            print(f"[RootCA] Chiave e certificato esistenti trovati, caricandoli...")
            self.load_ca_keypair()
            self.load_certificate()
        else:
            print(f"[RootCA] Chiave o certificato non trovati, generandoli da zero...")
            self.generate_ca_keypair()
            self.generate_self_signed_certificate()

    # Genera una chiave privata ECC e la salva su file
    def generate_ca_keypair(self):
        print(f"[RootCA] Generando chiave privata ECC (SECP256R1)...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        print(f"[RootCA] Salvando chiave privata in: {self.ca_key_path}")
        with open(self.ca_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        print(f"[RootCA] Chiave privata generata e salvata con successo!")

    # Genera e salva un certificato X.509 self-signed per la Root CA
    def generate_self_signed_certificate(self):
        print(f"[RootCA] Generando certificato self-signed...")
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test RootCA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "RootCA"),
            ]
        )
        print(f"[RootCA] Subject/Issuer: C=IT, O=Test RootCA, CN=RootCA")
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(
                # Valido per 10 anni
                datetime.now(timezone.utc)
                + timedelta(days=3650)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .sign(self.private_key, hashes.SHA256())
        )

        self.certificate = cert
        print(f"[RootCA] Certificato generato con serial number: {cert.serial_number}")
        print(f"[RootCA] Validità: dal {cert.not_valid_before_utc} al {cert.not_valid_after_utc}")
        print(f"[RootCA] Salvando certificato in: {self.ca_certificate_path}")
        with open(self.ca_certificate_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[RootCA] Certificato self-signed generato e salvato con successo!")

    # Carica la chiave privata ECC dal file PEM
    def load_ca_keypair(self):
        print(f"[RootCA] Caricando chiave privata da: {self.ca_key_path}")
        with open(self.ca_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        print(f"[RootCA] Chiave privata caricata con successo!")

    # Carica il certificato Root CA dal file PEM
    def load_certificate(self):
        print(f"[RootCA] Caricando certificato da: {self.ca_certificate_path}")
        with open(self.ca_certificate_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        print(f"[RootCA] Certificato caricato con successo!")
        print(f"[RootCA] Subject: {self.certificate.subject}")
        print(f"[RootCA] Serial number: {self.certificate.serial_number}")
        print(
            f"[RootCA] Validità: dal {self.certificate.not_valid_before_utc} al {self.certificate.not_valid_after_utc}"
        )

    # Firma un certificato subordinato (EA/AA)
    def sign_certificate(self, subject_public_key, subject_name, is_ca=False):
        print(f"[RootCA] Firmando certificato per: {subject_name}")
        print(f"[RootCA] Tipo certificato: {'CA' if is_ca else 'End Entity'}")

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name),
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            ]
        )

        serial_number = x509.random_serial_number()
        print(f"[RootCA] Serial number assegnato: {serial_number}")

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(subject_public_key)
            .serial_number(serial_number)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))  # 1 anno di validità
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
                critical=True,
            )
            .sign(self.private_key, hashes.SHA256())
        )

        print(f"[RootCA] Certificato firmato con successo!")
        print(f"[RootCA] Validità: dal {cert.not_valid_before_utc} al {cert.not_valid_after_utc}")
        return cert

    # Salva certificato subordinato su file
    def save_subordinate_certificate(self, cert, base_dir="./data/"):
        """
        Salva il certificato subordinato firmato nell'archivio della RootCA.

        Ogni certificato viene salvato con un nome univoco che include l'ID
        dell'autorità, permettendo di archiviare certificati di più EA e AA.

        Nota: Ogni autorità subordinata (EA/AA) salva già il proprio certificato
        nella propria cartella durante l'inizializzazione. Questo metodo serve
        solo per mantenere una copia archivio centralizzata presso la RootCA.

        Args:
            cert: Il certificato X.509 firmato da salvare
            base_dir: Directory base (default: "./data/")
        """
        subject = cert.subject
        serial_number = cert.serial_number

        # Usa identificatore basato su SKI (come AT)
        cert_ski = get_certificate_ski(cert)[:8]  # Primi 8 caratteri dello SKI

        # Estrae Organization (O) e Common Name (CN) per determinare il tipo
        org_attrs = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        cn_attrs = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        org = org_attrs[0].value if org_attrs else ""
        cn = cn_attrs[0].value if cn_attrs else ""

        # Determina il nome del file usando solo prefisso + SKI
        if "EnrollmentAuthority" in org or "EnrollmentAuthority" in cn:
            cert_filename = f"EA_{cert_ski}.pem"
            authority_type = "Enrollment Authority"
        elif "AuthorizationAuthority" in org or "AuthorizationAuthority" in cn:
            cert_filename = f"AA_{cert_ski}.pem"
            authority_type = "Authorization Authority"
        else:
            # Default: autorità generica
            authority_type = "Subordinate Authority"
            cert_filename = f"SUB_{cert_ski}.pem"

        # Salva nella cartella archivio della RootCA
        archive_dir = os.path.join(base_dir, "root_ca/subordinates")
        os.makedirs(archive_dir, exist_ok=True)
        archive_path = os.path.join(archive_dir, cert_filename)

        print(f"[RootCA] ========================================")
        print(f"[RootCA] Archiviando certificato subordinato")
        print(f"[RootCA] Tipo: {authority_type}")
        print(f"[RootCA] Subject: {subject}")
        print(f"[RootCA] Identificatore SKI: {cert_ski}")
        print(f"[RootCA] Serial: {serial_number}")
        print(f"[RootCA] File: {cert_filename}")
        print(f"[RootCA] Path completo: {archive_path}")

        with open(archive_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"[RootCA] Certificato archiviato con successo!")
        print(f"[RootCA] ========================================")

    # Aggiunge un seriale alla lista dei certificati revocati
    def revoke_certificate(self, certificate, reason=ReasonFlags.unspecified):
        """
        Revoca un certificato aggiungendolo alla lista dei certificati revocati.

        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number

        print(f"[RootCA] Revocando certificato con serial number: {serial_number}")
        print(f"[RootCA] Motivo revoca: {reason}")

        # Aggiungi al CRLManager invece che alla lista locale
        self.crl_manager.add_revoked_certificate(certificate, reason)

        # Mantieni anche nella lista locale per retrocompatibilità (se necessario)
        expiry_date = certificate.not_valid_after
        self.revoked.append(
            {
                "serial_number": serial_number,
                "revocation_date": datetime.now(timezone.utc),
                "expiry_date": expiry_date,
                "reason": reason,
            }
        )

        print(f"[RootCA] Certificato aggiunto alla lista di revoca")
        print(f"[RootCA] Revoca completata!")

    # Genera e pubblica una Full CRL usando il CRLManager
    def publish_full_crl(self, validity_days=7):
        """
        Genera e pubblica una Full CRL contenente tutti i certificati revocati.

        Args:
            validity_days: Giorni di validità della Full CRL (default: 7 giorni)

        Returns:
            La CRL generata
        """
        print(f"[RootCA] Pubblicando Full CRL...")
        crl = self.crl_manager.publish_full_crl(validity_days=validity_days)
        print(f"[RootCA] Full CRL pubblicata con successo!")
        return crl

    # Genera e pubblica una Delta CRL usando il CRLManager
    def publish_delta_crl(self, validity_hours=24):
        """
        Genera e pubblica una Delta CRL contenente solo le nuove revoche.

        Args:
            validity_hours: Ore di validità della Delta CRL (default: 24 ore)

        Returns:
            La Delta CRL generata o None se non ci sono nuove revoche
        """
        print(f"[RootCA] Pubblicando Delta CRL...")
        crl = self.crl_manager.publish_delta_crl(validity_hours=validity_hours)
        if crl:
            print(f"[RootCA] Delta CRL pubblicata con successo!")
        else:
            print(f"[RootCA] Nessuna nuova revoca, Delta CRL non necessaria")
        return crl

    def publish_crl(self):
        """Pubblica una Full CRL (wrapper per retrocompatibilità)."""
        print(f"[RootCA] Pubblicazione Full CRL via metodo legacy")
        return self.publish_full_crl()

    # Carica la Full CRL da file
    def load_full_crl(self):
        """
        Carica la Full CRL dal file usando il CRLManager.

        Returns:
            La Full CRL o None se non esiste
        """
        print(f"[RootCA] Caricando Full CRL...")
        return self.crl_manager.load_full_crl()

    # Carica la Delta CRL da file
    def load_delta_crl(self):
        """
        Carica la Delta CRL dal file usando il CRLManager.

        Returns:
            La Delta CRL o None se non esiste
        """
        print(f"[RootCA] Caricando Delta CRL...")
        return self.crl_manager.load_delta_crl()

    def load_crl(self):
        """Carica la Full CRL (wrapper per retrocompatibilità)."""
        print(f"[RootCA] Caricamento Full CRL via metodo legacy")
        return self.load_full_crl()

    # Ottiene statistiche sul CRL Manager
    def get_crl_statistics(self):
        """
        Restituisce statistiche sullo stato del CRL Manager.

        Returns:
            dict con statistiche (crl_number, certificati revocati, delta pending, ecc.)
        """
        print(f"[RootCA] Recuperando statistiche CRL...")
        stats = self.crl_manager.get_statistics()
        print(f"[RootCA] Statistiche CRL:")
        print(f"[RootCA]   CRL Number attuale: {stats['crl_number']}")
        print(f"[RootCA]   Base CRL Number: {stats['base_crl_number']}")
        print(f"[RootCA]   Certificati revocati totali: {stats['total_revoked']}")
        print(f"[RootCA]   Revoche delta pending: {stats['delta_pending']}")
        return stats
