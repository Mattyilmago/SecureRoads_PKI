import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ReasonFlags
from cryptography.x509.oid import NameOID

from managers.crl_manager import CRLManager
from utils.cert_utils import (
    get_certificate_expiry_time,
    get_certificate_identifier,
    get_certificate_not_before,
    get_certificate_ski,
    get_short_identifier,
)
from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler
from utils.pki_paths import PKIPathManager


class RootCA:
    def __init__(self, base_dir="./data/root_ca/"):
        # Usa PKIPathManager per gestire i path in modo centralizzato
        # Per RootCA, entity_id è sempre "ROOT_CA"
        paths = PKIPathManager.get_entity_paths("RootCA", "ROOT_CA", base_dir)
        
        self.base_dir = str(paths.base_dir)
        self.ca_certificate_path = str(paths.certificates_dir / "root_ca_certificate.pem")
        self.ca_key_path = str(paths.private_keys_dir / "root_ca_key.pem")
        self.crl_path = str(paths.crl_dir / "root_ca_crl.pem")
        self.log_dir = str(paths.logs_dir)
        self.backup_dir = str(paths.backup_dir)
        
        # Directory per certificati subordinati (EA, AA, ecc.)
        self.subordinates_dir = str(paths.data_dir)  # subordinates/
        
        # Crea tutte le directory necessarie
        paths.create_all()
        
        # Inizializza logger
        self.logger = PKILogger.get_logger(
            name="RootCA",
            log_dir=self.log_dir,
            console_output=True
        )
        
        self.logger.info("Inizializzando Root CA...")
        self.logger.info(f"Percorso certificato: {self.ca_certificate_path}")
        self.logger.info(f"Percorso chiave privata: {self.ca_key_path}")
        self.logger.info(f"Percorso CRL: {self.crl_path}")
        self.logger.info(f"Directory subordinati: {self.subordinates_dir}")
        self.logger.info(f"✅ Struttura directory creata da PKIPathManager")

        self.private_key = None
        self.certificate = None

        # Prova a caricare chiave/cert
        self.logger.info("Caricando o generando chiave e certificato...")
        self.load_or_generate_ca()

        # Inizializza CRLManager dopo aver caricato certificato e chiave privata
        self.logger.info("Inizializzando CRLManager per RootCA...")
        self.crl_manager = CRLManager(
            authority_id="RootCA",
            base_dir=self.base_dir,  # Usa il path specifico dell'istanza (data/root_ca)
            issuer_certificate=self.certificate,
            issuer_private_key=self.private_key,
        )
        self.logger.info("CRLManager inizializzato con successo!")

        self.logger.info("Inizializzazione completata!")

    # Carica chiave/cert se esistono, altrimenti li genera
    def load_or_generate_ca(self):
        self.logger.info("Verificando esistenza chiave e certificato...")
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_certificate_path):
            self.logger.info("Chiave e certificato esistenti trovati, caricandoli...")
            self.load_ca_keypair()
            self.load_certificate()
        else:
            self.logger.info("Chiave o certificato non trovati, generandoli da zero...")
            self.generate_ca_keypair()
            self.generate_self_signed_certificate()

    # Genera una chiave privata ECC e la salva su file
    def generate_ca_keypair(self):
        self.logger.info("Generando chiave privata ECC (SECP256R1)...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.logger.info(f"Salvando chiave privata in: {self.ca_key_path}")
        with open(self.ca_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        self.logger.info("Chiave privata generata e salvata con successo!")

    # Genera e salva un certificato X.509 self-signed per la Root CA
    def generate_self_signed_certificate(self):
        self.logger.info("Generando certificato self-signed...")
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test RootCA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "RootCA"),
            ]
        )
        self.logger.info("Subject/Issuer: C=IT, O=Test RootCA, CN=RootCA")
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
        self.logger.info(f"Certificate generated with serial number: {cert.serial_number}")
        # Usa utility per datetime UTC-aware
        valid_from = get_certificate_not_before(cert)
        valid_to = get_certificate_expiry_time(cert)
        self.logger.info(f"Validity: from {valid_from} to {valid_to}")
        self.logger.info(f"Saving certificate to: {self.ca_certificate_path}")
        with open(self.ca_certificate_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Invalidate certificate cache to ensure all entities load new cert
        from utils.cert_cache import invalidate_certificate_cache
        invalidate_certificate_cache(self.ca_certificate_path)
        self.logger.info("Certificate cache invalidated - entities will load new cert")
        
        self.logger.info("Certificato self-signed generato e salvato con successo!")

    # Carica la chiave privata ECC dal file PEM
    def load_ca_keypair(self):
        self.logger.info(f"Caricando chiave privata da: {self.ca_key_path}")
        self.private_key = PKIFileHandler.load_private_key(self.ca_key_path)
        self.logger.info("Chiave privata caricata con successo!")

    def load_certificate(self):
        self.logger.info(f"Caricando certificato da: {self.ca_certificate_path}")
        self.certificate = PKIFileHandler.load_certificate(self.ca_certificate_path)
        self.logger.info("Certificato caricato con successo!")
        self.logger.info(f"Subject: {self.certificate.subject}")
        self.logger.info(f"Serial number: {self.certificate.serial_number}")
        # Usa utility per datetime UTC-aware
        valid_from = get_certificate_not_before(self.certificate)
        valid_to = get_certificate_expiry_time(self.certificate)
        self.logger.info(f"Validit: dal {valid_from} al {valid_to}")

    # Firma un certificato subordinato (EA/AA)
    def sign_certificate(self, subject_public_key, subject_name, is_ca=False):
        self.logger.info(f"Firmando certificato per: {subject_name}")
        self.logger.info(f"Tipo certificato: {'CA' if is_ca else 'End Entity'}")

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name),
                x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
            ]
        )

        serial_number = x509.random_serial_number()
        self.logger.info(f"Serial number assegnato: {serial_number}")

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(subject_public_key)
            .serial_number(serial_number)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))  # 1 anno di validit
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None),
                critical=True,
            )
            .sign(self.private_key, hashes.SHA256())
        )

        self.logger.info("Certificato firmato con successo!")
        # Usa utility per datetime UTC-aware
        valid_from = get_certificate_not_before(cert)
        valid_to = get_certificate_expiry_time(cert)
        self.logger.info(f"Validit: dal {valid_from} al {valid_to}")
        return cert

    # Salva certificato subordinato su file
    def save_subordinate_certificate(self, cert):
        """
        Salva il certificato subordinato firmato nell'archivio della RootCA.

        Ogni certificato viene salvato con un nome univoco che include l'ID
        dell'autorit, permettendo di archiviare certificati di pi EA e AA.

        Nota: Ogni autorit subordinata (EA/AA) salva gi il proprio certificato
        nella propria cartella durante l'inizializzazione. Questo metodo serve
        solo per mantenere una copia archivio centralizzata presso la RootCA.

        Args:
            cert: Il certificato X.509 firmato da salvare
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
            # Default: autorit generica
            authority_type = "Subordinate Authority"
            cert_filename = f"SUB_{cert_ski}.pem"

        # Salva nella cartella archivio della RootCA usando self.base_dir
        archive_dir = os.path.join(self.base_dir, "subordinates")
        os.makedirs(archive_dir, exist_ok=True)
        archive_path = os.path.join(archive_dir, cert_filename)

        self.logger.info("=" * 50)
        self.logger.info("Archiviando certificato subordinato")
        self.logger.info(f"Tipo: {authority_type}")
        self.logger.info(f"Subject: {subject}")
        self.logger.info(f"Identificatore SKI: {cert_ski}")
        self.logger.info(f"Serial: {serial_number}")
        self.logger.info(f"File: {cert_filename}")
        self.logger.info(f"Path completo: {archive_path}")

        with open(archive_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self.logger.info("Certificato archiviato con successo!")
        self.logger.info("=" * 50)

    # Aggiunge un seriale alla lista dei certificati revocati
    def revoke_certificate(self, certificate, reason=ReasonFlags.unspecified):
        """
        Revoca un certificato aggiungendolo alla lista dei certificati revocati.

        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number

        self.logger.info(f"Revocando certificato con serial number: {serial_number}")
        self.logger.info(f"Motivo revoca: {reason}")

        # Aggiungi al CRLManager invece che alla lista locale
        self.crl_manager.add_revoked_certificate(certificate, reason)

        # Mantieni anche nella lista locale per retrocompatibilit (se necessario)
        expiry_date = get_certificate_expiry_time(certificate)
        self.revoked.append(
            {
                "serial_number": serial_number,
                "revocation_date": datetime.now(timezone.utc),
                "expiry_date": expiry_date,
                "reason": reason,
            }
        )

        self.logger.info("Certificato aggiunto alla lista di revoca")
        self.logger.info("Revoca completata!")

    # Genera e pubblica una Full CRL usando il CRLManager
    def publish_full_crl(self, validity_days=7):
        """
        Genera e pubblica una Full CRL contenente tutti i certificati revocati.

        Args:
            validity_days: Giorni di validit della Full CRL (default: 7 giorni)

        Returns:
            La CRL generata
        """
        self.logger.info("Pubblicando Full CRL...")
        crl = self.crl_manager.publish_full_crl(validity_days=validity_days)
        self.logger.info("Full CRL pubblicata con successo!")
        return crl

    # Genera e pubblica una Delta CRL usando il CRLManager
    def publish_delta_crl(self, validity_hours=24):
        """
        Genera e pubblica una Delta CRL contenente solo le nuove revoche.

        Args:
            validity_hours: Ore di validit della Delta CRL (default: 24 ore)

        Returns:
            La Delta CRL generata o None se non ci sono nuove revoche
        """
        self.logger.info("Pubblicando Delta CRL...")
        crl = self.crl_manager.publish_delta_crl(validity_hours=validity_hours)
        if crl:
            self.logger.info("Delta CRL pubblicata con successo!")
        else:
            self.logger.info("Nessuna nuova revoca, Delta CRL non necessaria")
        return crl

    def publish_crl(self):
        """Pubblica una Full CRL (wrapper method for backward compatibility)."""
        self.logger.info("Publishing Full CRL via wrapper method")
        return self.publish_full_crl()

    # Carica la Full CRL da file
    def load_full_crl(self):
        """
        Carica la Full CRL dal file usando il CRLManager.

        Returns:
            La Full CRL o None se non esiste
        """
        self.logger.info("Caricando Full CRL...")
        return self.crl_manager.load_full_crl()

    # Carica la Delta CRL da file
    def load_delta_crl(self):
        """
        Carica la Delta CRL dal file usando il CRLManager.

        Returns:
            La Delta CRL o None se non esiste
        """
        self.logger.info("Caricando Delta CRL...")
        return self.crl_manager.load_delta_crl()

    def load_crl(self):
        """Carica la Full CRL (wrapper per retrocompatibilit)."""
        self.logger.info("Caricamento Full CRL via metodo legacy")
        return self.load_full_crl()

    # Ottiene statistiche sul CRL Manager
    def get_crl_statistics(self):
        """
        Restituisce statistiche sullo stato del CRL Manager.

        Returns:
            dict con statistiche (crl_number, certificati revocati, delta pending, ecc.)
        """
        self.logger.info("Recuperando statistiche CRL...")
        stats = self.crl_manager.get_statistics()
        self.logger.info("Statistiche CRL:")
        self.logger.info(f"  CRL Number attuale: {stats['crl_number']}")
        self.logger.info(f"  Base CRL Number: {stats['base_crl_number']}")
        self.logger.info(f"  Certificati revocati totali: {stats['total_revoked']}")
        self.logger.info(f"  Revoche delta pending: {stats['delta_pending']}")
        return stats
    
    def get_subordinate_statistics(self):
        """
        Restituisce statistiche sui certificati subordinati emessi dalla Root CA.
        
        Conta i certificati subordinati (EA, AA) nella directory 'subordinates'.
        Include il conteggio totale e per tipo (EA, AA).
        
        IMPORTANTE - AGGIORNAMENTO AUTOMATICO METRICHE:
        Questo metodo calcola dinamicamente le statistiche in tempo reale:
        
        1. Legge tutti i certificati dalla directory 'subordinates'
        2. Verifica per ogni certificato se è ancora valido (non scaduto)
        3. Controlla se il certificato è stato revocato (presente nella CRL)
        4. Conta solo i certificati attivi (validi E non revocati)
        
        Viene chiamato automaticamente quando:
        - Il dashboard richiede metriche (/api/monitoring/metrics)
        - Viene richiesto lo stato dell'entità (/api/stats)
        
        Questo garantisce che:
        - I certificati scaduti non vengono contati come attivi
        - I certificati revocati non vengono contati come attivi
        - Le metriche riflettono sempre lo stato reale del sistema
        - La dashboard mostra conteggi accurati e aggiornati
        - Il sistema è conforme agli standard ETSI TS 102 941
        
        Returns:
            dict con:
                - total_subordinates: numero totale di certificati subordinati
                - ea_count: numero di Enrollment Authorities
                - aa_count: numero di Authorization Authorities
                - active_subordinates: numero di certificati subordinati validi (non scaduti, non revocati)
        """
        from pathlib import Path
        
        subordinates_dir = Path(self.base_dir) / "subordinates"
        
        stats = {
            'total_subordinates': 0,
            'ea_count': 0,
            'aa_count': 0,
            'active_subordinates': 0
        }
        
        if not subordinates_dir.exists():
            return stats
        
        # Conta tutti i certificati subordinati
        cert_files = list(subordinates_dir.glob("*.pem"))
        stats['total_subordinates'] = len(cert_files)
        
        # Conta per tipo e verifica validità
        now = datetime.now(timezone.utc)
        for cert_file in cert_files:
            try:
                # Leggi il certificato
                with open(cert_file, 'rb') as f:
                    from cryptography.hazmat.backends import default_backend
                    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                
                # Determina il tipo dal nome del file
                if cert_file.name.startswith('EA_'):
                    stats['ea_count'] += 1
                elif cert_file.name.startswith('AA_'):
                    stats['aa_count'] += 1
                
                # Verifica se il certificato è ancora valido (non scaduto e non revocato)
                expiry_date = get_certificate_expiry_time(cert)
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                
                # Verifica scadenza
                is_expired = expiry_date <= now
                
                # Verifica revoca (controlla se il serial è nella CRL)
                is_revoked = False
                if hasattr(self, 'crl_manager'):
                    # Controlla se il certificato è nella lista dei revocati
                    is_revoked = any(
                        rev['serial_number'] == cert.serial_number 
                        for rev in self.crl_manager.revoked_certificates
                    )
                
                # Se non scaduto e non revocato, è attivo
                if not is_expired and not is_revoked:
                    stats['active_subordinates'] += 1
                    
            except Exception as e:
                self.logger.warning(f"Errore nel processare {cert_file.name}: {e}")
                continue
        
        self.logger.info(f"Statistiche subordinati RootCA:")
        self.logger.info(f"  Totale certificati: {stats['total_subordinates']}")
        self.logger.info(f"  EA: {stats['ea_count']}")
        self.logger.info(f"  AA: {stats['aa_count']}")
        self.logger.info(f"  Attivi: {stats['active_subordinates']}")
        
        return stats
