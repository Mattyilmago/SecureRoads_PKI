import json
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ReasonFlags

from utils.cert_utils import get_certificate_expiry_time, get_certificate_identifier, get_certificate_ski
from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler


class CRLManager:
    """
    Manages Full CRL and Delta CRL creation and publication.
    """

    def __init__(self, authority_id, base_dir, issuer_certificate, issuer_private_key):
        """Initializes CRL Manager for a specific authority."""
        self.authority_id = authority_id
        self.issuer_certificate = issuer_certificate
        self.issuer_private_key = issuer_private_key

        # Percorsi file con separazione full/delta
        self.crl_dir = os.path.join(base_dir, "crl/")
        self.full_crl_dir = os.path.join(self.crl_dir, "full/")
        self.delta_crl_dir = os.path.join(self.crl_dir, "delta/")
        self.full_crl_path = os.path.join(self.full_crl_dir, "full_crl.pem")
        self.delta_crl_path = os.path.join(self.delta_crl_dir, "delta_crl.pem")
        self.metadata_path = os.path.join(self.crl_dir, "crl_metadata.json")
        self.log_dir = os.path.join(base_dir, "logs/")
        self.backup_dir = os.path.join(base_dir, "backup/")
        
        # Inizializza logger
        self.logger = PKILogger.get_logger(
            name=f"CRLManager_{authority_id}",
            log_dir=self.log_dir,
            console_output=True
        )

        # Crea directory
        PKIFileHandler.ensure_directories(
            self.crl_dir,
            self.full_crl_dir,
            self.delta_crl_dir,
            self.log_dir,
            self.backup_dir,
        )

        # Lista completa dei certificati revocati (per Full CRL)
        self.revoked_certificates = []

        # Metadata per tracking
        self.crl_number = 0  # Numero sequenziale CRL
        self.base_crl_number = 0  # Numero della Full CRL di riferimento per Delta
        self.last_full_crl_time = None  # Timestamp ultima Full CRL
        self.delta_revocations = []  # Revoche per il prossimo Delta CRL

        # Carica metadata se esistono
        self.load_metadata()

        # Carica Full CRL metadata per ricostruire lista certificati revocati
        self.load_full_crl_metadata()

        self.logger.info(f"Inizializzato per {authority_id}")
        self.logger.info(f"CRL Number attuale: {self.crl_number}")
        self.logger.info(f"Base CRL Number: {self.base_crl_number}")

    def add_revoked_certificate(self, certificate, reason=ReasonFlags.unspecified):
        """
        Aggiunge un certificato alla lista di revoca.

        Questo metodo:
        1. Aggiunge alla lista completa (per Full CRL)
        2. Aggiunge alla lista delta (per prossimo Delta CRL)
        3. Salva expiry_date per cleanup automatico

        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number
        ski = get_certificate_ski(certificate)
        cert_id = get_certificate_identifier(certificate)
        expiry_date = get_certificate_expiry_time(certificate)

        revocation_date = datetime.now(timezone.utc)

        self.logger.info(f"Aggiungendo certificato revocato:")
        self.logger.info(f"  Identificatore: {cert_id}")
        self.logger.info(f"  SKI: {ski[:16]}...")
        self.logger.info(f"  Serial: {serial_number}")
        self.logger.info(f"  Motivo: {reason}")
        self.logger.info(f"  Data scadenza: {expiry_date}")

        # Controlla se già revocato (usa SKI per confronto, con backward compatibility)
        for entry in self.revoked_certificates:
            # Prova prima con SKI (nuovo), poi con serial_number (vecchio)
            if entry.get("ski") == ski or entry.get("serial_number") == serial_number:
                self.logger.info(f"Certificato già presente nella lista revocati")
                return

        # Log revocation
        self.log_operation(
            "REVOKE_CERTIFICATE",
            {
                "certificate_id": cert_id,
                "serial_number": str(serial_number),
                "reason": str(reason),
                "expiry_date": expiry_date.isoformat(),
            },
        )

        revoked_entry = {
            "serial_number": serial_number,  # Necessario per la CRL X.509
            "ski": ski,  # Per identificazione univoca
            "cert_id": cert_id,  # Human-readable
            "revocation_date": revocation_date,
            "expiry_date": expiry_date,
            "reason": reason,
        }

        # Aggiunge a entrambe le liste
        self.revoked_certificates.append(revoked_entry)
        self.delta_revocations.append(revoked_entry)

        self.logger.info(
            f"Certificato aggiunto. Totale revocati: {len(self.revoked_certificates)}"
        )
        self.logger.info(f"Revoche delta pending: {len(self.delta_revocations)}")

    def revoke_by_serial(self, serial_number, reason=ReasonFlags.unspecified):
        """
        Revoca un certificato usando solo il serial number (senza certificato completo).
        Usato quando il certificato non è disponibile.

        Args:
            serial_number: Il serial number del certificato (int o hex string)
            reason: Il motivo della revoca (ReasonFlags o string)
        """
        # Converti hex string a int se necessario
        if isinstance(serial_number, str):
            serial_number = int(serial_number, 16)

        # Converti string reason a ReasonFlags se necessario
        if isinstance(reason, str):
            reason = getattr(ReasonFlags, reason, ReasonFlags.unspecified)

        revocation_date = datetime.now(timezone.utc)
        # Imposta una data di scadenza di default (1 anno da ora)
        expiry_date = datetime.now(timezone.utc) + timedelta(days=365)

        self.logger.info(f"Aggiungendo revoca per serial: {serial_number}")
        self.logger.info(f"  Motivo: {reason}")

        # Controlla se già revocato
        for entry in self.revoked_certificates:
            if entry.get("serial_number") == serial_number:
                self.logger.info(f"Serial già presente nella lista revocati")
                return

        # Log revocation
        self.log_operation(
            "REVOKE_BY_SERIAL",
            {
                "serial_number": str(serial_number),
                "reason": str(reason),
            },
        )

        revoked_entry = {
            "serial_number": serial_number,
            "ski": None,  # Non disponibile
            "cert_id": f"SERIAL_{serial_number}",
            "revocation_date": revocation_date,
            "expiry_date": expiry_date,
            "reason": reason,
        }

        # Aggiunge a entrambe le liste
        self.revoked_certificates.append(revoked_entry)
        self.delta_revocations.append(revoked_entry)

        self.logger.info(f"Serial aggiunto. Totale revocati: {len(self.revoked_certificates)}")
        self.logger.info(f"Revoche delta pending: {len(self.delta_revocations)}")

    def publish_full_crl(self, validity_days=7):
        """
        Genera e pubblica una Full CRL contenente TUTTI i certificati revocati.

        La Full CRL:
        - Contiene tutte le revoche dalla creazione dell'autorità
        - Viene pubblicata periodicamente (es. settimanalmente)
        - Serve come base di riferimento per i Delta CRL
        - Include un CRL Number per identificazione univoca

        Args:
            validity_days: Giorni di validità della CRL
        """
        self.logger.info(f"=== GENERAZIONE FULL CRL ===")

        # Incrementa CRL number
        self.crl_number += 1
        self.base_crl_number = self.crl_number
        self.last_full_crl_time = datetime.now(timezone.utc)

        # Pulisce certificati scaduti prima di pubblicare
        self._cleanup_expired_certificates()

        self.logger.info(f"CRL Number: {self.crl_number}")
        self.logger.info(f"Certificati revocati: {len(self.revoked_certificates)}")

        # Crea CRL builder
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer_certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=validity_days))

        # Aggiunge CRL Number extension (obbligatoria per Full CRL)
        builder = builder.add_extension(x509.CRLNumber(self.crl_number), critical=False)

        # Aggiunge tutti i certificati revocati
        for entry in self.revoked_certificates:
            self.logger.info(
                f"  Serial: {entry['serial_number']}, "
                f"Revocato: {entry['revocation_date']}, "
                f"Scade: {entry['expiry_date']}, "
                f"Motivo: {entry['reason']}"
            )

            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(entry["serial_number"])
                .revocation_date(entry["revocation_date"])
                .add_extension(x509.CRLReason(entry["reason"]), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        # Firma la CRL
        crl = builder.sign(private_key=self.issuer_private_key, algorithm=hashes.SHA256())

        # Salva su file
        with open(self.full_crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        self.logger.info(f"Full CRL salvata: {self.full_crl_path}")

        # Salva metadata Full CRL (snapshot completo)
        self.save_full_crl_metadata(validity_days)

        # Reset delta revocations (tutto è ora nella Full CRL)
        self.delta_revocations = []

        # Salva metadata manager generale
        self.save_metadata()

        # Log e backup
        self.log_operation(
            "PUBLISH_FULL_CRL",
            {
                "crl_number": self.crl_number,
                "revoked_count": len(self.revoked_certificates),
                "validity_days": validity_days,
            },
        )
        self.backup_crl("full")

        self.logger.info(f"=== FULL CRL PUBBLICATA ===")
        return self.full_crl_path

    def publish_delta_crl(self, validity_hours=24):
        """
        Genera e pubblica una Delta CRL contenente SOLO le nuove revoche.

        La Delta CRL:
        - Contiene solo certificati revocati dall'ultima Full CRL
        - È molto più piccola e veloce da distribuire
        - Include riferimento alla Full CRL base (Base CRL Number)
        - Viene pubblicata frequentemente (es. ogni ora)

        Args:
            validity_hours: Ore di validità della Delta CRL
        """
        self.logger.info(f"=== GENERAZIONE DELTA CRL ===")

        # Controlla se ci sono nuove revoche
        if not self.delta_revocations:
            self.logger.info(f"Nessuna nuova revoca, Delta CRL non necessaria")
            return None

        # Incrementa CRL number
        self.crl_number += 1

        self.logger.info(f"CRL Number: {self.crl_number}")
        self.logger.info(f"Base CRL Number: {self.base_crl_number}")
        self.logger.info(f"Nuove revoche dal Full CRL: {len(self.delta_revocations)}")

        # Crea CRL builder
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer_certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(hours=validity_hours))

        # Aggiunge CRL Number extension
        builder = builder.add_extension(x509.CRLNumber(self.crl_number), critical=False)

        # Aggiunge Delta CRL Indicator extension (identifica come Delta CRL)
        # Punta alla Full CRL base
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(self.base_crl_number),
            critical=True,  # DEVE essere critical secondo RFC 5280
        )

        # Aggiunge SOLO le nuove revoche
        for entry in self.delta_revocations:
            self.logger.info(
                f"  Serial: {entry['serial_number']}, "
                f"Revocato: {entry['revocation_date']}, "
                f"Motivo: {entry['reason']}"
            )

            revoked_cert = (
                x509.RevokedCertificateBuilder()
                .serial_number(entry["serial_number"])
                .revocation_date(entry["revocation_date"])
                .add_extension(x509.CRLReason(entry["reason"]), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(revoked_cert)

        # Firma la Delta CRL
        crl = builder.sign(private_key=self.issuer_private_key, algorithm=hashes.SHA256())

        # Salva su file
        with open(self.delta_crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))

        self.logger.info(f"Delta CRL salvata: {self.delta_crl_path}")

        # Salva metadata Delta CRL (snapshot modifiche)
        self.save_delta_crl_metadata(validity_hours / 24)  # Converti ore in giorni

        # Salva metadata manager generale
        self.save_metadata()

        # Log e backup
        self.log_operation(
            "PUBLISH_DELTA_CRL",
            {
                "crl_number": self.crl_number,
                "base_crl_number": self.base_crl_number,
                "delta_revocations_count": len(self.delta_revocations),
                "validity_hours": validity_hours,
            },
        )
        self.backup_crl("delta")

        self.logger.info(f"=== DELTA CRL PUBBLICATA ===")
        return crl

    def _cleanup_expired_certificates(self):
        """Rimuove certificati scaduti dalla lista revocati per ridurre dimensione CRL."""
        now = datetime.now(timezone.utc)
        old_count = len(self.revoked_certificates)

        # Filtra solo certificati non ancora scaduti
        # Gestisce sia date naive che aware
        filtered = []
        for entry in self.revoked_certificates:
            expiry_date = entry.get("expiry_date")
            if expiry_date:
                # Se la data è naive, la rendiamo aware assumendo UTC
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                if expiry_date > now:
                    filtered.append(entry)

        self.revoked_certificates = filtered

        removed = old_count - len(self.revoked_certificates)
        if removed > 0:
            self.logger.info(f"Pulizia: rimossi {removed} certificati scaduti")
            self.logger.info(f"Certificati attivi rimasti: {len(self.revoked_certificates)}")

    def load_full_crl(self):
        """
        Carica la Full CRL dal file.

        Returns:
            x509.CertificateRevocationList o None se non esiste
        """
        if not os.path.exists(self.full_crl_path):
            self.logger.info(f"Full CRL non trovata")
            return None

        with open(self.full_crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        self.logger.info(f"Full CRL caricata:")
        self.logger.info(f"  Certificati revocati: {len(crl)}")
        self.logger.info(f"  Ultimo aggiornamento: {crl.last_update_utc}")
        self.logger.info(f"  Prossimo aggiornamento: {crl.next_update_utc}")

        return crl

    def load_delta_crl(self):
        """
        Carica la Delta CRL dal file.

        Returns:
            x509.CertificateRevocationList o None se non esiste
        """
        if not os.path.exists(self.delta_crl_path):
            self.logger.info(f"Delta CRL non trovata")
            return None

        with open(self.delta_crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        self.logger.info(f"Delta CRL caricata:")
        self.logger.info(f"  Nuove revoche: {len(crl)}")
        self.logger.info(f"  Ultimo aggiornamento: {crl.last_update_utc}")
        self.logger.info(f"  Prossimo aggiornamento: {crl.next_update_utc}")

        return crl

    def save_metadata(self):
        """
        Salva metadata CRL su file JSON per persistenza.

        Questo permette di:
        - Ripristinare stato dopo restart
        - Mantenere CRL Number sequence corretta
        - Tracciare storico pubblicazioni
        """
        metadata = {
            "authority_id": self.authority_id,
            "crl_number": self.crl_number,
            "base_crl_number": self.base_crl_number,
            "last_full_crl_time": (
                self.last_full_crl_time.isoformat() if self.last_full_crl_time else None
            ),
            "revoked_count": len(self.revoked_certificates),
            "delta_pending": len(self.delta_revocations),
        }

        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        self.logger.info(f"Metadata salvati: {self.metadata_path}")

    def load_metadata(self):
        """
        Carica metadata CRL da file JSON.
        """
        if not os.path.exists(self.metadata_path):
            self.logger.info(f"Nessun metadata esistente, inizializzo nuovo")
            return

        try:
            with open(self.metadata_path, "r") as f:
                metadata = json.load(f)

            self.crl_number = metadata.get("crl_number", 0)
            self.base_crl_number = metadata.get("base_crl_number", 0)

            last_full = metadata.get("last_full_crl_time")
            if last_full:
                self.last_full_crl_time = datetime.fromisoformat(last_full)

            self.logger.info(f"Metadata caricati con successo")
            self.logger.info(f"  CRL Number: {self.crl_number}")
            self.logger.info(f"  Base CRL Number: {self.base_crl_number}")

        except Exception as e:
            self.logger.info(f"Errore caricamento metadata: {e}")

    def get_statistics(self):
        """
        Restituisce statistiche sullo stato del CRL Manager.

        Returns:
            dict con statistiche
        """
        stats = {
            "authority_id": self.authority_id,
            "crl_number": self.crl_number,
            "base_crl_number": self.base_crl_number,
            "total_revoked": len(self.revoked_certificates),
            "delta_pending": len(self.delta_revocations),
            "last_full_crl": (
                self.last_full_crl_time.isoformat() if self.last_full_crl_time else None
            ),
        }

        return stats

    def save_full_crl_metadata(self, validity_days=7):
        """
        Salva metadata completi della Full CRL con lista certificati revocati.

        Questo snapshot JSON serve per:
        - Backup human-readable della Full CRL
        - API REST per download metadata
        - Ricostruzione stato dopo crash
        - Audit trail completo delle revoche
        """
        metadata = {
            "version": "1.0",
            "crl_number": self.crl_number,
            "authority_id": self.authority_id,
            "issuer": self.issuer_certificate.subject.rfc4514_string(),
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "next_update": (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat(),
            "revoked_certificates": [],
        }

        # Converti ReasonFlags in stringa per JSON
        for entry in self.revoked_certificates:
            metadata["revoked_certificates"].append(
                {
                    "serial_number": entry["serial_number"],
                    "revocation_date": entry["revocation_date"].isoformat(),
                    "reason": (
                        entry["reason"].name
                        if isinstance(entry["reason"], ReasonFlags)
                        else str(entry["reason"])
                    ),
                    "expiry_date": entry["expiry_date"].isoformat(),
                }
            )

        # Salva su file
        full_metadata_path = self.full_crl_path.replace(".pem", "_metadata.json")
        with open(full_metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        self.logger.info(f"Metadata Full CRL salvati: {full_metadata_path}")

    def save_delta_crl_metadata(self, validity_days=7):
        """
        Salva metadata completi della Delta CRL con nuove revoche.

        Questo snapshot JSON serve per:
        - ITS-S sa esattamente cosa è cambiato
        - API REST per download incrementale
        - Audit delle modifiche recenti
        """
        metadata = {
            "version": "1.0",
            "crl_number": self.crl_number,
            "base_crl_number": self.base_crl_number,
            "authority_id": self.authority_id,
            "issuer": self.issuer_certificate.subject.rfc4514_string(),
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "next_update": (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat(),
            "new_revocations": [],
        }

        # Converti ReasonFlags in stringa per JSON
        for entry in self.delta_revocations:
            metadata["new_revocations"].append(
                {
                    "serial_number": entry["serial_number"],
                    "revocation_date": entry["revocation_date"].isoformat(),
                    "reason": (
                        entry["reason"].name
                        if isinstance(entry["reason"], ReasonFlags)
                        else str(entry["reason"])
                    ),
                    "expiry_date": entry["expiry_date"].isoformat(),
                }
            )

        # Salva su file
        delta_metadata_path = self.delta_crl_path.replace(".pem", "_metadata.json")
        with open(delta_metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)

        self.logger.info(f"Metadata Delta CRL salvati: {delta_metadata_path}")

    def load_full_crl_metadata(self):
        """
        Carica metadata Full CRL e ricostruisce lista certificati revocati.

        Questo permette di ripristinare lo stato completo dopo un riavvio,
        evitando la perdita della lista revoked_certificates.
        """
        full_metadata_path = self.full_crl_path.replace(".pem", "_metadata.json")

        if not os.path.exists(full_metadata_path):
            self.logger.info(f"Nessun metadata Full CRL esistente")
            return

        try:
            with open(full_metadata_path, "r") as f:
                metadata = json.load(f)

            # Ricostruisci lista certificati revocati
            self.revoked_certificates = []
            for entry in metadata.get("revoked_certificates", []):
                # Converti stringa reason in ReasonFlags
                reason_str = entry["reason"]
                reason = getattr(ReasonFlags, reason_str, ReasonFlags.unspecified)

                self.revoked_certificates.append(
                    {
                        "serial_number": entry["serial_number"],
                        "revocation_date": datetime.fromisoformat(entry["revocation_date"]),
                        "reason": reason,
                        "expiry_date": datetime.fromisoformat(entry["expiry_date"]),
                    }
                )

            self.logger.info(
                f"Full CRL metadata caricati: {len(self.revoked_certificates)} certificati revocati"
            )

        except Exception as e:
            self.logger.info(f"Errore caricamento Full CRL metadata: {e}")

    def log_operation(self, operation, details):
        """
        Log delle operazioni CRL per audit trail ETSI-compliant.

        Args:
            operation: Tipo di operazione (es. "PUBLISH_FULL_CRL", "REVOKE_CERTIFICATE")
            details: Dettagli dell'operazione
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        log_file = os.path.join(self.log_dir, f"{self.authority_id}_crl_audit.log")

        log_entry = {
            "timestamp": timestamp,
            "authority_id": self.authority_id,
            "operation": operation,
            "crl_number": self.crl_number,
            "details": details,
        }

        try:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
            self.logger.info(f"Operazione loggata: {operation}")
        except Exception as e:
            self.logger.info(f"Errore logging: {e}")

    def backup_crl(self, crl_type="full"):
        """
        Crea backup delle CRL per disaster recovery.

        Args:
            crl_type: Tipo di CRL ("full" o "delta")
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if crl_type == "full":
            source = self.full_crl_path
            backup_name = f"full_crl_backup_{timestamp}.pem"
        else:
            source = self.delta_crl_path
            backup_name = f"delta_crl_backup_{timestamp}.pem"

        backup_path = os.path.join(self.backup_dir, backup_name)

        try:
            if os.path.exists(source):
                import shutil

                shutil.copy2(source, backup_path)
                self.logger.info(f"Backup creato: {backup_path}")

                # Log backup operation
                self.log_operation("BACKUP_CRL", {"crl_type": crl_type, "backup_path": backup_path})
        except Exception as e:
            self.logger.info(f"Errore creazione backup: {e}")
