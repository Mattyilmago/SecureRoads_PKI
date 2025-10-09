from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import ReasonFlags
from datetime import datetime, timedelta, timezone
import os
import json
from utils.cert_utils import get_certificate_ski, get_certificate_identifier



class CRLManager:
    """
    Gestisce la creazione e pubblicazione di Full CRL e Delta CRL.
    
    Concetti chiave:
    - Full CRL: Lista completa di tutti i certificati revocati
    - Delta CRL: Lista incrementale delle revoche dall'ultimo Full CRL
    - Base CRL Number: Numero della Full CRL di riferimento per il Delta
    - CRL Sequence: Numero progressivo per tracciare la versione CRL
    """
    
    def __init__(self, authority_id, base_dir, issuer_certificate, issuer_private_key):
        """
        Inizializza il CRL Manager per una specifica autorità.
        
        Args:
            authority_id: ID dell'autorità (es. "EA_001", "AA_001", "RootCA")
            base_dir: Directory base per salvare CRL
            issuer_certificate: Certificato dell'autorità che firma le CRL
            issuer_private_key: Chiave privata per firmare le CRL
        """
        self.authority_id = authority_id
        self.issuer_certificate = issuer_certificate
        self.issuer_private_key = issuer_private_key
        
        # Percorsi file
        self.crl_dir = os.path.join(base_dir, "crl/")
        self.full_crl_path = os.path.join(self.crl_dir, "full_crl.pem")
        self.delta_crl_path = os.path.join(self.crl_dir, "delta_crl.pem")
        self.metadata_path = os.path.join(self.crl_dir, "crl_metadata.json")
        
        # Crea directory
        os.makedirs(self.crl_dir, exist_ok=True)
        
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
        
        print(f"[CRLManager] Inizializzato per {authority_id}")
        print(f"[CRLManager] CRL Number attuale: {self.crl_number}")
        print(f"[CRLManager] Base CRL Number: {self.base_crl_number}")


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
        expiry_date = certificate.not_valid_after_utc
        
        revocation_date = datetime.now(timezone.utc)
        
        print(f"[CRLManager] Aggiungendo certificato revocato:")
        print(f"[CRLManager]   Identificatore: {cert_id}")
        print(f"[CRLManager]   SKI: {ski[:16]}...")
        print(f"[CRLManager]   Serial: {serial_number}")
        print(f"[CRLManager]   Motivo: {reason}")
        print(f"[CRLManager]   Data scadenza: {expiry_date}")
        
        # Controlla se già revocato (usa SKI per confronto, con backward compatibility)
        for entry in self.revoked_certificates:
            # Prova prima con SKI (nuovo), poi con serial_number (vecchio)
            if entry.get("ski") == ski or entry.get("serial_number") == serial_number:
                print(f"[CRLManager] Certificato già presente nella lista revocati")
                return
        
        revoked_entry = {
            "serial_number": serial_number,  # Necessario per la CRL X.509
            "ski": ski,  # Per identificazione univoca
            "cert_id": cert_id,  # Human-readable
            "revocation_date": revocation_date,
            "expiry_date": expiry_date,
            "reason": reason
        }
        
        # Aggiunge a entrambe le liste
        self.revoked_certificates.append(revoked_entry)
        self.delta_revocations.append(revoked_entry)
        
        print(f"[CRLManager] Certificato aggiunto. Totale revocati: {len(self.revoked_certificates)}")
        print(f"[CRLManager] Revoche delta pending: {len(self.delta_revocations)}")


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
        print(f"[CRLManager] === GENERAZIONE FULL CRL ===")
        
        # Incrementa CRL number
        self.crl_number += 1
        self.base_crl_number = self.crl_number
        self.last_full_crl_time = datetime.now(timezone.utc)
        
        # Pulisce certificati scaduti prima di pubblicare
        self._cleanup_expired_certificates()
        
        print(f"[CRLManager] CRL Number: {self.crl_number}")
        print(f"[CRLManager] Certificati revocati: {len(self.revoked_certificates)}")
        
        # Crea CRL builder
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer_certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=validity_days))
        
        # Aggiunge CRL Number extension (obbligatoria per Full CRL)
        builder = builder.add_extension(
            x509.CRLNumber(self.crl_number),
            critical=False
        )
        
        # Aggiunge tutti i certificati revocati
        for entry in self.revoked_certificates:
            print(f"[CRLManager]   Serial: {entry['serial_number']}, "
                  f"Revocato: {entry['revocation_date']}, "
                  f"Scade: {entry['expiry_date']}, "
                  f"Motivo: {entry['reason']}")
            
            revoked_cert = x509.RevokedCertificateBuilder()\
                .serial_number(entry["serial_number"])\
                .revocation_date(entry["revocation_date"])\
                .add_extension(
                    x509.CRLReason(entry["reason"]),
                    critical=False
                ).build()
            builder = builder.add_revoked_certificate(revoked_cert)
        
        # Firma la CRL
        crl = builder.sign(private_key=self.issuer_private_key, algorithm=hashes.SHA256())
        
        # Salva su file
        with open(self.full_crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        
        print(f"[CRLManager] Full CRL salvata: {self.full_crl_path}")
        
        # Salva metadata Full CRL (snapshot completo)
        self.save_full_crl_metadata(validity_days)
        
        # Reset delta revocations (tutto è ora nella Full CRL)
        self.delta_revocations = []
        
        # Salva metadata manager generale
        self.save_metadata()
        
        print(f"[CRLManager] === FULL CRL PUBBLICATA ===")
        return crl


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
        print(f"[CRLManager] === GENERAZIONE DELTA CRL ===")
        
        # Controlla se ci sono nuove revoche
        if not self.delta_revocations:
            print(f"[CRLManager] Nessuna nuova revoca, Delta CRL non necessaria")
            return None
        
        # Incrementa CRL number
        self.crl_number += 1
        
        print(f"[CRLManager] CRL Number: {self.crl_number}")
        print(f"[CRLManager] Base CRL Number: {self.base_crl_number}")
        print(f"[CRLManager] Nuove revoche dal Full CRL: {len(self.delta_revocations)}")
        
        # Crea CRL builder
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.issuer_certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(hours=validity_hours))
        
        # Aggiunge CRL Number extension
        builder = builder.add_extension(
            x509.CRLNumber(self.crl_number),
            critical=False
        )
        
        # Aggiunge Delta CRL Indicator extension (identifica come Delta CRL)
        # Punta alla Full CRL base
        builder = builder.add_extension(
            x509.DeltaCRLIndicator(self.base_crl_number),
            critical=True  # DEVE essere critical secondo RFC 5280
        )
        
        # Aggiunge SOLO le nuove revoche
        for entry in self.delta_revocations:
            print(f"[CRLManager]   Serial: {entry['serial_number']}, "
                  f"Revocato: {entry['revocation_date']}, "
                  f"Motivo: {entry['reason']}")
            
            revoked_cert = x509.RevokedCertificateBuilder()\
                .serial_number(entry["serial_number"])\
                .revocation_date(entry["revocation_date"])\
                .add_extension(
                    x509.CRLReason(entry["reason"]),
                    critical=False
                ).build()
            builder = builder.add_revoked_certificate(revoked_cert)
        
        # Firma la Delta CRL
        crl = builder.sign(private_key=self.issuer_private_key, algorithm=hashes.SHA256())
        
        # Salva su file
        with open(self.delta_crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        
        print(f"[CRLManager] Delta CRL salvata: {self.delta_crl_path}")
        
        # Salva metadata Delta CRL (snapshot modifiche)
        self.save_delta_crl_metadata(validity_hours / 24)  # Converti ore in giorni
        
        # Salva metadata manager generale
        self.save_metadata()
        
        print(f"[CRLManager] === DELTA CRL PUBBLICATA ===")
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
            print(f"[CRLManager] Pulizia: rimossi {removed} certificati scaduti")
            print(f"[CRLManager] Certificati attivi rimasti: {len(self.revoked_certificates)}")


    def load_full_crl(self):
        """
        Carica la Full CRL dal file.
        
        Returns:
            x509.CertificateRevocationList o None se non esiste
        """
        if not os.path.exists(self.full_crl_path):
            print(f"[CRLManager] Full CRL non trovata")
            return None
        
        with open(self.full_crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        
        print(f"[CRLManager] Full CRL caricata:")
        print(f"[CRLManager]   Certificati revocati: {len(crl)}")
        print(f"[CRLManager]   Ultimo aggiornamento: {crl.last_update_utc}")
        print(f"[CRLManager]   Prossimo aggiornamento: {crl.next_update_utc}")
        
        return crl


    def load_delta_crl(self):
        """
        Carica la Delta CRL dal file.
        
        Returns:
            x509.CertificateRevocationList o None se non esiste
        """
        if not os.path.exists(self.delta_crl_path):
            print(f"[CRLManager] Delta CRL non trovata")
            return None
        
        with open(self.delta_crl_path, "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())
        
        print(f"[CRLManager] Delta CRL caricata:")
        print(f"[CRLManager]   Nuove revoche: {len(crl)}")
        print(f"[CRLManager]   Ultimo aggiornamento: {crl.last_update_utc}")
        print(f"[CRLManager]   Prossimo aggiornamento: {crl.next_update_utc}")
        
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
            "last_full_crl_time": self.last_full_crl_time.isoformat() if self.last_full_crl_time else None,
            "revoked_count": len(self.revoked_certificates),
            "delta_pending": len(self.delta_revocations)
        }
        
        with open(self.metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"[CRLManager] Metadata salvati: {self.metadata_path}")


    def load_metadata(self):
        """
        Carica metadata CRL da file JSON.
        """
        if not os.path.exists(self.metadata_path):
            print(f"[CRLManager] Nessun metadata esistente, inizializzo nuovo")
            return
        
        try:
            with open(self.metadata_path, "r") as f:
                metadata = json.load(f)
            
            self.crl_number = metadata.get("crl_number", 0)
            self.base_crl_number = metadata.get("base_crl_number", 0)
            
            last_full = metadata.get("last_full_crl_time")
            if last_full:
                self.last_full_crl_time = datetime.fromisoformat(last_full)
            
            print(f"[CRLManager] Metadata caricati con successo")
            print(f"[CRLManager]   CRL Number: {self.crl_number}")
            print(f"[CRLManager]   Base CRL Number: {self.base_crl_number}")
            
        except Exception as e:
            print(f"[CRLManager] Errore caricamento metadata: {e}")


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
            "last_full_crl": self.last_full_crl_time.isoformat() if self.last_full_crl_time else None
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
            "revoked_certificates": []
        }
        
        # Converti ReasonFlags in stringa per JSON
        for entry in self.revoked_certificates:
            metadata["revoked_certificates"].append({
                "serial_number": entry["serial_number"],
                "revocation_date": entry["revocation_date"].isoformat(),
                "reason": entry["reason"].name if isinstance(entry["reason"], ReasonFlags) else str(entry["reason"]),
                "expiry_date": entry["expiry_date"].isoformat()
            })
        
        # Salva su file
        full_metadata_path = self.full_crl_path.replace('.pem', '_metadata.json')
        with open(full_metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"[CRLManager] Metadata Full CRL salvati: {full_metadata_path}")


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
            "new_revocations": []
        }
        
        # Converti ReasonFlags in stringa per JSON
        for entry in self.delta_revocations:
            metadata["new_revocations"].append({
                "serial_number": entry["serial_number"],
                "revocation_date": entry["revocation_date"].isoformat(),
                "reason": entry["reason"].name if isinstance(entry["reason"], ReasonFlags) else str(entry["reason"]),
                "expiry_date": entry["expiry_date"].isoformat()
            })
        
        # Salva su file
        delta_metadata_path = self.delta_crl_path.replace('.pem', '_metadata.json')
        with open(delta_metadata_path, "w") as f:
            json.dump(metadata, f, indent=2)
        
        print(f"[CRLManager] Metadata Delta CRL salvati: {delta_metadata_path}")


    def load_full_crl_metadata(self):
        """
        Carica metadata Full CRL e ricostruisce lista certificati revocati.
        
        Questo permette di ripristinare lo stato completo dopo un riavvio,
        evitando la perdita della lista revoked_certificates.
        """
        full_metadata_path = self.full_crl_path.replace('.pem', '_metadata.json')
        
        if not os.path.exists(full_metadata_path):
            print(f"[CRLManager] Nessun metadata Full CRL esistente")
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
                
                self.revoked_certificates.append({
                    "serial_number": entry["serial_number"],
                    "revocation_date": datetime.fromisoformat(entry["revocation_date"]),
                    "reason": reason,
                    "expiry_date": datetime.fromisoformat(entry["expiry_date"])
                })
            
            print(f"[CRLManager] Full CRL metadata caricati: {len(self.revoked_certificates)} certificati revocati")
            
        except Exception as e:
            print(f"[CRLManager] Errore caricamento Full CRL metadata: {e}")
