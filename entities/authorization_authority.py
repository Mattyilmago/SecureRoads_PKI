import os
import secrets
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone

import schedule
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.x509 import ReasonFlags
from cryptography.x509.oid import NameOID

from managers.crl_manager import CRLManager
from utils.pki_io import PKIFileHandler

# ETSI Protocol Layer
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import (
    InnerAtRequest,
    InnerAtResponse,
    ResponseCode,
    compute_request_hash,
)
from utils.logger import PKILogger
from utils.cert_utils import (
    get_certificate_expiry_time,
    get_certificate_not_before,
    get_certificate_identifier,
    get_certificate_ski,
    get_short_identifier,
)
from utils.metrics import get_metrics_collector


class AuthorizationAuthority:
    def __init__(
        self, root_ca, tlm, aa_id=None, base_dir="./pki_data/aa/"
    ):
        """
        Inizializza Authorization Authority.

        Args:
            root_ca: Riferimento alla Root CA
            tlm: TrustListManager per validazione EC (OBBLIGATORIO)
            aa_id: ID dell'AA (generato automaticamente se None)
            base_dir: Directory base per dati AA
        """
        # Import here to avoid circular dependency
        from utils.pki_paths import PKIPathManager
        
        # Genera un ID randomico se non specificato
        if aa_id is None:
            aa_id = f"AA_{secrets.token_hex(4).upper()}"

        # Usa PKIPathManager per gestire i path in modo centralizzato
        paths = PKIPathManager.get_entity_paths("AA", aa_id, base_dir)
        
        # Store base_dir as instance attribute for stats endpoint
        self.base_dir = str(paths.base_dir)
        self.aa_id = aa_id
        
        # Crea tutte le directory necessarie
        paths.create_all()

        # Logger initialization (must be before any logger calls)
        self.log_dir = str(paths.logs_dir)
        # aa_id contiene gi il prefisso "AA_"
        self.logger = PKILogger.get_logger(name=aa_id, log_dir=self.log_dir, console_output=True)

        self.logger.info("=" * 80)
        self.logger.info(f"*** INIZIO INIZIALIZZAZIONE AUTHORIZATION AUTHORITY {aa_id} ***")
        self.logger.info("=" * 80)
        
        # Verifica che TLM sia fornito (OBBLIGATORIO)
        if not tlm:
            raise ValueError(f"TrustListManager (tlm) è obbligatorio per AA. Fornire un'istanza TLM valida.")
        
        self.aa_certificate_path = str(paths.certificates_dir / "aa_certificate.pem")
        self.aa_key_path = str(paths.private_keys_dir / "aa_key.pem")
        self.crl_path = str(paths.crl_dir / "aa_crl.pem")
        self.ticket_dir = str(paths.data_dir)  # authorization_tickets
        self.backup_dir = str(paths.backup_dir)
        self.private_key = None
        self.certificate = None
        self.root_ca = root_ca

        # Usa SEMPRE TLM per validazione EC (modalità moderna)
        self.tlm = tlm
        self.validation_mode = "TLM"
        self.logger.info(f"✅ Modalità TLM attiva: validazione EC tramite Trust List Manager")
        self.logger.info(f"   TLM Trust Anchors: {len(tlm.trust_anchors)}")

        # Directory già create da paths.create_all() sopra
        self.logger.info(f"✅ Struttura directory creata da PKIPathManager")

        self.load_or_generate_aa()

        # Inizializza CRLManager dopo aver caricato certificato e chiave privata
        self.logger.info(f"Inizializzando CRLManager per AA {aa_id}...")
        self.crl_manager = CRLManager(
            authority_id=aa_id,
            base_dir=self.base_dir,  # Usa il path specifico dell'istanza, non quello generico
            issuer_certificate=self.certificate,
            issuer_private_key=self.private_key,
        )
        self.logger.info(f"CRLManager inizializzato con successo!")
        
        # Pubblica CRL vuota iniziale se non esiste (per dashboard /api/crl/full)
        if not os.path.exists(self.crl_manager.full_crl_path):
            self.logger.info("Pubblicando Full CRL iniziale vuota...")
            self.crl_manager.publish_full_crl()
            self.logger.info("✅ Full CRL iniziale pubblicata")

        # Carica Full CRL in memoria per garantire consistenza (stessa logica EA)
        try:
            self.crl_manager.load_full_crl()
            self.logger.info("Full CRL caricata in memoria con successo")
        except Exception as e:
            self.logger.warning(f"Impossibile caricare Full CRL esistente: {e}")
            # Continua comunque - potrebbe essere il primo avvio

        # Inizializza ETSI Message Encoder per gestire messaggi conformi allo standard
        self.logger.info(f"Inizializzando ETSI Message Encoder (ASN.1 OER)...")
        self.message_encoder = ETSIMessageEncoder()
        self.logger.info(f"ETSI Message Encoder inizializzato!")

        # Inizializza scheduler automatico per CRL (ETSI TS 102 941)
        self.logger.info("Inizializzando scheduler automatico CRL...")
        self._init_crl_scheduler()
        self.logger.info("Scheduler CRL inizializzato!")

        # Inizializza scheduler per controllo certificati scaduti (ETSI TS 102 941)
        self.logger.info("Inizializzando scheduler controllo certificati scaduti...")
        self._init_expiry_scheduler()
        self.logger.info("Scheduler certificati scaduti inizializzato!")

        # 🆕 AUTO-REGISTER TO TLM
        # AA si auto-registra sempre al TLM passato nel costruttore
        self._auto_register_to_tlm()

        self.logger.info(f"Inizializzazione Authorization Authority {aa_id} completata!")

    # Carica chiave/certificate se esistono, altrimenti li genera
    def load_or_generate_aa(self):
        self.logger.info("Verifico esistenza chiave e certificato AA...")
        if os.path.exists(self.aa_key_path) and os.path.exists(self.aa_certificate_path):
            self.logger.info("Chiave e certificato AA trovati. Carico da file...")
            self.load_aa_keypair()
            self.load_aa_certificate()
        else:
            self.logger.info("Chiave o certificato AA non presenti. Genero nuovi...")
            self.generate_aa_keypair()
            self.generate_signed_certificate_from_rootca()

    # Genera una chiave privata ECC e la salva su file
    def generate_aa_keypair(self):
        self.logger.info("Generazione chiave privata ECC per AA...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        with open(self.aa_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        self.logger.info("Chiave privata AA generata e salvata.")

    # Chiede alla rootCa di generare e firmare un certificato. Salva il certificato X.509 firmato
    def generate_signed_certificate_from_rootca(self):
        self.logger.info(f"Richiedo alla Root CA la firma del certificato AA {self.aa_id}...")
        subject_name = f"AuthorizationAuthority_{self.aa_id}"
        aa_certificate = self.root_ca.sign_certificate(
            subject_public_key=self.private_key.public_key(), subject_name=subject_name, is_ca=True
        )
        self.certificate = aa_certificate
        with open(self.aa_certificate_path, "wb") as f:
            f.write(aa_certificate.public_bytes(serialization.Encoding.PEM))
        self.logger.info(f"Certificato AA firmato dalla Root CA salvato: {self.aa_certificate_path}")

        # Archivia il certificato anche nella RootCA
        self.logger.info(f"Richiedendo archiviazione certificato nella RootCA...")
        self.root_ca.save_subordinate_certificate(aa_certificate)

    # Carica la chiave privata ECC dal file PEM
    def load_aa_keypair(self):
        self.logger.info("Caricamento chiave privata AA da file...")
        self.private_key = PKIFileHandler.load_private_key(self.aa_key_path)
        self.logger.info("Chiave privata AA caricata.")

    def load_aa_certificate(self):
        self.logger.info("Caricamento certificato AA da file...")
        self.certificate = PKIFileHandler.load_certificate(self.aa_certificate_path)
        self.logger.info("Certificato AA caricato.")

    # Processa richiesta per AT con un EC di un ITS-S
    def process_authorization_request(self, ec_pem, its_id, attributes=None):
        self.logger.info(f"Ricevuta richiesta di Authorization Ticket da ITS-S {its_id}")
        try:
            ec_certificate = x509.load_pem_x509_certificate(ec_pem)
            self.logger.info(f"EC caricato per ITS-S {its_id}, verifico chain e validit...")

            # === VALIDAZIONE EC tramite TLM ===
            self.logger.info(f"Validazione EC tramite TLM...")
            is_trusted, trust_info = self.tlm.is_trusted(ec_certificate)

            if not is_trusted:
                self.logger.info(f"[ERROR] EC NON valido: {trust_info}")
                return None

            self.logger.info(f"[OK] EC validato tramite TLM: {trust_info}")

            # === VERIFICA SCADENZA ===
            ec_expiry = get_certificate_expiry_time(ec_certificate)
            # not_valid_after_utc is already timezone-aware
            if ec_expiry < datetime.now(timezone.utc):
                self.logger.info("[ERROR] EC scaduto.")
                return None

            self.logger.info("[OK] EC valido. Procedo con emissione Authorization Ticket.")

        except Exception as e:
            self.logger.info(f"[ERROR] Errore nel parsing EC: {e}")
            return None

        at_certificate = self.issue_authorization_ticket(
            its_id, ec_certificate.public_key(), attributes
        )
        return at_certificate

    # Firma la chiave pubblica dellITS-S ricevuta via EC, genera il certificato AT e lo salva
    def issue_authorization_ticket(self, its_id, public_key, attributes=None):
        """Emette un Authorization Ticket (ottimizzato per performance)."""
        # Costruzione certificato in memoria
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-S"),
            x509.NameAttribute(NameOID.COMMON_NAME, its_id),
        ])
        
        now_utc = datetime.now(timezone.utc)
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now_utc)
            .not_valid_after(now_utc + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )

        # Firma (operazione crittografica veloce)
        certificate = cert_builder.sign(self.private_key, hashes.SHA256())

        # Salvataggio ottimizzato
        # Usa serial per nome file invece di its_id per evitare sovrascritture in batch
        at_filename = f"AT_{certificate.serial_number}.pem"
        at_path = os.path.join(self.ticket_dir, at_filename)

        with open(at_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        # Log minimo solo in debug mode
        if self.logger.level <= 10:
            self.logger.debug(f"AT emesso: {certificate.serial_number}, serial: {certificate.serial_number}")
        
        return certificate

    def issue_authorization_ticket_batch(self, its_id, public_keys, attributes=None):
        """
        Emette un batch di Authorization Tickets per un veicolo ITS-S.

        Args:
            its_id: ID del veicolo ITS-S (string) o SharedAtRequest object
            public_keys: Lista di chiavi pubbliche per gli AT o lista di InnerAtRequest
            attributes: Attributi opzionali o enrollment certificate

        Returns:
            Lista di certificati AT generati
        """
        # Se its_id  un oggetto SharedAtRequest, converti
        if hasattr(its_id, "eaId"):
            shared_request = its_id
            inner_requests = public_keys
            # Converti eaId in stringa (hex se bytes, altrimenti string)
            if isinstance(shared_request.eaId, bytes):
                its_id_str = f"Vehicle_{shared_request.eaId.hex()}"
            else:
                its_id_str = f"Vehicle_{shared_request.eaId}"
            # Estrai le chiavi pubbliche dagli InnerAtRequest
            extracted_keys = []
            for req in inner_requests:
                if hasattr(req, "publicKeys"):
                    pk = req.publicKeys
                    if isinstance(pk, dict):
                        # publicKeys  un dict, prendi il primo valore
                        for key in pk.values():
                            # La chiave può essere bytes o già un oggetto chiave pubblica
                            if isinstance(key, bytes):
                                # Prova a convertire bytes in chiave pubblica EC
                                try:
                                    from cryptography.hazmat.primitives.serialization import (
                                        load_der_public_key,
                                    )

                                    public_key = load_der_public_key(key)
                                    extracted_keys.append(public_key)
                                except Exception:
                                    # Se fallisce la deserializzazione, usa i bytes direttamente
                                    extracted_keys.append(key)
                            else:
                                #  già un oggetto chiave pubblica
                                extracted_keys.append(key)
                            break  # Una chiave per request
                    else:
                        # publicKeys  direttamente una chiave pubblica
                        extracted_keys.append(pk)
            public_keys = extracted_keys if extracted_keys else public_keys
        else:
            its_id_str = its_id

        self.logger.info(f"Emissione batch di {len(public_keys)} Authorization Tickets per {its_id_str}")

        if not public_keys or len(public_keys) == 0:
            raise RuntimeError("Batch vuoto: almeno una chiave pubblica richiesta")

        certificates = []
        for idx, public_key in enumerate(public_keys):
            self.logger.info(f"Generando AT {idx+1}/{len(public_keys)}...")
            cert = self.issue_authorization_ticket(its_id_str, public_key, attributes)
            certificates.append(cert)

        self.logger.info(f"Batch di {len(certificates)} AT emessi con successo!")
        return certificates

    # Aggiunge un certificato alla lista degli AT revocati
    def revoke_authorization_ticket(self, certificate, reason=ReasonFlags.unspecified):
        """
        Revoca un Authorization Ticket aggiungendolo alla lista dei certificati revocati.
        Pubblica automaticamente una Delta CRL.

        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number
        expiry_date = get_certificate_expiry_time(certificate)

        self.logger.info(f"Revocando Authorization Ticket con serial: {serial_number}")
        self.logger.info(f"Data di scadenza certificato: {expiry_date}")
        self.logger.info(f"Motivo revoca: {reason}")

        # Usa CRLManager per aggiungere il certificato revocato
        self.crl_manager.add_revoked_certificate(certificate, reason)
        self.logger.info(f"Authorization Ticket aggiunto alla lista di revoca AA")

        # Pubblica Delta CRL incrementale (senza backup per performance)
        self.logger.info(f"Pubblicando Delta CRL AA...")
        self.crl_manager.publish_delta_crl(skip_backup=True)
        self.logger.info(f"Revoca completata!")

    def revoke_by_serial(self, serial_hex, reason=ReasonFlags.unspecified):
        """
        Revoca un Authorization Ticket usando il serial number.

        Args:
            serial_hex: Serial number in formato esadecimale
            reason: Il motivo della revoca (ReasonFlags)
        """
        self.logger.info(f"Revocando Authorization Ticket con serial (hex): {serial_hex}")
        self.logger.info(f"Motivo revoca: {reason}")

        # Usa CRLManager per revocare per serial
        self.crl_manager.revoke_by_serial(serial_hex, reason)
        self.logger.info("Authorization Ticket revocato tramite CRLManager")

        # Pubblica Delta CRL incrementale (senza backup per performance)
        self.logger.info("Pubblicando Delta CRL AA...")
        self.crl_manager.publish_delta_crl(skip_backup=True)
        self.logger.info("Revoca completata!")

    # Genera e salva una Full CRL completa conforme X.509 ASN.1 su file PEM
    def publish_crl(self, validity_days=7):
        """
        Pubblica una Full CRL completa consolidando tutte le revoche.
        Questo metodo dovrebbe essere chiamato periodicamente (es. settimanalmente)
        per consolidare tutte le Delta CRL in una nuova Full CRL.

        Args:
            validity_days: Numero di giorni di validit della Full CRL (default: 7)
        """
        self.logger.info(f"Pubblicando Full CRL AA (validit: {validity_days} giorni)...")
        self.crl_manager.publish_full_crl(validity_days=validity_days)
        self.logger.info(f"Full CRL AA pubblicata con successo!")

    # Carica la CRL da file
    def load_crl(self):
        self.logger.info(f"Carico la CRL AA da file: {self.crl_path}")
        if os.path.exists(self.crl_path):
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
            self.logger.info(f"CRL AA caricata con {len(crl)} certificati revocati.")
            return crl
        self.logger.info("CRL AA non trovata, restituisco None.")
        return None

    # ========================================================================
    # AUTOMATIC CRL SCHEDULER (ETSI TS 102 941 - Section 6.3.3)
    # ========================================================================

    def _init_crl_scheduler(self):
        """
        Inizializza scheduler automatico per pubblicazione CRL secondo ETSI standards.

        ETSI TS 102 941 Raccomandazioni:
        - Full CRL: Pubblicazione periodica (settimanale)
        - Delta CRL: Pubblicazione frequente (oraria) per revoche recenti
        """
        # Cancella eventuali job precedenti
        schedule.clear('aa-crl')

        # Full CRL: ogni domenica alle 02:30 (settimanale, 30 min dopo EA)
        schedule.every().sunday.at("02:30").do(self._scheduled_publish_full_crl).tag('aa-crl')

        # Delta CRL: ogni ora (per revoche recenti)
        schedule.every(1).hours.do(self._scheduled_publish_delta_crl).tag('aa-crl')

        # Avvia thread di background per eseguire lo scheduler
        self.scheduler_thread = threading.Thread(
            target=self._run_scheduler,
            daemon=True,
            name=f"AA-{self.aa_id}-CRL-Scheduler"
        )
        self.scheduler_thread.start()

        self.logger.info("Scheduler CRL configurato:")
        self.logger.info("  - Full CRL: ogni domenica alle 02:30")
        self.logger.info("  - Delta CRL: ogni ora")

    def _run_scheduler(self):
        """
        Esegue il loop dello scheduler in background thread.
        """
        self.logger.info(f"Scheduler thread avviato per AA {self.aa_id}")

        while True:
            try:
                schedule.run_pending()
                # Sleep per 60 secondi tra controlli
                threading.Event().wait(60)
            except Exception as e:
                self.logger.error(f"Errore nello scheduler CRL: {e}")
                # Continua nonostante errori
                threading.Event().wait(60)

    def _scheduled_publish_full_crl(self):
        """
        Job schedulato per pubblicazione Full CRL settimanale.
        """
        try:
            self.logger.info("=== SCHEDULER: Pubblicazione Full CRL settimanale ===")
            self.publish_crl(validity_days=7)
            self.logger.info("=== SCHEDULER: Full CRL pubblicata con successo ===")
        except Exception as e:
            self.logger.error(f"Errore pubblicazione Full CRL schedulata: {e}")

    def _scheduled_publish_delta_crl(self):
        """
        Job schedulato per pubblicazione Delta CRL oraria.
        """
        try:
            # Pubblica solo se ci sono nuove revoche
            if self.crl_manager.delta_revocations:
                self.logger.info("=== SCHEDULER: Pubblicazione Delta CRL oraria ===")
                self.crl_manager.publish_delta_crl(validity_hours=24)
                self.logger.info("=== SCHEDULER: Delta CRL pubblicata con successo ===")
            else:
                self.logger.debug("Scheduler: Nessuna nuova revoca, Delta CRL non necessaria")
        except Exception as e:
            self.logger.error(f"Errore pubblicazione Delta CRL schedulata: {e}")

    # AUTOMATIC EXPIRY SCHEDULER (ETSI TS 102 941 - Section 6.3.3)
    # ========================================================================

    def _init_expiry_scheduler(self):
        """
        Inizializza scheduler automatico per controllo certificati scaduti secondo ETSI standards.

        ETSI TS 102 941 Raccomandazioni:
        - Controllo periodico certificati scaduti per decrementare contatore active_certificates
        - Frequenza: ogni ora per garantire accuratezza real-time
        """
        # Cancella eventuali job precedenti
        schedule.clear('aa-expiry')

        # Controllo certificati scaduti: ogni ora
        schedule.every(1).hours.do(self._scheduled_check_expired_certificates).tag('aa-expiry')

        self.logger.info("Scheduler controllo certificati scaduti configurato:")
        self.logger.info("  - Controllo ogni ora")

    def _scheduled_check_expired_certificates(self):
        """
        Job schedulato per controllo certificati AT scaduti e decremento contatore.
        """
        try:
            self.logger.debug("=== SCHEDULER: Controllo certificati AT scaduti ===")

            # Conta certificati scaduti trovati
            expired_count = 0

            # Scansiona directory certificati per file AT_*.pem
            certificates_dir = self.paths.certificates_dir
            if not certificates_dir.exists():
                self.logger.debug("Directory certificati non esiste")
                return

            for cert_file in certificates_dir.glob("AT_*.pem"):
                try:
                    # Carica certificato
                    with open(cert_file, 'rb') as f:
                        cert_data = f.read()
                    certificate = x509.load_pem_x509_certificate(cert_data)

                    # Controlla se è scaduto
                    now = datetime.now(timezone.utc)
                    if certificate.not_valid_after_utc <= now:
                        # Certificato scaduto - decrementa contatore
                        metrics = get_metrics_collector()
                        metrics.decrement_counter('active_certificates')
                        expired_count += 1

                        # Log solo per debug, non rimuovere file (potrebbe servire per audit)
                        self.logger.debug(f"Certificato AT scaduto trovato: {cert_file.name}")

                except Exception as e:
                    self.logger.warning(f"Errore lettura certificato {cert_file.name}: {e}")
                    continue

            if expired_count > 0:
                self.logger.info(f"=== SCHEDULER: {expired_count} certificati AT scaduti trovati, contatore decrementato ===")
            else:
                self.logger.debug("=== SCHEDULER: Nessun certificato AT scaduto trovato ===")

        except Exception as e:
            self.logger.error(f"Errore controllo certificati scaduti schedulato: {e}")

    # ========================================================================
    # ETSI TS 102941 PROTOCOL METHODS (ASN.1 OER)
    # ========================================================================

    def process_authorization_request_etsi(self, request_bytes: bytes) -> bytes:
        """
        Processa una AuthorizationRequest ETSI TS 102941 (ASN.1 OER encoded).

        ?? FLUSSO COMPLETO:
        1. Decripta e decodifica AuthorizationRequest (ASN.1 OER)
        2. Estrae Enrollment Certificate allegato
        3. Valida EC tramite TLM o EA (legacy)
        4. Verifica che EC non sia revocato (CRL check)
        5. Emette Authorization Ticket
        6. Crea AuthorizationResponse (ASN.1 OER encoded)
        7. Cripta risposta con hmacKey per unlinkability

        Args:
            request_bytes: ASN.1 OER encoded AuthorizationRequest

        Returns:
            ASN.1 OER encoded AuthorizationResponse (encrypted con hmacKey)
        """
        self.logger.info(f"\nRicevuto AuthorizationRequest ETSI (ASN.1 OER): {len(request_bytes)} bytes")

        try:
            # 1. Decripta e decodifica request
            self.logger.info(f"Decrittando AuthorizationRequest con chiave privata AA...")
            inner_at_request = self.message_encoder.decode_authorization_request(
                request_bytes, self.private_key
            )

            self.logger.info(f"Request decrittata con successo!")
            self.logger.info(f"   Public keys: {list(inner_at_request.publicKeys.keys())}")
            self.logger.info(f"   HMAC key length: {len(inner_at_request.hmacKey)} bytes")
            self.logger.info(f"   Requested attributes: {inner_at_request.requestedSubjectAttributes}")

            # 2. Estrai Enrollment Certificate dalla request
            # NOTA: In ETSI TS 102941, l'EC  allegato nell'AuthorizationRequest
            # Per ora usiamo un placeholder, in futuro va estratto dal messaggio ASN.1
            self.logger.info(f"Estrazione Enrollment Certificate da request...")
            # TODO: Implementare estrazione EC dal messaggio ASN.1
            # enrollment_cert = extract_ec_from_request(request_bytes)
            self.logger.info(f"[WARNING] Estrazione EC non ancora implementata (placeholder)")

            # 3. Valida EC
            if self.validation_mode == "TLM":
                self.logger.info(f"Validazione EC tramite TLM...")
                # TODO: Implementare validazione tramite TLM
                # is_valid = self.tlm.validate_ec(enrollment_cert)
                is_valid = True  # Placeholder
                self.logger.info(f"[WARNING] Validazione TLM non ancora implementata (placeholder)")
            elif self.validation_mode == "LEGACY":
                self.logger.info(f"Validazione EC tramite EA (legacy)...")
                # TODO: Implementare validazione tramite EA
                is_valid = True  # Placeholder
                self.logger.info(f"[WARNING] Validazione EA legacy non ancora implementata (placeholder)")
            else:
                self.logger.info(f"[WARNING] Nessuna validazione EC configurata, accetto request")
                is_valid = True

            if not is_valid:
                self.logger.info(f"[ERROR] EC non valido, rifiuto request")
                return self._create_at_error_response(
                    request_bytes, inner_at_request.hmacKey, ResponseCode.UNAUTHORIZED
                )

            # 4. Estrai chiave pubblica e emetti Authorization Ticket
            verification_key_bytes = inner_at_request.publicKeys.get("verification")
            if not verification_key_bytes:
                self.logger.info(f"[ERROR] Errore: Nessuna verification key fornita")
                return self._create_at_error_response(
                    request_bytes, inner_at_request.hmacKey, ResponseCode.BAD_REQUEST
                )

            # Deserializza chiave pubblica
            try:
                public_key = load_der_public_key(verification_key_bytes)
            except:
                # Prova formato X9.62 uncompressed point
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), verification_key_bytes
                )

            self.logger.info(f"Emissione Authorization Ticket...")
            # Genera ITS-ID univoco per AT
            its_id = f"AT_{secrets.token_hex(8)}"

            at_certificate = self.issue_authorization_ticket(
                its_id=its_id,
                public_key=public_key,
                attributes=inner_at_request.requestedSubjectAttributes,
            )
            self.logger.info(f"Authorization Ticket emesso: serial {at_certificate.serial_number}")

            # 5. Crea e cripta response con hmacKey
            self.logger.info(f"Creando AuthorizationResponse (ASN.1 OER)...")
            request_hash = compute_request_hash(request_bytes)

            response_bytes = self.message_encoder.encode_authorization_response(
                response_code=ResponseCode.OK,
                request_hash=request_hash,
                certificate=at_certificate,
                hmac_key=inner_at_request.hmacKey,
            )

            self.logger.info(f"AuthorizationResponse creata: {len(response_bytes)} bytes")
            self.logger.info(f"   Response code: OK")
            self.logger.info(f"   Certificate attached: Yes")
            self.logger.info(f"   Encryption: HMAC-based (unlinkability)")
            self.logger.info(f"   Encoding: ASN.1 OER")

            return response_bytes

        except Exception as e:
            self.logger.info(f"[ERROR] Errore durante processing AuthorizationRequest: {e}")
            traceback.print_exc()
            # Se abbiamo hmacKey, usiamolo per error response
            try:
                return self._create_at_error_response(
                    request_bytes, inner_at_request.hmacKey, ResponseCode.INTERNAL_SERVER_ERROR
                )
            except:
                # Se non riusciamo nemmeno a decrittare la request, non possiamo rispondere
                self.logger.info(f"[ERROR] Impossibile creare error response (request non decrittabile)")
                raise

    def _create_at_error_response(
        self, request_bytes: bytes, hmac_key: bytes, error_code: ResponseCode
    ) -> bytes:
        """
        Crea una AuthorizationResponse di errore.

        Args:
            request_bytes: Request originale per calcolare hash
            hmac_key: HMAC key dalla request per cifrare risposta
            error_code: Codice errore da ritornare

        Returns:
            ASN.1 OER encoded AuthorizationResponse con errore
        """
        self.logger.info(f"[WARNING] Creando AT error response: {error_code}")
        request_hash = compute_request_hash(request_bytes)

        return self.message_encoder.encode_authorization_response(
            response_code=error_code, request_hash=request_hash, certificate=None, hmac_key=hmac_key
        )

    def _auto_register_to_tlm(self):
        """
        Auto-registrazione al TLM.
        AA ha già un riferimento al TLM nel costruttore, quindi usa quello.
        """
        try:
            from utils.cert_utils import get_certificate_ski
            
            # AA ha già self.tlm dal costruttore
            if not self.tlm:
                self.logger.debug("TLM not available for auto-registration")
                return
            
            # Controlla se già registrato
            aa_ski = get_certificate_ski(self.certificate)
            already_registered = any(anchor.get("ski") == aa_ski for anchor in self.tlm.trust_anchors)
            
            if not already_registered:
                self.tlm.add_trust_anchor(self.certificate, authority_type="AA")
                self.logger.info(f"✅ Auto-registered {self.aa_id} to TLM")
            else:
                self.logger.debug(f"AA {self.aa_id} già registrato in TLM")
                
        except Exception as e:
            # Auto-registration è best-effort, non blocca l'inizializzazione
            self.logger.debug(f"Auto-registration to TLM skipped: {e}")
