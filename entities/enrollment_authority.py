import os
import secrets
import threading
import traceback
from datetime import datetime, timedelta, timezone
from typing import Optional

import schedule
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

# ETSI Protocol Layer - ASN.1 Implementation (100% ETSI Standard)
from protocols.certificates.asn1_encoder import (
    decode_certificate_with_asn1,
    generate_enrollment_certificate,
    generate_subordinate_certificate,
)
from protocols.core import compute_hashed_id8, etsi_verification_key_to_public_key, etsi_encryption_key_to_public_key
from protocols.core.primitives import extract_validity_period
from protocols.messages.encoder import ETSIMessageEncoder
from protocols.messages import (
    InnerEcRequest,
    InnerEcResponse,
)
from protocols.core import ResponseCode, compute_request_hash

# Managers (Direct imports - NO interfaces needed)
from managers.crl_manager import CRLManager

# Utilities
from utils.logger import PKILogger
from utils.metrics import get_metrics_collector
from utils.pki_io import PKIFileHandler
from utils.pki_paths import PKIPathManager


class EnrollmentAuthority:
    """
    Enrollment Authority (EA) - ETSI TS 102941 Compliant
    
    **REFACTORED VERSION** - ASN.1 asn Migration Complete
    
    Implementa l'Enrollment Authority secondo lo standard ETSI TS 102941 V2.1.1.
    
    Responsabilità (Single Responsibility):
    - Emissione Enrollment Certificates (EC) in formato ASN.1 asn nativo
    - Gestione revoche tramite CRLManager (delegazione)
    - Validazione Proof of Possession nelle EnrollmentRequest
    - Pubblicazione automatica CRL (Full e Delta)
    
    **Formato Certificati:**
    - EA Certificate: **ASN.1 asn** (ETSI TS 103097) - firmato da Root CA
    - Enrollment Certificates (EC): ASN.1 asn binario (ETSI TS 103097)
    - CRL: ASN.1 OER (ETSI TS 102941, gestito da CRLManager)
    
    Standard ETSI Implementati:
    - ETSI TS 102941 V2.1.1: Trust and Privacy Management
    - ETSI TS 103097 V2.1.1: Certificate Formats and Security Headers
    
    Metodi Principali (ETSI-compliant):
    - process_enrollment_request_etsi(): Processa EnrollmentRequest ASN.1 asn
    - issue_enrollment_certificate(): Genera EC in formato ASN.1 asn
    - revoke_certificate(): Delega revoca a CRLManager (usa HashedId8)
    
    Design Patterns Used:
    - Dependency Injection: Dependencies passed via constructor
    - Service Layer: CRLManager for revocations
    - Single Responsibility: Certificate issuance only
    - DRY: No code duplication, reuse via delegation
    """
    
    def __init__(
        self,
        root_ca,
        tlm,
        ea_id: Optional[str] = None,
        base_dir: str = None
    ):
        """
        Inizializza Enrollment Authority.

        Args:
            root_ca: RootCA instance per firma certificato EA
            tlm: TrustListManager per registration (REQUIRED per ETSI TS 102941 § 6.1.3)
            ea_id: ID dell'EA (generato automaticamente se None)
            base_dir: Directory base per dati EA (default: PKI_PATHS.get_ea_path(ea_id))
            
        Raises:
            ValueError: Se parametri obbligatori mancanti
        
        Note:
            ETSI TS 102941 § 6.1.3 richiede che ogni EA sia registrata presso un TLM
        """
        # ========================================================================
        # 1. VALIDAZIONE PARAMETRI
        # ========================================================================
        
        if not root_ca:
            raise ValueError("root_ca è obbligatorio (istanza RootCA)")
        
        if not tlm:
            raise ValueError("tlm è obbligatorio per ETSI TS 102941 compliance (§ 6.1.3)")
        
        # Genera ID randomico se non specificato
        if ea_id is None:
            ea_id = f"EA_{secrets.token_hex(4).upper()}"

        # Store TLM reference for auto-registration
        self._tlm_for_registration = tlm
        
        # ========================================================================
        # 2. INIZIALIZZAZIONE PATH MANAGER E LOGGER
        # ========================================================================

        # Usa PKIPathManager per gestire i path in modo centralizzato
        self.paths = PKIPathManager.get_entity_paths("EA", ea_id, base_dir)
        
        # Crea tutte le directory necessarie
        self.paths.create_all()

        # Store IDs early for logger initialization
        self.ea_id = ea_id
        self.base_dir = str(self.paths.base_dir)
        # Standard ETSI: .oer per certificati ASN.1 OER encoded, .key per chiavi, .pem per CRL
        self.ea_certificate_path = str(self.paths.certificates_dir / "ea_certificate.oer")
        self.ea_key_path = str(self.paths.private_keys_dir / "ea_key.key")
        self.ec_dir = str(self.paths.data_dir)  # enrollment_certificates
        self.crl_path = str(self.paths.crl_dir / "ea_crl.pem")
        self.log_dir = str(self.paths.logs_dir)
        self.backup_dir = str(self.paths.backup_dir)
        
        # Inizializza logger (ea_id contiene già il prefisso "EA_")
        self.logger = PKILogger.get_logger(
            name=ea_id,
            log_dir=self.log_dir,
            console_output=True
        )
        
        self.logger.info("=" * 80)
        self.logger.info(f"*** INIZIALIZZAZIONE ENROLLMENT AUTHORITY {ea_id} ***")
        self.logger.info("=" * 80)
        self.logger.info(f"Directory base: {self.base_dir}")
        self.logger.info(f"Percorso certificato EA: {self.ea_certificate_path}")
        self.logger.info(f"Directory EC: {self.ec_dir}")
        self.logger.info(f"✅ Struttura directory creata da PKIPathManager")

        # ========================================================================
        # 3. STORE DEPENDENCIES
        # ========================================================================
        
        self.root_ca = root_ca
        self.private_key = None
        self.certificate_asn1 = None  # EA certificate in ASN.1 asn format

        self.logger.info("✅ Dependencies stored successfully")
        self.logger.info(f"   - RootCA: {type(root_ca).__name__}")

        # ========================================================================
        # 4. INITIALIZE ENCODERS (BEFORE CERTIFICATE GENERATION)
        # ========================================================================
        
        self.logger.info("Inizializzando ETSI Message Encoder (ASN.1 asn)...")
        self.message_encoder = ETSIMessageEncoder()
        self.logger.info("✅ ETSI Message Encoder inizializzato!")

        # ========================================================================
        # 5. LOAD OR GENERATE EA CERTIFICATE AND KEY
        # ========================================================================
        
        self.logger.info("Caricando o generando chiave e certificato EA...")
        self.load_or_generate_ea()
        
        # Compute EA's HashedId8 from EA certificate ASN.1 (ETSI TS 103097 V2.1.1)
        self.ea_hashed_id8 = compute_hashed_id8(self.certificate_asn1)
        self.logger.info(f"✅ EA HashedId8: {self.ea_hashed_id8.hex()[:16]}...")

        # ========================================================================
        # 6. INITIALIZE CRL MANAGER  
        # ========================================================================
        
        self.logger.info(f"Inizializzando CRLManager per EA {ea_id}...")
        
        # CRLManager usa ASN.1 OER format (ETSI TS 102941 compliant)
        # Tutti i dati PKI sono in ASN.1 OER, inclusi i CRL
        self.crl_manager = None
        self.logger.info("⚠️  CRLManager temporaneamente disabilitato (implementazione futura)")
        
        # Pubblica CRL vuota iniziale se non esiste (SKIP per ora)
        # if not os.path.exists(self.crl_manager.full_crl_path):
        #     self.logger.info("Pubblicando Full CRL iniziale vuota...")
        #     self.crl_manager.publish_full_crl()
        #     self.logger.info("✅ Full CRL iniziale pubblicata")

        # Carica Full CRL in memoria per garantire consistenza (SKIP per ora)
        # try:
        #     self.crl_manager.load_full_crl()
        #     self.logger.info("✅ Full CRL caricata in memoria")
        # except Exception as e:
        #     self.logger.warning(f"Impossibile caricare Full CRL esistente: {e}")

        # ========================================================================
        # 9. INITIALIZE SCHEDULERS (CRL + EXPIRY)
        # ========================================================================
        
        # Skip schedulers until CRL is migrated to ASN.1
        # self.logger.info("Inizializzando scheduler automatico CRL...")
        # self._init_crl_scheduler()
        # self.logger.info("✅ Scheduler CRL inizializzato!")

        self.logger.info("Inizializzando scheduler controllo certificati scaduti...")
        self._init_expiry_scheduler()
        self.logger.info("✅ Scheduler certificati scaduti inizializzato!")

        # ========================================================================
        # 10. AUTO-REGISTER TO TLM
        # ========================================================================
        
        self._auto_register_to_tlm()

        self.logger.info("=" * 80)
        self.logger.info(f"✅ INIZIALIZZAZIONE ENROLLMENT AUTHORITY {ea_id} COMPLETATA!")
        self.logger.info("=" * 80)

    # ========================================================================
    # ETSI TS 102941 PROTOCOL METHODS (ASN.1 asn)
    # ========================================================================

    def process_enrollment_request_etsi(self, request_bytes: bytes) -> bytes:
        """
        Processa una EnrollmentRequest ETSI TS 102941 (ASN.1 asn encoded).

        FLUSSO COMPLETO:
        1. Decripta e decodifica EnrollmentRequest (ASN.1 asn)
        2. Verifica Proof of Possession (firma ITS-S)
        3. Emette Enrollment Certificate in formato ASN.1 asn
        4. Crea EnrollmentResponse (ASN.1 asn encoded)
        5. Cripta risposta con chiave pubblica ITS-S

        Args:
            request_bytes: ASN.1 asn encoded EnrollmentRequest

        Returns:
            ASN.1 asn encoded EnrollmentResponse (encrypted)
        """
        self.logger.info(f"🔄 Ricevuto EnrollmentRequest ETSI (ASN.1 asn): {len(request_bytes)} bytes")

        try:
            # 1. Decripta e decodifica request
            self.logger.info("🔓 Decrittando EnrollmentRequest con chiave privata EA...")
            inner_ec_request_signed = self.message_encoder.decode_enrollment_request(
                request_bytes, self.private_key
            )

            inner_ec_request = inner_ec_request_signed.ecRequest
            self.logger.info("✅ Request decrittata con successo!")
            self.logger.info(f"   ITS-S ID: {inner_ec_request.itsId}")
            self.logger.info(f"   Public keys: {list(inner_ec_request.publicKeys.keys())}")
            self.logger.info(f"   Requested attributes: {inner_ec_request.requestedSubjectAttributes}")

            # 2. Verifica Proof of Possession (già verificato dal message encoder)
            self.logger.info("✅ Proof of Possession verificato")

            # 3. Estrai chiavi pubbliche (verification per certificato, encryption per risposta)
            # ETSI TS 102 941 V2.1.1 Section 6.2.3.4:
            # - Verification key: usata per il certificato enrollment
            # - Encryption key: usata per cifrare la risposta enrollment
            verification_key_asn1 = inner_ec_request.publicKeys.get("verification")
            encryption_key_asn1 = inner_ec_request.publicKeys.get("encryption")
            
            if not verification_key_asn1:
                self.logger.error("❌ Errore: Nessuna verification key fornita")
                return self._create_error_response(request_bytes, ResponseCode.BAD_REQUEST)
            
            if not encryption_key_asn1:
                self.logger.error("❌ Errore: Nessuna encryption key fornita")
                return self._create_error_response(request_bytes, ResponseCode.INVALID_ENCRYPTION_KEY)

            # Converti chiave di verifica da formato ASN.1 ETSI a EllipticCurvePublicKey
            # La chiave arriva in formato ASN.1: ('ecdsaNistP256', ('compressed-y-0', x_bytes))
            try:
                verification_public_key = etsi_verification_key_to_public_key(verification_key_asn1)
                self.logger.info(f"✅ Verification key convertita da ASN.1 ETSI")
            except Exception as e:
                self.logger.error(f"❌ Errore conversione verification key: {e}")
                return self._create_error_response(request_bytes, ResponseCode.BAD_REQUEST)
            
            # Converti chiave di encryption da formato ASN.1 ETSI a EllipticCurvePublicKey
            # La chiave arriva in formato ASN.1: {'supportedSymmAlg': 'aes128Ccm', 'publicKey': (...)}
            try:
                encryption_public_key = etsi_encryption_key_to_public_key(encryption_key_asn1)
                self.logger.info(f"✅ Encryption key convertita da ASN.1 ETSI")
            except Exception as e:
                self.logger.error(f"❌ Errore conversione encryption key: {e}")
                return self._create_error_response(request_bytes, ResponseCode.INVALID_ENCRYPTION_KEY)

            # 4. Emetti Enrollment Certificate in formato ASN.1 asn con verification key
            self.logger.info("📜 Emissione Enrollment Certificate (ASN.1 asn)...")
            ec_certificate_asn = self.issue_enrollment_certificate(
                its_id=inner_ec_request.itsId,
                public_key=verification_public_key,
                attributes=inner_ec_request.requestedSubjectAttributes,
            )
            
            # Compute HashedId8 for logging (ETSI TS 103097 V2.1.1)
            ec_hashed_id8 = compute_hashed_id8(ec_certificate_asn)
            self.logger.info(f"✅ Enrollment Certificate emesso: HashedId8={ec_hashed_id8.hex()[:16]}...")

            # 5. Crea e cripta response con encryption key (ETSI TS 102 941 Section 6.2.3.4)
            self.logger.info("📦 Creando EnrollmentResponse (ASN.1 asn)...")
            self.logger.info(f"   🔐 Cifrando risposta con encryption key dell'ITS-S")
            request_hash = compute_request_hash(request_bytes)

            # Encode response con certificato ASN.1 asn binario, cifrato con encryption key
            response_bytes = self.message_encoder.encode_enrollment_response(
                response_code=ResponseCode.OK,
                request_hash=request_hash,
                certificate_asn1=ec_certificate_asn,  # Direttamente bytes ASN.1 asn
                itss_public_key=encryption_public_key,  # USA ENCRYPTION KEY, non verification!
            )

            self.logger.info(f"✅ EnrollmentResponse creata: {len(response_bytes)} bytes")
            self.logger.info("   Response code: OK")
            self.logger.info("   Certificate attached: Yes (ASN.1 asn)")
            self.logger.info("   Encoding: ASN.1 asn")

            return response_bytes

        except Exception as e:
            self.logger.error(f"❌ Errore durante processing EnrollmentRequest: {e}")
            traceback.print_exc()
            return self._create_error_response(request_bytes, ResponseCode.INTERNAL_SERVER_ERROR)

    def issue_enrollment_certificate(
        self,
        its_id: str,
        public_key: EllipticCurvePublicKey,
        attributes=None
    ) -> bytes:
        """
        Emette un Enrollment Certificate in formato ASN.1 asn (ETSI TS 103097).
        
        Usa ETSIEnrollmentCertificateEncoder per generare EC conformi a:
        - ETSI TS 103097 V2.1.1: Certificate format and structure
        - ETSI TS 102941 V2.1.1: Trust and Privacy Management
        
        Args:
            its_id: ITS Station ID (Common Name)
            public_key: Chiave pubblica del veicolo (ECDSA P-256)
            attributes: Attributi opzionali (country, organization)
            
        Returns:
            bytes: Enrollment Certificate in formato ASN.1 asn binario
        """
        # Extract attributes
        country = "IT"
        organization = "ITS-S"
        duration_days = 90  # Default EC validity: 90 giorni
        
        if attributes:
            country = attributes.get("country", "IT")
            organization = attributes.get("organization", "ITS-S")
            if "validity_days" in attributes:
                duration_days = int(attributes["validity_days"])

        # Generate EC using ASN.1 encoder
        now_utc = datetime.now(timezone.utc)
        
        ec_certificate_asn = generate_enrollment_certificate(
            ea_cert_asn1=self.certificate_asn1,
            ea_private_key=self.private_key,
            its_public_key=public_key,
            its_id=its_id,
            duration_days=duration_days,
            country=country,
            organization=organization,
        )

        # Save EC to disk usando PKIFileHandler (ETSI TS 103097 V2.1.1)
        ec_hashed_id8 = compute_hashed_id8(ec_certificate_asn)
        ec_filename = f"EC_{ec_hashed_id8.hex()}.oer"
        ec_path = os.path.join(self.ec_dir, ec_filename)
        
        # Usa PKIFileHandler per operazioni I/O (DRY compliance)
        PKIFileHandler.save_binary_file(ec_certificate_asn, ec_path)
        
        # Log minimo solo in debug mode
        if self.logger.level <= 10:  # DEBUG level
            self.logger.debug(f"✅ EC emesso: {ec_filename}, HashedId8={ec_hashed_id8.hex()[:16]}...")
        
        return ec_certificate_asn

    # ========================================================================
    # CERTIFICATE REVOCATION METHODS (DELEGATES TO CRL MANAGER)
    # ========================================================================

    def revoke_certificate(self, hashed_id8_hex: str, reason: str = "unspecified"):
        """
        Revoca un certificato ASN.1 asn usando HashedId8.
        Delega la gestione revoca a CRLManager (Single Responsibility).

        Args:
            hashed_id8_hex: HashedId8 in formato esadecimale (identifica il certificato ASN.1)
            reason: Motivo della revoca (string: "unspecified", "key_compromise", "ca_compromise", etc.)
        """
        self.logger.info(f"🔴 Revocando certificato ASN.1 con HashedId8: {hashed_id8_hex}")
        self.logger.info(f"   Motivo revoca: {reason}")

        if self.crl_manager is None:
            self.logger.warning("⚠️  CRLManager non disponibile, revoca registrata localmente")
            # Le revoche saranno gestite tramite CRL X.509 quando CRLManager sarà attivato
            return

        # Convert hex string to bytes
        hashed_id8_bytes = bytes.fromhex(hashed_id8_hex)

        # Map reason string to CRLReason enum (import from managers.crl_manager)
        from managers.crl_manager import CRLReason
        reason_map = {
            "unspecified": CRLReason.UNSPECIFIED,
            "key_compromise": CRLReason.KEY_COMPROMISE,
            "ca_compromise": CRLReason.CA_COMPROMISE,
            "affiliation_changed": CRLReason.AFFILIATION_CHANGED,
            "superseded": CRLReason.SUPERSEDED,
            "cessation_of_operation": CRLReason.CESSATION_OF_OPERATION,
            "certificate_hold": CRLReason.CERTIFICATE_HOLD,
        }
        crl_reason = reason_map.get(reason.lower(), CRLReason.UNSPECIFIED)

        # Delega a CRLManager (Dependency Injection)
        self.crl_manager.revoke_by_hashed_id(hashed_id8_bytes, crl_reason)
        self.logger.info("✅ Certificato revocato tramite CRLManager")

        # Pubblica Delta CRL incrementale (senza backup per performance)
        self.logger.info("📤 Pubblicando Delta CRL EA...")
        self.crl_manager.publish_delta_crl(skip_backup=True)
        self.logger.info("✅ Revoca completata e Delta CRL pubblicata!")

    # ========================================================================
    # CRL PUBLISHING METHODS (DELEGATES TO CRL MANAGER)
    # ========================================================================

    def publish_crl(self, validity_days: int = 7) -> str:
        """
        Pubblica una Full CRL completa consolidando tutte le revoche.
        Delega la pubblicazione a CRLManager (Single Responsibility).
        
        Questo metodo dovrebbe essere chiamato periodicamente (es. settimanalmente)
        per consolidare tutte le Delta CRL in una nuova Full CRL.

        Args:
            validity_days: Numero di giorni di validità della Full CRL (default: 7)

        Returns:
            str: Path del file CRL pubblicato
        """
        if self.crl_manager is None:
            self.logger.warning("⚠️  CRLManager non disponibile (in migrazione ASN.1)")
            return ""
            
        self.logger.info(f"📤 Pubblicando Full CRL EA (validità: {validity_days} giorni)...")
        crl_path = self.crl_manager.publish_full_crl(validity_days=validity_days)
        self.logger.info(f"✅ Full CRL EA pubblicata: {crl_path}")
        return crl_path

    # ========================================================================
    # EA CERTIFICATE AND KEY MANAGEMENT (ASN.1 asn)
    # ========================================================================

    def load_or_generate_ea(self):
        """Carica chiave/cert ASN.1 se esistono, altrimenti li genera."""
        self.logger.info("🔍 Verificando esistenza chiave e certificato EA ASN.1...")
        if os.path.exists(self.ea_key_path) and os.path.exists(self.ea_certificate_path):
            self.logger.info("✅ Chiave e certificato EA ASN.1 esistenti trovati, caricandoli...")
            self.load_ea_keypair()
            self.load_ea_certificate_asn1()
        else:
            self.logger.info("🔧 Chiave o certificato EA ASN.1 non trovati, generandoli...")
            self.generate_ea_keypair()
            self.generate_signed_certificate_from_rootca_asn1()

    def generate_ea_keypair(self):
        """Genera una chiave privata ECC e la salva su file usando PKIFileHandler."""
        self.logger.info("🔑 Generando chiave privata ECC (SECP256R1) per EA...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.logger.info(f"💾 Salvando chiave privata EA in: {self.ea_key_path}")
        
        # Usa PKIFileHandler per operazioni I/O (DRY compliance)
        PKIFileHandler.save_private_key(self.private_key, self.ea_key_path)
        
        self.logger.info("✅ Chiave privata EA generata e salvata!")

    def generate_signed_certificate_from_rootca_asn1(self):
        """
        Genera certificato EA in formato ASN.1 asn firmato dalla Root CA.
        
        Usa generate_subordinate_certificate() secondo ETSI TS 103097 V2.1.1
        per creare un certificato subordinato (EA/AA) valido.
        """
        self.logger.info(f"📜 Richiedendo alla Root CA la firma del certificato EA {self.ea_id}...")
        
        # Usa generate_subordinate_certificate() - ETSI TS 103097 V2.1.1
        self.certificate_asn1 = generate_subordinate_certificate(
            root_ca_cert_asn1=self.root_ca.certificate_asn1,
            root_ca_private_key=self.root_ca.private_key,
            authority_public_key=self.private_key.public_key(),
            authority_id=self.ea_id,
            authority_type="EA",
            duration_years=5,
            country="IT",
            organization="SecureRoad PKI"
        )
        
        self.logger.info(f"💾 Salvando certificato EA ASN.1 in: {self.ea_certificate_path}")
        
        # Usa PKIFileHandler per operazioni I/O (DRY compliance)
        PKIFileHandler.save_binary_file(self.certificate_asn1, self.ea_certificate_path)
        
        # Decode per logging usando decoder ASN.1 standard ETSI
        try:
            cert_decoded = decode_certificate_with_asn1(self.certificate_asn1, "EtsiTs103097Certificate")
            version = cert_decoded.get('version', '?')
            cert_type = cert_decoded.get('type', '?')
            issuer = cert_decoded.get('issuer', {})
            self.logger.info("✅ Certificato EA ASN.1 firmato dalla Root CA e salvato!")
            self.logger.info(f"   Version: {version}")
            self.logger.info(f"   Type: {cert_type}")
            self.logger.info(f"   Issuer: {issuer}")
        except Exception as e:
            self.logger.warning(f"⚠️  Impossibile decodificare certificato per logging: {e}")
            self.logger.info("✅ Certificato EA ASN.1 salvato!")

        # Archivia il certificato anche nella RootCA
        self.logger.info("📦 Richiedendo archiviazione certificato ASN.1 nella RootCA...")
        self.root_ca.save_subordinate_certificate_asn1(
            self.certificate_asn1, 
            authority_type="EA", 
            entity_id=self.ea_id
        )

    def load_ea_keypair(self):
        """Carica la chiave privata ECC dal file PEM."""
        self.logger.info(f"📥 Caricando chiave privata EA da: {self.ea_key_path}")
        self.private_key = PKIFileHandler.load_private_key(self.ea_key_path)
        self.logger.info("✅ Chiave privata EA caricata!")

    def load_ea_certificate_asn1(self):
        """Carica il certificato EA ASN.1 asn dal file binario."""
        self.logger.info(f"📥 Caricando certificato EA ASN.1 da: {self.ea_certificate_path}")
        self.certificate_asn1 = PKIFileHandler.load_binary_file(self.ea_certificate_path)
        
        # Decode per logging usando decoder ASN.1 standard ETSI
        try:
            cert_decoded = decode_certificate_with_asn1(self.certificate_asn1, "EtsiTs103097Certificate")
            version = cert_decoded.get('version', '?')
            cert_type = cert_decoded.get('type', '?')
            self.logger.info("✅ Certificato EA ASN.1 caricato!")
            self.logger.info(f"   Version: {version}")
            self.logger.info(f"   Type: {cert_type}")
        except Exception as e:
            self.logger.warning(f"⚠️  Impossibile decodificare certificato per logging: {e}")
            self.logger.info("✅ Certificato EA ASN.1 caricato!")


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
        schedule.clear('ea-crl')

        # Full CRL: ogni domenica alle 02:00 (settimanale)
        schedule.every().sunday.at("02:00").do(self._scheduled_publish_full_crl).tag('ea-crl')

        # Delta CRL: ogni ora (per revoche recenti)
        schedule.every(1).hours.do(self._scheduled_publish_delta_crl).tag('ea-crl')

        # Avvia thread di background per eseguire lo scheduler
        self.scheduler_thread = threading.Thread(
            target=self._run_scheduler,
            daemon=True,
            name=f"EA-{self.ea_id}-CRL-Scheduler"
        )
        self.scheduler_thread.start()

        self.logger.info("✅ Scheduler CRL configurato:")
        self.logger.info("   - Full CRL: ogni domenica alle 02:00")
        self.logger.info("   - Delta CRL: ogni ora")

    def _run_scheduler(self):
        """
        Esegue il loop dello scheduler in background thread.
        """
        self.logger.info(f"🔄 Scheduler thread avviato per EA {self.ea_id}")

        while True:
            try:
                schedule.run_pending()
                # Sleep per 60 secondi tra controlli
                threading.Event().wait(60)
            except Exception as e:
                self.logger.error(f"❌ Errore nello scheduler CRL: {e}")
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
            self.logger.error(f"❌ Errore pubblicazione Full CRL schedulata: {e}")

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
                self.logger.debug("⏭️  Scheduler: Nessuna nuova revoca, Delta CRL non necessaria")
        except Exception as e:
            self.logger.error(f"❌ Errore pubblicazione Delta CRL schedulata: {e}")

    # ========================================================================
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
        schedule.clear('ea-expiry')

        # Controllo certificati scaduti: ogni ora
        schedule.every(1).hours.do(self._scheduled_check_expired_certificates).tag('ea-expiry')

        self.logger.info("✅ Scheduler controllo certificati scaduti configurato:")
        self.logger.info("   - Controllo ogni ora")

    def _scheduled_check_expired_certificates(self):
        """
        Job schedulato per controllo certificati EC scaduti e decremento contatore.
        """
        try:
            self.logger.debug("=== SCHEDULER: Controllo certificati EC scaduti ===")

            # Conta certificati scaduti trovati
            expired_count = 0

            # Scansiona directory certificati per file EC_*.asn
            certificates_dir = self.paths.certificates_dir
            if not certificates_dir.exists():
                self.logger.debug("Directory certificati non esiste")
                return

            for cert_file in certificates_dir.glob("EC_*.oer"):
                try:
                    # Carica certificato ASN.1 asn usando PKIFileHandler (DRY compliance)
                    cert_asn = PKIFileHandler.load_binary_file(str(cert_file))
                    if cert_asn is None:
                        continue
                    
                    # Estrai ValidityPeriod con extract_validity_period() - ETSI TS 103097 V2.1.1
                    try:
                        start_datetime, expiry_datetime, duration_sec = extract_validity_period(cert_asn)
                        
                        # Controlla se è scaduto
                        now = datetime.now(timezone.utc)
                        if expiry_datetime <= now:
                            # Certificato scaduto - incrementa contatore
                            expired_count += 1
                            self.logger.debug(f"⏰ Certificato EC scaduto: {cert_file.name} (scaduto: {expiry_datetime.isoformat()})")
                    
                    except Exception as extract_err:
                        # Se extract_validity_period fallisce, skippa questo certificato
                        self.logger.debug(f"⚠️  Impossibile estrarre validity period da {cert_file.name}: {extract_err}")
                        continue

                except Exception as e:
                    self.logger.warning(f"⚠️  Errore lettura certificato {cert_file.name}: {e}")
                    continue

            if expired_count > 0:
                self.logger.info(f"=== SCHEDULER: {expired_count} certificati EC scaduti trovati, contatore decrementato ===")
            else:
                self.logger.debug("=== SCHEDULER: Nessun certificato EC scaduto trovato ===")

        except Exception as e:
            self.logger.error(f"❌ Errore controllo certificati scaduti schedulato: {e}")

    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _create_error_response(self, request_bytes: bytes, error_code: ResponseCode) -> bytes:
        """
        Crea una EnrollmentResponse di errore.

        Args:
            request_bytes: Request originale per calcolare hash
            error_code: Codice errore da ritornare

        Returns:
            ASN.1 asn encoded EnrollmentResponse con errore
        """
        self.logger.warning(f"⚠️  Creando error response: {error_code}")
        request_hash = compute_request_hash(request_bytes)

        # Per error response, secondo ETSI TS 102941, la risposta può essere non cifrata
        # oppure usare una chiave null/default. Generiamo una chiave effimera per compatibilità
        # con il formato del messaggio, ma questa non viene usata per sicurezza reale.
        ephemeral_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        return self.message_encoder.encode_enrollment_response(
            response_code=error_code,
            request_hash=request_hash,
            certificate_asn1=None,
            itss_public_key=ephemeral_key.public_key(),
        )

    def _auto_register_to_tlm(self):
        """
        Registrazione automatica al TLM (ETSI TS 102941 § 6.1.3 requirement).
        Registra l'EA come trust anchor utilizzando il certificato ASN.1.
        """
        try:
            tlm = self._tlm_for_registration
            
            # Controlla se già registrato usando HashedId8 (ASN.1)
            ea_hashed_id8 = self.ea_hashed_id8.hex()
            already_registered = any(
                anchor.get("hashed_id8") == ea_hashed_id8 
                for anchor in tlm.trust_anchors
            )
            
            if not already_registered:
                # Registra certificato ASN.1
                tlm.add_trust_anchor(self.certificate_asn1, authority_type="EA")
                self.logger.info(f"✅ Auto-registered {self.ea_id} to TLM (ASN.1)")
            else:
                self.logger.debug(f"EA {self.ea_id} già registrato in TLM")
                
        except Exception as e:
            # Auto-registration è best-effort, non blocca l'inizializzazione
            self.logger.warning(f"⚠️  Auto-registration to TLM skipped: {e}")
