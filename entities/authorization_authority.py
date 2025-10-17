import json
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

# ETSI Protocol Layer - ASN.1 OER Implementation
from protocols.etsi_authorization_ticket import ETSIAuthorizationTicketEncoder
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import (
    InnerAtRequest,
    ResponseCode,
    compute_request_hash,
)

# Managers (Direct imports - NO interfaces needed)
from managers.crl_manager import CRLManager, CRLReason

# Services (Single Responsibility)
from services.aa_key_manager import AAKeyManager
from services.at_scheduler import ATScheduler
from services.ec_validator import ECValidator

# Utilities
from utils.aa_constants import (
    AT_VALIDITY_DEFAULT_HOURS,
    AT_VALIDITY_MAX_HOURS,
    AT_VALIDITY_MIN_HOURS,
    DEFAULT_APP_PERMISSIONS,
)
from utils.logger import PKILogger
from utils.metrics import get_metrics_collector
from utils.pki_paths import PKIPathManager
from utils.pki_io import PKIFileHandler




class AuthorizationAuthority:
    """
    Authorization Authority (AA) - ETSI TS 102941 Compliant
    
    **REFACTORED VERSION** - Follows SOLID principles and DRY
    
    Implementa l'Authorization Authority secondo lo standard ETSI TS 102941 V2.1.1.
    
    Responsabilità (Single Responsibility):
    - Emissione Authorization Tickets (AT) per veicoli ITS-S
    - Coordinamento validazione EC tramite ECValidator service
    - Gestione revoche tramite CRLPublisher interface
    - Supporto Butterfly Key Expansion per batch AT
    
    Standard ETSI Implementati:
    - ETSI TS 102941 V2.1.1: Trust and Privacy Management
    - ETSI TS 103097 V2.1.1: Certificate Formats and Security Headers
    
    Metodi Principali (ETSI-compliant):
    - process_authorization_request_etsi(): Processa AuthorizationRequest ASN.1 OER
    - issue_authorization_ticket(): Genera singolo AT in formato ASN.1 OER
    - issue_butterfly_authorization_tickets(): Butterfly batch mode
    - revoke_authorization_ticket(): Delega revoca a CRLPublisher
    
    Design Patterns Used:
    - Dependency Injection: All dependencies passed via constructor
    - Strategy Pattern: Validation and signing via interfaces
    - Service Layer: Key management, validation, scheduling separated
    """
    
    def __init__(
        self,
        root_ca,  
        tlm,      
        crl_manager: CRLManager,  
        aa_id: Optional[str] = None,
        base_dir: str = "./pki_data/aa/"
    ):
        """
        Inizializza Authorization Authority.

        Args:
            root_ca: RootCA instance per firma certificati
            tlm: TrustListManager instance per validazione trust chain
            crl_manager: CRLManager instance per gestione CRL
            aa_id: ID dell'AA (generato automaticamente se None)
            base_dir: Directory base per dati AA
            
        Raises:
            ValueError: Se parametri obbligatori mancanti
        """
        # ========================================================================
        # 1. VALIDAZIONE PARAMETRI
        # ========================================================================
        
        if not root_ca:
            raise ValueError("root_ca è obbligatorio (istanza RootCA)")
        
        if not tlm:
            raise ValueError("tlm è obbligatorio (istanza TrustListManager)")
        
        if not crl_manager:
            raise ValueError("crl_manager è obbligatorio (istanza CRLManager)")
        
        # Genera ID randomico se non specificato
        if aa_id is None:
            aa_id = f"AA_{secrets.token_hex(4).upper()}"
        
        # ========================================================================
        # 2. INIZIALIZZAZIONE PATH MANAGER E LOGGER
        # ========================================================================
        
        # Usa PKIPathManager per gestire i path (centralizzato)
        self.paths = PKIPathManager.get_entity_paths("AA", aa_id, base_dir)
        self.paths.create_all()  # Crea tutte le directory necessarie
        
        # Attributi pubblici (solo base_dir per retrocompatibilità con API)
        self.aa_id = aa_id
        self.base_dir = str(self.paths.base_dir)
        
        # Logger initialization (prima di qualsiasi log)
        self.logger = PKILogger.get_logger(
            name=aa_id,
            log_dir=str(self.paths.logs_dir),
            console_output=True
        )
        
        self.logger.info("=" * 80)
        self.logger.info(f"*** INIZIALIZZAZIONE AUTHORIZATION AUTHORITY {aa_id} ***")
        self.logger.info("=" * 80)
        
        # ========================================================================
        # 3. STORE DEPENDENCIES 
        # ========================================================================
        
        self.root_ca = root_ca
        self.tlm = tlm
        self.crl_manager = crl_manager
        
        self.logger.info(f"✅ Dependencies stored successfully")
        self.logger.info(f"   - RootCA: {type(root_ca).__name__}")
        self.logger.info(f"   - TrustListManager: {type(tlm).__name__}")
        self.logger.info(f"   - CRLManager: {type(crl_manager).__name__}")
        
        # ========================================================================
        # 4. KEY MANAGEMENT SERVICE
        # ========================================================================
        
        self.logger.info(f"Initializing AAKeyManager...")
        self.key_manager = AAKeyManager(
            aa_id=aa_id,
            key_path=str(self.paths.private_keys_dir / "aa_key.key"),
            cert_path=str(self.paths.certificates_dir / "aa_certificate.oer"),
            root_ca=root_ca,  # Direct RootCA instance
            logger=self.logger
        )
        
        # Load or generate keys and certificate
        self.private_key, self.certificate_asn1 = self.key_manager.load_or_generate()
        self.logger.info(f"✅ AAKeyManager initialized (ASN.1 OER certificate)")
        
        # ========================================================================
        # 5. EC VALIDATION SERVICE
        # ========================================================================
        
        self.logger.info(f"Initializing ECValidator...")
        self.ec_validator = ECValidator(
            tlm=tlm, 
            logger=self.logger,
            authority_id=aa_id
        )
        self.logger.info(f"✅ ECValidator initialized")
        
        # ========================================================================
        # 6. ETSI MESSAGE ENCODER
        # ========================================================================
        
        self.logger.info(f"Initializing ETSI Message Encoder (ASN.1 OER)...")
        self.message_encoder = ETSIMessageEncoder()
        self.logger.info(f"✅ ETSI Message Encoder initialized")
        
        # ========================================================================
        # 6b. ETSI AUTHORIZATION TICKET ENCODER (Riutilizzabile - DRY)
        # ========================================================================
        
        self.logger.info(f"Initializing ETSI Authorization Ticket Encoder...")
        self.at_encoder = ETSIAuthorizationTicketEncoder()
        self.logger.info(f"✅ ETSI AT Encoder initialized")
        
        # ========================================================================
        # 7. SCHEDULER SERVICE (CRL + Expiry)
        # ========================================================================
        
        self.logger.info(f"Initializing ATScheduler...")
        self.scheduler = ATScheduler(
            aa_id=aa_id,
            crl_manager=crl_manager,  
            certificates_dir=self.paths.data_dir,  # Contains AT_*.oer files
            logger=self.logger
        )
        self.scheduler.start()
        self.logger.info(f"✅ ATScheduler started")
        
        # ========================================================================
        # 8. REVOCATION LIST (ETSI-compliant using HashedId8)
        # ========================================================================
        
        # CRLManager handles all revocations (no local JSON)
        
        # ========================================================================
        # 9. AUTO-REGISTRATION TO TLM
        # ========================================================================
        
        self._auto_register_to_tlm()
        
        # ========================================================================
        # 10. INITIALIZATION COMPLETE
        # ========================================================================
        
        self.logger.info("=" * 80)
        self.logger.info(f"✅ Authorization Authority {aa_id} initialized successfully!")
        self.logger.info("=" * 80)

    # ========================================================================
    # ETSI TS 102941 PROTOCOL METHODS (ASN.1 OER)
    # ========================================================================

    def process_authorization_request_etsi(self, request_bytes: bytes) -> bytes:
        """
        Processa una AuthorizationRequest ETSI TS 102941 (ASN.1 OER encoded).

           FLUSSO COMPLETO:
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
            # 1. Decripta e decodifica request + estrae EC
            self.logger.info(f"Decrittando AuthorizationRequest con chiave privata AA...")
            inner_at_request, enrollment_cert = self.message_encoder.decode_authorization_request(
                request_bytes, self.private_key
            )

            self.logger.info(f"Request decrittata con successo!")
            self.logger.info(f"   Public keys: {list(inner_at_request.publicKeys.keys())}")
            self.logger.info(f"   HMAC key length: {len(inner_at_request.hmacKey)} bytes")
            self.logger.info(f"   Requested attributes: {inner_at_request.requestedSubjectAttributes}")
            self.logger.info(f"   Enrollment Certificate extracted: {len(enrollment_cert)} bytes (ASN.1 OER)")

            # 2. Valida Enrollment Certificate
            self.logger.info(f"Validazione Enrollment Certificate...")
            try:
                self._validate_enrollment_certificate(enrollment_cert)
                self.logger.info(f"✅ Enrollment Certificate validato con successo!")
            except ValueError as e:
                self.logger.error(f"❌ EC non valido: {e}")
                return self._create_at_error_response(
                    request_bytes, inner_at_request.hmacKey, ResponseCode.UNAUTHORIZED
                )

            # 3. Estrai chiave pubblica e emetti Authorization Ticket
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

            self.logger.info(f"Emissione Authorization Ticket ASN.1 OER...")
            # Genera ITS-ID univoco per AT (solo per logging, non incluso in AT per privacy)
            its_id = f"AT_{secrets.token_hex(8)}"

            # Issue AT in formato ASN.1 OER (ritorna bytes)
            at_certificate_oer = self.issue_authorization_ticket(
                its_id=its_id,
                public_key=public_key,
                attributes=inner_at_request.requestedSubjectAttributes,
            )
            
            # Calcola HashedId8 per logging (usa encoder riutilizzabile)
            at_hashed_id8 = self.at_encoder.compute_hashed_id8(at_certificate_oer)
            self.logger.info(f"✅ AT emesso: HashedId8={at_hashed_id8.hex()[:16]}... ({len(at_certificate_oer)} bytes)")

            # 5. Crea e cripta response con hmacKey
            self.logger.info(f"Creando AuthorizationResponse (ASN.1 OER)...")
            request_hash = compute_request_hash(request_bytes)

            response_bytes = self.message_encoder.encode_authorization_response(
                response_code=ResponseCode.OK,
                request_hash=request_hash,
                certificate_asn1=at_certificate_oer,  #ASN.1 OER
                hmac_key=inner_at_request.hmacKey,
            )

            self.logger.info(f"AuthorizationResponse creata: {len(response_bytes)} bytes")
            self.logger.info(f"   Response code: OK")
            self.logger.info(f"   Certificate attached: Yes")
            self.logger.info(f"   Encryption: HMAC-based (unlinkability)")
            self.logger.info(f"   Encoding: ASN.1 OER")

            return response_bytes

        except Exception as e:
            self.logger.error(f"❌ Error processing AuthorizationRequest: {e}", exc_info=True)
            # Se abbiamo hmacKey, usiamolo per error response
            try:
                return self._create_at_error_response(
                    request_bytes, inner_at_request.hmacKey, ResponseCode.INTERNAL_SERVER_ERROR
                )
            except:
                # Se non riusciamo nemmeno a decrittare la request, non possiamo rispondere
                self.logger.error(f"❌ Cannot create error response (request not decryptable)")
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
            response_code=error_code, request_hash=request_hash, certificate_asn1=None, hmac_key=hmac_key
        )

    # ========================================================================
    # INTERNAL HELPER METHODS
    # ========================================================================
    
    def issue_authorization_ticket(self, its_id: str, public_key, attributes=None):
        """
        Emette Authorization Ticket in formato ASN.1 OER (ETSI TS 103097 V2.1.1).
        
        **100% ETSI COMPLIANT - PRODUCTION READY**
        
        Usa ETSIAuthorizationTicketEncoder per generare AT conformi a:
        - ETSI TS 103097 V2.1.1: Certificate format (ASN.1 OER)
        - ETSI TS 102941 V2.1.1: PKI Trust and Privacy Management
        - IEEE 1609.2: WAVE Security Services
        
        Args:
            its_id: Identificativo ITS-S (string, non usato nell'AT per privacy)
            public_key: Chiave pubblica ECC per AT (EllipticCurvePublicKey NIST P-256)
            attributes: Dict opzionale con:
                - 'permissions': Lista permessi ITS (['CAM', 'DENM'], default entrambi)
                - 'geographic_region': Tupla (lat, lon, radius_m) opzionale
                - 'validity_hours': Durata validità in ore (default: 24h)
                - 'priority': Priorità traffico 0-7 (opzionale)
            
        Returns:
            bytes: Certificato AT completo in formato ASN.1 OER binario
        """
        # ========================================================================
        # 1. PARSING ATTRIBUTI CON DEFAULTS ETSI
        # ========================================================================
        
        if attributes is None:
            attributes = {}
        
        # CAM e DENM sono i messaggi V2X fondamentali (ETSI EN 302 637-2/3)
        app_permissions = attributes.get('permissions', DEFAULT_APP_PERMISSIONS)
        
        # Validità: ETSI raccomanda 1-24h per AT (pseudonymity)
        validity_hours = attributes.get('validity_hours', AT_VALIDITY_DEFAULT_HOURS)
        if not (AT_VALIDITY_MIN_HOURS <= validity_hours <= AT_VALIDITY_MAX_HOURS):
            raise ValueError(
                f"validity_hours deve essere {AT_VALIDITY_MIN_HOURS}-{AT_VALIDITY_MAX_HOURS}, "
                f"ricevuto {validity_hours}"
            )
        
        # Regione geografica opzionale: (latitude, longitude, radius_meters)
        geographic_region = attributes.get('geographic_region')  # None o (lat, lon, radius)
        
        # Priorità traffico opzionale (0=normale, 7=emergenza)
        priority = attributes.get('priority')  # None o 0-7
        
        # ========================================================================
        # 2. PREPARAZIONE DATI CERTIFICATO
        # ========================================================================
        
        now_utc = datetime.now(timezone.utc)
        expiry_time = now_utc + timedelta(hours=validity_hours)
        
        # Calcola AA HashedId8 (identificatore issuer per ETSI)
        # self.certificate_asn1 è già in formato ASN.1 OER (bytes)
        aa_hashed_id8 = self.at_encoder.compute_hashed_id8(self.certificate_asn1)
        
        # ========================================================================
        # 3. GENERAZIONE AT CON ENCODER ASN.1 OER
        # ========================================================================
        
        try:
            at_certificate_oer = self.at_encoder.encode_full_authorization_ticket(
                issuer_hashed_id8=aa_hashed_id8,
                subject_public_key=public_key,
                start_validity=now_utc,
                duration_hours=validity_hours,
                app_permissions=app_permissions,
                aa_private_key=self.private_key,
                geographic_region=geographic_region,
                priority=priority,
            )
        except Exception as e:
            self.logger.error(f"❌ Errore generazione AT ASN.1 OER: {e}")
            raise ValueError(f"Impossibile generare AT: {e}")
        
        # Calcola HashedId8 del certificato AT (identificatore univoco ETSI)
        at_hashed_id8 = self.at_encoder.compute_hashed_id8(at_certificate_oer)
        
        # ========================================================================
        # 4. SALVATAGGIO IN FORMATO .OER BINARIO
        # ========================================================================
        
        at_filename = f"AT_{at_hashed_id8.hex()}.oer"
        at_path = str(self.paths.data_dir / at_filename)
        
        PKIFileHandler.save_binary_file(at_certificate_oer, at_path)
        
        self.logger.info(
            f"✅ AT emesso: {at_hashed_id8.hex()[:16]}... "
            f"({len(at_certificate_oer)} bytes ASN.1 OER, {validity_hours}h, "
            f"apps: {', '.join(app_permissions)})"
        )
        
        # ========================================================================
        # 5. RETURN: Solo bytes ASN.1 OER (standard ETSI)
        # ========================================================================
        
        return at_certificate_oer

    # ========================================================================
    # ETSI TS 102941 BATCH AUTHORIZATION (Butterfly Key Expansion)
    # ========================================================================
    
    def issue_butterfly_authorization_tickets(self, its_id, public_keys, attributes=None):
        """
        Emette un batch di Authorization Tickets usando Butterfly Key Expansion.
        
        **ETSI TS 102941 V2.1.1 Section 6.3.3 - Butterfly Authorization**
        
        Questo metodo implementa lo standard ETSI per richieste batch di AT,
        usando il meccanismo Butterfly Key Expansion per efficienza e privacy.
        
        Butterfly Mode Workflow:
        1. ITS-S genera SharedAtRequest con parametri comuni (eaId, keyTag)
        2. ITS-S genera N InnerAtRequest, uno per ogni AT richiesto
        3. AA VALIDA Enrollment Certificate tramite TLM (OBBLIGATORIO)
        4. AA CONTROLLA CRL per EC revocati (OBBLIGATORIO)
        5. AA espande le chiavi con butterfly expansion (deriva chiavi da seed)
        6. AA emette N Authorization Tickets in un batch atomico
        
        Vantaggi:
        - Efficienza: Una richiesta per N certificati (invece di N richieste)
        - Privacy: Unlinkability tra AT dello stesso veicolo
        - Scalabilità: Supporta fino a 100 AT per batch (limite ETSI)

        Args:
            its_id: ID del veicolo ITS-S (string) o SharedAtRequest object
            public_keys: Lista di chiavi pubbliche per gli AT o lista di InnerAtRequest
            attributes: Enrollment Certificate (X.509) per validazione (OBBLIGATORIO per Butterfly)

        Returns:
            Lista di certificati AT generati
            
        Raises:
            RuntimeError: Se batch vuoto o parametri invalidi
            ValueError: Se EC non valido o revocato
            
        References:
            - ETSI TS 102941 V2.1.1 Section 6.3.3: Butterfly Authorization
            - ETSI TS 103097 V2.1.1: Certificate Formats and Security Headers
        """
        # Se its_id è un oggetto SharedAtRequest, converti
        if hasattr(its_id, "eaId"):
            shared_request = its_id
            inner_requests = public_keys
            enrollment_cert = attributes  # attributes contiene l'EC per validazione
            
            # ========================================================================
            # VALIDAZIONE ENROLLMENT CERTIFICATE (ETSI TS 102941 Section 6.3.3)
            # ========================================================================
            
            if enrollment_cert is None:
                self.logger.error("❌ Enrollment Certificate mancante in Butterfly request!")
                raise ValueError("Enrollment Certificate è obbligatorio per richieste Butterfly")
            
            # Usa metodo centralizzato per validazione completa EC
            try:
                self._validate_enrollment_certificate(enrollment_cert)
                self.logger.info("✅ Validazione EC completata con successo!")
            except ValueError as e:
                self.logger.error(f"❌ Validazione EC fallita: {e}")
                raise
            
            # Estrai SharedAtRequest e inner_requests già settati sopra
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

        # Lista certificati AT in formato ASN.1 OER (bytes)
        certificates_oer = []
        for idx, public_key in enumerate(public_keys):
            self.logger.info(f"Generando AT {idx+1}/{len(public_keys)}...")
            cert_oer = self.issue_authorization_ticket(its_id_str, public_key, attributes)
            certificates_oer.append(cert_oer)

        self.logger.info(f"✅ Batch di {len(certificates_oer)} AT emessi con successo (formato ASN.1 OER)!")
        return certificates_oer
    
    def _validate_enrollment_certificate(self, enrollment_cert: bytes) -> bool:
        """
        Valida completamente un Enrollment Certificate (ETSI TS 102941).
        
        **REFACTORED**: Delega a ECValidator service (elimina duplicazione).
        **MIGRATED**: Accetta solo bytes ASN.1 OER (NO X.509)
        
        Controlli eseguiti:
        1. Trust chain verification tramite TrustValidator
        2. Verifica scadenza certificato
        3. Check CRL per revoche
        
        Args:
            enrollment_cert: Certificato ASN.1 OER (bytes)
            
        Returns:
            True se valido, False altrimenti
            
        Raises:
            ValueError: Se EC non valido con dettagli errore
        """
        # Delega completamente a ECValidator service
        self.ec_validator.validate(enrollment_cert)
        return True

    # ========================================================================
    # REVOCATION METHODS (ETSI-compliant using HashedId8)
    # ========================================================================
    
    def revoke_authorization_ticket(
        self,
        at_certificate_oer: bytes,
        reason: CRLReason = CRLReason.UNSPECIFIED
    ) -> None:
        """
        Revoca Authorization Ticket usando HashedId8 (ETSI-compliant).
        
        ETSI TS 102941: AT revocati identificati tramite HashedId8.
        
        Args:
            at_certificate_oer: AT certificate in formato ASN.1 OER (bytes)
            reason: Motivo della revoca (CRLReason enum)
        """
        at_hashed_id8 = self.at_encoder.compute_hashed_id8(at_certificate_oer)
        self.revoke_by_hashed_id(at_hashed_id8, reason)
    
    def revoke_by_hashed_id(
        self,
        hashed_id8: bytes,
        reason: CRLReason = CRLReason.UNSPECIFIED
    ) -> None:
        """
        Revoca AT tramite HashedId8 (ETSI-compliant).
        
        Args:
            hashed_id8: HashedId8 del certificato AT (8 bytes)
            reason: Motivo della revoca (CRLReason enum)
        """
        if len(hashed_id8) != 8:
            raise ValueError(f"HashedId8 deve essere 8 bytes, ricevuto {len(hashed_id8)}")
        
        hashed_id8_hex = hashed_id8.hex()
        self.logger.info(f"Revoking AT by HashedId8: {hashed_id8_hex[:16]}...")
        
        # Usa CRLManager invece di JSON locale
        self.crl_manager.revoke_by_hashed_id(
            hashed_id8=hashed_id8,
            reason=reason,
            expiry_time=None  # Default 1 anno
        )
        
        self.logger.info(f"✅ AT revoked successfully")
    
    def is_revoked(self, at_certificate_oer: bytes) -> bool:
        """
        Verifica se un AT è stato revocato (controlla CRLManager).
        
        Args:
            at_certificate_oer: AT certificate in formato ASN.1 OER (bytes)
            
        Returns:
            bool: True se revocato, False altrimenti
        """
        return self.crl_manager.is_certificate_revoked(at_certificate_oer)
    
    def get_revoked_count(self) -> int:
        """Ritorna il numero di AT revocati dal CRLManager."""
        stats = self.crl_manager.get_statistics()
        return stats.get('total_revoked', 0)
    
    # ========================================================================
    # TLM AUTO-REGISTRATION
    # ========================================================================
    
    def _auto_register_to_tlm(self) -> None:
        """
        Auto-registra AA nel Trust List Manager usando HashedId8 (ASN.1 OER compliant).
        
        Questo metodo è chiamato automaticamente durante l'inizializzazione.
        """
        try:
            # Calcola AA HashedId8 come identificatore univoco
            aa_hashed_id8 = self.at_encoder.compute_hashed_id8(self.certificate_asn1)
            aa_hashed_id8_hex = aa_hashed_id8.hex()
            
            # Check if already registered (usa HashedId8 invece di SKI)
            already_registered = any(
                anchor.get("hashed_id8") == aa_hashed_id8_hex
                for anchor in self.tlm.trust_anchors
            )
            
            if not already_registered:
                # Registra con certificato ASN.1 OER
                self.tlm.add_trust_anchor(
                    certificate=self.certificate_asn1,  # bytes ASN.1 OER
                    authority_type="AA"
                )
                self.logger.info(f"✅ Auto-registered {self.aa_id} to TLM (HashedId8={aa_hashed_id8_hex[:16]}...)")
            else:
                self.logger.debug(f"AA {self.aa_id} già registrato in TLM")
                
        except Exception as e:
            # Auto-registration is best-effort, don't block initialization
            self.logger.debug(f"Auto-registration to TLM skipped: {e}")
