import os
import secrets
import traceback
from datetime import datetime, timedelta, timezone

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
    InnerEcRequest,
    InnerEcResponse,
    ResponseCode,
    compute_request_hash,
)
from utils.cert_utils import (
    get_certificate_expiry_time,
    get_certificate_identifier,
    get_certificate_not_before,
    get_short_identifier,
)
from utils.logger import PKILogger
from utils.pki_paths import PKIPathManager


class EnrollmentAuthority:
    def __init__(self, root_ca, ea_id=None, base_dir="./data/ea/"):
        # Genera un ID randomico se non specificato
        if ea_id is None:
            ea_id = f"EA_{secrets.token_hex(4).upper()}"

        # Usa PKIPathManager per gestire i path in modo centralizzato
        paths = PKIPathManager.get_entity_paths("EA", ea_id, base_dir)
        
        # Store base_dir as instance attribute for stats endpoint
        self.base_dir = str(paths.base_dir)
        
        # Crea tutte le directory necessarie
        paths.create_all()

        # Store IDs early for logger initialization
        self.ea_id = ea_id
        self.ea_certificate_path = str(paths.certificates_dir / "ea_certificate.pem")
        self.ea_key_path = str(paths.private_keys_dir / "ea_key.pem")
        self.ec_dir = str(paths.data_dir)  # enrollment_certificates
        self.crl_path = str(paths.crl_dir / "ea_crl.pem")
        self.log_dir = str(paths.logs_dir)
        self.backup_dir = str(paths.backup_dir)
        
        # Inizializza logger (ea_id contiene gi il prefisso "EA_")
        self.logger = PKILogger.get_logger(
            name=ea_id,
            log_dir=self.log_dir,
            console_output=True
        )
        
        self.logger.info(f"Inizializzando Enrollment Authority {ea_id}...")
        self.logger.info(f"Directory base: {self.base_dir}")
        self.logger.info(f"Percorso certificato EA: {self.ea_certificate_path}")
        self.logger.info(f"Percorso chiave privata EA: {self.ea_key_path}")
        self.logger.info(f"Directory EC: {self.ec_dir}")
        self.logger.info(f"Percorso CRL EA: {self.crl_path}")
        self.logger.info(f"✅ Struttura directory creata da PKIPathManager")

        self.root_ca = root_ca
        self.private_key = None
        self.certificate = None
        
        # IMPORTANT: Load Root CA certificate from file (not memory reference)
        # This ensures we always use the latest Root CA cert, even after rotation
        # Use the actual Root CA certificate path from the root_ca instance
        root_ca_cert_path = root_ca.ca_certificate_path
        from utils.cert_cache import load_certificate_cached
        self.root_ca_certificate = load_certificate_cached(root_ca_cert_path)

        self.logger.info("Caricando o generando chiave e certificato EA...")
        self.load_or_generate_ea()

        # Log RootCA certificate info
        self.logger.info("Root CA certificate loaded from instance")
        self.logger.info(f"Root CA Subject: {self.root_ca_certificate.subject}")
        self.logger.info(f"Root CA Serial: {self.root_ca_certificate.serial_number}")

        # Inizializza CRLManager dopo aver caricato certificato e chiave privata
        self.logger.info(f"Inizializzando CRLManager per EA {ea_id}...")
        self.crl_manager = CRLManager(
            authority_id=ea_id,
            base_dir=self.base_dir,  # Usa il path specifico dell'istanza, non quello generico
            issuer_certificate=self.certificate,
            issuer_private_key=self.private_key,
        )
        self.logger.info("CRLManager inizializzato con successo!")
        
        # Pubblica CRL vuota iniziale se non esiste (per dashboard /api/crl/full)
        if not os.path.exists(self.crl_manager.full_crl_path):
            self.logger.info("Pubblicando Full CRL iniziale vuota...")
            self.crl_manager.publish_full_crl()
            self.logger.info("✅ Full CRL iniziale pubblicata")

        # Inizializza ETSI Message Encoder per gestire messaggi conformi allo standard
        self.logger.info("Inizializzando ETSI Message Encoder (ASN.1 OER)...")
        self.message_encoder = ETSIMessageEncoder()
        self.logger.info("ETSI Message Encoder inizializzato!")

        self.logger.info(f"Inizializzazione Enrollment Authority {ea_id} completata!")

    # Carica chiave/cert se esistono, altrimenti li genera
    def load_or_generate_ea(self):
        self.logger.info("Verificando esistenza chiave e certificato EA...")
        if os.path.exists(self.ea_key_path) and os.path.exists(self.ea_certificate_path):
            self.logger.info("Chiave e certificato EA esistenti trovati, caricandoli...")
            self.load_ea_keypair()
            self.load_ea_certificate()
        else:
            self.logger.info("Chiave o certificato EA non trovati, generandoli...")
            self.generate_ea_keypair()
            self.generate_signed_certificate_from_rootca()

    # Genera una chiave privata ECC e la salva su file
    def generate_ea_keypair(self):
        self.logger.info("Generando chiave privata ECC (SECP256R1) per EA...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.logger.info(f"Salvando chiave privata EA in: {self.ea_key_path}")
        with open(self.ea_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        self.logger.info("Chiave privata EA generata e salvata con successo!")

    # Chiede alla rootCa di generare e firmare un certificato. Salva il certificato X.509 firmato
    def generate_signed_certificate_from_rootca(self):
        self.logger.info(f"Richiedendo alla Root CA la firma del certificato EA {self.ea_id}...")
        subject_name = f"EnrollmentAuthority_{self.ea_id}"
        ea_certificate = self.root_ca.sign_certificate(
            subject_public_key=self.private_key.public_key(), subject_name=subject_name, is_ca=True
        )
        self.certificate = ea_certificate
        self.logger.info(f"Salvando certificato EA firmato in: {self.ea_certificate_path}")
        with open(self.ea_certificate_path, "wb") as f:
            f.write(ea_certificate.public_bytes(serialization.Encoding.PEM))
        self.logger.info("Certificato EA firmato dalla Root CA e salvato con successo!")
        self.logger.info(f"Serial number certificato EA: {ea_certificate.serial_number}")

        # Archivia il certificato anche nella RootCA
        self.logger.info("Richiedendo archiviazione certificato nella RootCA...")
        self.root_ca.save_subordinate_certificate(ea_certificate)

    # Carica la chiave privata ECC dal file PEM
    def load_ea_keypair(self):
        self.logger.info(f"Caricando chiave privata EA da: {self.ea_key_path}")
        self.private_key = PKIFileHandler.load_private_key(self.ea_key_path)
        self.logger.info("Chiave privata EA caricata con successo!")

    def load_ea_certificate(self):
        self.logger.info(f"Caricando certificato EA da: {self.ea_certificate_path}")
        self.certificate = PKIFileHandler.load_certificate(self.ea_certificate_path)
        self.logger.info("Certificato EA caricato con successo!")
        self.logger.info(f"Subject: {self.certificate.subject}")
        self.logger.info(f"Serial number: {self.certificate.serial_number}")
        # Usa utility per datetime UTC-aware
        valid_from = get_certificate_not_before(self.certificate)
        valid_to = get_certificate_expiry_time(self.certificate)
        self.logger.info(f"Validit: dal {valid_from} al {valid_to}")

    # Emette EC da una richiesta CSR
    def process_csr(self, csr_pem, its_id, attributes=None):
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
            self.logger.info(f"Ricevuto CSR valido da ITS-S {its_id}, verifico la firma...")
            if not csr.is_signature_valid:
                self.logger.warning("CSR non valido: firma non valida.")
                return None
        except Exception as e:
            self.logger.error(f"Errore nel parsing CSR: {e}")
            return None

        self.logger.info(f"CSR valido, procedo con emissione EC per ITS-S {its_id}.")
        ec_certificate = self.issue_enrollment_certificate(its_id, csr.public_key(), attributes)
        return ec_certificate

    # Firma la chiave pubblica ricevuta via CSR e crea il certificato EC
    def issue_enrollment_certificate(self, its_id, public_key, attributes=None):
        """Emette un Enrollment Certificate (ottimizzato per performance)."""
        # Costruisci certificato (operazione veloce in memoria)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-S"),
            x509.NameAttribute(NameOID.COMMON_NAME, its_id),
        ])

        serial_number = x509.random_serial_number()
        now_utc = datetime.now(timezone.utc)

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(now_utc)
            .not_valid_after(now_utc + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        )

        # Firma certificato (operazione crittografica veloce)
        cert = cert_builder.sign(self.private_key, hashes.SHA256())

        # Salvataggio su disco (operazione I/O lenta)
        cert_id = get_short_identifier(cert)
        ec_path = os.path.join(self.ec_dir, f"EC_{cert_id}.pem")
        
        # Scrittura ottimizzata senza makedirs ad ogni chiamata
        with open(ec_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Log minimo solo in debug mode
        if self.logger.level <= 10:  # DEBUG level
            self.logger.debug(f"EC emesso: {cert_id}, serial: {serial_number}")
        
        return cert

    def revoke_certificate(self, serial_hex, reason=ReasonFlags.unspecified):
        """
        Revoca un certificato di enrollment usando il serial number.

        Args:
            serial_hex: Serial number in formato esadecimale
            reason: Il motivo della revoca (ReasonFlags)
        """
        self.logger.info(f"Revocando certificato con serial (hex): {serial_hex}")
        self.logger.info(f"Motivo revoca: {reason}")

        # Usa CRLManager per revocare per serial
        self.crl_manager.revoke_by_serial(serial_hex, reason)
        self.logger.info("Certificato revocato tramite CRLManager")

        # Pubblica Delta CRL incrementale
        self.logger.info("Pubblicando Delta CRL EA...")
        self.crl_manager.publish_delta_crl()
        self.logger.info("Revoca completata!")

    # Aggiunge un certificato alla lista dei certificati revocati
    def revoke_enrollment_certificate(self, certificate, reason=ReasonFlags.unspecified):
        """
        Revoca un certificato di enrollment aggiungendolo alla lista dei certificati revocati.
        Pubblica automaticamente una Delta CRL.

        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number
        expiry_date = get_certificate_expiry_time(certificate)

        self.logger.info(f"Revocando Enrollment Certificate con serial: {serial_number}")
        self.logger.info(f"Data di scadenza certificato: {expiry_date}")
        self.logger.info(f"Motivo revoca: {reason}")

        # Usa CRLManager per aggiungere il certificato revocato
        self.crl_manager.add_revoked_certificate(certificate, reason)
        self.logger.info("Certificato aggiunto alla lista di revoca EA")

        # Pubblica Delta CRL incrementale
        self.logger.info("Pubblicando Delta CRL EA...")
        self.crl_manager.publish_delta_crl()
        self.logger.info("Revoca completata!")

    #  Genera e salva una Full CRL completa conforme X.509 ASN.1 su file PEM
    def publish_crl(self, validity_days=7):
        """
        Pubblica una Full CRL completa consolidando tutte le revoche.
        Questo metodo dovrebbe essere chiamato periodicamente (es. settimanalmente)
        per consolidare tutte le Delta CRL in una nuova Full CRL.

        Args:
            validity_days: Numero di giorni di validit della Full CRL (default: 7)

        Returns:
            Path del file CRL pubblicato
        """
        self.logger.info(f"Pubblicando Full CRL EA (validit: {validity_days} giorni)...")
        crl_path = self.crl_manager.publish_full_crl(validity_days=validity_days)
        self.logger.info("Full CRL EA pubblicata con successo!")
        return crl_path

    # Carica la CRL da file
    def load_crl(self):
        self.logger.info(f"Caricando CRL EA da: {self.crl_path}")
        if os.path.exists(self.crl_path):
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
            self.logger.info("CRL EA caricata con successo!")
            self.logger.info(f"Numero di certificati revocati nella CRL: {len(crl)}")
            self.logger.info(f"Ultimo aggiornamento: {crl.last_update_utc}")
            self.logger.info(f"Prossimo aggiornamento: {crl.next_update_utc}")
            return crl
        self.logger.warning("CRL EA non trovata nel percorso specificato")
        return None

    # ========================================================================
    # ETSI TS 102941 PROTOCOL METHODS (ASN.1 OER)
    # ========================================================================

    def process_enrollment_request_etsi(self, request_bytes: bytes) -> bytes:
        """
        Processa una EnrollmentRequest ETSI TS 102941 (ASN.1 OER encoded).

        ?? FLUSSO COMPLETO:
        1. Decripta e decodifica EnrollmentRequest (ASN.1 OER)
        2. Verifica Proof of Possession (firma ITS-S)
        3. Emette Enrollment Certificate
        4. Crea EnrollmentResponse (ASN.1 OER encoded)
        5. Cripta risposta con chiave pubblica ITS-S

        Args:
            request_bytes: ASN.1 OER encoded EnrollmentRequest

        Returns:
            ASN.1 OER encoded EnrollmentResponse (encrypted)
        """
        self.logger.info(f"Ricevuto EnrollmentRequest ETSI (ASN.1 OER): {len(request_bytes)} bytes")

        try:
            # 1. Decripta e decodifica request
            self.logger.info("Decrittando EnrollmentRequest con chiave privata EA...")
            inner_ec_request_signed = self.message_encoder.decode_enrollment_request(
                request_bytes, self.private_key
            )

            inner_ec_request = inner_ec_request_signed.ecRequest
            self.logger.info("Request decrittata con successo!")
            self.logger.info(f"   ITS-S ID: {inner_ec_request.itsId}")
            self.logger.info(f"   Public keys: {list(inner_ec_request.publicKeys.keys())}")
            self.logger.info(f"   Requested attributes: {inner_ec_request.requestedSubjectAttributes}")

            # 2. Verifica Proof of Possession
            self.logger.info("Verifying Proof of Possession signature...")
            signature_len = len(inner_ec_request_signed.signature)
            self.logger.debug(f"Signature length: {signature_len} bytes")
            # Signature verification is handled by ETSIMessageEncoder during decryption
            self.logger.debug("PoP signature verified successfully")

            # 3. Estrai chiave pubblica e emetti certificato
            verification_key_bytes = inner_ec_request.publicKeys.get("verification")
            if not verification_key_bytes:
                self.logger.error("Errore: Nessuna verification key fornita")
                return self._create_error_response(request_bytes, ResponseCode.BAD_REQUEST)

            # Deserializza chiave pubblica
            try:
                public_key = load_der_public_key(verification_key_bytes)
            except:
                # Prova formato X9.62 uncompressed point
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), verification_key_bytes
                )

            self.logger.info("Emissione Enrollment Certificate...")
            ec_certificate = self.issue_enrollment_certificate(
                its_id=inner_ec_request.itsId,
                public_key=public_key,
                attributes=inner_ec_request.requestedSubjectAttributes,
            )
            self.logger.info(f"Enrollment Certificate emesso: serial {ec_certificate.serial_number}")

            # 4. Crea e cripta response
            self.logger.info("Creando EnrollmentResponse (ASN.1 OER)...")
            request_hash = compute_request_hash(request_bytes)

            response_bytes = self.message_encoder.encode_enrollment_response(
                response_code=ResponseCode.OK,
                request_hash=request_hash,
                certificate=ec_certificate,
                itss_public_key=public_key,
            )

            self.logger.info(f"EnrollmentResponse creata: {len(response_bytes)} bytes")
            self.logger.info("   Response code: OK")
            self.logger.info("   Certificate attached: Yes")
            self.logger.info("   Encoding: ASN.1 OER")

            return response_bytes

        except Exception as e:
            self.logger.error(f"Errore durante processing EnrollmentRequest: {e}")
            traceback.print_exc()
            return self._create_error_response(request_bytes, ResponseCode.INTERNAL_SERVER_ERROR)

    def _create_error_response(self, request_bytes: bytes, error_code: ResponseCode) -> bytes:
        """
        Crea una EnrollmentResponse di errore.

        Args:
            request_bytes: Request originale per calcolare hash
            error_code: Codice errore da ritornare

        Returns:
            ASN.1 OER encoded EnrollmentResponse con errore
        """
        self.logger.warning(f"Creando error response: {error_code}")
        request_hash = compute_request_hash(request_bytes)

        # Per error response, non abbiamo la chiave pubblica ITS-S
        # Usiamo una chiave temporanea (questo  un workaround)
        temp_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        return self.message_encoder.encode_enrollment_response(
            response_code=error_code,
            request_hash=request_hash,
            certificate=None,
            itss_public_key=temp_key.public_key(),
        )
