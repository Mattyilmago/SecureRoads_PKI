from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags
from datetime import datetime, timedelta, timezone
import os
import secrets
import traceback

from managers.crl_manager import CRLManager
from utils.cert_utils import get_certificate_identifier, get_short_identifier

# ETSI Protocol Layer
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import (
    InnerEcRequest,
    InnerEcResponse,
    ResponseCode,
    compute_request_hash,
)


class EnrollmentAuthority:
    def __init__(self, root_ca, ea_id=None, base_dir="./data/ea/"):
        # Genera un ID randomico se non specificato
        if ea_id is None:
            ea_id = f"EA_{secrets.token_hex(4).upper()}"

        # Sottocartelle uniche per ogni EA
        base_dir = os.path.join(base_dir, f"{ea_id}/")

        print(f"[EA] Inizializzando Enrollment Authority {ea_id}...")
        print(f"[EA] Directory base: {base_dir}")

        self.ea_id = ea_id
        self.ea_certificate_path = os.path.join(base_dir, "certificates/ea_certificate.pem")
        self.ea_key_path = os.path.join(base_dir, "private_keys/ea_key.pem")
        self.root_ca_certificate_path = "./data/root_ca/certificates/root_ca_certificate.pem"
        self.ec_dir = os.path.join(base_dir, "enrollment_certificates/")
        self.crl_path = os.path.join(base_dir, "crl/ea_crl.pem")

        print(f"[EA] Percorso certificato EA: {self.ea_certificate_path}")
        print(f"[EA] Percorso chiave privata EA: {self.ea_key_path}")
        print(f"[EA] Percorso certificato Root CA: {self.root_ca_certificate_path}")
        print(f"[EA] Directory EC: {self.ec_dir}")
        print(f"[EA] Percorso CRL EA: {self.crl_path}")

        self.root_ca = root_ca
        self.private_key = None
        self.certificate = None
        self.root_ca_certificate = None

        print(f"[EA] Creando directory necessarie...")
        for d in [
            os.path.dirname(self.ea_certificate_path),
            os.path.dirname(self.ea_key_path),
            os.path.dirname(self.root_ca_certificate_path),
            self.ec_dir,
            os.path.dirname(self.crl_path),
        ]:
            os.makedirs(d, exist_ok=True)

        print(f"[EA] Caricando o generando chiave e certificato EA...")
        self.load_or_generate_ea()
        print(f"[EA] Caricando certificato Root CA...")
        self.load_root_ca_certificate()

        # Inizializza CRLManager dopo aver caricato certificato e chiave privata
        print(f"[EA] Inizializzando CRLManager per EA {ea_id}...")
        self.crl_manager = CRLManager(
            authority_id=ea_id,
            base_dir=base_dir,
            issuer_certificate=self.certificate,
            issuer_private_key=self.private_key,
        )
        print(f"[EA] CRLManager inizializzato con successo!")

        # Inizializza ETSI Message Encoder per gestire messaggi conformi allo standard
        print(f"[EA] Inizializzando ETSI Message Encoder (ASN.1 OER)...")
        self.message_encoder = ETSIMessageEncoder()
        print(f"[EA] ETSI Message Encoder inizializzato!")

        print(f"[EA] Inizializzazione Enrollment Authority {ea_id} completata!")

    # Carica chiave/cert se esistono, altrimenti li genera
    def load_or_generate_ea(self):
        print(f"[EA] Verificando esistenza chiave e certificato EA...")
        if os.path.exists(self.ea_key_path) and os.path.exists(self.ea_certificate_path):
            print(f"[EA] Chiave e certificato EA esistenti trovati, caricandoli...")
            self.load_ea_keypair()
            self.load_ea_certificate()
        else:
            print(f"[EA] Chiave o certificato EA non trovati, generandoli...")
            self.generate_ea_keypair()
            self.generate_signed_certificate_from_rootca()

    # Genera una chiave privata ECC e la salva su file
    def generate_ea_keypair(self):
        print("[EA] Generando chiave privata ECC (SECP256R1) per EA...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        print(f"[EA] Salvando chiave privata EA in: {self.ea_key_path}")
        with open(self.ea_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        print("[EA] Chiave privata EA generata e salvata con successo!")

    # Chiede alla rootCa di generare e firmare un certificato. Salva il certificato X.509 firmato
    def generate_signed_certificate_from_rootca(self):
        print(f"[EA] Richiedendo alla Root CA la firma del certificato EA {self.ea_id}...")
        subject_name = f"EnrollmentAuthority_{self.ea_id}"
        ea_certificate = self.root_ca.sign_certificate(
            subject_public_key=self.private_key.public_key(), subject_name=subject_name, is_ca=True
        )
        self.certificate = ea_certificate
        print(f"[EA] Salvando certificato EA firmato in: {self.ea_certificate_path}")
        with open(self.ea_certificate_path, "wb") as f:
            f.write(ea_certificate.public_bytes(serialization.Encoding.PEM))
        print(f"[EA] Certificato EA firmato dalla Root CA e salvato con successo!")
        print(f"[EA] Serial number certificato EA: {ea_certificate.serial_number}")

        # Archivia il certificato anche nella RootCA
        print(f"[EA] Richiedendo archiviazione certificato nella RootCA...")
        self.root_ca.save_subordinate_certificate(ea_certificate)

    # Carica la chiave privata ECC dal file PEM
    def load_ea_keypair(self):
        print(f"[EA] Caricando chiave privata EA da: {self.ea_key_path}")
        with open(self.ea_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        print("[EA] Chiave privata EA caricata con successo!")

    # Carica il certificato EA dal file PEM
    def load_ea_certificate(self):
        print(f"[EA] Caricando certificato EA da: {self.ea_certificate_path}")
        with open(self.ea_certificate_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        print("[EA] Certificato EA caricato con successo!")
        print(f"[EA] Subject: {self.certificate.subject}")
        print(f"[EA] Serial number: {self.certificate.serial_number}")
        print(
            f"[EA] Validità: dal {self.certificate.not_valid_before_utc} al {self.certificate.not_valid_after_utc}"
        )

    # Carica il certificato della RootCa
    def load_root_ca_certificate(self):
        print(f"[EA] Caricando certificato Root CA da: {self.root_ca_certificate_path}")
        with open(self.root_ca_certificate_path, "rb") as f:
            self.root_ca_certificate = x509.load_pem_x509_certificate(f.read())
        print("[EA] Certificato Root CA caricato con successo!")
        print(f"[EA] Root CA Subject: {self.root_ca_certificate.subject}")
        print(f"[EA] Root CA Serial: {self.root_ca_certificate.serial_number}")

    # Emette EC da una richiesta CSR
    def process_csr(self, csr_pem, its_id, attributes=None):
        try:
            csr = x509.load_pem_x509_csr(csr_pem)
            print(f"[EA] Ricevuto CSR valido da ITS-S {its_id}, verifico la firma...")
            if not csr.is_signature_valid:
                print("[EA] CSR non valido: firma non valida.")
                return None
        except Exception as e:
            print(f"[EA] Errore nel parsing CSR: {e}")
            return None

        print(f"[EA] CSR valido, procedo con emissione EC per ITS-S {its_id}.")
        ec_certificate = self.issue_enrollment_certificate(its_id, csr.public_key(), attributes)
        return ec_certificate

    # Firma la chiave pubblica ricevuta via CSR e crea il certificato EC
    def issue_enrollment_certificate(self, its_id, public_key, attributes=None):
        print(f"[EA] Emettendo Enrollment Certificate per ITS-S: {its_id}")
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-S"),
                x509.NameAttribute(NameOID.COMMON_NAME, its_id),
            ]
        )

        serial_number = x509.random_serial_number()
        print(f"[EA] Serial number assegnato: {serial_number}")

        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(serial_number)
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(
                datetime.now(timezone.utc)
                + timedelta(days=365)  # ETSI TS 102 941: EC validity 1-3 anni
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )

        cert = cert_builder.sign(self.private_key, hashes.SHA256())

        # Usa identificatore basato su Subject + SKI invece di serial number
        cert_id = get_short_identifier(cert)
        ec_path = os.path.join(self.ec_dir, f"EC_{cert_id}.pem")

        print(f"[EA] Salvando Enrollment Certificate in: {ec_path}")
        os.makedirs(os.path.dirname(ec_path), exist_ok=True)
        with open(ec_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[EA] Enrollment Certificate emesso e salvato con successo!")
        print(f"[EA] Identificatore: {cert_id}")
        print(f"[EA] Validità EC: dal {cert.not_valid_before_utc} al {cert.not_valid_after_utc}")
        return cert

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
        expiry_date = certificate.not_valid_after

        print(f"[EA] Revocando Enrollment Certificate con serial: {serial_number}")
        print(f"[EA] Data di scadenza certificato: {expiry_date}")
        print(f"[EA] Motivo revoca: {reason}")

        # Usa CRLManager per aggiungere il certificato revocato
        self.crl_manager.add_revoked_certificate(certificate, reason)
        print(f"[EA] Certificato aggiunto alla lista di revoca EA")

        # Pubblica Delta CRL incrementale
        print(f"[EA] Pubblicando Delta CRL EA...")
        self.crl_manager.publish_delta_crl()
        print(f"[EA] Revoca completata!")

    #  Genera e salva una Full CRL completa conforme X.509 ASN.1 su file PEM
    def publish_crl(self, validity_days=7):
        """
        Pubblica una Full CRL completa consolidando tutte le revoche.
        Questo metodo dovrebbe essere chiamato periodicamente (es. settimanalmente)
        per consolidare tutte le Delta CRL in una nuova Full CRL.

        Args:
            validity_days: Numero di giorni di validità della Full CRL (default: 7)
        """
        print(f"[EA] Pubblicando Full CRL EA (validità: {validity_days} giorni)...")
        self.crl_manager.publish_full_crl(validity_days=validity_days)
        print(f"[EA] Full CRL EA pubblicata con successo!")

    # Carica la CRL da file
    def load_crl(self):
        print(f"[EA] Caricando CRL EA da: {self.crl_path}")
        if os.path.exists(self.crl_path):
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
            print(f"[EA] CRL EA caricata con successo!")
            print(f"[EA] Numero di certificati revocati nella CRL: {len(crl)}")
            print(f"[EA] Ultimo aggiornamento: {crl.last_update_utc}")
            print(f"[EA] Prossimo aggiornamento: {crl.next_update_utc}")
            return crl
        print("[EA] CRL EA non trovata nel percorso specificato")
        return None

    # ========================================================================
    # ETSI TS 102941 PROTOCOL METHODS (ASN.1 OER)
    # ========================================================================

    def process_enrollment_request_etsi(self, request_bytes: bytes) -> bytes:
        """
        Processa una EnrollmentRequest ETSI TS 102941 (ASN.1 OER encoded).

        🔄 FLUSSO COMPLETO:
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
        print(f"\n[EA] Ricevuto EnrollmentRequest ETSI (ASN.1 OER): {len(request_bytes)} bytes")

        try:
            # 1. Decripta e decodifica request
            print(f"[EA] Decrittando EnrollmentRequest con chiave privata EA...")
            inner_ec_request_signed = self.message_encoder.decode_enrollment_request(
                request_bytes, self.private_key
            )

            inner_ec_request = inner_ec_request_signed.ecRequest
            print(f"[EA] Request decrittata con successo!")
            print(f"[EA]    ITS-S ID: {inner_ec_request.itsId}")
            print(f"[EA]    Public keys: {list(inner_ec_request.publicKeys.keys())}")
            print(f"[EA]    Requested attributes: {inner_ec_request.requestedSubjectAttributes}")

            # 2. Verifica Proof of Possession
            print(f"[EA] Verifica Proof of Possession signature...")
            signature_len = len(inner_ec_request_signed.signature)
            print(f"[EA]    Signature length: {signature_len} bytes")
            # TODO: Implementare verifica firma completa
            print(f"[EA] [WARNING] Verifica firma non ancora implementata (placeholder)")

            # 3. Estrai chiave pubblica e emetti certificato
            verification_key_bytes = inner_ec_request.publicKeys.get("verification")
            if not verification_key_bytes:
                print(f"[EA] [ERROR] Errore: Nessuna verification key fornita")
                return self._create_error_response(request_bytes, ResponseCode.BAD_REQUEST)

            # Deserializza chiave pubblica
            try:
                public_key = load_der_public_key(verification_key_bytes)
            except:
                # Prova formato X9.62 uncompressed point
                public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(), verification_key_bytes
                )

            print(f"[EA] Emissione Enrollment Certificate...")
            ec_certificate = self.issue_enrollment_certificate(
                its_id=inner_ec_request.itsId,
                public_key=public_key,
                attributes=inner_ec_request.requestedSubjectAttributes,
            )
            print(f"[EA] Enrollment Certificate emesso: serial {ec_certificate.serial_number}")

            # 4. Crea e cripta response
            print(f"[EA] Creando EnrollmentResponse (ASN.1 OER)...")
            request_hash = compute_request_hash(request_bytes)

            response_bytes = self.message_encoder.encode_enrollment_response(
                response_code=ResponseCode.OK,
                request_hash=request_hash,
                certificate=ec_certificate,
                itss_public_key=public_key,
            )

            print(f"[EA] EnrollmentResponse creata: {len(response_bytes)} bytes")
            print(f"[EA]    Response code: OK")
            print(f"[EA]    Certificate attached: Yes")
            print(f"[EA]    Encoding: ASN.1 OER")

            return response_bytes

        except Exception as e:
            print(f"[EA] [ERROR] Errore durante processing EnrollmentRequest: {e}")
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
        print(f"[EA] [WARNING] Creando error response: {error_code}")
        request_hash = compute_request_hash(request_bytes)

        # Per error response, non abbiamo la chiave pubblica ITS-S
        # Usiamo una chiave temporanea (questo è un workaround)
        temp_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        return self.message_encoder.encode_enrollment_response(
            response_code=error_code,
            request_hash=request_hash,
            certificate=None,
            itss_public_key=temp_key.public_key(),
        )
