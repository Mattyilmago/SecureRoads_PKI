import os
import secrets
import time
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
    InnerAtRequest,
    InnerAtResponse,
    ResponseCode,
    compute_request_hash,
)
from utils.cert_utils import (
    get_certificate_identifier,
    get_certificate_ski,
    get_short_identifier,
)


class AuthorizationAuthority:
    def __init__(
        self, root_ca, tlm=None, ea_certificate_path=None, aa_id=None, base_dir="./data/aa/"
    ):
        """
        Inizializza Authorization Authority.

        Args:
            root_ca: Riferimento alla Root CA
            tlm: TrustListManager per validazione EC
            ea_certificate_path: Path certificato EA singola (modalità legacy)
            aa_id: ID dell'AA (generato automaticamente se None)
            base_dir: Directory base per dati AA
        """
        # Genera un ID randomico se non specificato
        if aa_id is None:
            aa_id = f"AA_{secrets.token_hex(4).upper()}"

        # Sottocartelle uniche per ogni AA
        base_dir = os.path.join(base_dir, f"{aa_id}/")

        print("\n" + "=" * 80)
        print(f"[AA] *** INIZIO INIZIALIZZAZIONE AUTHORIZATION AUTHORITY {aa_id} ***")
        print("=" * 80)
        self.aa_id = aa_id
        self.aa_certificate_path = os.path.join(base_dir, "certificates/aa_certificate.pem")
        self.aa_key_path = os.path.join(base_dir, "private_keys/aa_key.pem")
        self.crl_path = os.path.join(base_dir, "crl/aa_crl.pem")
        self.ticket_dir = os.path.join(base_dir, "authorization_tickets/")
        self.log_dir = os.path.join(base_dir, "logs/")
        self.backup_dir = os.path.join(base_dir, "backup/")
        self.private_key = None
        self.certificate = None
        self.root_ca = root_ca

        self.tlm = tlm
        self.ea_certificate_path = ea_certificate_path
        self.ea_certificate = None

        # Determina modalità operativa
        if self.tlm:
            print(f"[AA] Modalità TLM: validazione EC tramite Trust List Manager")
            self.validation_mode = "TLM"
        elif self.ea_certificate_path:
            print(f"[AA] [WARNING] Modalità LEGACY: validazione EC tramite EA singola")
            self.validation_mode = "LEGACY"
        else:
            print(f"[AA] [WARNING] WARNING: Nessun metodo di validazione EC configurato!")
            print(f"[AA] [WARNING] Fornire 'tlm' o 'ea_certificate_path'")
            self.validation_mode = "NONE"

        # Crea tutte le directory necessarie
        dirs_to_create = [
            os.path.dirname(self.aa_certificate_path),
            os.path.dirname(self.aa_key_path),
            os.path.dirname(self.crl_path),
            self.ticket_dir,
            self.log_dir,
            self.backup_dir,
        ]

        # Legacy: crea anche directory EA se specificata
        if self.ea_certificate_path:
            dirs_to_create.append(os.path.dirname(self.ea_certificate_path))

        PKIFileHandler.ensure_directories(*dirs_to_create)
        print(f"[AA] Directory create o già esistenti: {len(dirs_to_create)} cartelle")

        self.load_or_generate_aa()

        # Legacy: carica EA certificate se modalità legacy
        if self.validation_mode == "LEGACY":
            self.load_ea_certificate()

        # Inizializza CRLManager dopo aver caricato certificato e chiave privata
        print(f"[AA] Inizializzando CRLManager per AA {aa_id}...")
        self.crl_manager = CRLManager(
            authority_id=aa_id,
            base_dir=base_dir,
            issuer_certificate=self.certificate,
            issuer_private_key=self.private_key,
        )
        print(f"[AA] CRLManager inizializzato con successo!")

        # Inizializza ETSI Message Encoder per gestire messaggi conformi allo standard
        print(f"[AA] Inizializzando ETSI Message Encoder (ASN.1 OER)...")
        self.message_encoder = ETSIMessageEncoder()
        print(f"[AA] ETSI Message Encoder inizializzato!")

        print(f"[AA] Inizializzazione AA {aa_id} completata!")

    # Carica chiave/certificate se esistono, altrimenti li genera
    def load_or_generate_aa(self):
        print("[AA] Verifico esistenza chiave e certificato AA...")
        if os.path.exists(self.aa_key_path) and os.path.exists(self.aa_certificate_path):
            print("[AA] Chiave e certificato AA trovati. Carico da file...")
            self.load_aa_keypair()
            self.load_aa_certificate()
        else:
            print("[AA] Chiave o certificato AA non presenti. Genero nuovi...")
            self.generate_aa_keypair()
            self.generate_signed_certificate_from_rootca()

    # Genera una chiave privata ECC e la salva su file
    def generate_aa_keypair(self):
        print("[AA] Generazione chiave privata ECC per AA...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        with open(self.aa_key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        print("[AA] Chiave privata AA generata e salvata.")

    # Chiede alla rootCa di generare e firmare un certificato. Salva il certificato X.509 firmato
    def generate_signed_certificate_from_rootca(self):
        print(f"[AA] Richiedo alla Root CA la firma del certificato AA {self.aa_id}...")
        subject_name = f"AuthorizationAuthority_{self.aa_id}"
        aa_certificate = self.root_ca.sign_certificate(
            subject_public_key=self.private_key.public_key(), subject_name=subject_name, is_ca=True
        )
        self.certificate = aa_certificate
        with open(self.aa_certificate_path, "wb") as f:
            f.write(aa_certificate.public_bytes(serialization.Encoding.PEM))
        print(f"[AA] Certificato AA firmato dalla Root CA salvato: {self.aa_certificate_path}")

        # Archivia il certificato anche nella RootCA
        print(f"[AA] Richiedendo archiviazione certificato nella RootCA...")
        self.root_ca.save_subordinate_certificate(aa_certificate)

    # Carica la chiave privata ECC dal file PEM
    def load_aa_keypair(self):
        print("[AA] Caricamento chiave privata AA da file...")
        self.private_key = PKIFileHandler.load_private_key(self.aa_key_path)
        print("[AA] Chiave privata AA caricata.")

    def load_aa_certificate(self):
        print("[AA] Caricamento certificato AA da file...")
        self.certificate = PKIFileHandler.load_certificate(self.aa_certificate_path)
        print("[AA] Certificato AA caricato.")

    def load_ea_certificate(self):
        print("[AA] Caricamento certificato EA da file...")
        self.ea_certificate = PKIFileHandler.load_certificate(self.ea_certificate_path)
        print("[AA] Certificato EA caricato.")

    # Processa richiesta per AT con un EC di un ITS-S
    def process_authorization_request(self, ec_pem, its_id, attributes=None):
        print(f"[AA] Ricevuta richiesta di Authorization Ticket da ITS-S {its_id}")
        try:
            ec_certificate = x509.load_pem_x509_certificate(ec_pem)
            print(f"[AA] EC caricato per ITS-S {its_id}, verifico chain e validità...")

            # === VALIDAZIONE EC ===
            if self.validation_mode == "TLM":
                print(f"[AA] Validazione EC tramite TLM...")
                is_trusted, trust_info = self.tlm.is_trusted(ec_certificate)

                if not is_trusted:
                    print(f"[AA] [ERROR] EC NON valido: {trust_info}")
                    return None

                print(f"[AA] [OK] EC validato tramite TLM: {trust_info}")

            elif self.validation_mode == "LEGACY":
                print(f"[AA] Validazione EC tramite EA singola (legacy mode)...")

                # Verifica chain: EC deve essere stato emesso dalla EA trusted
                if ec_certificate.issuer != self.ea_certificate.subject:
                    print("[AA] [ERROR] EC NON valido: issuer non corrisponde a EA.")
                    return None

                print(f"[AA] [OK] EC issuer verificato")

            else:
                print(f"[AA] [ERROR] ERRORE: Nessun metodo di validazione EC configurato!")
                raise ValueError("Authorization Authority non configurata correttamente")

            # === VERIFICA SCADENZA ===
            ec_expiry = ec_certificate.not_valid_after_utc
            # not_valid_after_utc is already timezone-aware
            if ec_expiry < datetime.now(timezone.utc):
                print("[AA] [ERROR] EC scaduto.")
                return None

            print("[AA] [OK] EC valido. Procedo con emissione Authorization Ticket.")

        except Exception as e:
            print(f"[AA] [ERROR] Errore nel parsing EC: {e}")
            return None

        at_certificate = self.issue_authorization_ticket(
            its_id, ec_certificate.public_key(), attributes
        )
        return at_certificate

    # Firma la chiave pubblica dell’ITS-S ricevuta via EC, genera il certificato AT e lo salva
    def issue_authorization_ticket(self, its_id, public_key, attributes=None):
        print(f"[AA] Inizio emissione Authorization Ticket")
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-S"),
                x509.NameAttribute(NameOID.COMMON_NAME, its_id),
            ]
        )
        cert_builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(
                datetime.now(timezone.utc)
                + timedelta(weeks=1)  # ETSI TS 102 941: AT validity tipicamente 1 settimana
            )
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
        )

        certificate = cert_builder.sign(self.private_key, hashes.SHA256())

        # Usa identificatore univoco basato su SKI (come RootCA per subordinates)
        cert_ski = get_certificate_ski(certificate)[:8]  # Primi 8 caratteri dello SKI
        at_filename = f"AT_{cert_ski}.pem"
        at_path = os.path.join(self.ticket_dir, at_filename)

        print(f"[AA] ========================================")
        print(f"[AA] Authorization Ticket generato")
        print(f"[AA] ITS-S: {its_id}")
        print(f"[AA] Identificatore SKI: {cert_ski}")
        print(f"[AA] Serial: {certificate.serial_number}")
        print(f"[AA] Validità: {certificate.not_valid_before_utc} → {certificate.not_valid_after_utc}")
        print(f"[AA] File: {at_filename}")
        print(f"[AA] Path: {at_path}")

        os.makedirs(os.path.dirname(at_path), exist_ok=True)
        with open(at_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        print(f"[AA] Authorization Ticket salvato con successo!")
        print(f"[AA] ========================================")
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
        # Se its_id è un oggetto SharedAtRequest, converti
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
                        # publicKeys è un dict, prendi il primo valore
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
                                # È già un oggetto chiave pubblica
                                extracted_keys.append(key)
                            break  # Una chiave per request
                    else:
                        # publicKeys è direttamente una chiave pubblica
                        extracted_keys.append(pk)
            public_keys = extracted_keys if extracted_keys else public_keys
        else:
            its_id_str = its_id

        print(f"[AA] Emissione batch di {len(public_keys)} Authorization Tickets per {its_id_str}")

        if not public_keys or len(public_keys) == 0:
            raise RuntimeError("Batch vuoto: almeno una chiave pubblica richiesta")

        certificates = []
        for idx, public_key in enumerate(public_keys):
            print(f"[AA] Generando AT {idx+1}/{len(public_keys)}...")
            cert = self.issue_authorization_ticket(its_id_str, public_key, attributes)
            certificates.append(cert)

        print(f"[AA] Batch di {len(certificates)} AT emessi con successo!")
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
        expiry_date = certificate.not_valid_after_utc

        print(f"[AA] Revocando Authorization Ticket con serial: {serial_number}")
        print(f"[AA] Data di scadenza certificato: {expiry_date}")
        print(f"[AA] Motivo revoca: {reason}")

        # Usa CRLManager per aggiungere il certificato revocato
        self.crl_manager.add_revoked_certificate(certificate, reason)
        print(f"[AA] Authorization Ticket aggiunto alla lista di revoca AA")

        # Pubblica Delta CRL incrementale
        print(f"[AA] Pubblicando Delta CRL AA...")
        self.crl_manager.publish_delta_crl()
        print(f"[AA] Revoca completata!")

    # Genera e salva una Full CRL completa conforme X.509 ASN.1 su file PEM
    def publish_crl(self, validity_days=7):
        """
        Pubblica una Full CRL completa consolidando tutte le revoche.
        Questo metodo dovrebbe essere chiamato periodicamente (es. settimanalmente)
        per consolidare tutte le Delta CRL in una nuova Full CRL.

        Args:
            validity_days: Numero di giorni di validità della Full CRL (default: 7)
        """
        print(f"[AA] Pubblicando Full CRL AA (validità: {validity_days} giorni)...")
        self.crl_manager.publish_full_crl(validity_days=validity_days)
        print(f"[AA] Full CRL AA pubblicata con successo!")

    # Carica la CRL da file
    def load_crl(self):
        print(f"[AA] Carico la CRL AA da file: {self.crl_path}")
        if os.path.exists(self.crl_path):
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
            print(f"[AA] CRL AA caricata con {len(crl)} certificati revocati.")
            return crl
        print("[AA] CRL AA non trovata, restituisco None.")
        return None

    # ========================================================================
    # ETSI TS 102941 PROTOCOL METHODS (ASN.1 OER)
    # ========================================================================

    def process_authorization_request_etsi(self, request_bytes: bytes) -> bytes:
        """
        Processa una AuthorizationRequest ETSI TS 102941 (ASN.1 OER encoded).

        🔄 FLUSSO COMPLETO:
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
        print(f"\n[AA] Ricevuto AuthorizationRequest ETSI (ASN.1 OER): {len(request_bytes)} bytes")

        try:
            # 1. Decripta e decodifica request
            print(f"[AA] Decrittando AuthorizationRequest con chiave privata AA...")
            inner_at_request = self.message_encoder.decode_authorization_request(
                request_bytes, self.private_key
            )

            print(f"[AA] Request decrittata con successo!")
            print(f"[AA]    Public keys: {list(inner_at_request.publicKeys.keys())}")
            print(f"[AA]    HMAC key length: {len(inner_at_request.hmacKey)} bytes")
            print(f"[AA]    Requested attributes: {inner_at_request.requestedSubjectAttributes}")

            # 2. Estrai Enrollment Certificate dalla request
            # NOTA: In ETSI TS 102941, l'EC è allegato nell'AuthorizationRequest
            # Per ora usiamo un placeholder, in futuro va estratto dal messaggio ASN.1
            print(f"[AA] Estrazione Enrollment Certificate da request...")
            # TODO: Implementare estrazione EC dal messaggio ASN.1
            # enrollment_cert = extract_ec_from_request(request_bytes)
            print(f"[AA] [WARNING] Estrazione EC non ancora implementata (placeholder)")

            # 3. Valida EC
            if self.validation_mode == "TLM":
                print(f"[AA] Validazione EC tramite TLM...")
                # TODO: Implementare validazione tramite TLM
                # is_valid = self.tlm.validate_ec(enrollment_cert)
                is_valid = True  # Placeholder
                print(f"[AA] [WARNING] Validazione TLM non ancora implementata (placeholder)")
            elif self.validation_mode == "LEGACY":
                print(f"[AA] Validazione EC tramite EA (legacy)...")
                # TODO: Implementare validazione tramite EA
                is_valid = True  # Placeholder
                print(f"[AA] [WARNING] Validazione EA legacy non ancora implementata (placeholder)")
            else:
                print(f"[AA] [WARNING] Nessuna validazione EC configurata, accetto request")
                is_valid = True

            if not is_valid:
                print(f"[AA] [ERROR] EC non valido, rifiuto request")
                return self._create_at_error_response(
                    request_bytes, inner_at_request.hmacKey, ResponseCode.UNAUTHORIZED
                )

            # 4. Estrai chiave pubblica e emetti Authorization Ticket
            verification_key_bytes = inner_at_request.publicKeys.get("verification")
            if not verification_key_bytes:
                print(f"[AA] [ERROR] Errore: Nessuna verification key fornita")
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

            print(f"[AA] Emissione Authorization Ticket...")
            # Genera ITS-ID univoco per AT
            its_id = f"AT_{secrets.token_hex(8)}"

            at_certificate = self.issue_authorization_ticket(
                its_id=its_id,
                public_key=public_key,
                attributes=inner_at_request.requestedSubjectAttributes,
            )
            print(f"[AA] Authorization Ticket emesso: serial {at_certificate.serial_number}")

            # 5. Crea e cripta response con hmacKey
            print(f"[AA] Creando AuthorizationResponse (ASN.1 OER)...")
            request_hash = compute_request_hash(request_bytes)

            response_bytes = self.message_encoder.encode_authorization_response(
                response_code=ResponseCode.OK,
                request_hash=request_hash,
                certificate=at_certificate,
                hmac_key=inner_at_request.hmacKey,
            )

            print(f"[AA] AuthorizationResponse creata: {len(response_bytes)} bytes")
            print(f"[AA]    Response code: OK")
            print(f"[AA]    Certificate attached: Yes")
            print(f"[AA]    Encryption: HMAC-based (unlinkability)")
            print(f"[AA]    Encoding: ASN.1 OER")

            return response_bytes

        except Exception as e:
            print(f"[AA] [ERROR] Errore durante processing AuthorizationRequest: {e}")
            traceback.print_exc()
            # Se abbiamo hmacKey, usiamolo per error response
            try:
                return self._create_at_error_response(
                    request_bytes, inner_at_request.hmacKey, ResponseCode.INTERNAL_SERVER_ERROR
                )
            except:
                # Se non riusciamo nemmeno a decrittare la request, non possiamo rispondere
                print(f"[AA] [ERROR] Impossibile creare error response (request non decrittabile)")
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
        print(f"[AA] [WARNING] Creando AT error response: {error_code}")
        request_hash = compute_request_hash(request_bytes)

        return self.message_encoder.encode_authorization_response(
            response_code=error_code, request_hash=request_hash, certificate=None, hmac_key=hmac_key
        )
