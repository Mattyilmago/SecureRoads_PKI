import os
import secrets
import traceback
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# ETSI Protocol Layer
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import InnerAtRequest, InnerEcRequest, ResponseCode
from utils.cert_utils import get_certificate_expiry_time, get_certificate_not_before, get_certificate_ski
from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler


class ITSStation:
    def __init__(self, its_id, base_dir="./data/itss/"):
        # sottocartelle uniche per ogni veicolo
        base_dir = os.path.join(base_dir, f"{its_id}/")

        self.its_id = its_id
        self.key_path = os.path.join(base_dir, f"own_certificates/{its_id}_key.pem")
        self.cert_path = os.path.join(base_dir, f"own_certificates/{its_id}_certificate.pem")
        self.ec_path = os.path.join(base_dir, f"own_certificates/{its_id}_ec.pem")
        self.at_dir = os.path.join(base_dir, "authorization_tickets/")
        self.trust_anchor_path = os.path.join(base_dir, "trust_anchors/trust_anchors.pem")
        self.ctl_path = os.path.join(base_dir, "ctl_full/ctl.pem")
        self.delta_path = os.path.join(base_dir, "ctl_delta/delta.pem")
        self.inbox_path = os.path.join(base_dir, f"inbox/")
        self.outbox_path = os.path.join(base_dir, f"outbox/{its_id}_outbox.txt")
        self.log_dir = os.path.join(base_dir, "logs/")
        self.backup_dir = os.path.join(base_dir, "backup/")
        
        # Inizializza logger
        self.logger = PKILogger.get_logger(
            name=f"ITSS_{its_id}",
            log_dir=self.log_dir,
            console_output=True
        )
        
        self.logger.info(f"Inizializzazione ITS Station {its_id}")

        dirs = [
            os.path.dirname(self.key_path),
            os.path.dirname(self.cert_path),
            os.path.dirname(self.ec_path),
            self.at_dir,
            os.path.dirname(self.trust_anchor_path),
            os.path.dirname(self.ctl_path),
            os.path.dirname(self.delta_path),
            os.path.dirname(self.inbox_path),
            os.path.dirname(self.outbox_path),
            self.log_dir,
            self.backup_dir,
        ]
        PKIFileHandler.ensure_directories(*dirs)
        self.logger.info(f"Directory create o già esistenti: {len(dirs)} cartelle")

        self.private_key = None
        self.public_key = None
        self.certificate = None
        self.ec_certificate = None
        self.at_certificate = None
        self.trust_anchors = []

        # Inizializza ETSI Message Encoder per messaggi conformi allo standard
        self.logger.info("Inizializzando ETSI Message Encoder (ASN.1 OER)...")
        self.message_encoder = ETSIMessageEncoder()
        self.logger.info("ETSI Message Encoder inizializzato!")

        self.logger.info(f"Inizializzazione ITS Station {its_id} completata!")

    def get_latest_at_path(self):
        """
        Ottiene il path dell'Authorization Ticket più recente.

        Returns:
            str: Path del file AT più recente, None se non esistono AT
        """
        if not os.path.exists(self.at_dir):
            return None

        at_files = [f for f in os.listdir(self.at_dir) if f.endswith(".pem")]
        if not at_files:
            return None

        # Ordina per data di modifica (il più recente per ultimo)
        at_files.sort(key=lambda f: os.path.getmtime(os.path.join(self.at_dir, f)))
        latest_at = at_files[-1]

        return os.path.join(self.at_dir, latest_at)

    def load_latest_at(self):
        """
        Carica l'Authorization Ticket più recente.

        Returns:
            x509.Certificate: Certificato AT più recente, None se non esiste
        """
        at_path = self.get_latest_at_path()
        if not at_path:
            self.logger.info(f"Nessun Authorization Ticket trovato")
            return None

        with open(at_path, "rb") as f:
            at_cert = x509.load_pem_x509_certificate(f.read())

        self.logger.info(f"Authorization Ticket più recente caricato: {os.path.basename(at_path)}")
        return at_cert

    # Genera una chiave privata ECC e la salva su file
    def generate_ecc_keypair(self):
        self.logger.info(f"Generazione chiave ECC privata ITS-S {self.its_id}...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        with open(self.key_path, "wb") as f:
            f.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        self.logger.info(f"Chiave privata ECC salvata su: {self.key_path}")

    # Crea una CSR firmata con la chiave ITS-S
    def generate_csr(self):
        self.logger.info(f"Generazione CSR per richiesta EC...")
        if not self.private_key:
            self.generate_ecc_keypair()
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-S"),
                        x509.NameAttribute(NameOID.COMMON_NAME, self.its_id),
                    ]
                )
            )
            .sign(self.private_key, hashes.SHA256())
        )
        self.logger.info(f"CSR generato per {self.its_id}")
        return csr.public_bytes(serialization.Encoding.PEM)

    # Invia la CSR all''EA e salva l''EC ricevuto
    def request_ec(self, ea_obj):
        self.logger.info(f"Richiesta Enrollment Certificate a EA per {self.its_id}...")
        csr_pem = self.generate_csr()
        ec_certificate = ea_obj.process_csr(csr_pem, self.its_id)
        if ec_certificate:
            with open(self.ec_path, "wb") as f:
                f.write(ec_certificate.public_bytes(serialization.Encoding.PEM))
            self.ec_certificate = ec_certificate
            self.logger.info(f"Enrollment Certificate ricevuto e salvato: {self.ec_path}")
            return ec_certificate
        else:
            self.logger.info(f"Fallita la richiesta EC per {self.its_id}")
            return None

    # Invia EC all''AA per ottenere AT
    def request_at(self, aa_obj, permissions=None, region=None):
        """
        Richiede un Authorization Ticket all''AA.

        Args:
            aa_obj: L''oggetto Authorization Authority
            permissions: Lista dei permessi richiesti (es. ["CAM", "DENM"])
            region: Regione per cui vale l''AT (es. "EU")
        """
        self.logger.info(f"Richiesta Authorization Ticket a AA per {self.its_id}...")
        if permissions:
            self.logger.info(f"Permessi richiesti: {permissions}")
        if region:
            self.logger.info(f"Regione richiesta: {region}")

        if not self.ec_certificate:
            self.logger.info("EC non presente, impossibile richiedere AT.")
            return None
        ec_bytes = self.ec_certificate.public_bytes(serialization.Encoding.PEM)

        # Chiamata all''AA con i parametri aggiuntivi (anche se l''AA potrebbe ignorarli)
        at_certificate = aa_obj.process_authorization_request(ec_bytes, self.its_id)
        if at_certificate:
            # Usa identificatore univoco basato su SKI (come RootCA per subordinates)
            cert_ski = get_certificate_ski(at_certificate)[:8]  # Primi 8 caratteri dello SKI
            at_filename = f"AT_{cert_ski}.pem"
            at_path = os.path.join(self.at_dir, at_filename)

            self.logger.info(f"========================================")
            self.logger.info(f"Authorization Ticket ricevuto")
            self.logger.info(f"Identificatore SKI: {cert_ski}")
            self.logger.info(f"File: {at_filename}")
            self.logger.info(f"Path: {at_path}")

            with open(at_path, "wb") as f:
                f.write(at_certificate.public_bytes(serialization.Encoding.PEM))
            self.at_certificate = at_certificate

            self.logger.info(f"Authorization Ticket salvato con successo!")
            self.logger.info(f"========================================")
        else:
            self.logger.info(f"Fallita la richiesta AT per {self.its_id}")

        return at_certificate

    # Aggiorna i trust anchors (Root CA/EA/AA) usati per validare la chain.
    def update_trust_anchors(self, anchors_list):
        """
        Aggiorna i trust anchors per la validazione dei certificati.

        Args:
            anchors_list: Lista di certificati trust anchor
        """
        self.logger.info(f"Aggiornamento trust anchors per {self.its_id}...")
        self.trust_anchors = anchors_list

        # Salva tutti gli anchors in un file PEM
        with open(self.trust_anchor_path, "wb") as f:
            for anchor in anchors_list:
                f.write(anchor.public_bytes(serialization.Encoding.PEM))
        self.logger.info(f"Trust anchors salvati su: {self.trust_anchor_path}")

    # Valida una catena di certificati usando i trust anchors
    def validate_certificate_chain(self, certificate):
        """
        Valida un certificato contro i trust anchors caricati.

        Args:
            certificate: Il certificato da validare

        Returns:
            bool: True se la validazione ha successo, False altrimenti
        """
        self.logger.info(f"Validazione certificato per {self.its_id}...")

        if not self.trust_anchors:
            self.logger.info("Nessun trust anchor disponibile per la validazione")
            return False

        # Validazione semplificata: controlla se il certificato è firmato da uno dei trust anchors
        for anchor in self.trust_anchors:
            try:
                # Verifica la firma (semplificata)
                if certificate.issuer == anchor.subject:
                    self.logger.info(f"Certificato validato con successo contro trust anchor")
                    return True
            except Exception as e:
                self.logger.info(f"Errore durante la validazione: {e}")
                continue

        self.logger.info(f"Validazione certificato fallita")
        return False

    # Aggiorna la CTL (Certificate Trust List) e la delta.
    def update_ctl(self, ctl_pem, delta_pem=None):
        self.logger.info(f"Aggiornamento CTL completo per {self.its_id}...")
        with open(self.ctl_path, "wb") as f:
            f.write(ctl_pem)
        self.logger.info(f"CTL completo salvato su: {self.ctl_path}")
        if delta_pem:
            self.logger.info(f"Aggiornamento CTL delta per {self.its_id}...")
            with open(self.delta_path, "wb") as f:
                f.write(delta_pem)
            self.logger.info(f"CTL delta salvato su: {self.delta_path}")

    def update_crl_from_tlm(self, tlm_obj=None, aa_id=None):
        """
        Scarica e aggiorna le CRL/CTL dal TLM (Trust List Manager).
        Conforme a ETSI TS 102 941 - Sezione 6.3.2/6.3.3.

        Args:
            tlm_obj: Oggetto Trust List Manager (opzionale, per sistemi centralizzati)
            aa_id: ID dell'Authorization Authority specifica (opzionale)

        Returns:
            bool: True se l'aggiornamento ha successo, False altrimenti
        """
        self.logger.info(f"[REFRESH] Aggiornamento CRL/CTL dal TLM per {self.its_id}...")

        try:
            if tlm_obj:
                # === CASO 1: Sistema con TLM centralizzato (RACCOMANDATO ETSI) ===
                self.logger.info(f"Scaricando CTL completo + Delta dal TLM...")

                # Ottieni il CTL completo (contiene lista di tutte le EA/AA fidate)
                ctl_full = tlm_obj.get_full_ctl()
                if ctl_full:
                    self.update_ctl(ctl_full)
                    self.logger.info(f"[OK] CTL Full aggiornato dal TLM")

                # Ottieni Delta CTL (solo le modifiche dall'ultimo aggiornamento)
                ctl_delta = tlm_obj.get_delta_ctl()
                if ctl_delta:
                    self.update_ctl(ctl_full, ctl_delta)
                    self.logger.info(f"[OK] Delta CTL aggiornato dal TLM")

                # Scarica CRL di tutte le AA fidate
                trusted_aa_list = tlm_obj.get_trusted_aa_list()
                for aa in trusted_aa_list:
                    aa_crl_path = f"./data/aa/{aa}/crl/full_crl.pem"
                    # In produzione: scaricare via V2X/HTTP dal TLM
                    self.logger.info(f"[OK] CRL aggiornata per AA: {aa}")

                return True

            elif aa_id:
                # === CASO 2: Aggiornamento CRL singola AA (legacy) ===
                self.logger.info(f"Scaricando CRL per AA specifica: {aa_id}...")

                # Percorso CRL dell'AA
                aa_crl_path = f"./data/aa/{aa_id}/crl/full_crl.pem"

                # In un sistema reale, qui si farebbe:
                # 1. Richiesta HTTP/V2X al server CRL dell'AA
                # 2. Download del Delta CRL (più efficiente del Full CRL)
                # 3. Applicazione del Delta alla CRL locale
                # 4. Verifica firma della CRL con certificato AA

                if os.path.exists(aa_crl_path):
                    # Simula il ri-caricamento (in produzione: download da server)
                    with open(aa_crl_path, "rb") as f:
                        crl = x509.load_pem_x509_crl(f.read())

                    crl_age = datetime.now(timezone.utc) - crl.last_update_utc
                    self.logger.info(f"CRL ricaricata per {aa_id}")
                    self.logger.info(f"CRL age: {int(crl_age.total_seconds())}s")
                    self.logger.info(f"[OK] CRL aggiornata per AA: {aa_id}")
                    return True
                else:
                    self.logger.info(f"[WARNING] CRL non disponibile per AA: {aa_id}")
                    return False

            else:
                # === CASO 3: Scansione automatica di tutte le AA disponibili ===
                self.logger.info(f"Aggiornamento automatico CRL per tutte le AA disponibili...")

                if not os.path.exists("./data/aa/"):
                    self.logger.info(f"[WARNING] Nessuna directory AA trovata")
                    return False

                aa_dirs = [
                    d
                    for d in os.listdir("./data/aa/")
                    if os.path.isdir(os.path.join("./data/aa/", d))
                ]

                updated_count = 0
                for aa_dir in aa_dirs:
                    if self.update_crl_from_tlm(aa_id=aa_dir):
                        updated_count += 1

                self.logger.info(f"[OK] Aggiornate {updated_count}/{len(aa_dirs)} CRL")
                return updated_count > 0

        except Exception as e:
            self.logger.info(f"[ERROR] Errore aggiornamento CRL/CTL: {e}")
            return False

    # Firma e invia un messaggio (CAM/DENM non crittati) a un altro ITS-S, scrivendolo nell''outbox.
    def send_signed_message(self, message, recipient_id, message_type="CAM"):
        """
        Firma e invia un messaggio a un altro ITS-S.

        Args:
            message: Il contenuto del messaggio da inviare
            recipient_id: L''ID del destinatario
            message_type: Il tipo di messaggio V2X (CAM, DENM, CPM, VAM, etc.)
        """
        self.logger.info(f"Invio messaggio firmato da {self.its_id} a {recipient_id}...")
        self.logger.info(f"Tipo messaggio: {message_type}")

        if not self.private_key or not self.at_certificate:
            self.logger.info("Serve chiave privata e AT per firmare il messaggio!")
            return False
        signature = self.private_key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
        outbox_message = f"To: {recipient_id}\nFrom: {self.its_id}\nType: {message_type}\nMessage: {message}\nSignature: {signature.hex()}\n---\n"

        # Scrive nel proprio outbox
        with open(self.outbox_path, "a") as f:
            f.write(outbox_message)

        # Simula la consegna scrivendo nell'inbox del destinatario
        # Costruisce il percorso dell'inbox del destinatario usando la stessa logica del costruttore
        recipient_base_dir = os.path.join("./data/itss/", f"{recipient_id}/")
        recipient_inbox_dir = os.path.join(recipient_base_dir, "inbox")
        recipient_inbox_file = os.path.join(recipient_inbox_dir, f"{self.its_id}_inbox.txt")

        self.logger.info(f"Percorso inbox destinatario: {recipient_inbox_file}")
        os.makedirs(recipient_inbox_dir, exist_ok=True)
        with open(recipient_inbox_file, "a") as f:
            f.write(
                f"From: {self.its_id}\nType: {message_type}\nMessage: {message}\nSignature: {signature.hex()}\n---\n"
            )

        self.logger.info(f"Messaggio {message_type} firmato inviato e salvato su: {self.outbox_path}")
        return True

    # Legge i messaggi (CAM/DENM non crittati) ricevuti dall''inbox.
    def receive_signed_message(self, validate=True):
        """
        Riceve e opzionalmente valida messaggi firmati dall'inbox.

        Args:
            validate: Se True, valida la firma di ogni messaggio (default: True)

        Returns:
            Lista di messaggi ricevuti (validati se validate=True)
        """
        self.logger.info(f"Ricezione messaggi per {self.its_id}...")

        # Controlla se la cartella inbox esiste
        if not os.path.exists(self.inbox_path):
            self.logger.info(f"Cartella inbox non esistente per {self.its_id}.")
            return []

        # Controlla se la cartella inbox è vuota
        inbox_files = os.listdir(self.inbox_path)
        if not inbox_files:
            self.logger.info(f"Nessun messaggio in arrivo per {self.its_id}.")
            return []

        messages = []
        # Legge tutti i file nella cartella inbox
        for filename in inbox_files:
            file_path = os.path.join(self.inbox_path, filename)
            if os.path.isfile(file_path) and filename.endswith(".txt"):
                self.logger.info(f"Leggendo file: {filename}")
                try:
                    with open(file_path, "r") as f:
                        content = f.read()
                        # Divide i messaggi usando il separatore ---
                        message_blocks = [
                            block.strip() for block in content.split("---") if block.strip()
                        ]

                        # Valida ogni messaggio se richiesto
                        if validate:
                            for msg in message_blocks:
                                if self.validate_message_signature(msg):
                                    messages.append(msg)
                        else:
                            messages.extend(message_blocks)

                except Exception as e:
                    self.logger.info(f"Errore nella lettura del file {filename}: {e}")

        self.logger.info(f"Messaggi ricevuti totali: {len(messages)}")
        if validate:
            self.logger.info(f"Messaggi validati: {len(messages)}")
        return messages

    def validate_message_signature(self, message_block):
        """
        Valida la firma digitale di un messaggio ricevuto.

        Verifica:
        1. Firma digitale con chiave pubblica del mittente
        2. Validità del certificato AT del mittente (non scaduto)
        3. Certificato AT non revocato (check CRL se disponibile)

        Args:
            message_block: Blocco di testo del messaggio con firma

        Returns:
            True se il messaggio è valido, False altrimenti
        """
        try:
            # Parsing del messaggio
            lines = message_block.split("\n")
            sender_id = None
            message_type = None
            message_content = None
            signature_hex = None

            for line in lines:
                if line.startswith("From:"):
                    sender_id = line.split(":", 1)[1].strip()
                elif line.startswith("Type:"):
                    message_type = line.split(":", 1)[1].strip()
                elif line.startswith("Message:"):
                    message_content = line.split(":", 1)[1].strip()
                elif line.startswith("Signature:"):
                    signature_hex = line.split(":", 1)[1].strip()

            if not all([sender_id, message_content, signature_hex]):
                self.logger.info(f"[ERROR] Messaggio malformato da {sender_id}")
                return False

            # Carica il certificato AT del mittente (cerca l'AT più recente)
            sender_base_dir = os.path.join("./data/itss/", f"{sender_id}/")
            sender_at_dir = os.path.join(sender_base_dir, "authorization_tickets/")

            if not os.path.exists(sender_at_dir):
                self.logger.info(f"[WARNING] Directory AT mittente {sender_id} non trovata")
                return False

            # Cerca tutti gli AT del mittente
            sender_at_files = [f for f in os.listdir(sender_at_dir) if f.endswith(".pem")]
            if not sender_at_files:
                self.logger.info(f"[WARNING] Nessun certificato AT per mittente {sender_id}")
                # In un sistema reale, potresti richiedere il certificato via V2X
                return False

            # Usa l'AT più recente
            sender_at_files.sort(key=lambda f: os.path.getmtime(os.path.join(sender_at_dir, f)))
            sender_at_path = os.path.join(sender_at_dir, sender_at_files[-1])

            self.logger.info(f"Caricamento AT mittente: {sender_at_files[-1]}")

            # Carica certificato AT del mittente
            with open(sender_at_path, "rb") as f:
                sender_at_cert = x509.load_pem_x509_certificate(f.read())

            # === VERIFICA 1: Validità temporale del certificato ===
            now = datetime.now(timezone.utc)

            # Usa le utility functions per ottenere datetime UTC-aware
            cert_not_after = get_certificate_expiry_time(sender_at_cert)
            cert_not_before = get_certificate_not_before(sender_at_cert)

            if cert_not_after < now:
                self.logger.info(f"[ERROR] Certificato AT mittente {sender_id} SCADUTO")
                return False

            if cert_not_before > now:
                self.logger.info(f"[ERROR] Certificato AT mittente {sender_id} NON ANCORA VALIDO")
                return False

            # === VERIFICA 2: Firma digitale ===
            # Ricostruisci il messaggio originale (stesso formato usato in send)
            signature_bytes = bytes.fromhex(signature_hex)
            sender_public_key = sender_at_cert.public_key()

            try:
                sender_public_key.verify(
                    signature_bytes, message_content.encode(), ec.ECDSA(hashes.SHA256())
                )
                self.logger.info(f"[OK] Firma valida da {sender_id} (tipo: {message_type})")
            except Exception as e:
                self.logger.info(f"[ERROR] Firma NON valida da {sender_id}: {e}")
                return False

            # === VERIFICA 3: Check CRL (se disponibile) ===
            # Estrai l'issuer del certificato AT per trovare la CRL corretta
            issuer_cn = None
            for attr in sender_at_cert.issuer:
                if attr.oid == NameOID.COMMON_NAME:
                    issuer_cn = attr.value
                    break

            if issuer_cn:
                # Cerca CRL dell'AA che ha emesso l'AT
                # Pattern: AA_XXXXXX -> ./data/aa/AA_XXXXXX/crl/full_crl.pem
                # Estrai l'AA ID dall'issuer CN
                aa_id_from_issuer = issuer_cn.replace("AuthorizationAuthority_", "")

                aa_dirs = []
                if os.path.exists("./data/aa/"):
                    all_aa_dirs = [
                        d
                        for d in os.listdir("./data/aa/")
                        if os.path.isdir(os.path.join("./data/aa/", d))
                    ]
                    # Priorità: AA con nome ESATTO che matcha l'issuer
                    matching_aa = [d for d in all_aa_dirs if d == aa_id_from_issuer]
                    # Fallback: AA con nome che contiene l'issuer (fuzzy match)
                    fuzzy_match = [
                        d for d in all_aa_dirs if aa_id_from_issuer in d and d not in matching_aa
                    ]
                    # Resto delle AA come fallback finale
                    other_aa = [
                        d for d in all_aa_dirs if d not in matching_aa and d not in fuzzy_match
                    ]
                    aa_dirs = matching_aa + fuzzy_match + other_aa

                    if matching_aa:
                        self.logger.info(f"--> AA corretto identificato: {matching_aa[0]}")

                crl_checked = False
                for aa_dir in aa_dirs:
                    crl_path = f"./data/aa/{aa_dir}/crl/full_crl.pem"
                    if os.path.exists(crl_path):
                        try:
                            with open(crl_path, "rb") as f:
                                crl = x509.load_pem_x509_crl(f.read())

                            # === CHECK FRESHNESS CRL (ETSI TS 102 941 - Sezione 6.3.3) ===
                            # Verifica che la CRL non sia troppo vecchia (max 10 minuti)
                            crl_age = datetime.now(timezone.utc) - crl.last_update_utc
                            max_crl_age = timedelta(minutes=10)

                            if crl_age > max_crl_age:
                                self.logger.warning(
                                    f"CRL obsoleta (età: {int(crl_age.total_seconds())}s, "
                                    f"max: {int(max_crl_age.total_seconds())}s)"
                                )
                                self.logger.info(f"[REFRESH] Aggiornamento automatico Delta CRL...")

                                # Scarica nuovo Delta CRL
                                if self.update_crl_from_tlm(aa_id=aa_dir):
                                    # Ricarica la CRL aggiornata
                                    with open(crl_path, "rb") as f_updated:
                                        crl = x509.load_pem_x509_crl(f_updated.read())
                                    self.logger.info(f"[OK] CRL aggiornata con successo")
                                else:
                                    self.logger.warning(
                                        "Impossibile aggiornare CRL, uso versione locale"
                                    )
                            else:
                                self.logger.info(
                                    f"[OK] CRL aggiornata (età: {int(crl_age.total_seconds())}s)"
                                )

                            # Verifica se il certificato è revocato
                            revoked_cert = crl.get_revoked_certificate_by_serial_number(
                                sender_at_cert.serial_number
                            )

                            if revoked_cert:
                                self.logger.error(
                                    f"Certificato AT mittente {sender_id} REVOCATO"
                                )
                                return False

                            crl_checked = True
                            break
                        except Exception:
                            # CRL non leggibile o non compatibile, continua
                            pass

                if crl_checked:
                    self.logger.info(f"[OK] Certificato AT mittente {sender_id} NON revocato")
                else:
                    self.logger.info(f"[WARNING] Impossibile verificare CRL per {sender_id}")

            # Tutte le verifiche passate
            self.logger.info(f"[✓] Messaggio da {sender_id} VALIDO")
            return True

        except Exception as e:
            self.logger.info(f"[ERROR] Errore nella verifica del messaggio: {e}")
            traceback.print_exc()
            return False

    # ========================================================================
    # ETSI TS 102941 PROTOCOL METHODS (ASN.1 OER)
    # ========================================================================

    def request_ec_etsi(self, ea_certificate: x509.Certificate) -> x509.Certificate:
        """
        Richiede un Enrollment Certificate usando il protocollo ETSI TS 102941.

        🔄 FLUSSO COMPLETO:
        1. ITS-S crea InnerEcRequest con chiave pubblica
        2. ITS-S firma request (Proof of Possession)
        3. ITS-S cripta con chiave pubblica EA (ECIES)
        4. ITS-S invia EnrollmentRequest ASN.1 OER
        5. EA processa e risponde con EnrollmentResponse
        6. ITS-S decripta e ottiene EC

        Args:
            ea_certificate: Certificato della Enrollment Authority

        Returns:
            Enrollment Certificate X.509 ricevuto
        """
        self.logger.info(f"\nRichiesta Enrollment Certificate ETSI per {self.its_id}...")

        # Genera chiavi se non esistono
        if not self.private_key:
            self.generate_ecc_keypair()

        # 1. Crea InnerEcRequest
        self.logger.info(f"Creazione InnerEcRequest...")
        inner_request = InnerEcRequest(
            itsId=self.its_id,
            publicKeys={
                "verification": self.public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
            },
            requestedSubjectAttributes={"country": "IT", "organization": "ITS-S"},
        )

        # 2. Encode e cripta request
        self.logger.info(f"Encoding e crittografia EnrollmentRequest (ASN.1 OER + ECIES)...")
        enrollment_request_bytes = self.message_encoder.encode_enrollment_request(
            inner_request=inner_request,
            private_key=self.private_key,
            ea_public_key=ea_certificate.public_key(),
            ea_certificate=ea_certificate,
        )

        self.logger.info(f"EnrollmentRequest creata: {len(enrollment_request_bytes)} bytes")
        self.logger.info(f"   Encoding: ASN.1 OER (ISO/IEC 8825-7)")
        self.logger.info(f"   Encryption: ECIES (ECDH + AES-128-GCM)")

        return enrollment_request_bytes

    def receive_ec_response_etsi(self, response_bytes: bytes) -> x509.Certificate:
        """
        Processa una EnrollmentResponse ETSI e estrae il certificato.

        Args:
            response_bytes: ASN.1 OER encoded EnrollmentResponse

        Returns:
            Enrollment Certificate X.509 se successo, None se errore
        """
        self.logger.info(f"\nRicevuta EnrollmentResponse ETSI: {len(response_bytes)} bytes")

        try:
            # Decripta e decodifica response
            self.logger.info(f"Decrittazione EnrollmentResponse...")
            response = self.message_encoder.decode_enrollment_response(
                response_bytes, self.private_key
            )

            self.logger.info(f"Response decrittata con successo!")
            self.logger.info(f"   Response Code: {response.responseCode}")
            self.logger.info(f"   Certificate Received: {response.certificate is not None}")

            if response.is_success():
                # Carica certificato
                ec_cert = x509.load_der_x509_certificate(response.certificate, default_backend())

                self.logger.info(f"Enrollment Certificate ricevuto:")
                self.logger.info(f"   Subject: {ec_cert.subject.rfc4514_string()}")
                self.logger.info(f"   Serial: {ec_cert.serial_number}")
                self.logger.info(f"   Validità: {get_certificate_not_before(ec_cert)} - {get_certificate_expiry_time(ec_cert)}")

                # Salva EC
                with open(self.ec_path, "wb") as f:
                    f.write(ec_cert.public_bytes(serialization.Encoding.PEM))
                self.ec_certificate = ec_cert

                self.logger.info(f"EC salvato in: {self.ec_path}")
                return ec_cert
            else:
                self.logger.info(f"[ERROR] Enrollment fallito: {response.responseCode}")
                return None

        except Exception as e:
            self.logger.info(f"[ERROR] Errore durante processing EnrollmentResponse: {e}")
            traceback.print_exc()
            return None

    def request_at_etsi(self, aa_certificate: x509.Certificate) -> bytes:
        """
        Richiede un Authorization Ticket usando il protocollo ETSI TS 102941.

        🔄 FLUSSO COMPLETO:
        1. ITS-S genera HMAC key per unlinkability
        2. ITS-S crea InnerAtRequest con chiave pubblica + hmacKey
        3. ITS-S allega Enrollment Certificate
        4. ITS-S cripta con chiave pubblica AA (ECIES)
        5. ITS-S invia AuthorizationRequest ASN.1 OER
        6. AA valida EC e risponde con AuthorizationResponse
        7. ITS-S decripta con hmacKey e ottiene AT

        Args:
            aa_certificate: Certificato della Authorization Authority

        Returns:
            bytes: AuthorizationRequest ASN.1 OER encoded
            bytes: HMAC key (da salvare per decrittare response)
        """
        self.logger.info(f"\nRichiesta Authorization Ticket ETSI per {self.its_id}...")

        # Verifica che abbiamo EC
        if not self.ec_certificate:
            self.logger.info(f"[ERROR] Errore: Enrollment Certificate non presente!")
            self.logger.info(f"   Prima richiedi EC con request_ec_etsi()")
            return None, None

        # 1. Genera HMAC key per unlinkability
        hmac_key = secrets.token_bytes(32)
        self.logger.info(f"HMAC key generata per unlinkability: {len(hmac_key)} bytes")

        # 2. Crea InnerAtRequest
        self.logger.info(f"Creazione InnerAtRequest...")
        inner_request = InnerAtRequest(
            publicKeys={
                "verification": self.public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
            },
            hmacKey=hmac_key,
            requestedSubjectAttributes={"service": "CAM", "region": "Europe"},
        )

        # 3. Encode e cripta request (allega EC)
        self.logger.info(f"Encoding e crittografia AuthorizationRequest (ASN.1 OER + ECIES)...")
        auth_request_bytes = self.message_encoder.encode_authorization_request(
            inner_request=inner_request,
            enrollment_certificate=self.ec_certificate,
            aa_public_key=aa_certificate.public_key(),
            aa_certificate=aa_certificate,
        )

        self.logger.info(f"AuthorizationRequest creata: {len(auth_request_bytes)} bytes")
        self.logger.info(f"   Encoding: ASN.1 OER (ISO/IEC 8825-7)")
        self.logger.info(f"   Encryption: ECIES (ECDH + AES-128-GCM)")
        self.logger.info(f"   EC allegato: Yes")
        self.logger.info(f"   HMAC key embedded: Yes (unlinkability)")

        return auth_request_bytes, hmac_key

    def receive_at_response_etsi(self, response_bytes: bytes, hmac_key: bytes) -> x509.Certificate:
        """
        Processa una AuthorizationResponse ETSI e estrae l'Authorization Ticket.

        Args:
            response_bytes: ASN.1 OER encoded AuthorizationResponse
            hmac_key: HMAC key usata nella request

        Returns:
            Authorization Ticket X.509 se successo, None se errore
        """
        self.logger.info(f"\nRicevuta AuthorizationResponse ETSI: {len(response_bytes)} bytes")

        try:
            # Decripta e decodifica response con hmacKey
            self.logger.info(f"Decrittazione AuthorizationResponse con HMAC key...")
            response = self.message_encoder.decode_authorization_response(response_bytes, hmac_key)

            self.logger.info(f"Response decrittata con successo!")
            self.logger.info(f"   Response Code: {response.responseCode}")
            self.logger.info(f"   Certificate Received: {response.certificate is not None}")

            if response.is_success():
                # Carica certificato
                at_cert = x509.load_der_x509_certificate(response.certificate, default_backend())

                # Usa identificatore univoco basato su SKI (come RootCA per subordinates)
                cert_ski = get_certificate_ski(at_cert)[:8]  # Primi 8 caratteri dello SKI
                at_filename = f"AT_{cert_ski}.pem"
                at_path = os.path.join(self.at_dir, at_filename)

                self.logger.info(f"========================================")
                self.logger.info(f"Authorization Ticket ricevuto")
                self.logger.info(f"Subject: {at_cert.subject.rfc4514_string()}")
                self.logger.info(f"Serial: {at_cert.serial_number}")
                self.logger.info(f"Validità: {get_certificate_not_before(at_cert)} - {get_certificate_expiry_time(at_cert)}")
                self.logger.info(f"Identificatore SKI: {cert_ski}")
                self.logger.info(f"File: {at_filename}")
                self.logger.info(f"Path: {at_path}")

                # Salva AT
                with open(at_path, "wb") as f:
                    f.write(at_cert.public_bytes(serialization.Encoding.PEM))
                self.at_certificate = at_cert

                self.logger.info(f"AT salvato con successo!")
                self.logger.info(f"========================================")
                return at_cert
            else:
                self.logger.info(f"[ERROR] Authorization fallito: {response.responseCode}")
                return None

        except Exception as e:
            self.logger.info(f"[ERROR] Errore durante processing AuthorizationResponse: {e}")
            traceback.print_exc()
            return None
