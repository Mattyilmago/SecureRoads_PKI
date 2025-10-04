from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags
from datetime import datetime, timedelta, timezone
import os
import time
import secrets
from managers.crl_manager import CRLManager
from utils.cert_utils import get_certificate_identifier, get_short_identifier



class AuthorizationAuthority:
    def __init__(self, root_ca, tlm=None, ea_certificate_path=None, aa_id=None, base_dir="./data/aa/"):
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
        
        print("\n" + "="*80)
        print(f"[AA] *** INIZIO INIZIALIZZAZIONE AUTHORIZATION AUTHORITY {aa_id} ***")
        print("="*80)
        self.aa_id = aa_id
        self.aa_certificate_path = os.path.join(base_dir, "certificates/aa_certificate.pem")
        self.aa_key_path = os.path.join(base_dir, "private_keys/aa_key.pem")
        self.crl_path = os.path.join(base_dir, "crl/aa_crl.pem")
        self.ticket_dir = os.path.join(base_dir, "authorization_tickets/")
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
            self.ticket_dir
        ]
        
        # Legacy: crea anche directory EA se specificata
        if self.ea_certificate_path:
            dirs_to_create.append(os.path.dirname(self.ea_certificate_path))
        
        for d in dirs_to_create:
            os.makedirs(d, exist_ok=True)
            print(f"[AA] Directory creata o già esistente: {d}")

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
            issuer_private_key=self.private_key
        )
        print(f"[AA] CRLManager inizializzato con successo!")
        
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
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("[AA] Chiave privata AA generata e salvata.")


    # Chiede alla rootCa di generare e firmare un certificato. Salva il certificato X.509 firmato
    def generate_signed_certificate_from_rootca(self):
        print(f"[AA] Richiedo alla Root CA la firma del certificato AA {self.aa_id}...")
        subject_name = f"AuthorizationAuthority_{self.aa_id}"
        aa_certificate = self.root_ca.sign_certificate(
            subject_public_key=self.private_key.public_key(),
            subject_name=subject_name,
            is_ca=True
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
        with open(self.aa_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None)
        print("[AA] Chiave privata AA caricata.")


    # Carica il certificato AA dal file PEM
    def load_aa_certificate(self):
        print("[AA] Caricamento certificato AA da file...")
        with open(self.aa_certificate_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        print("[AA] Certificato AA caricato.")


    # Carica il certificato EA dal file PEM
    def load_ea_certificate(self):
        print("[AA] Caricamento certificato EA da file...")
        with open(self.ea_certificate_path, "rb") as f:
            self.ea_certificate = x509.load_pem_x509_certificate(f.read())
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
            if ec_expiry < datetime.now(timezone.utc):
                print("[AA] [ERROR] EC scaduto.")
                return None
            
            print("[AA] [OK] EC valido. Procedo con emissione Authorization Ticket.")
            
        except Exception as e:
            print(f"[AA] [ERROR] Errore nel parsing EC: {e}")
            return None

        at_certificate = self.issue_authorization_ticket(its_id, ec_certificate.public_key(), attributes)
        return at_certificate


    # Firma la chiave pubblica dell’ITS-S ricevuta via EC, genera il certificato AT e lo salva
    def issue_authorization_ticket(self, its_id, public_key, attributes=None):
        print(f"[AA] Inizio emissione Authorization Ticket")
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ITS-S"),
            x509.NameAttribute(NameOID.COMMON_NAME, its_id),
        ])
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(weeks=1)  # ETSI TS 102 941: AT validity tipicamente 1 settimana
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )

        certificate = cert_builder.sign(self.private_key, hashes.SHA256())
        
        # Usa identificatore basato su Subject + SKI invece di serial number
        cert_id = get_short_identifier(certificate)
        at_path = os.path.join(self.ticket_dir, f"AT_{cert_id}.pem")
        
        os.makedirs(os.path.dirname(at_path), exist_ok=True)
        with open(at_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"[AA] Authorization Ticket emesso e salvato: {at_path}")
        print(f"[AA] Identificatore AT: {cert_id}")
        return certificate


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