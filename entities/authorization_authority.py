from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags
from datetime import datetime, timedelta, timezone
import os
import time
import secrets

# COMPITI AA:
#   Ricezione richieste AT (standard) #TODO butterfly
#   Validazione EC tramite EA
#   Emissione Authorization Ticket (AT)
#   Gestione revoca AT (pubblicazione CRL Delta)

class AuthorizationAuthority:
    def __init__(self, ea_certificate_path, root_ca, aa_id=None, base_dir="./data/aa/"):
        # Genera un ID randomico se non specificato
        if aa_id is None:
            aa_id = f"AA_{secrets.token_hex(4).upper()}"
        
        # Sottocartelle uniche per ogni AA
        base_dir = os.path.join(base_dir, f"{aa_id}/")
        
        print(f"[AA] Inizializzando Authorization Authority {aa_id}...")
        self.aa_id = aa_id
        self.aa_certificate_path = os.path.join(base_dir, "certificates/aa_certificate.pem")
        self.aa_key_path = os.path.join(base_dir, "private_keys/aa_key.pem")
        self.ea_certificate_path = ea_certificate_path
        self.crl_path = os.path.join(base_dir, "crl/aa_crl.pem")
        self.ticket_dir = os.path.join(base_dir, "authorization_tickets/")
        self.revoked = []
        self.private_key = None
        self.certificate = None
        self.ea_certificate = None
        self.root_ca = root_ca

        # Crea tutte le directory necessarie
        for d in [
            os.path.dirname(self.aa_certificate_path),
            os.path.dirname(self.aa_key_path),
            os.path.dirname(self.ea_certificate_path),
            os.path.dirname(self.crl_path),
            self.ticket_dir
        ]:
            os.makedirs(d, exist_ok=True)
            print(f"[AA] Directory creata o già esistente: {d}")

        self.load_or_generate_aa()
        self.load_ea_certificate()
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

            # Verifica chain: EC deve essere stato emesso dalla EA trusted
            if ec_certificate.issuer != self.ea_certificate.subject:
                print("[AA] EC NON valido: issuer non corrisponde a EA.")
                return None
            if ec_certificate.not_valid_after_utc < datetime.now(timezone.utc):
                print("[AA] EC scaduto.")
                return None
            print("[AA] EC valido. Procedo con emissione Authorization Ticket.")
        except Exception as e:
            print(f"[AA] Errore nel parsing EC: {e}")
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
            datetime.now(timezone.utc) + timedelta(seconds=1)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )

        certificate = cert_builder.sign(self.private_key, hashes.SHA256())
        at_path = os.path.join(self.ticket_dir, f"AT_{its_id}_{certificate.serial_number}.pem")
        os.makedirs(os.path.dirname(at_path), exist_ok=True)
        with open(at_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        print(f"[AA] Authorization Ticket emesso e salvato: {at_path}")
        return certificate


    # Aggiunge un certificato alla lista degli AT revocati
    def revoke_authorization_ticket(self, certificate, reason=ReasonFlags.unspecified):
        """
        Revoca un Authorization Ticket aggiungendolo alla lista dei certificati revocati.
        
        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number
        expiry_date = certificate.not_valid_after_utc
        
        print(f"[AA] Revocando Authorization Ticket con serial: {serial_number}")
        print(f"[AA] Data di scadenza certificato: {expiry_date}")
        print(f"[AA] Motivo revoca: {reason}")
        
        self.revoked.append({
            "serial_number": serial_number,
            "revocation_date": datetime.now(timezone.utc),
            "expiry_date": expiry_date,
            "reason": reason
        })
        print(f"[AA] Authorization Ticket aggiunto alla lista di revoca AA")
        print(f"[AA] Pubblicando nuova CRL AA...")
        self.publish_crl()
        print(f"[AA] Revoca completata!")


    # Genera e salva una CRL conforme X.509 ASN.1 su file PEM 
    def publish_crl(self):
        print("[AA] Generazione e firma CRL AA...")
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=7))
        print(f"[AA] Numero Authorization Ticket revocati nella CRL: {len(self.revoked)}")
        for entry in self.revoked:
            print(f"[AA] Aggiungo AT revocato: serial={entry['serial_number']}, "
                  f"data revoca={entry['revocation_date']}, "
                  f"data scadenza={entry.get('expiry_date', 'N/A')}, "
                  f"motivo={entry['reason']}")
            revoked_certificate = x509.RevokedCertificateBuilder()\
                .serial_number(entry["serial_number"])\
                .revocation_date(entry["revocation_date"])\
                .add_extension(
                    x509.CRLReason(entry["reason"]),
                    critical=False
                ).build()
            builder = builder.add_revoked_certificate(revoked_certificate)
        crl = builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())
        with open(self.crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        print(f"[AA] CRL AA salvata su file: {self.crl_path}")

        # Dopo la pubblicazione, rimuovo dalla lista delle revoche i certificati scaduti
        now = datetime.now(timezone.utc)
        old_count = len(self.revoked)
        self.revoked = [
            entry for entry in self.revoked
            if entry.get("expiry_date", None) is None or entry["expiry_date"] > now
        ]
        print(f"[AA] Pulizia revoche: da {old_count} a {len(self.revoked)} ancora attive.")



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