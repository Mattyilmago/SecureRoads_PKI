from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags
from datetime import datetime, timedelta, timezone
import os

# COMPITI EA:   
#   Ricezione e verifica CSR da ITS-S
#   Validazione proof of possession e identità
#   Emissione Enrollment Certificate (EC)
#   Gestione revoca EC (pubblicazione CRL Delta)

class EnrollmentAuthority:
    def __init__(self, root_ca, base_dir="./data/ea/"):
        print(f"[EA] Inizializzando Enrollment Authority...")
        print(f"[EA] Directory base: {base_dir}")
        
        self.ea_certificate_path = os.path.join(base_dir, "enrollment_certificates/ea_certificate.pem")
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
        self.revoked = []

        print(f"[EA] Creando directory necessarie...")
        for d in [
            os.path.dirname(self.ea_certificate_path), os.path.dirname(self.ea_key_path),
            os.path.dirname(self.root_ca_certificate_path), self.ec_dir, os.path.dirname(self.crl_path)
        ]:
            os.makedirs(d, exist_ok=True)

        print(f"[EA] Caricando o generando chiave e certificato EA...")
        self.load_or_generate_ea()
        print(f"[EA] Caricando certificato Root CA...")
        self.load_root_ca_certificate()
        print(f"[EA] Inizializzazione Enrollment Authority completata!")

   
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
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print("[EA] Chiave privata EA generata e salvata con successo!")


    # Chiede alla rootCa di generare e firmare un certificato. Salva il certificato X.509 firmato
    def generate_signed_certificate_from_rootca(self):
        print("[EA] Richiedendo alla Root CA la firma del certificato EA...")
        subject_name = "EnrollmentAuthority"
        ea_certificate = self.root_ca.sign_certificate(
            subject_public_key=self.private_key.public_key(),
            subject_name=subject_name,
            is_ca=True
        )
        self.certificate = ea_certificate
        print(f"[EA] Salvando certificato EA firmato in: {self.ea_certificate_path}")
        with open(self.ea_certificate_path, "wb") as f:
            f.write(ea_certificate.public_bytes(serialization.Encoding.PEM))
        print(f"[EA] Certificato EA firmato dalla Root CA e salvato con successo!")
        print(f"[EA] Serial number certificato EA: {ea_certificate.serial_number}")


    # Carica la chiave privata ECC dal file PEM
    def load_ea_keypair(self):
        print(f"[EA] Caricando chiave privata EA da: {self.ea_key_path}")
        with open(self.ea_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None)
        print("[EA] Chiave privata EA caricata con successo!")


    # Carica il certificato EA dal file PEM
    def load_ea_certificate(self):
        print(f"[EA] Caricando certificato EA da: {self.ea_certificate_path}")
        with open(self.ea_certificate_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        print("[EA] Certificato EA caricato con successo!")
        print(f"[EA] Subject: {self.certificate.subject}")
        print(f"[EA] Serial number: {self.certificate.serial_number}")
        print(f"[EA] Validità: dal {self.certificate.not_valid_before_utc} al {self.certificate.not_valid_after_utc}")


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
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ITS-S"),
            x509.NameAttribute(NameOID.COMMON_NAME, its_id),
        ])
        
        serial_number = x509.random_serial_number()
        print(f"[EA] Serial number assegnato: {serial_number}")
        
        cert_builder = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            public_key
        ).serial_number(
            serial_number
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(seconds=1)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )

        cert = cert_builder.sign(self.private_key, hashes.SHA256())
        ec_path = os.path.join(self.ec_dir, f"EC_{its_id}_{cert.serial_number}.pem")
        print(f"[EA] Salvando Enrollment Certificate in: {ec_path}")
        os.makedirs(os.path.dirname(ec_path), exist_ok=True)
        with open(ec_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[EA] Enrollment Certificate emesso e salvato con successo!")
        print(f"[EA] Validità EC: dal {cert.not_valid_before_utc} al {cert.not_valid_after_utc}")
        return cert

    
    # Aggiunge un certificato alla lista dei certificati revocati
    def revoke_enrollment_certificate(self, certificate, reason=ReasonFlags.unspecified):
        """
        Revoca un certificato di enrollment aggiungendolo alla lista dei certificati revocati.
        
        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number
        expiry_date = certificate.not_valid_after_utc
        
        print(f"[EA] Revocando Enrollment Certificate con serial: {serial_number}")
        print(f"[EA] Data di scadenza certificato: {expiry_date}")
        print(f"[EA] Motivo revoca: {reason}")
        
        self.revoked.append({
            "serial_number": serial_number,
            "revocation_date": datetime.now(timezone.utc),
            "expiry_date": expiry_date,
            "reason": reason
        })
        print(f"[EA] Certificato aggiunto alla lista di revoca EA")
        print(f"[EA] Pubblicando nuova CRL EA...")
        self.publish_crl()
        print(f"[EA] Revoca completata!")


    #  Genera e salva una CRL conforme X.509 ASN.1 su file PEM
    def publish_crl(self):
        print("[EA] Generando Certificate Revocation List EA...")
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=7))
        print(f"[EA] Numero di Enrollment Certificates revocati: {len(self.revoked)}")
        for entry in self.revoked:
            print(f"[EA] Aggiungendo alla CRL EA: serial={entry['serial_number']}, "
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
        print(f"[EA] Salvando CRL EA in: {self.crl_path}")
        with open(self.crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        print(f"[EA] CRL EA generata e salvata con successo!")

        # Dopo la pubblicazione, rimuovo dalla lista delle revoche i certificati scaduti
        now = datetime.now(timezone.utc)
        old_count = len(self.revoked)
        self.revoked = [
            entry for entry in self.revoked
            if entry.get("expiry_date", None) is None or entry["expiry_date"] > now
        ]
        print(f"[EA] Pulizia revoche: da {old_count} a {len(self.revoked)} ancora attive.")



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