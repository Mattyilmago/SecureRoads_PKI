from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import ReasonFlags
from datetime import datetime, timedelta, timezone
import os

# COMPITI RootCa:
#   Generazione chiave privata
#   Generazione certificato Root CA self-signed
#   Firma certificati subordinati (es. EA, AA)
#   Pubblicazione CRL 

class RootCA:
    def __init__(self, base_dir="./data/root_ca/"):
        self.ca_certificate_path = os.path.join(base_dir, "certificates/root_ca_certificate.pem")
        self.ca_key_path = os.path.join(base_dir, "private_keys/root_ca_key.pem")
        self.crl_path = os.path.join(base_dir, "crl/root_ca_crl.pem")
        print(f"[RootCA] Inizializzando Root CA...")
        print(f"[RootCA] Percorso certificato: {self.ca_certificate_path}")
        print(f"[RootCA] Percorso chiave privata: {self.ca_key_path}")
        print(f"[RootCA] Percorso CRL: {self.crl_path}")

        self.private_key = None
        self.certificate = None
        self.revoked = []

        # Assicura che le directory esistano
        print(f"[RootCA] Creando directory necessarie...")
        for d in [
            os.path.dirname(self.ca_certificate_path),
            os.path.dirname(self.ca_key_path),
            os.path.dirname(self.crl_path)
        ]:
            os.makedirs(d, exist_ok=True)

        # Prova a caricare chiave/cert
        print(f"[RootCA] Caricando o generando chiave e certificato...")
        self.load_or_generate_ca()
        print(f"[RootCA] Inizializzazione completata!")

   
    # Carica chiave/cert se esistono, altrimenti li genera
    def load_or_generate_ca(self):
        print(f"[RootCA] Verificando esistenza chiave e certificato...")
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_certificate_path):
            print(f"[RootCA] Chiave e certificato esistenti trovati, caricandoli...")
            self.load_ca_keypair()
            self.load_certificate()
        else:
            print(f"[RootCA] Chiave o certificato non trovati, generandoli da zero...")
            self.generate_ca_keypair()
            self.generate_self_signed_certificate()

   
    # Genera una chiave privata ECC e la salva su file
    def generate_ca_keypair(self):
        print(f"[RootCA] Generando chiave privata ECC (SECP256R1)...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        print(f"[RootCA] Salvando chiave privata in: {self.ca_key_path}")
        with open(self.ca_key_path, "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"[RootCA] Chiave privata generata e salvata con successo!")

   
    # Genera e salva un certificato X.509 self-signed per la Root CA
    def generate_self_signed_certificate(self):
        print(f"[RootCA] Generando certificato self-signed...")
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test RootCA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"RootCA"),
        ])
        print(f"[RootCA] Subject/Issuer: C=IT, O=Test RootCA, CN=RootCA")
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            # Valido per 10 anni
            datetime.now(timezone.utc) + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(self.private_key, hashes.SHA256())
        
        self.certificate = cert
        print(f"[RootCA] Certificato generato con serial number: {cert.serial_number}")
        print(f"[RootCA] Validità: dal {cert.not_valid_before_utc} al {cert.not_valid_after_utc}")
        print(f"[RootCA] Salvando certificato in: {self.ca_certificate_path}")
        with open(self.ca_certificate_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[RootCA] Certificato self-signed generato e salvato con successo!")

    
    # Carica la chiave privata ECC dal file PEM
    def load_ca_keypair(self):
        print(f"[RootCA] Caricando chiave privata da: {self.ca_key_path}")
        with open(self.ca_key_path, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None)
        print(f"[RootCA] Chiave privata caricata con successo!")

    
    # Carica il certificato Root CA dal file PEM
    def load_certificate(self):
        print(f"[RootCA] Caricando certificato da: {self.ca_certificate_path}")
        with open(self.ca_certificate_path, "rb") as f:
            self.certificate = x509.load_pem_x509_certificate(f.read())
        print(f"[RootCA] Certificato caricato con successo!")
        print(f"[RootCA] Subject: {self.certificate.subject}")
        print(f"[RootCA] Serial number: {self.certificate.serial_number}")
        print(f"[RootCA] Validità: dal {self.certificate.not_valid_before_utc} al {self.certificate.not_valid_after_utc}")

   
    # Firma un certificato subordinato (EA/AA)
    def sign_certificate(self, subject_public_key, subject_name, is_ca=False):
        print(f"[RootCA] Firmando certificato per: {subject_name}")
        print(f"[RootCA] Tipo certificato: {'CA' if is_ca else 'End Entity'}")
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_name),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
        ])
        
        serial_number = x509.random_serial_number()
        print(f"[RootCA] Serial number assegnato: {serial_number}")
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.certificate.subject
        ).public_key(
            subject_public_key
        ).serial_number(
            serial_number
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(seconds=1)
        ).add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True,
        ).sign(self.private_key, hashes.SHA256())

        print(f"[RootCA] Certificato firmato con successo!")
        print(f"[RootCA] Validità: dal {cert.not_valid_before_utc} al {cert.not_valid_after_utc}")
        return cert

    
    # Salva certificato subordinato su file
    def save_subordinate_certificate(self, cert, base_dir="./data/"):
        """
        Salva il certificato subordinato nella cartella corretta dell'autorità,
        riconoscendo EA/AA dal campo Organization o CommonName del certificato.
        Salva anche una copia archivio in RootCA/subordinates.
        """
        subject = cert.subject
        # Prova a estrarre Organization (O) e Common Name (CN)
        org_attrs = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        cn_attrs = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        org = org_attrs[0].value if org_attrs else ""
        cn = cn_attrs[0].value if cn_attrs else ""

        # Determina tipo autorità
        if "EnrollmentAuthority" in org or "EA" in cn:
            authority_folder = "ea"
            cert_subfolder = "enrollment_certificates"
            cert_filename = "ea_certificate.pem"
        elif "AuthorizationAuthority" in org or "AA" in cn:
            authority_folder = "aa"
            cert_subfolder = "authorization_tickets"
            cert_filename = "aa_certificate.pem"
        else:
            # Default: usa CN come nome cartella, filename generico
            authority_folder = cn.lower()
            cert_subfolder = ""
            cert_filename = f"{cn}_certificate.pem"

        # Path operativo subordinato
        authority_base_dir = os.path.join(base_dir, authority_folder)
        if cert_subfolder:
            authority_certificate_path = os.path.join(authority_base_dir, cert_subfolder, cert_filename)
        else:
            authority_certificate_path = os.path.join(authority_base_dir, cert_filename)

        print(f"[RootCA] Salvo certificato subordinato operativo in: {authority_certificate_path}")
        os.makedirs(os.path.dirname(authority_certificate_path), exist_ok=True)
        with open(authority_certificate_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[RootCA] Certificato subordinato salvato nell'autorità operativa!")

        # Salva anche copia archivio in RootCA/subordinates
        archive_dir = os.path.join(base_dir, "root_ca/subordinates")
        os.makedirs(archive_dir, exist_ok=True)
        archive_path = os.path.join(archive_dir, cert_filename)
        print(f"[RootCA] Salvo certificato subordinato archivio in: {archive_path}")
        with open(archive_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        print(f"[RootCA] Certificato subordinato salvato in archivio RootCA!")


    
    # Aggiunge un seriale alla lista dei certificati revocati
    def revoke_certificate(self, certificate, reason=ReasonFlags.unspecified):
        """
        Revoca un certificato aggiungendolo alla lista dei certificati revocati.
        
        Args:
            certificate: Il certificato X.509 da revocare
            reason: Il motivo della revoca (ReasonFlags)
        """
        serial_number = certificate.serial_number
        expiry_date = certificate.not_valid_after_utc
        
        print(f"[RootCA] Revocando certificato con serial number: {serial_number}")
        print(f"[RootCA] Data di scadenza certificato: {expiry_date}")
        
        self.revoked.append({
            "serial_number": serial_number,
            "revocation_date": datetime.now(timezone.utc),
            "expiry_date": expiry_date,
            "reason": reason
        })
        print(f"[RootCA] Certificato aggiunto alla lista di revoca")
        print(f"[RootCA] Pubblicando nuova CRL...")
        self.publish_crl()
        print(f"[RootCA] Revoca completata!")

   
    # Genera e salva una CRL conforme X.509 ASN.1 su file PEM
    def publish_crl(self):
        print(f"[RootCA] Generando Certificate Revocation List (CRL)...")
        builder = x509.CertificateRevocationListBuilder()
        builder = builder.issuer_name(self.certificate.subject)
        builder = builder.last_update(datetime.now(timezone.utc))
        builder = builder.next_update(datetime.now(timezone.utc) + timedelta(seconds=1))

        print(f"[RootCA] Numero di certificati revocati: {len(self.revoked)}")
        for entry in self.revoked:
            print(f"[RootCA] Aggiungendo alla CRL serial number: {entry['serial_number']}")
            print(f"[RootCA]   Data revoca: {entry['revocation_date']}")
            print(f"[RootCA]   Data scadenza originale: {entry['expiry_date']}")
            print(f"[RootCA]   Motivo: {entry['reason']}")
            
            revoked_certificate = x509.RevokedCertificateBuilder()\
                .serial_number(entry["serial_number"])\
                .revocation_date(entry["revocation_date"])\
                .add_extension(
                    x509.CRLReason(entry["reason"]),
                    critical=False
                ).build()
            builder = builder.add_revoked_certificate(revoked_certificate)

        crl = builder.sign(private_key=self.private_key, algorithm=hashes.SHA256())
        print(f"[RootCA] Salvando CRL in: {self.crl_path}")
        with open(self.crl_path, "wb") as f:
            f.write(crl.public_bytes(serialization.Encoding.PEM))
        print(f"[RootCA] CRL generata e pubblicata con successo!")

        # Dopo la pubblicazione, rimuovo dalla lista delle revoche i certificati scaduti
        now = datetime.now(timezone.utc)
        old_count = len(self.revoked)
        
        self.revoked = [
            entry for entry in self.revoked
            if entry.get("expiry_date", None) is None or entry["expiry_date"] > now
        ]
        print(f"[RootCA] Pulizia revoche: da {old_count} a {len(self.revoked)} ancora attive.")

    
    # Carica la CRL da file
    def load_crl(self):
        print(f"[RootCA] Caricando CRL da: {self.crl_path}")
        if os.path.exists(self.crl_path):
            with open(self.crl_path, "rb") as f:
                crl = x509.load_pem_x509_crl(f.read())
                print(f"[RootCA] CRL caricata con successo!")
                print(f"[RootCA] Ultimo aggiornamento: {crl.last_update_utc}")
                print(f"[RootCA] Prossimo aggiornamento: {crl.next_update_utc}")
                return crl
        else:
            print(f"[RootCA] Nessuna CRL trovata nel percorso specificato")
        return None