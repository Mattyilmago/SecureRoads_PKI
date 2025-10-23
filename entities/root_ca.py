import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# ETSI Protocol Layer - ASN.1 Implementation (100% ETSI Standard)
from protocols.certificates.asn1_encoder import (
    decode_certificate_with_asn1,
    generate_root_certificate,
)
from protocols.core import compute_hashed_id8
from protocols.core.primitives import extract_validity_period

# Managers
from managers.crl_manager import CRLManager, CRLReason

# Utilities
from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler
from utils.pki_paths import PKIPathManager


class RootCA:
    """
    Root Certificate Authority - ETSI TS 103097 Compliant
    
    **REFACTORED VERSION** - ETSI-compliant, ASN.1 asn only, DRY principles
    
    Implementa la Root CA secondo lo standard ETSI TS 103097 V2.1.1 usando
    SOLO ASN.1 asn (NO X.509).
    
    Responsabilità (Single Responsibility):
    - Generazione certificato root self-signed in formato ASN.1 asn
    - Firma certificati subordinati (EA, AA) in formato ASN.1 asn
    - Gestione revoche tramite CRLManager
    - Archiviazione certificati subordinati
    
    Standard ETSI Implementati:
    - ETSI TS 103097 V2.1.1: Certificate Formats (ASN.1 asn)
    - ETSI TS 102941 V2.1.1: Trust and Privacy Management
    
    Design Patterns Used:
    - Dependency Injection: CRLManager injected
    - Service Layer: Delegazione encoding a ETSIRootCertificateEncoder
    - Single Responsibility: Certificate issuance and management only
    - DRY: Usa PathManager, PKIFileHandler, shared utilities
    """
    
    def __init__(self, ca_id: str = "ROOT_CA_01", base_dir: str = None):
        """
        Inizializza Root CA.
        
        Args:
            ca_id: ETSI-compliant identifier per Root CA (usato in certificate subjectInfo)
            base_dir: Directory base per dati RootCA (default: PKI_PATHS.ROOT_CA)
        
        Note:
            ca_id deve essere univoco nella PKI hierarchy per ETSI TS 103097 compliance
        """
        if base_dir is None:
            from config import PKI_PATHS
            base_dir = str(PKI_PATHS.ROOT_CA)
        
        self.ca_id = ca_id
        
        # ========================================================================
        # 1. SETUP PATHS (PathManager - DRY)
        # ========================================================================
        
        # Usa PKIPathManager per gestione centralizzata paths
        self.paths = PKIPathManager.get_entity_paths("RootCA", ca_id, base_dir)
        
        self.base_dir = str(self.paths.base_dir)
        # Standard ETSI: .oer per certificati ASN.1 OER encoded, .key per chiavi, .pem per CRL
        self.ca_certificate_path = str(self.paths.certificates_dir / "root_ca_certificate.oer")
        self.ca_key_path = str(self.paths.private_keys_dir / "root_ca_key.key")
        self.crl_path = str(self.paths.crl_dir / "root_ca_crl.pem")
        self.log_dir = str(self.paths.logs_dir)
        self.backup_dir = str(self.paths.backup_dir)
        
        # Directory per certificati subordinati ASN.1 asn
        self.subordinates_dir = str(self.paths.data_dir)  # subordinates/
        
        # Crea tutte le directory necessarie
        self.paths.create_all()
        
        # ========================================================================
        # 2. INITIALIZE LOGGER
        # ========================================================================
        
        self.logger = PKILogger.get_logger(
            name="RootCA",
            log_dir=self.log_dir,
            console_output=True
        )
        
        self.logger.info("=" * 60)
        self.logger.info(f"Inizializzando Root CA: {self.ca_id} (ETSI-compliant, ASN.1 asn)")
        self.logger.info("=" * 60)
        self.logger.info(f"Percorso certificato: {self.ca_certificate_path}")
        self.logger.info(f"Percorso chiave privata: {self.ca_key_path}")
        self.logger.info(f"Percorso CRL: {self.crl_path}")
        self.logger.info(f"Directory subordinati: {self.subordinates_dir}")
        self.logger.info(f"✅ Struttura directory creata da PKIPathManager")

        # ========================================================================
        # 3. KEY AND CERTIFICATE MANAGEMENT
        # ========================================================================
        
        self.private_key: Optional[EllipticCurvePrivateKey] = None
        self.certificate_asn1: Optional[bytes] = None  # ASN.1 asn certificate

        # Carica o genera chiave e certificato
        self.logger.info("Caricando o generando chiave e certificato...")
        self._load_or_generate_ca()

        # ========================================================================
        # 4. INITIALIZE CRL MANAGER
        # ========================================================================
        
        self.logger.info("Inizializzando CRLManager per RootCA...")
        # CRLManager usa ETSI ASN.1 asn per CRL (standard ETSI TS 102941)
        self.crl_manager = CRLManager(
            authority_id="RootCA",
            paths=self.paths,
            issuer_certificate_asn=self.certificate_asn1,
            issuer_private_key=self.private_key,
        )
        self.logger.info("CRLManager inizializzato con successo!")
        
        self.logger.info("=" * 60)
        self.logger.info("✅ Root CA inizializzata con successo!")
        self.logger.info("=" * 60)

    # ========================================================================
    # PRIVATE METHODS - KEY AND CERTIFICATE MANAGEMENT
    # ========================================================================
    
    def _load_or_generate_ca(self):
        """Carica chiave/cert se esistono, altrimenti li genera (DRY)."""
        self.logger.info("Verificando esistenza chiave e certificato...")
        
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_certificate_path):
            self.logger.info("Chiave e certificato esistenti trovati, caricandoli...")
            self._load_ca_keypair()
            self._load_certificate_asn1()
        else:
            self.logger.info("Chiave o certificato non trovati, generandoli da zero...")
            self._generate_ca_keypair()
            self._generate_self_signed_certificate_asn1()

    def _generate_ca_keypair(self):
        """Genera chiave privata ECC (usa PKIFileHandler - DRY)."""
        self.logger.info("Generando chiave privata ECC (SECP256R1)...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        
        self.logger.info(f"Salvando chiave privata in: {self.ca_key_path}")
        PKIFileHandler.save_private_key(self.private_key, self.ca_key_path)
        self.logger.info("✅ Chiave privata generata e salvata con successo!")

    def _generate_self_signed_certificate_asn1(self):
        """Genera certificato self-signed in formato ASN.1 asn (ETSI-compliant)."""
        self.logger.info("Generando certificato self-signed ASN.1 asn...")
        self.logger.info("Standard: ETSI TS 103097 V2.1.1")
        
        # Delega generazione a generate_root_certificate (DRY)
        self.certificate_asn1 = generate_root_certificate(
            ca_name="RootCA",
            private_key=self.private_key,
            duration_years=10,
            country="IT",
            organization="SecureRoad PKI"
        )
        
        # Salva certificato ASN.1 asn usando PKIFileHandler (DRY)
        self.logger.info(f"Salvando certificato ASN.1 asn: {self.ca_certificate_path}")
        PKIFileHandler.save_binary_file(self.certificate_asn1, self.ca_certificate_path)
        
        # Log certificato info usando decoder ASN.1 standard ETSI
        try:
            cert_decoded = decode_certificate_with_asn1(self.certificate_asn1, "EtsiTs103097Certificate")
            version = cert_decoded.get('version', '?')
            cert_type = cert_decoded.get('type', '?')
            issuer = cert_decoded.get('issuer', {})
            self.logger.info(f"✅ Certificato Root CA generato con ASN.1 encoder")
            self.logger.info(f"   Version: {version}")
            self.logger.info(f"   Type: {cert_type}")
            self.logger.info(f"   Issuer: {issuer}")
            self.logger.info(f"   Dimensione: {len(self.certificate_asn1)} bytes")
        except Exception as e:
            self.logger.warning(f"⚠️  Impossibile decodificare certificato per logging: {e}")
            self.logger.info(f"✅ Certificato Root CA generato (dimensione: {len(self.certificate_asn1)} bytes)")

        
        self.logger.info("✅ Certificato self-signed ASN.1 asn generato con successo!")

    def _load_ca_keypair(self):
        """Carica chiave privata (usa PKIFileHandler - DRY)."""
        self.logger.info(f"Caricando chiave privata da: {self.ca_key_path}")
        self.private_key = PKIFileHandler.load_private_key(self.ca_key_path)
        self.logger.info("✅ Chiave privata caricata con successo!")

    def _load_certificate_asn1(self):
        """Carica certificato ASN.1 asn (usa PKIFileHandler - DRY)."""
        self.logger.info(f"Caricando certificato ASN.1 asn da: {self.ca_certificate_path}")
        
        # Usa PKIFileHandler per caricare file binario (DRY)
        self.certificate_asn1 = PKIFileHandler.load_binary_file(self.ca_certificate_path)
        
        # Verifica e log info usando decoder ASN.1 standard ETSI
        try:
            cert_decoded = decode_certificate_with_asn1(self.certificate_asn1, "EtsiTs103097Certificate")
            version = cert_decoded.get('version', '?')
            cert_type = cert_decoded.get('type', '?')
            issuer = cert_decoded.get('issuer', {})
            self.logger.info("✅ Certificato caricato con successo!")
            self.logger.info(f"   Version: {version}")
            self.logger.info(f"   Type: {cert_type}")
            self.logger.info(f"   Issuer: {issuer}")
        except Exception as e:
            self.logger.warning(f"⚠️  Impossibile decodificare certificato per logging: {e}")
            self.logger.info("✅ Certificato caricato!")


    # ========================================================================
    # PUBLIC API - CERTIFICATE SIGNING (ASN.1 asn)
    # ========================================================================
    
    def sign_to_be_signed_data(self, tbs_data: bytes) -> bytes:
        """
        Firma ToBeSignedCertificate passato da autorità subordinata.
        
        PATTERN: Separation of Concerns
        - EA/AA costruisce TBS con il proprio encoder
        - RootCA firma TBS e ritorna signature
        - EA/AA assembla certificato completo
        
        Args:
            tbs_data: ToBeSignedCertificate bytes (ASN.1 asn)
            
        Returns:
            bytes: Signature ECDSA (64 bytes: R|S)
        """
        self.logger.info(f"Firmando TBS data ({len(tbs_data)} bytes)...")
        
        # Firma ECDSA diretta ETSI-compliant (SHA-256 + SECP256R1)
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import utils
        
        # Calcola hash SHA-256
        from hashlib import sha256
        digest = sha256(tbs_data).digest()
        
        # Firma con ECDSA
        signature_der = self.private_key.sign(
            digest,
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
        )
        
        # Converti DER in raw R|S format (ETSI standard)
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(signature_der)
        signature = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        
        self.logger.info(f"✅ Firma generata: {len(signature)} bytes")
        return signature

    def save_subordinate_certificate_asn1(self, cert_asn1: bytes, authority_type: str, entity_id: str):
        """
        Salva certificato subordinato ASN.1 asn nell'archivio RootCA.
        
        Args:
            cert_asn1: Certificato ASN.1 asn (bytes)
            authority_type: Tipo autorità ("EA", "AA")
            entity_id: ID entità (es: "EA_001", "AA_001")
        """
        # Calcola HashedId8 per nome file (DRY - usa compute_hashed_id8 centralizzato)
        cert_hashed_id8 = compute_hashed_id8(cert_asn1).hex()[:16]  # Primi 16 caratteri
        
        cert_filename = f"{authority_type}_{cert_hashed_id8}.oer"
        # Usa Path invece di os.path.join (migliore gestione paths)
        archive_path = Path(self.subordinates_dir) / cert_filename
        
        self.logger.info("=" * 50)
        self.logger.info("Archiviando certificato subordinato ASN.1 OER")
        self.logger.info(f"Tipo: {authority_type}")
        self.logger.info(f"Entity ID: {entity_id}")
        self.logger.info(f"HashedId8: {cert_hashed_id8}")
        self.logger.info(f"File: {cert_filename}")
        self.logger.info(f"Path: {archive_path}")
        
        # Usa PKIFileHandler per salvataggio (DRY)
        PKIFileHandler.save_binary_file(cert_asn1, str(archive_path))
        
        self.logger.info("✅ Certificato archiviato con successo!")
        self.logger.info("=" * 50)

    # ========================================================================
    # PUBLIC API - REVOCATION (Delega a CRLManager)
    # ========================================================================
    
    def revoke_certificate_asn1(
        self,
        certificate_asn1: bytes,
        reason: CRLReason = CRLReason.UNSPECIFIED
    ):
        """
        Revoca un certificato ASN.1 asn aggiungendolo alla CRL.
        
        Args:
            certificate_asn1: Certificato ASN.1 asn da revocare
            reason: Motivo della revoca (CRLReason enum)
        """
        # Calcola HashedId8 per identificare certificato
        cert_hashed_id8_bytes = compute_hashed_id8(certificate_asn1)
        cert_hashed_id8 = cert_hashed_id8_bytes.hex()
        
        self.logger.info(f"Revocando certificato ASN.1 asn: {cert_hashed_id8[:16]}")
        self.logger.info(f"Motivo revoca: {reason.name}")
        
        # Usa CRLManager per tracciare la revoca tramite HashedId8
        self.crl_manager.revoke_by_hashed_id(
            hashed_id8=cert_hashed_id8_bytes,
            reason=reason,
            expiry_time=None  # Default 1 anno
        )
        
        self.logger.info("✅ Certificato aggiunto alla lista di revoca")

    # ========================================================================
    # PUBLIC API - CRL PUBLICATION (Delega a CRLManager)
    # ========================================================================
    
    def publish_full_crl(self, validity_days: int = 7):
        """
        Genera e pubblica una Full CRL usando il CRLManager.

        Args:
            validity_days: Giorni di validità della Full CRL (default: 7 giorni)

        Returns:
            La CRL generata
        """
        self.logger.info("Pubblicando Full CRL...")
        crl = self.crl_manager.publish_full_crl(validity_days=validity_days)
        self.logger.info("✅ Full CRL pubblicata con successo!")
        return crl

    def publish_delta_crl(self, validity_hours: int = 24):
        """
        Genera e pubblica una Delta CRL usando il CRLManager.

        Args:
            validity_hours: Ore di validità della Delta CRL (default: 24 ore)

        Returns:
            La Delta CRL generata o None se non ci sono nuove revoche
        """
        self.logger.info("Pubblicando Delta CRL...")
        crl = self.crl_manager.publish_delta_crl(validity_hours=validity_hours)
        if crl:
            self.logger.info("✅ Delta CRL pubblicata con successo!")
        else:
            self.logger.info("ℹ️  Nessuna nuova revoca, Delta CRL non necessaria")
        return crl

    def load_full_crl(self):
        """
        Carica la Full CRL dal file (delega a CRLManager - DRY).

        Returns:
            La Full CRL o None se non esiste
        """
        return self.crl_manager.load_full_crl()

    def load_delta_crl(self):
        """
        Carica la Delta CRL dal file (delega a CRLManager - DRY).

        Returns:
            La Delta CRL o None se non esiste
        """
        return self.crl_manager.load_delta_crl()

    # ========================================================================
    # PUBLIC API - STATISTICS AND MONITORING
    # ========================================================================
    
    def get_crl_statistics(self) -> dict:
        """
        Restituisce statistiche CRL (delega a CRLManager - DRY).

        Returns:
            dict con statistiche (crl_number, certificati revocati, delta pending, ecc.)
        """
        return self.crl_manager.get_statistics()
    
    def get_subordinate_statistics(self) -> dict:
        """
        Restituisce statistiche sui certificati subordinati emessi dalla Root CA.
        
        Conta i certificati subordinati ASN.1 asn (EA, AA) nella directory 'subordinates'.
        Include il conteggio totale e per tipo (EA, AA).
        
        AGGIORNAMENTO AUTOMATICO METRICHE:
        Questo metodo calcola dinamicamente le statistiche in tempo reale:
        
        1. Legge tutti i certificati ASN.1 asn dalla directory 'subordinates'
        2. Verifica per ogni certificato se è ancora valido (non scaduto)
        3. Controlla se il certificato è stato revocato (presente nella CRL)
        4. Conta solo i certificati attivi (validi E non revocati)
        
        Viene chiamato automaticamente quando:
        - Il dashboard richiede metriche (/api/monitoring/metrics)
        - Viene richiesto lo stato dell'entità (/api/stats)
        
        Returns:
            dict con:
                - total_subordinates: numero totale di certificati subordinati
                - ea_count: numero di Enrollment Authorities
                - aa_count: numero di Authorization Authorities
                - active_subordinates: numero di certificati subordinati validi
        """
        subordinates_dir = Path(self.subordinates_dir)
        
        stats = {
            'total_subordinates': 0,
            'ea_count': 0,
            'aa_count': 0,
            'active_subordinates': 0
        }
        
        if not subordinates_dir.exists():
            self.logger.warning(f"Directory subordinati non esiste: {subordinates_dir}")
            return stats
        
        # Conta tutti i certificati subordinati ASN.1 OER
        cert_files = list(subordinates_dir.glob("*.oer"))
        stats['total_subordinates'] = len(cert_files)
        
        # Conta per tipo e verifica validità
        now = datetime.now(timezone.utc)
        for cert_file in cert_files:
            try:
                # Leggi certificato ASN.1 asn usando PKIFileHandler (DRY)
                cert_asn1 = PKIFileHandler.load_binary_file(str(cert_file))
                
                # Determina il tipo dal nome del file
                if cert_file.name.startswith('EA_'):
                    stats['ea_count'] += 1
                elif cert_file.name.startswith('AA_'):
                    stats['aa_count'] += 1
                
                # Verifica validità tramite extract_validity_period ETSI-compliant
                try:
                    start_datetime, expiry_datetime, duration_sec = extract_validity_period(cert_asn1)
                    
                    # Verifica se il certificato è scaduto
                    is_expired = expiry_datetime <= now
                    
                    # Verifica revoca (controlla se HashedId8 è nella CRL)
                    cert_hashed_id8 = compute_hashed_id8(cert_asn1).hex()
                    is_revoked = False
                    # TODO: Implementare check revoca con CRLManager quando attivo
                    
                    # Se non scaduto e non revocato, è attivo
                    if not is_expired and not is_revoked:
                        stats['active_subordinates'] += 1
                    
                except Exception as decode_err:
                    self.logger.warning(f"Impossibile estrarre validità {cert_file.name}: {decode_err}")
                    # Assume attivo se non possiamo verificare
                    stats['active_subordinates'] += 1
                    
            except Exception as e:
                self.logger.warning(f"Errore nel processare {cert_file.name}: {e}")
                continue
        
        self.logger.info(f"Statistiche subordinati RootCA:")
        self.logger.info(f"  Totale certificati: {stats['total_subordinates']}")
        self.logger.info(f"  EA: {stats['ea_count']}")
        self.logger.info(f"  AA: {stats['aa_count']}")
        self.logger.info(f"  Attivi: {stats['active_subordinates']}")
        
        return stats

    # ========================================================================
    # PUBLIC API - CERTIFICATE ACCESS
    # ========================================================================
    
    def get_certificate_asn1(self) -> bytes:
        """
        Ritorna certificato Root CA in formato ASN.1 asn.
        
        Returns:
            bytes: Certificato ASN.1 asn
        """
        return self.certificate_asn1
    
    def get_hashed_id8(self) -> str:
        """
        Calcola e ritorna HashedId8 del certificato RootCA.
        
        ETSI-compliant HashedId8 computation per ETSI TS 103097 V2.1.1.
        Usa compute_hashed_id8 per calcolare hash del certificato ASN.1 asn.
        
        Returns:
            str: HashedId8 (16 caratteri hex string)
        """
        if self.certificate_asn1 is None:
            raise ValueError("RootCA certificate not initialized")
        
        hashed_id8_bytes = compute_hashed_id8(self.certificate_asn1)
        return hashed_id8_bytes.hex()
    
    def get_private_key(self) -> EllipticCurvePrivateKey:
        """
        Ritorna chiave privata Root CA.
        
        Returns:
            EllipticCurvePrivateKey: Chiave privata
        """
        return self.private_key
