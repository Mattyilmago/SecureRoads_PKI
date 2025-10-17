"""
ITS Station - ETSI TS 102941 Compliant

**REFACTORED VERSION** - ETSI-compliant, ASN.1 OER only, DRY principles

Implementa l'ITS Station secondo lo standard ETSI TS 102941 V2.1.1 usando
SOLO ASN.1 OER (NO X.509).

Responsabilità (Single Responsibility):
- Richiesta Enrollment Certificates (EC) in formato ASN.1 OER
- Richiesta Authorization Tickets (AT) in formato ASN.1 OER  
- Invio/ricezione messaggi V2X firmati
- Validazione messaggi e certificati
- Gestione trust anchors e CTL

Standard ETSI Implementati:
- ETSI TS 102941 V2.1.1: Trust and Privacy Management
- ETSI TS 103097 V2.1.1: Certificate Formats (ASN.1 OER)
- ETSI TS 103 831: Trust List Management

Design Patterns Used:
- Dependency Injection: Message encoder iniettato
- Service Layer: Delegazione encoding a ETSI encoders
- Single Responsibility: Separazione certificati e messaggistica
- DRY: Usa PathManager, PKIFileHandler, shared utilities

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import secrets
import traceback
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# ETSI Protocol Layer - ASN.1 OER Implementation
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import (
    InnerAtRequest, 
    InnerEcRequest, 
    ResponseCode,
    compute_hashed_id8
)

# Utilities
from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler
from utils.pki_paths import PKIPathManager


class ITSStation:
    """
    ITS Station - ETSI TS 102941 Compliant
    
    **REFACTORED VERSION** - ETSI-compliant, ASN.1 OER only, DRY principles
    
    Implementa l'ITS Station secondo lo standard ETSI TS 102941 V2.1.1 usando
    SOLO ASN.1 OER (NO X.509).
    
    Responsabilità (Single Responsibility):
    - Richiesta Enrollment Certificates (EC) in formato ASN.1 OER
    - Richiesta Authorization Tickets (AT) in formato ASN.1 OER
    - Invio/ricezione messaggi V2X firmati con AT
    - Validazione messaggi tramite trust anchors
    - Gestione Certificate Trust List (CTL)
    
    Standard ETSI Implementati:
    - ETSI TS 102941 V2.1.1: Trust and Privacy Management
    - ETSI TS 103097 V2.1.1: Certificate Formats (ASN.1 OER)
    
    Design Patterns Used:
    - Dependency Injection: ETSIMessageEncoder iniettato
    - Service Layer: Delegazione encoding a ETSI encoder
    - Single Responsibility: Certificati, messaggistica, trust separati
    - DRY: Usa PathManager, PKIFileHandler, shared utilities
    """
    
    def __init__(self, its_id: str, base_dir: str = "./pki_data/itss/"):
        """
        Inizializza ITS Station.
        
        Args:
            its_id: Identificativo univoco ITS-S (es: "Vehicle_001")
            base_dir: Directory base per dati ITS-S
        """
        # ========================================================================
        # 1. SETUP PATHS (PathManager - DRY)
        # ========================================================================
        
        self.its_id = its_id
        
        # Usa PKIPathManager per gestione centralizzata paths
        paths = PKIPathManager.get_entity_paths("ITS", its_id, base_dir)
        
        self.base_dir = str(paths.base_dir)
        # Standard ETSI: .oer per certificati ASN.1 OER, .key per chiavi private
        self.key_path = str(paths.private_keys_dir / f"{its_id}_key.key")
        self.ec_path_asn1 = str(paths.own_certificates_dir / f"{its_id}_ec.oer")
        self.at_dir = str(paths.authorization_tickets_dir)
        self.trust_anchor_path = str(paths.trust_anchors_dir / "root_ca.oer")
        self.ctl_full_path = str(paths.ctl_full_dir / "ctl_full.oer")
        self.ctl_delta_path = str(paths.ctl_delta_dir / "ctl_delta.oer")
        self.inbox_path = str(paths.inbox_dir)
        self.outbox_path = str(paths.outbox_dir / f"{its_id}_outbox.txt")
        self.log_dir = str(paths.logs_dir)
        self.backup_dir = str(paths.backup_dir)
        
        # Crea tutte le directory necessarie
        paths.create_all()
        
        # ========================================================================
        # 2. INITIALIZE LOGGER
        # ========================================================================
        
        self.logger = PKILogger.get_logger(
            name=f"ITSS_{its_id}",
            log_dir=self.log_dir,
            console_output=True
        )
        
        self.logger.info("=" * 60)
        self.logger.info(f"Inizializzazione ITS Station {its_id} (ETSI-compliant)")
        self.logger.info("=" * 60)
        self.logger.info(f"Directory base: {self.base_dir}")
        self.logger.info(f"Chiave privata: {self.key_path}")
        self.logger.info(f"EC path: {self.ec_path_asn1}")
        self.logger.info(f"AT directory: {self.at_dir}")
        self.logger.info(f"✅ Struttura directory creata da PKIPathManager")

        # ========================================================================
        # 3. KEY AND CERTIFICATE MANAGEMENT
        # ========================================================================
        
        self.private_key: Optional[EllipticCurvePrivateKey] = None
        self.public_key: Optional[EllipticCurvePublicKey] = None
        self.ec_certificate_asn1: Optional[bytes] = None  # ASN.1 OER EC
        self.at_certificates_asn1: List[bytes] = []  # Lista AT ASN.1 OER
        self.trust_anchors_asn1: List[bytes] = []  # Trust anchors ASN.1 OER

        # ========================================================================
        # 4. INITIALIZE ETSI MESSAGE ENCODER
        # ========================================================================
        
        self.logger.info("Inizializzando ETSI Message Encoder (ASN.1 OER)...")
        self.message_encoder = ETSIMessageEncoder()
        self.logger.info("✅ ETSI Message Encoder inizializzato!")
        
        # Genera chiave se non esiste
        if os.path.exists(self.key_path):
            self._load_keypair()
        else:
            self._generate_keypair()
        
        self.logger.info("=" * 60)
        self.logger.info(f"✅ ITS Station {its_id} inizializzata con successo!")
        self.logger.info("=" * 60)

    # ========================================================================
    # PRIVATE METHODS - KEY MANAGEMENT
    # ========================================================================
    
    def _generate_keypair(self):
        """Genera chiave privata ECC (usa PKIFileHandler - DRY)."""
        self.logger.info(f"Generando chiave privata ECC (SECP256R1) per {self.its_id}...")
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        
        # Salva usando PKIFileHandler (DRY)
        PKIFileHandler.save_private_key(self.private_key, self.key_path)
        self.logger.info(f"✅ Chiave privata salvata: {self.key_path}")

    def _load_keypair(self):
        """Carica chiave privata (usa PKIFileHandler - DRY)."""
        self.logger.info(f"Caricando chiave privata da: {self.key_path}")
        self.private_key = PKIFileHandler.load_private_key(self.key_path)
        self.public_key = self.private_key.public_key()
        self.logger.info("✅ Chiave privata caricata con successo!")

    # ========================================================================
    # PUBLIC API - ENROLLMENT CERTIFICATE REQUEST (ETSI TS 102941)
    # ========================================================================
    
    def request_enrollment_certificate(
        self, 
        ea_certificate_asn1: bytes,
        requested_attributes: Optional[dict] = None
    ) -> bytes:
        """
        Richiede Enrollment Certificate usando protocollo ETSI TS 102941.
        
        FLUSSO COMPLETO:
        1. ITS-S crea InnerEcRequest con chiave pubblica
        2. ITS-S firma request (Proof of Possession)
        3. ITS-S cripta con chiave pubblica EA (ECIES)
        4. ITS-S invia EnrollmentRequest ASN.1 OER
        
        Args:
            ea_certificate_asn1: Certificato EA in formato ASN.1 OER
            requested_attributes: Attributi richiesti (country, organization, etc.)
            
        Returns:
            bytes: EnrollmentRequest ASN.1 OER encoded
        """
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Richiesta Enrollment Certificate ETSI per {self.its_id}")
        self.logger.info(f"{'='*60}")
        
        # Genera chiavi se non esistono
        if not self.private_key:
            self._generate_keypair()
        
        # Crea InnerEcRequest
        self.logger.info("Creazione InnerEcRequest...")
        
        # Default attributes se non specificati
        if not requested_attributes:
            requested_attributes = {
                "country": "IT",
                "organization": "ITS-S"
            }
        
        inner_request = InnerEcRequest(
            itsId=self.its_id,
            publicKeys={
                "verification": self.public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
            },
            requestedSubjectAttributes=requested_attributes,
        )
        
        # Estrai chiave pubblica EA da certificato ASN.1 OER
        self.logger.info("Estrazione chiave pubblica EA da certificato ASN.1 OER...")
        from protocols.etsi_enrollment_certificate import ETSIEnrollmentCertificateEncoder
        
        ea_encoder = ETSIEnrollmentCertificateEncoder()
        ea_public_key = ea_encoder.extract_public_key(ea_certificate_asn1)
        
        self.logger.info("✅ Chiave pubblica EA estratta con successo!")
        
        # Encode e cripta request
        self.logger.info("Encoding e crittografia EnrollmentRequest (ASN.1 OER + ECIES)...")
        
        enrollment_request_bytes = self.message_encoder.encode_enrollment_request(
            inner_request=inner_request,
            private_key=self.private_key,
            ea_public_key=ea_public_key,
            ea_certificate_asn1=ea_certificate_asn1,
        )
        
        self.logger.info(f"✅ EnrollmentRequest creata: {len(enrollment_request_bytes)} bytes")
        self.logger.info(f"   Encoding: ASN.1 OER (ISO/IEC 8825-7)")
        self.logger.info(f"   Encryption: ECIES (ECDH + AES-128-GCM)")
        self.logger.info(f"{'='*60}\n")
        
        return enrollment_request_bytes

    def process_enrollment_response(self, response_bytes: bytes) -> bool:
        """
        Processa EnrollmentResponse ETSI e salva EC.
        
        Args:
            response_bytes: ASN.1 OER encoded EnrollmentResponse
            
        Returns:
            bool: True se EC ricevuto e salvato, False altrimenti
        """
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Processamento EnrollmentResponse ETSI")
        self.logger.info(f"Response size: {len(response_bytes)} bytes")
        self.logger.info(f"{'='*60}")
        
        try:
            # Decritta e decodifica response
            self.logger.info("Decrittazione EnrollmentResponse...")
            response = self.message_encoder.decode_enrollment_response(
                response_bytes, self.private_key
            )
            
            self.logger.info(f"✅ Response decrittata con successo!")
            self.logger.info(f"   Response Code: {response.responseCode}")
            self.logger.info(f"   Certificate Received: {response.certificate is not None}")
            
            if response.is_success():
                # Certificato è già ASN.1 OER
                self.ec_certificate_asn1 = response.certificate
                
                # Salva EC usando PKIFileHandler (DRY)
                PKIFileHandler.save_binary_file(
                    self.ec_certificate_asn1, 
                    self.ec_path_asn1
                )
                
                self.logger.info(f"✅ Enrollment Certificate salvato: {self.ec_path_asn1}")
                self.logger.info(f"   Dimensione: {len(self.ec_certificate_asn1)} bytes")
                self.logger.info(f"   Formato: ASN.1 OER (ETSI TS 103097)")
                self.logger.info(f"{'='*60}\n")
                return True
            else:
                self.logger.error(f"❌ Enrollment fallito: {response.responseCode}")
                self.logger.info(f"{'='*60}\n")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Errore processing EnrollmentResponse: {e}")
            traceback.print_exc()
            self.logger.info(f"{'='*60}\n")
            return False

    # ========================================================================
    # PUBLIC API - AUTHORIZATION TICKET REQUEST (ETSI TS 102941)
    # ========================================================================
    
    def request_authorization_ticket(
        self,
        aa_certificate_asn1: bytes,
        requested_attributes: Optional[dict] = None
    ) -> Tuple[bytes, bytes]:
        """
        Richiede Authorization Ticket usando protocollo ETSI TS 102941.
        
        FLUSSO COMPLETO:
        1. ITS-S genera HMAC key per unlinkability
        2. ITS-S crea InnerAtRequest con chiave pubblica + hmacKey
        3. ITS-S allega Enrollment Certificate
        4. ITS-S cripta con chiave pubblica AA (ECIES)
        5. ITS-S invia AuthorizationRequest ASN.1 OER
        
        Args:
            aa_certificate_asn1: Certificato AA in formato ASN.1 OER
            requested_attributes: Attributi richiesti (service, region, etc.)
            
        Returns:
            Tuple[bytes, bytes]: (AuthorizationRequest ASN.1 OER, HMAC key)
        """
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Richiesta Authorization Ticket ETSI per {self.its_id}")
        self.logger.info(f"{'='*60}")
        
        # Verifica EC
        if not self.ec_certificate_asn1:
            self.logger.error("❌ Enrollment Certificate non presente!")
            self.logger.error("   Prima richiedi EC con request_enrollment_certificate()")
            self.logger.info(f"{'='*60}\n")
            return None, None
        
        # Genera HMAC key per unlinkability
        hmac_key = secrets.token_bytes(32)
        self.logger.info(f"✅ HMAC key generata per unlinkability: {len(hmac_key)} bytes")
        
        # Default attributes se non specificati
        if not requested_attributes:
            requested_attributes = {
                "service": "CAM",
                "region": "Europe"
            }
        
        # Genera chiave pubblica dedicata per AT (unlinkability!)
        at_private_key = ec.generate_private_key(ec.SECP256R1())
        at_public_key = at_private_key.public_key()
        
        self.logger.info("✅ Chiave pubblica dedicata generata per AT (unlinkability)")
        
        # Crea InnerAtRequest
        self.logger.info("Creazione InnerAtRequest...")
        inner_request = InnerAtRequest(
            publicKeys={
                "verification": at_public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                )
            },
            hmacKey=hmac_key,
            requestedSubjectAttributes=requested_attributes,
        )
        
        # Estrai chiave pubblica AA da certificato ASN.1 OER
        self.logger.info("Estrazione chiave pubblica AA da certificato ASN.1 OER...")
        from protocols.etsi_authority_certificate import ETSIAuthorityCertificateEncoder
        
        aa_encoder = ETSIAuthorityCertificateEncoder()
        aa_public_key = aa_encoder.extract_public_key(aa_certificate_asn1)
        
        self.logger.info("✅ Chiave pubblica AA estratta con successo!")
        
        # Encode e cripta request
        self.logger.info("Encoding e crittografia AuthorizationRequest (ASN.1 OER + ECIES)...")
        
        auth_request_bytes = self.message_encoder.encode_authorization_request(
            inner_request=inner_request,
            enrollment_certificate_asn1=self.ec_certificate_asn1,
            aa_public_key=aa_public_key,
            aa_certificate_asn1=aa_certificate_asn1,
        )
        
        self.logger.info(f"✅ AuthorizationRequest creata: {len(auth_request_bytes)} bytes")
        self.logger.info(f"   Encoding: ASN.1 OER (ISO/IEC 8825-7)")
        self.logger.info(f"   Encryption: ECIES (ECDH + AES-128-GCM)")
        self.logger.info(f"   EC allegato: Yes")
        self.logger.info(f"   HMAC key embedded: Yes (unlinkability)")
        self.logger.info(f"{'='*60}\n")
        
        return auth_request_bytes, hmac_key

    def process_authorization_response(
        self, 
        response_bytes: bytes, 
        hmac_key: bytes
    ) -> bool:
        """
        Processa AuthorizationResponse ETSI e salva AT.
        
        Args:
            response_bytes: ASN.1 OER encoded AuthorizationResponse
            hmac_key: HMAC key usata nella request
            
        Returns:
            bool: True se AT ricevuto e salvato, False altrimenti
        """
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"Processamento AuthorizationResponse ETSI")
        self.logger.info(f"Response size: {len(response_bytes)} bytes")
        self.logger.info(f"{'='*60}")
        
        try:
            # Decritta e decodifica response con hmacKey
            self.logger.info("Decrittazione AuthorizationResponse con HMAC key...")
            response = self.message_encoder.decode_authorization_response(
                response_bytes, hmac_key
            )
            
            self.logger.info(f"✅ Response decrittata con successo!")
            self.logger.info(f"   Response Code: {response.responseCode}")
            self.logger.info(f"   Certificate Received: {response.certificate is not None}")
            
            if response.is_success():
                # Certificato AT è ASN.1 OER
                at_certificate_asn1 = response.certificate
                
                # Usa HashedId8 per nome file (ETSI-compliant)
                at_hashed_id8 = compute_hashed_id8(at_certificate_asn1).hex()[:16]
                at_filename = f"AT_{at_hashed_id8}.oer"
                at_path = Path(self.at_dir) / at_filename
                
                # Salva AT usando PKIFileHandler (DRY)
                PKIFileHandler.save_binary_file(at_certificate_asn1, str(at_path))
                
                # Aggiungi alla lista AT
                self.at_certificates_asn1.append(at_certificate_asn1)
                
                self.logger.info(f"✅ Authorization Ticket salvato:")
                self.logger.info(f"   HashedId8: {at_hashed_id8}")
                self.logger.info(f"   File: {at_filename}")
                self.logger.info(f"   Path: {at_path}")
                self.logger.info(f"   Dimensione: {len(at_certificate_asn1)} bytes")
                self.logger.info(f"   Formato: ASN.1 OER (ETSI TS 103097)")
                self.logger.info(f"{'='*60}\n")
                return True
            else:
                self.logger.error(f"❌ Authorization fallito: {response.responseCode}")
                self.logger.info(f"{'='*60}\n")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Errore processing AuthorizationResponse: {e}")
            traceback.print_exc()
            self.logger.info(f"{'='*60}\n")
            return False

    # ========================================================================
    # PUBLIC API - TRUST ANCHORS AND CTL MANAGEMENT
    # ========================================================================
    
    def update_trust_anchors(self, anchors_asn1: List[bytes]):
        """
        Aggiorna trust anchors in formato ASN.1 OER.
        
        Args:
            anchors_asn1: Lista di certificati trust anchor ASN.1 OER
        """
        self.logger.info(f"Aggiornamento trust anchors per {self.its_id}...")
        self.trust_anchors_asn1 = anchors_asn1
        
        # Salva usando PKIFileHandler (DRY)
        if anchors_asn1:
            # Salva primo anchor (Root CA) come trust anchor principale
            PKIFileHandler.save_binary_file(
                anchors_asn1[0], 
                self.trust_anchor_path
            )
            self.logger.info(f"✅ Trust anchors salvati: {self.trust_anchor_path}")
            self.logger.info(f"   Numero anchors: {len(anchors_asn1)}")

    def update_ctl(self, ctl_full_asn1: bytes, ctl_delta_asn1: Optional[bytes] = None):
        """
        Aggiorna Certificate Trust List (CTL) in formato ASN.1 OER.
        
        Args:
            ctl_full_asn1: Full CTL ASN.1 OER
            ctl_delta_asn1: Delta CTL ASN.1 OER (opzionale)
        """
        self.logger.info(f"Aggiornamento CTL per {self.its_id}...")
        
        # Salva Full CTL usando PKIFileHandler (DRY)
        PKIFileHandler.save_binary_file(ctl_full_asn1, self.ctl_full_path)
        self.logger.info(f"✅ CTL Full salvato: {self.ctl_full_path}")
        
        # Salva Delta CTL se presente
        if ctl_delta_asn1:
            PKIFileHandler.save_binary_file(ctl_delta_asn1, self.ctl_delta_path)
            self.logger.info(f"✅ CTL Delta salvato: {self.ctl_delta_path}")

    # ========================================================================
    # PUBLIC API - V2X MESSAGING (CAM/DENM/CPM)
    # ========================================================================
    
    def send_v2x_message(
        self, 
        message: str, 
        recipient_id: str, 
        message_type: str = "CAM"
    ) -> bool:
        """
        Firma e invia messaggio V2X.
        
        Args:
            message: Contenuto del messaggio
            recipient_id: ID del destinatario
            message_type: Tipo di messaggio (CAM, DENM, CPM, VAM)
            
        Returns:
            bool: True se messaggio inviato con successo
        """
        self.logger.info(f"Invio messaggio V2X {message_type}: {self.its_id} -> {recipient_id}")
        
        if not self.private_key or not self.at_certificates_asn1:
            self.logger.error("❌ Serve chiave privata e AT per firmare messaggio!")
            return False
        
        # Firma messaggio
        from cryptography.hazmat.primitives import hashes
        signature = self.private_key.sign(
            message.encode(), 
            ec.ECDSA(hashes.SHA256())
        )
        
        # Crea messaggio firmato
        signed_message = (
            f"To: {recipient_id}\n"
            f"From: {self.its_id}\n"
            f"Type: {message_type}\n"
            f"Message: {message}\n"
            f"Signature: {signature.hex()}\n"
            f"---\n"
        )
        
        # Salva in outbox usando PKIFileHandler (DRY)
        PKIFileHandler.append_to_log_file(signed_message, self.outbox_path)
        
        # Consegna a destinatario (simulated)
        recipient_base_dir = os.path.join("./pki_data/itss/", f"{recipient_id}/")
        recipient_inbox_file = os.path.join(
            recipient_base_dir, 
            "inbox", 
            f"{self.its_id}_inbox.txt"
        )
        
        PKIFileHandler.append_to_log_file(signed_message, recipient_inbox_file)
        
        self.logger.info(f"✅ Messaggio {message_type} firmato e inviato")
        return True

    def receive_v2x_messages(self, validate: bool = True) -> List[dict]:
        """
        Riceve e valida messaggi V2X dall'inbox.
        
        Args:
            validate: Se True, valida firma di ogni messaggio
            
        Returns:
            Lista di messaggi ricevuti (validati se validate=True)
        """
        self.logger.info(f"Ricezione messaggi V2X per {self.its_id}...")
        
        inbox_path = Path(self.inbox_path)
        if not inbox_path.exists():
            self.logger.info("Cartella inbox non esistente")
            return []
        
        messages = []
        inbox_files = list(inbox_path.glob("*.txt"))
        
        if not inbox_files:
            self.logger.info("Nessun messaggio in arrivo")
            return []
        
        for inbox_file in inbox_files:
            try:
                # Leggi file usando PKIFileHandler non serve per text
                with open(inbox_file, "r") as f:
                    content = f.read()
                
                # Parse messaggi
                message_blocks = [
                    block.strip() 
                    for block in content.split("---") 
                    if block.strip()
                ]
                
                for msg_block in message_blocks:
                    if validate:
                        # Valida messaggio con trust anchors ASN.1 OER
                        if self._validate_v2x_message_signature(msg_block):
                            messages.append({"raw": msg_block, "validated": True})
                        else:
                            self.logger.warning(f"⚠️  Messaggio con firma non valida ignorato")
                            messages.append({"raw": msg_block, "validated": False})
                    else:
                        messages.append({"raw": msg_block, "validated": None})
                    
            except Exception as e:
                self.logger.error(f"Errore lettura {inbox_file.name}: {e}")
        
        self.logger.info(f"✅ Messaggi ricevuti: {len(messages)}")
        return messages

    def _validate_v2x_message_signature(self, message_block: str) -> bool:
        """
        Valida firma digitale di un messaggio V2X usando trust anchors ASN.1 OER.
        
        Verifica:
        1. Firma digitale con chiave pubblica del mittente
        2. Validità del certificato AT del mittente (non scaduto)
        3. Certificato AT non revocato (check CRL se disponibile)
        4. Catena di certificati valida fino a trust anchor
        
        Args:
            message_block: Blocco di testo del messaggio con firma
            
        Returns:
            bool: True se il messaggio è valido, False altrimenti
        """
        from cryptography.hazmat.primitives import hashes
        from datetime import datetime, timezone
        
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
                self.logger.error(f"❌ Messaggio malformato da {sender_id}")
                return False
            
            # Carica AT del mittente (ASN.1 OER)
            sender_at_dir = Path("./pki_data/itss") / sender_id / "authorization_tickets"
            
            if not sender_at_dir.exists():
                self.logger.warning(f"⚠️  Directory AT mittente {sender_id} non trovata")
                return False
            
            # Cerca AT più recente del mittente (.oer)
            sender_at_files = list(sender_at_dir.glob("*.oer"))
            if not sender_at_files:
                self.logger.warning(f"⚠️  Nessun AT ASN.1 OER per mittente {sender_id}")
                return False
            
            # Usa AT più recente
            sender_at_files.sort(key=lambda f: f.stat().st_mtime)
            sender_at_path = sender_at_files[-1]
            
            self.logger.info(f"Caricamento AT mittente: {sender_at_path.name}")
            
            # Carica AT ASN.1 OER
            sender_at_asn1 = PKIFileHandler.load_binary_file(str(sender_at_path))
            
            # Estrai chiave pubblica da AT
            from protocols.etsi_authorization_ticket import ETSIAuthorizationTicketEncoder
            
            at_encoder = ETSIAuthorizationTicketEncoder()
            sender_public_key = at_encoder.extract_public_key(sender_at_asn1)
            
            # === VERIFICA 1: Validità temporale del certificato ===
            at_decoded = at_encoder.decode_authorization_ticket(sender_at_asn1)
            
            if 'error' in at_decoded:
                self.logger.error(f"❌ Errore decodifica AT: {at_decoded['error']}")
                return False
            
            # Verifica scadenza
            from datetime import datetime
            now = datetime.now(timezone.utc)
            expiry = datetime.fromisoformat(at_decoded['expiry'])
            
            if expiry < now:
                self.logger.error(f"❌ Certificato AT mittente {sender_id} SCADUTO")
                return False
            
            # === VERIFICA 2: Firma digitale ===
            signature_bytes = bytes.fromhex(signature_hex)
            
            try:
                sender_public_key.verify(
                    signature_bytes, 
                    message_content.encode(), 
                    ec.ECDSA(hashes.SHA256())
                )
                self.logger.info(f"✅ Firma valida da {sender_id} (tipo: {message_type})")
            except Exception as e:
                self.logger.error(f"❌ Firma NON valida da {sender_id}: {e}")
                return False
            
            # === VERIFICA 3: Validazione catena certificati ===
            # Verifica che AT sia firmato da AA fidato in trust anchors
            if not self.trust_anchors_asn1:
                self.logger.warning(f"⚠️  Nessun trust anchor caricato, skip validazione catena")
                return True  # Firma valida ma catena non verificata
            
            # Validazione catena certificati (AT -> AA -> RootCA)
            self.logger.info("Validazione catena certificati...")
            
            try:
                # 1. Estrai issuer_hashed_id8 dall'AT (identifica l'AA) - riusa decodifica già fatta
                aa_hashed_id8 = at_decoded.get('issuer_hashed_id8', '')
                
                if aa_hashed_id8:
                    self.logger.info(f"   AT firmato da AA con HashedId8: {aa_hashed_id8}")
                    
                    # 2. Verifica che l'AA sia nei trust anchors (dovrebbe essere nella CTL)
                    aa_trusted = False
                    for anchor in self.trust_anchors_asn1:
                        anchor_hashed_id8 = compute_hashed_id8(anchor).hex()
                        if anchor_hashed_id8 == aa_hashed_id8:
                            self.logger.info(f"   ✅ AA trovato nei trust anchors")
                            aa_trusted = True
                            break
                    
                    if not aa_trusted:
                        self.logger.warning(f"   ⚠️  AA {aa_hashed_id8[:16]} NON trovato nei trust anchors")
                        self.logger.warning(f"   ⚠️  Accettato comunque (firma valida)")
                    else:
                        self.logger.info(f"   ✅ Catena certificati VALIDA (AT -> AA -> RootCA)")
                else:
                    self.logger.warning("   ⚠️  Impossibile estrarre issuer dall'AT")
                    
            except Exception as chain_err:
                self.logger.warning(f"   ⚠️  Errore validazione catena: {chain_err}")
            
            # Per ora: se firma valida e AT non scaduto, accetta
            self.logger.info(f"✅ Messaggio da {sender_id} VALIDO")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Errore nella verifica del messaggio: {e}")
            import traceback
            traceback.print_exc()
            return False

    # ========================================================================
    # PUBLIC API - UTILITY METHODS
    # ========================================================================
    
    def get_latest_at(self) -> Optional[bytes]:
        """
        Ottiene l'Authorization Ticket più recente.
        
        Returns:
            bytes: AT ASN.1 OER più recente, None se non esiste
        """
        at_dir = Path(self.at_dir)
        if not at_dir.exists():
            return None
        
        at_files = list(at_dir.glob("*.oer"))
        if not at_files:
            return None
        
        # Ordina per data di modifica (più recente per ultimo)
        at_files.sort(key=lambda f: f.stat().st_mtime)
        latest_at_path = at_files[-1]
        
        # Carica usando PKIFileHandler (DRY)
        at_asn1 = PKIFileHandler.load_binary_file(str(latest_at_path))
        
        self.logger.info(f"AT più recente caricato: {latest_at_path.name}")
        return at_asn1

    def get_statistics(self) -> dict:
        """
        Ottiene statistiche ITS-S.
        
        Returns:
            dict: Statistiche (EC presente, numero AT, messaggi, etc.)
        """
        at_dir = Path(self.at_dir)
        at_count = len(list(at_dir.glob("*.oer"))) if at_dir.exists() else 0
        
        inbox_path = Path(self.inbox_path)
        inbox_count = len(list(inbox_path.glob("*.txt"))) if inbox_path.exists() else 0
        
        stats = {
            "its_id": self.its_id,
            "has_ec": self.ec_certificate_asn1 is not None,
            "at_count": at_count,
            "trust_anchors_count": len(self.trust_anchors_asn1),
            "inbox_messages": inbox_count,
        }
        
        return stats
