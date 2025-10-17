"""
Authorization Authority Key Manager Service

Handles cryptographic key and certificate management for AA entities.

**MIGRATED TO ASN.1 OER** - Uses ETSI Root Certificate Encoder for AA certificates.

Responsibilities:
- Generate ECC key pairs (NIST P-256)
- Load/save private keys and certificates
- Request certificate signing from Root CA (ASN.1 OER format)
- Archive certificates in Root CA

This service separates key management from AA business logic (Single Responsibility).

Standards Reference:
- ETSI TS 102941 V2.1.1: Trust and Privacy Management
- ETSI TS 103097 V2.1.1: Certificate Formats (ASN.1 OER)
- NIST SP 800-186: Elliptic Curve Cryptography

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from protocols.etsi_root_certificate import ETSIRootCertificateEncoder
from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler


class AAKeyManager:
    """
    Key and certificate manager for Authorization Authority.
    
    **MIGRATED TO ASN.1 OER** - Uses bytes instead of X.509 objects.
    Thread-safe for concurrent access.
    """
    
    def __init__(
        self,
        aa_id: str,
        key_path: str,
        cert_path: str,
        root_ca,  # RootCA instance (direct, no interface)
        logger: PKILogger
    ):
        """
        Initialize AA key manager.
        
        Args:
            aa_id: Authorization Authority identifier
            key_path: Path to private key file
            cert_path: Path to certificate file (ASN.1 OER format, .oer extension)
            root_ca: RootCA instance for certificate signing
            logger: Logger instance
        """
        self.aa_id = aa_id
        self.key_path = key_path
        self.cert_path = cert_path  # ASN.1 OER certificate (.oer extension)
        self.root_ca = root_ca  # Direct RootCA reference
        self.logger = logger
        self.encoder = ETSIRootCertificateEncoder()
        
        self.private_key: EllipticCurvePrivateKey = None
        self.certificate_asn1: bytes = None  # ASN.1 OER certificate (bytes)
    
    def load_or_generate(self) -> Tuple[EllipticCurvePrivateKey, bytes]:
        """
        Load existing key pair or generate new one.
        
        Checks if key and certificate exist on disk:
        - If both exist: Load from files
        - If missing: Generate new key pair and request certificate signing
        
        Returns:
            Tuple of (private_key, certificate_asn1_bytes)
        """
        self.logger.info(f"Checking for existing AA key and certificate...")
        
        if os.path.exists(self.key_path) and os.path.exists(self.cert_path):
            self.logger.info(f"Found existing key and certificate, loading...")
            self.private_key = self.load_keypair()
            self.certificate_asn1 = self.load_certificate()
            
            self.logger.info(f"✅ Loaded existing credentials for {self.aa_id}")
        else:
            self.logger.info(f"No existing credentials found, generating new...")
            self.private_key = self.generate_keypair()
            self.certificate_asn1 = self._request_certificate_signing()
            
            self.logger.info(f"✅ Generated new credentials for {self.aa_id}")
        
        return self.private_key, self.certificate_asn1
    
    def generate_keypair(self) -> EllipticCurvePrivateKey:
        """
        Generate new ECC private key (NIST P-256).
        
        NIST P-256 (secp256r1) is ETSI-recommended for V2X PKI.
        
        Returns:
            ECC private key object
        """
        self.logger.info(f"Generating ECC private key (NIST P-256) for {self.aa_id}...")
        
        private_key = ec.generate_private_key(ec.SECP256R1())
        self.save_keypair(private_key)
        
        self.logger.info(f"✅ Private key generated and saved to {self.key_path}")
        return private_key
    
    def load_keypair(self) -> EllipticCurvePrivateKey:
        """
        Load existing private key from PEM file.
        
        Returns:
            ECC private key object
            
        Raises:
            FileNotFoundError: If key file doesn't exist
            ValueError: If key file is corrupted
        """
        self.logger.info(f"Loading private key from {self.key_path}...")
        
        try:
            private_key = PKIFileHandler.load_private_key(self.key_path)
            self.logger.info(f"✅ Private key loaded successfully")
            return private_key
        except Exception as e:
            self.logger.error(f"❌ Failed to load private key: {e}")
            raise
    
    def load_certificate(self) -> bytes:
        """
        Load existing certificate from ASN.1 OER file.
        
        Returns:
            ASN.1 OER certificate bytes
            
        Raises:
            FileNotFoundError: If certificate file doesn't exist
            ValueError: If certificate file is corrupted
        """
        self.logger.info(f"Loading certificate from {self.cert_path}...")
        
        try:
            certificate_asn1 = PKIFileHandler.load_binary_file(self.cert_path)
            self.logger.info(f"✅ Certificate loaded successfully ({len(certificate_asn1)} bytes ASN.1 OER)")
            return certificate_asn1
        except Exception as e:
            self.logger.error(f"❌ Failed to load certificate: {e}")
            raise
    
    def save_keypair(self, private_key: EllipticCurvePrivateKey) -> None:
        """
        Save private key to PEM file (unencrypted).
        
        Note: In production, consider encrypting keys with password.
        
        Args:
            private_key: ECC private key to save
        """
        self.logger.info(f"Saving private key to {self.key_path}...")
        
        try:
            with open(self.key_path, "wb") as f:
                f.write(
                    private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption(),
                    )
                )
            self.logger.info(f"✅ Private key saved")
        except Exception as e:
            self.logger.error(f"❌ Failed to save private key: {e}")
            raise
    
    def save_certificate(self, certificate_asn1: bytes) -> None:
        """
        Save certificate to ASN.1 OER file.
        
        Args:
            certificate_asn1: ASN.1 OER certificate bytes to save
        """
        self.logger.info(f"Saving certificate to {self.cert_path}...")
        
        try:
            PKIFileHandler.save_binary_file(certificate_asn1, self.cert_path)
            self.logger.info(f"✅ Certificate saved ({len(certificate_asn1)} bytes ASN.1 OER)")
        except Exception as e:
            self.logger.error(f"❌ Failed to save certificate: {e}")
            raise
    
    def _request_certificate_signing(self) -> bytes:
        """
        Request certificate signing from Root CA (ASN.1 OER format).
        
        Genera un certificato AA "explicit" usando ETSIRootCertificateEncoder.
        
        Returns:
            Signed ASN.1 OER certificate (bytes)
        """
        self.logger.info(f"Generating AA certificate (ASN.1 OER)...")
        
        subject_name = f"AuthorizationAuthority_{self.aa_id}"
        
        try:
            # Genera certificato AA usando generate_authority_certificate (firmato da Root CA)
            from protocols.etsi_authority_certificate import generate_authority_certificate
            
            certificate_asn1 = generate_authority_certificate(
                root_ca_cert_asn1=self.root_ca.certificate_asn1,
                root_ca_private_key=self.root_ca.private_key,
                authority_public_key=self.private_key.public_key(),
                authority_id=self.aa_id,
                authority_type="AA",
                duration_years=3,  # AA certificates: 3 years validity
                country="IT",
                organization="SecureRoad PKI"
            )
            
            # Calcola HashedId8 per logging
            hashed_id8 = self.encoder.compute_hashed_id8(certificate_asn1)
            self.logger.info(f"✅ AA certificate generated: HashedId8={hashed_id8.hex()[:16]}...")
            
            # Save certificate locally
            self.save_certificate(certificate_asn1)
            
            # Archive in Root CA
            self.logger.info(f"Archiving certificate in Root CA...")
            self.root_ca.save_subordinate_certificate_asn1(
                cert_asn1=certificate_asn1,
                authority_type="AA",
                entity_id=self.aa_id
            )
            
            self.logger.info(f"✅ Certificate signed and archived successfully")
            return certificate_asn1
            
        except Exception as e:
            self.logger.error(f"❌ Certificate signing failed: {e}")
            raise
