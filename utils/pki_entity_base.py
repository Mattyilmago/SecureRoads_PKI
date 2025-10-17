"""
PKI Entity Base Class with Template Method Pattern.

Provides common functionality for RootCA, EnrollmentAuthority, and AuthorizationAuthority
including directory management, logging, file I/O, and certificate validation.

IMPORTANT: ETSI TS 102941 Certificate Encoding
----------------------------------------------
This base class supports BOTH X.509 (for infrastructure certificates) and ASN.1 OER 
(for end-entity certificates):

- Root CA, EA, AA certificates: X.509 format (RFC 5280)
- Enrollment Certificates (EC), Authorization Tickets (AT): ASN.1 OER (ETSI TS 103097)

The X.509 support is maintained for backward compatibility with traditional PKI infrastructure.
All V2X end-entity certificates use ASN.1 OER encoding as per ETSI standards.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, List
import logging

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography import x509

from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler
from utils.certificate_validator import CertificateValidator


class PKIEntityBase(ABC):
    """
    Abstract base class for PKI entities (RootCA, EA, AA).

    Provides common functionality:
    - Directory management
    - Centralized logging
    - File I/O for keys and certificates
    - Certificate validation
    - Template method initialization workflow
    """

    def __init__(self, base_dir: str, entity_id: str, log_level: int = logging.INFO):
        """
        Initializes PKI entity with template method pattern.

        Args:
            base_dir: Base directory for entity data
            entity_id: Unique identifier
            log_level: Logging level (default: INFO)
        """
        self.base_dir = Path(base_dir)
        self.entity_id = entity_id

        log_dir = self.base_dir / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        self.logger = PKILogger.get_logger(entity_id, log_dir=str(log_dir), level=log_level)
        self.file_handler = PKIFileHandler()
        self.validator = CertificateValidator()

        self.logger.info(f"═══ Initializing {self.entity_id} ═══")

        try:
            self.setup_directories()
            self.initialize()
            self.logger.info(f"✓ {self.entity_id} initialization complete!")
        except Exception as e:
            self.logger.error(f"✗ Initialization error: {e}", exc_info=True)
            raise

    @abstractmethod
    def setup_directories(self):
        """Sets up required directory structure. Must be implemented by subclasses."""
        pass

    @abstractmethod
    def initialize(self):
        """Initializes entity-specific components. Must be implemented by subclasses."""
        pass

    # ═══════════════════════════════════════════════════════════
    # DIRECTORY MANAGEMENT
    # ═══════════════════════════════════════════════════════════

    def create_directory(self, path: Path):
        """Creates directory if it doesn't exist."""
        try:
            path.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Directory OK: {path}")
        except Exception as e:
            self.logger.error(f"Directory creation error {path}: {e}")
            raise

    # ═══════════════════════════════════════════════════════════
    # PRIVATE KEY OPERATIONS
    # ═══════════════════════════════════════════════════════════

    def load_private_key(self, key_path: Path) -> ec.EllipticCurvePrivateKey:
        """Loads private key from PEM file."""
        self.logger.debug(f"Loading private key: {key_path}")

        try:
            private_key = self.file_handler.load_private_key(key_path)
            self.logger.info("✓ Private key loaded")
            return private_key
        except FileNotFoundError:
            self.logger.error(f"✗ Key file not found: {key_path}")
            raise
        except Exception as e:
            self.logger.error(f"✗ Key loading error: {e}")
            raise

    def save_private_key(self, private_key: ec.EllipticCurvePrivateKey, key_path: Path):
        """Saves private key to PEM file."""
        self.logger.debug(f"Saving private key: {key_path}")

        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            self.file_handler.save_private_key(private_key, key_path)
            self.logger.info("✓ Private key saved")
        except Exception as e:
            self.logger.error(f"✗ Key saving error: {e}")
            raise

    # ═══════════════════════════════════════════════════════════
    # CERTIFICATE OPERATIONS
    # ═══════════════════════════════════════════════════════════

    def load_certificate(self, cert_path: Path) -> x509.Certificate:
        """Loads certificate from PEM file."""
        self.logger.debug(f"Loading certificate: {cert_path}")

        try:
            certificate = self.file_handler.load_certificate(cert_path)
            subject = certificate.subject.rfc4514_string()
            serial = certificate.serial_number
            self.logger.info(f"✓ Certificate loaded")
            self.logger.debug(f"  Subject: {subject}")
            self.logger.debug(f"  Serial: {serial}")
            return certificate
        except FileNotFoundError:
            self.logger.error(f"✗ Certificate file not found: {cert_path}")
            raise
        except Exception as e:
            self.logger.error(f"✗ Certificate loading error: {e}")
            raise

    def save_certificate(self, certificate: x509.Certificate, cert_path: Path):
        """Saves certificate to PEM file."""
        self.logger.debug(f"Saving certificate: {cert_path}")

        try:
            cert_path.parent.mkdir(parents=True, exist_ok=True)
            self.file_handler.save_certificate(certificate, cert_path)
            subject = certificate.subject.rfc4514_string()
            self.logger.info(f"✓ Certificate saved: {subject}")
        except Exception as e:
            self.logger.error(f"✗ Certificate saving error: {e}")
            raise

    # ═══════════════════════════════════════════════════════════
    # CERTIFICATE VALIDATION
    # ═══════════════════════════════════════════════════════════

    def validate_certificate(
        self,
        certificate: x509.Certificate,
        issuer_cert: Optional[x509.Certificate] = None,
        trusted_certs: Optional[List[x509.Certificate]] = None,
    ) -> tuple[bool, str]:
        """
        Validates certificate using CertificateValidator.

        Args:
            certificate: Certificate to validate
            issuer_cert: Issuer certificate for signature verification (optional)
            trusted_certs: List of trusted certificates for chain validation (optional)

        Returns:
            Tuple (valid: bool, message: str)
        """
        subject = certificate.subject.rfc4514_string()
        self.logger.debug(f"Validating certificate: {subject}")

        is_valid = self.validator.validate(
            certificate, issuer_cert=issuer_cert, trusted_certs=trusted_certs
        )

        if is_valid:
            msg = "Certificate valid"
            self.logger.info(f"✓ {msg}")
            return True, msg
        else:
            msg = "Certificate invalid"
            self.logger.warning(f"✗ {msg}")
            return False, msg

    # ═══════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ═══════════════════════════════════════════════════════════

    def file_exists(self, path: Path) -> bool:
        """Checks if file exists."""
        exists = path.exists() and path.is_file()
        if exists:
            self.logger.debug(f"File found: {path}")
        else:
            self.logger.debug(f"File not found: {path}")
        return exists
