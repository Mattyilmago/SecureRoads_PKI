import json
import struct
import shutil
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from utils.logger import PKILogger
from utils.pki_io import PKIFileHandler
from utils.pki_paths import EntityPaths
from protocols.core import compute_hashed_id8, time32_encode


class CRLReason(IntEnum):
    """ETSI TS 102941 CRL Reason Codes"""
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    SUPERSEDED = 3
    CESSATION_OF_OPERATION = 4


class CRLManager:
    """
    ETSI-compliant CRL Manager using ASN.1 asn format.
    
    Manages Certificate Revocation Lists according to ETSI TS 102941 V2.1.1.
    Uses HashedId8 identifiers instead of X.509 serial numbers.
    
    Standards:
    - ETSI TS 102941 V2.1.1 Section 6.6: CRL Messages
    - ETSI TS 103097 V2.1.1: Certificate Formats (ASN.1 asn)
    """
    
    ETSI_EPOCH = datetime(2004, 1, 1, tzinfo=timezone.utc)

    def __init__(
        self,
        authority_id: str,
        paths: EntityPaths,
        issuer_certificate_asn: bytes,
        issuer_private_key
    ):
        """
        Initialize ETSI CRL Manager.
        
        Args:
            authority_id: Authority identifier (EA_001, AA_001, etc.)
            paths: EntityPaths object from PathManager
            issuer_certificate_asn: Issuer certificate in ASN.1 asn format (bytes)
            issuer_private_key: ECC private key for signing CRL
        """
        self.authority_id = authority_id
        self.issuer_certificate_asn = issuer_certificate_asn
        self.issuer_private_key = issuer_private_key
        
        self.issuer_hashed_id8 = compute_hashed_id8(issuer_certificate_asn)

        # Use EntityPaths (PathManager delegation)
        self.crl_dir = paths.crl_dir
        self.log_dir = paths.logs_dir
        self.backup_dir = paths.backup_dir
        
        # CRL subdirectories
        self.full_crl_dir = self.crl_dir / "full"
        self.delta_crl_dir = self.crl_dir / "delta"
        self.full_crl_path = self.full_crl_dir / "full_crl.oer"
        self.delta_crl_path = self.delta_crl_dir / "delta_crl.oer"
        self.metadata_path = self.crl_dir / "crl_metadata.json"
        
        self.logger = PKILogger.get_logger(
            name=f"CRLManager_{authority_id}",
            log_dir=str(self.log_dir),  # PKILogger needs string
            console_output=True
        )

        PKIFileHandler.ensure_directories(
            str(self.crl_dir),
            str(self.full_crl_dir),
            str(self.delta_crl_dir),
            str(self.log_dir),
            str(self.backup_dir),
        )

        self.revoked_certificates = []
        self.crl_number = 0
        self.base_crl_number = 0
        self.last_full_crl_time = None
        self.delta_revocations = []

        self.load_metadata()
        self.load_full_crl_metadata()
        
        if not self.metadata_path.exists():
            self.logger.info(f"First initialization: creating metadata")
            self.save_metadata()

        self.logger.info(f"ETSI CRL Manager initialized for {authority_id}")
        self.logger.info(f"  Issuer HashedId8: {self.issuer_hashed_id8.hex()[:16]}...")
        self.logger.info(f"  CRL Number: {self.crl_number}")
        self.logger.info(f"  Format: ASN.1 asn (ETSI TS 102941)")

    def add_revoked_certificate(self, certificate_asn: bytes, reason: CRLReason = CRLReason.UNSPECIFIED, expiry_time: Optional[datetime] = None):
        """
        Add certificate to revocation list (ETSI-compliant).
        
        Args:
            certificate_asn: Certificate in ASN.1 asn format (bytes)
            reason: Revocation reason (CRLReason enum)
            expiry_time: Certificate expiry time (optional, for cleanup)
        """
        hashed_id8 = compute_hashed_id8(certificate_asn)
        hashed_id8_hex = hashed_id8.hex()
        revocation_date = datetime.now(timezone.utc)
        
        if expiry_time is None:
            expiry_time = datetime.now(timezone.utc) + timedelta(days=365)

        self.logger.info(f"Adding revoked certificate:")
        self.logger.info(f"  HashedId8: {hashed_id8_hex[:16]}...")
        self.logger.info(f"  Reason: {reason.name}")
        self.logger.info(f"  Expiry: {expiry_time}")

        for entry in self.revoked_certificates:
            if entry.get("hashed_id8") == hashed_id8_hex:
                self.logger.info(f"Certificate already in revocation list")
                return

        self.log_operation(
            "REVOKE_CERTIFICATE",
            {
                "hashed_id8": hashed_id8_hex,
                "reason": reason.name,
                "expiry_time": expiry_time.isoformat(),
            },
        )

        revoked_entry = {
            "hashed_id8": hashed_id8_hex,
            "revocation_date": revocation_date,
            "expiry_date": expiry_time,
            "reason": reason,
        }

        self.revoked_certificates.append(revoked_entry)
        self.delta_revocations.append(revoked_entry)

        self.logger.info(f"Certificate added. Total revoked: {len(self.revoked_certificates)}")
        self.logger.info(f"Delta pending: {len(self.delta_revocations)}")

    def revoke_by_hashed_id(self, hashed_id8: bytes, reason: CRLReason = CRLReason.UNSPECIFIED, expiry_time: Optional[datetime] = None):
        """
        Revoke certificate using HashedId8 directly.
        
        Args:
            hashed_id8: Certificate HashedId8 (8 bytes)
            reason: Revocation reason
            expiry_time: Certificate expiry time (optional)
        """
        if len(hashed_id8) != 8:
            raise ValueError(f"HashedId8 must be 8 bytes, got {len(hashed_id8)}")
        
        hashed_id8_hex = hashed_id8.hex()
        revocation_date = datetime.now(timezone.utc)
        
        if expiry_time is None:
            expiry_time = datetime.now(timezone.utc) + timedelta(days=365)

        self.logger.info(f"Adding revocation by HashedId8: {hashed_id8_hex[:16]}...")

        for entry in self.revoked_certificates:
            if entry.get("hashed_id8") == hashed_id8_hex:
                self.logger.info(f"HashedId8 already in revocation list")
                return

        self.log_operation(
            "REVOKE_BY_HASHED_ID",
            {
                "hashed_id8": hashed_id8_hex,
                "reason": reason.name,
            },
        )

        revoked_entry = {
            "hashed_id8": hashed_id8_hex,
            "revocation_date": revocation_date,
            "expiry_date": expiry_time,
            "reason": reason,
        }

        self.revoked_certificates.append(revoked_entry)
        self.delta_revocations.append(revoked_entry)

        self.logger.info(f"HashedId8 added. Total revoked: {len(self.revoked_certificates)}")

    def is_certificate_revoked(self, certificate_asn: bytes) -> bool:
        """
        Check if ETSI certificate is revoked.
        
        Args:
            certificate_asn: Certificate in ASN.1 OER format (bytes) - ETSI TS 103097
            
        Returns:
            bool: True if revoked
        """
        hashed_id8 = compute_hashed_id8(certificate_asn)
        hashed_id8_hex = hashed_id8.hex()
        
        for entry in self.revoked_certificates:
            if entry.get("hashed_id8") == hashed_id8_hex:
                return True
        
        return False

    def publish_full_crl(self, validity_days=7):
        """
        Generate and publish Full CRL in ASN.1 asn format (ETSI TS 102941).
        
        Args:
            validity_days: CRL validity in days
        """
        self.logger.info(f"=== GENERATING FULL CRL (ETSI ASN.1 asn) ===")

        self.crl_number += 1
        self.base_crl_number = self.crl_number
        self.last_full_crl_time = datetime.now(timezone.utc)

        self._cleanup_expired_certificates()

        self.logger.info(f"CRL Number: {self.crl_number}")
        self.logger.info(f"Revoked certificates: {len(self.revoked_certificates)}")

        now = datetime.now(timezone.utc)
        next_update = now + timedelta(days=validity_days)

        crl_asn = self._encode_crl_asn(
            crl_number=self.crl_number,
            this_update=now,
            next_update=next_update,
            entries=self.revoked_certificates,
            is_delta=False
        )

        PKIFileHandler.save_binary_file(crl_asn, str(self.full_crl_path))

        self.logger.info(f"Full CRL saved: {self.full_crl_path} ({len(crl_asn)} bytes)")

        self.save_full_crl_metadata(validity_days)
        self.delta_revocations = []
        self.save_metadata()

        self.log_operation(
            "PUBLISH_FULL_CRL",
            {
                "crl_number": self.crl_number,
                "revoked_count": len(self.revoked_certificates),
                "validity_days": validity_days,
                "size_bytes": len(crl_asn),
            },
        )
        self.backup_crl("full")

        self.logger.info(f"=== FULL CRL PUBLISHED ===")
        return self.full_crl_path

    def publish_delta_crl(self, validity_hours=24, skip_backup=False):
        """
        Generate and publish Delta CRL in ASN.1 asn format (ETSI TS 102941).
        
        Args:
            validity_hours: CRL validity in hours
            skip_backup: Skip backup for performance
        """
        self.logger.info(f"=== GENERATING DELTA CRL (ETSI ASN.1 asn) ===")

        if not self.delta_revocations:
            self.logger.info(f"No new revocations, Delta CRL not needed")
            return None

        self.crl_number += 1

        self.logger.info(f"CRL Number: {self.crl_number}")
        self.logger.info(f"Base CRL Number: {self.base_crl_number}")
        self.logger.info(f"New revocations: {len(self.delta_revocations)}")

        now = datetime.now(timezone.utc)
        next_update = now + timedelta(hours=validity_hours)

        crl_asn = self._encode_crl_asn(
            crl_number=self.crl_number,
            this_update=now,
            next_update=next_update,
            entries=self.delta_revocations,
            is_delta=True,
            base_crl_number=self.base_crl_number
        )

        PKIFileHandler.save_binary_file(crl_asn, str(self.delta_crl_path))

        self.logger.info(f"Delta CRL saved: {self.delta_crl_path} ({len(crl_asn)} bytes)")

        self.save_delta_crl_metadata(validity_hours / 24)
        self.save_metadata()

        self.log_operation(
            "PUBLISH_DELTA_CRL",
            {
                "crl_number": self.crl_number,
                "base_crl_number": self.base_crl_number,
                "delta_revocations_count": len(self.delta_revocations),
                "validity_hours": validity_hours,
                "size_bytes": len(crl_asn),
            },
        )
        
        if not skip_backup:
            self.backup_crl("delta")

        self.logger.info(f"=== DELTA CRL PUBLISHED ===")
        return crl_asn

    def _encode_crl_asn(self, crl_number: int, this_update: datetime, next_update: datetime, entries: list, is_delta: bool = False, base_crl_number: int = 0) -> bytes:
        """
        Encode CRL in ASN.1 asn format according to ETSI TS 102941.
        
        Structure:
            EtsiTs102941Crl ::= SEQUENCE {
                version         Uint8,
                thisUpdate      Time32,
                nextUpdate      Time32,
                crlNumber       Uint32,
                entries         SEQUENCE OF CrlEntry,
                signature       Signature
            }
            
            CrlEntry ::= SEQUENCE {
                id              HashedId8,
                revocationDate  Time32,
                reason          CrlReason
            }
        """
        to_be_signed = bytearray()
        
        to_be_signed.append(2)
        
        to_be_signed.extend(struct.pack('>I', time32_encode(this_update)))
        to_be_signed.extend(struct.pack('>I', time32_encode(next_update)))
        to_be_signed.extend(struct.pack('>I', crl_number))
        
        if is_delta:
            to_be_signed.append(1)
            to_be_signed.extend(struct.pack('>I', base_crl_number))
        else:
            to_be_signed.append(0)
        
        to_be_signed.extend(struct.pack('>H', len(entries)))
        
        for entry in entries:
            hashed_id8_hex = entry["hashed_id8"]
            hashed_id8_bytes = bytes.fromhex(hashed_id8_hex)
            to_be_signed.extend(hashed_id8_bytes)
            
            revocation_time32 = time32_encode(entry["revocation_date"])
            to_be_signed.extend(struct.pack('>I', revocation_time32))
            
            reason = entry["reason"]
            if isinstance(reason, CRLReason):
                to_be_signed.append(reason.value)
            else:
                to_be_signed.append(CRLReason.UNSPECIFIED.value)
        
        signature = self.issuer_private_key.sign(
            bytes(to_be_signed),
            ec.ECDSA(hashes.SHA256())
        )
        
        crl_complete = bytearray()
        crl_complete.extend(to_be_signed)
        crl_complete.extend(struct.pack('>H', len(signature)))
        crl_complete.extend(signature)
        
        return bytes(crl_complete)

    def _cleanup_expired_certificates(self):
        """Remove expired certificates from revocation list."""
        now = datetime.now(timezone.utc)
        old_count = len(self.revoked_certificates)

        filtered = []
        for entry in self.revoked_certificates:
            expiry_date = entry.get("expiry_date")
            if expiry_date:
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                if expiry_date > now:
                    filtered.append(entry)

        self.revoked_certificates = filtered

        removed = old_count - len(self.revoked_certificates)
        if removed > 0:
            self.logger.info(f"Cleanup: removed {removed} expired certificates")

    def load_full_crl(self):
        """Load Full CRL from file (ASN.1 asn format)."""
        if not self.full_crl_path.exists():
            self.logger.info(f"Full CRL not found")
            return None

        crl_asn = PKIFileHandler.load_binary_file(str(self.full_crl_path))
        if crl_asn:
            self.logger.info(f"Full CRL loaded: {len(crl_asn)} bytes")
        return crl_asn

    def load_delta_crl(self):
        """Load Delta CRL from file (ASN.1 asn format)."""
        if not self.delta_crl_path.exists():
            self.logger.info(f"Delta CRL not found")
            return None

        crl_asn = PKIFileHandler.load_binary_file(str(self.delta_crl_path))
        if crl_asn:
            self.logger.info(f"Delta CRL loaded: {len(crl_asn)} bytes")
        return crl_asn

    def save_metadata(self):
        """Save CRL metadata to JSON file."""
        metadata = {
            "authority_id": self.authority_id,
            "crl_number": self.crl_number,
            "base_crl_number": self.base_crl_number,
            "last_full_crl_time": (
                self.last_full_crl_time.isoformat() if self.last_full_crl_time else None
            ),
            "revoked_count": len(self.revoked_certificates),
            "delta_pending": len(self.delta_revocations),
            "format": "ASN.1 asn (ETSI TS 102941)",
        }

        try:
            PKIFileHandler.save_json_file(metadata, str(self.metadata_path))
        except Exception as e:
            self.logger.error(f"Error saving metadata: {e}")

    def load_metadata(self):
        """Load CRL metadata from JSON file."""
        if not self.metadata_path.exists():
            return

        try:
            metadata = PKIFileHandler.load_json_file(str(self.metadata_path))
            if not metadata:
                return

            self.crl_number = metadata.get("crl_number", 0)
            self.base_crl_number = metadata.get("base_crl_number", 0)

            last_full = metadata.get("last_full_crl_time")
            if last_full:
                self.last_full_crl_time = datetime.fromisoformat(last_full)

            self.logger.info(f"Metadata loaded successfully")

        except Exception as e:
            self.logger.error(f"Error loading metadata: {e}")

    def get_statistics(self):
        """Get CRL Manager statistics."""
        return {
            "authority_id": self.authority_id,
            "crl_number": self.crl_number,
            "base_crl_number": self.base_crl_number,
            "total_revoked": len(self.revoked_certificates),
            "delta_pending": len(self.delta_revocations),
            "last_full_crl": (
                self.last_full_crl_time.isoformat() if self.last_full_crl_time else None
            ),
            "format": "ASN.1 asn",
        }

    def save_full_crl_metadata(self, validity_days=7):
        """Save Full CRL metadata with revocation list."""
        metadata = {
            "version": "2.0-ETSI",
            "format": "ASN.1 asn",
            "crl_number": self.crl_number,
            "authority_id": self.authority_id,
            "issuer_hashed_id8": self.issuer_hashed_id8.hex(),
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "next_update": (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat(),
            "revoked_certificates": [],
        }

        for entry in self.revoked_certificates:
            metadata["revoked_certificates"].append(
                {
                    "hashed_id8": entry["hashed_id8"],
                    "revocation_date": entry["revocation_date"].isoformat(),
                    "reason": (
                        entry["reason"].name
                        if isinstance(entry["reason"], CRLReason)
                        else str(entry["reason"])
                    ),
                    "expiry_date": entry["expiry_date"].isoformat(),
                }
            )

        full_metadata_path = str(self.full_crl_path).replace(".oer", "_metadata.json")
        try:
            PKIFileHandler.save_json_file(metadata, full_metadata_path)
        except Exception as e:
            self.logger.error(f"Error saving full CRL metadata: {e}")

    def save_delta_crl_metadata(self, validity_days=1):
        """Save Delta CRL metadata with new revocations."""
        metadata = {
            "version": "2.0-ETSI",
            "format": "ASN.1 asn",
            "crl_number": self.crl_number,
            "base_crl_number": self.base_crl_number,
            "authority_id": self.authority_id,
            "issuer_hashed_id8": self.issuer_hashed_id8.hex(),
            "issue_date": datetime.now(timezone.utc).isoformat(),
            "next_update": (datetime.now(timezone.utc) + timedelta(days=validity_days)).isoformat(),
            "new_revocations": [],
        }

        for entry in self.delta_revocations:
            metadata["new_revocations"].append(
                {
                    "hashed_id8": entry["hashed_id8"],
                    "revocation_date": entry["revocation_date"].isoformat(),
                    "reason": (
                        entry["reason"].name
                        if isinstance(entry["reason"], CRLReason)
                        else str(entry["reason"])
                    ),
                    "expiry_date": entry["expiry_date"].isoformat(),
                }
            )

        delta_metadata_path = str(self.delta_crl_path).replace(".oer", "_metadata.json")
        try:
            PKIFileHandler.save_json_file(metadata, delta_metadata_path)
        except Exception as e:
            self.logger.error(f"Error saving delta CRL metadata: {e}")

    def load_full_crl_metadata(self):
        """Load Full CRL metadata and rebuild revocation list."""
        full_metadata_path = str(self.full_crl_path).replace(".oer", "_metadata.json")

        if not Path(full_metadata_path).exists():
            return

        try:
            metadata = PKIFileHandler.load_json_file(full_metadata_path)
            if not metadata:
                return

            self.revoked_certificates = []
            for entry in metadata.get("revoked_certificates", []):
                reason_str = entry["reason"]
                reason = getattr(CRLReason, reason_str, CRLReason.UNSPECIFIED)

                self.revoked_certificates.append(
                    {
                        "hashed_id8": entry["hashed_id8"],
                        "revocation_date": datetime.fromisoformat(entry["revocation_date"]),
                        "reason": reason,
                        "expiry_date": datetime.fromisoformat(entry["expiry_date"]),
                    }
                )

            self.logger.info(
                f"Full CRL metadata loaded: {len(self.revoked_certificates)} certificates"
            )

        except Exception as e:
            self.logger.error(f"Error loading Full CRL metadata: {e}")

    def log_operation(self, operation, details):
        """Log CRL operations for audit trail."""
        timestamp = datetime.now(timezone.utc).isoformat()
        log_file = self.log_dir / f"{self.authority_id}_crl_audit.log"

        log_entry = {
            "timestamp": timestamp,
            "authority_id": self.authority_id,
            "operation": operation,
            "crl_number": self.crl_number,
            "format": "ASN.1 asn",
            "details": details,
        }

        try:
            PKIFileHandler.append_to_log_file(json.dumps(log_entry), str(log_file))
        except Exception as e:
            self.logger.error(f"Error logging: {e}")

    def backup_crl(self, crl_type="full"):
        """Create CRL backup for disaster recovery."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if crl_type == "full":
            source = self.full_crl_path
            backup_name = f"full_crl_backup_{timestamp}.oer"
        else:
            source = self.delta_crl_path
            backup_name = f"delta_crl_backup_{timestamp}.oer"

        backup_path = self.backup_dir / backup_name

        try:
            if source.exists():
                PKIFileHandler.copy_file(str(source), str(backup_path))
                self.logger.info(f"Backup created: {backup_path}")
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
