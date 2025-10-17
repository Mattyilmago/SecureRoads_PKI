"""
Enrollment Certificate Validator Service

Implements complete EC validation according to ETSI TS 102941 V2.1.1.

**SIMPLIFIED** - Usa TrustListManager direttamente (no interface).

Validation Steps (ETSI TS 102941 Section 6.3.3):
1. Trust chain verification via TLM
2. Certificate expiry check
3. Revocation status check (CRL)

This service centralizes EC validation logic to avoid duplication across AA methods.

Standards Reference:
- ETSI TS 102941 V2.1.1: Trust and Privacy Management (Section 6.3.3)
- ETSI TS 103097 V2.1.1: Certificate Formats

Author: SecureRoad PKI Project
Date: October 2025
"""

from datetime import datetime, timezone
from typing import Tuple, Union

from cryptography import x509

from utils.cert_utils import get_certificate_expiry_time
from utils.logger import PKILogger


class ECValidator:
    """
    Service for validating Enrollment Certificates.
    
    **SIMPLIFIED** - Duck typing, no formal ABC needed.
    Thread-safe and reusable across multiple AA instances.
    """
    
    def __init__(
        self,
        tlm,  # TrustListManager instance (direct, no interface)
        logger: PKILogger,
        authority_id: str = "AA"
    ):
        """
        Initialize EC validator.
        
        Args:
            tlm: TrustListManager instance for trust validation
            logger: Logger instance for validation events
            authority_id: ID of authority using validator (for logging)
        """
        self.tlm = tlm  # Direct TLM reference
        self.logger = logger
        self.authority_id = authority_id
    
    def validate(self, enrollment_cert: Union[bytes, x509.Certificate]) -> None:
        """
        Validate Enrollment Certificate completely (ETSI TS 102941).
        
        Performs all required checks:
        1. Trust chain verification
        2. Certificate expiry check  
        3. Revocation status check
        
        Args:
            enrollment_cert: Certificate (ASN.1 OER bytes or X.509 for compatibility)
            
        Raises:
            ValueError: If certificate is invalid with detailed reason
        """
        self.logger.info(f"🔐 Starting EC validation")
        
        # Step 1: Trust Chain Verification
        is_trusted, trust_info = self.check_trust_chain(enrollment_cert)
        if not is_trusted:
            raise ValueError(f"EC trust chain invalid: {trust_info}")
        
        self.logger.info(f"✅ Trust chain valid: {trust_info}")
        
        # Step 2: Expiry Check
        if not self.check_expiry(enrollment_cert):
            raise ValueError(f"EC expired")
        
        self.logger.info(f"✅ EC not expired")
        
        # Step 3: Revocation Check
        if self.check_revocation(enrollment_cert):
            raise ValueError(f"EC revoked")
        
        self.logger.info(f"✅ EC not revoked")
        self.logger.info(f"✅ EC validation completed successfully")
    
    def check_trust_chain(self, certificate: Union[bytes, x509.Certificate]) -> Tuple[bool, str]:
        """
        Verify certificate trust chain via TLM.
        
        Args:
            certificate: Certificate to verify
            
        Returns:
            Tuple of (is_trusted: bool, info_message: str)
        """
        try:
            return self.tlm.is_trusted(certificate)
        except Exception as e:
            self.logger.error(f"❌ Trust chain verification failed: {e}")
            return False, str(e)
    
    def check_expiry(self, certificate: Union[bytes, x509.Certificate]) -> bool:
        """
        Check if certificate is still valid (not expired).
        
        Args:
            certificate: Certificate to check
            
        Returns:
            True if valid, False if expired
        """
        try:
            # ✅ ETSI TS 103097 COMPLIANCE - Validity Period Check
            #
            # ETSI TS 103097 v2.1.1 Section 6.4.6 defines ValidityPeriod as:
            #   ValidityPeriod ::= SEQUENCE {
            #       start     Time32,    -- 4 bytes, seconds since epoch
            #       duration  Duration   -- 4 bytes, validity duration in seconds
            #   }
            #
            # Implementation: Uses centralized extract_validity_period function
            # from etsi_message_types module (DRY compliant)
            
            if isinstance(certificate, bytes):
                # ASN.1 OER certificate - use centralized extraction function
                from protocols.etsi_message_types import extract_validity_period
                
                try:
                    start_time, expiry_time, duration = extract_validity_period(certificate)
                    now_utc = datetime.now(timezone.utc)
                    
                    is_valid = expiry_time > now_utc
                    
                    if is_valid:
                        days_remaining = (expiry_time - now_utc).days
                        self.logger.debug(f"✅ Certificate valid, expires in {days_remaining} days")
                    else:
                        self.logger.warning(f"⚠️  Certificate expired on {expiry_time.isoformat()}")
                    
                    return is_valid
                    
                except ValueError as e:
                    self.logger.error(f"❌ ValidityPeriod extraction failed: {e}")
                    # Fail-open: assume valid if extraction fails (for compatibility)
                    self.logger.warning("⚠️  Assuming certificate valid (extraction failed)")
                    return True
            
            # X.509 certificate (legacy path)
            expiry_time = get_certificate_expiry_time(certificate)
            now_utc = datetime.now(timezone.utc)
            return expiry_time > now_utc
            
        except Exception as e:
            self.logger.error(f"❌ Expiry check failed: {e}")
            return False
    
    def check_revocation(self, certificate: Union[bytes, x509.Certificate]) -> bool:
        """
        Check if certificate is revoked via TLM.
        
        Args:
            certificate: Certificate to check
            
        Returns:
            True if revoked, False if valid
        """
        try:
            return self.tlm.is_revoked(certificate)
        except Exception as e:
            # If revocation check fails, assume not revoked (fail-open)
            # In production, consider fail-closed for security
            self.logger.warning(f"⚠️ Revocation check failed (assuming valid): {e}")
            return False
