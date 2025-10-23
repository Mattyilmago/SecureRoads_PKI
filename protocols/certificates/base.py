"""
Base Certificate Encoder

Provides abstract base class with common functionality for all ETSI certificate
encoders. Eliminates code duplication across certificate types (DRY principle).

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats

Author: SecureRoad PKI Project
Date: October 2025
"""

import struct
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# Import from core module (centralized utilities)
from protocols.core import (
    time32_encode,
    time32_decode,
    compute_hashed_id8,
    encode_public_key_compressed,
    sign_data_ecdsa_sha256,
)


class BaseCertificate(ABC):
    """
    Abstract base class for all ETSI certificate encoders.
    
    Provides common functionality:
    - Time32 encoding/decoding
    - HashedId8 computation
    - Public key compression
    - ECDSA signature generation
    - Validity period encoding
    
    Subclasses must implement:
    - encode_to_be_signed(): Certificate-specific TBS encoding
    - encode_full_certificate(): Complete certificate with signature
    """
    
    # Class constants (to be overridden by subclasses)
    CERT_TYPE: int = -1  # Certificate type identifier
    CERT_NAME: str = "Unknown"  # Human-readable name
    
    def __init__(self):
        """Initialize base certificate encoder"""
        if self.CERT_TYPE == -1:
            raise NotImplementedError(
                f"{self.__class__.__name__} must define CERT_TYPE class constant"
            )
    
    # ========================================================================
    # DELEGATED UTILITY METHODS (from core module)
    # ========================================================================
    
    @staticmethod
    def time32_encode(dt: datetime) -> int:
        """Encode datetime to Time32 format"""
        return time32_encode(dt)
    
    @staticmethod
    def time32_decode(time32: int) -> datetime:
        """Decode Time32 to datetime"""
        return time32_decode(time32)
    
    @staticmethod
    def compute_hashed_id8(cert_bytes: bytes) -> bytes:
        """Compute HashedId8 certificate identifier"""
        return compute_hashed_id8(cert_bytes)
    
    @staticmethod
    def encode_public_key(public_key: EllipticCurvePublicKey) -> bytes:
        """Encode public key in compressed format"""
        return encode_public_key_compressed(public_key)
    
    @staticmethod
    def sign_tbs(tbs_data: bytes, private_key: EllipticCurvePrivateKey) -> bytes:
        """Sign ToBeSignedCertificate with ECDSA-SHA256"""
        return sign_data_ecdsa_sha256(tbs_data, private_key)
    
    # ========================================================================
    # COMMON ENCODING METHODS
    # ========================================================================
    
    def encode_validity_period(
        self,
        start_validity: datetime,
        duration_seconds: int
    ) -> bytes:
        """
        Encode ValidityPeriod (start_time32 + Duration CHOICE).
        
        ETSI TS 103097 Section 6.4.6:
        ValidityPeriod ::= SEQUENCE {
            start Time32,      -- 4 bytes
            duration Duration  -- CHOICE with OER tag + Uint16
        }
        
        IEEE 1609.2 Duration CHOICE tags:
        - 0x82 = seconds (Uint16)
        - 0x84 = hours (Uint16)
        - 0x86 = years (Uint16)
        
        Args:
            start_validity: Certificate start time
            duration_seconds: Validity duration in seconds
            
        Returns:
            bytes: Encoded validity period (start + tag + duration)
        """
        start_time32 = self.time32_encode(start_validity)
        result = bytearray(struct.pack('>I', start_time32))
        
        # Encode Duration as CHOICE
        if duration_seconds <= 65535:
            # Use seconds (tag 0x82)
            result.append(0x82)
            result.extend(struct.pack('>H', duration_seconds))
        else:
            # Use hours (tag 0x84)
            duration_hours = (duration_seconds + 3599) // 3600  # Round up
            result.append(0x84)
            result.extend(struct.pack('>H', min(duration_hours, 65535)))
        
        return bytes(result)
    
    def encode_issuer_identifier(
        self,
        issuer_hashed_id8: Optional[bytes] = None
    ) -> bytes:
        """
        Encode IssuerIdentifier.
        
        ETSI TS 103097 Section 6.4.3:
        IssuerIdentifier ::= CHOICE {
            sha256AndDigest HashedId8,  -- 0x00 + 8 bytes
            self NULL,                  -- 0x01 (for self-signed)
            ...
        }
        
        Args:
            issuer_hashed_id8: HashedId8 of issuer (None = self-signed)
            
        Returns:
            bytes: Encoded issuer identifier (1 or 9 bytes)
        """
        if issuer_hashed_id8 is None:
            # Self-signed (Root CA)
            return b'\x01'
        else:
            # HashedId8 reference
            if len(issuer_hashed_id8) != 8:
                raise ValueError(f"issuer_hashed_id8 must be 8 bytes, got {len(issuer_hashed_id8)}")
            return b'\x00' + issuer_hashed_id8
    
    def encode_signature_with_type(self, signature: bytes) -> bytes:
        """
        Encode signature with algorithm type prefix.
        
        ETSI TS 103097 Section 5.3.1:
        Signature ::= CHOICE {
            ecdsaNistP256Signature ...,  -- 0x00
            ecdsaBrainpoolP256r1Signature ...,  -- 0x01
            ...
        }
        
        Args:
            signature: Raw ECDSA signature (64 bytes: r || s)
            
        Returns:
            bytes: Type prefix + signature (65 bytes)
        """
        if len(signature) != 64:
            raise ValueError(f"Signature must be 64 bytes, got {len(signature)}")
        
        # 0x00 = ecdsaNistP256Signature
        return b'\x00' + signature
    
    # ========================================================================
    # ABSTRACT METHODS (to be implemented by subclasses)
    # ========================================================================
    
    @abstractmethod
    def encode_to_be_signed(self, **kwargs) -> bytes:
        """
        Encode ToBeSignedCertificate.
        
        Must be implemented by subclasses with certificate-specific logic.
        
        Returns:
            bytes: Encoded TBS certificate
        """
        pass
    
    @abstractmethod
    def encode_full_certificate(self, **kwargs) -> bytes:
        """
        Encode complete signed certificate.
        
        Must be implemented by subclasses.
        
        Returns:
            bytes: Complete certificate with signature
        """
        pass
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _encode_certificate_wrapper(
        self,
        tbs_certificate: bytes,
        signature: bytes
    ) -> bytes:
        """
        Wrap TBS certificate and signature into complete certificate.
        
        Structure:
            [TBS_length(2)] [TBS_data] [Signature_type(1)] [Signature(64)]
        
        Args:
            tbs_certificate: ToBeSignedCertificate bytes
            signature: Raw ECDSA signature (64 bytes)
            
        Returns:
            bytes: Complete certificate
        """
        tbs_len = len(tbs_certificate)
        signature_with_type = self.encode_signature_with_type(signature)
        
        # Build certificate: TBS length + TBS + signature
        cert = bytearray()
        cert.extend(struct.pack('>H', tbs_len))  # 2 bytes TBS length
        cert.extend(tbs_certificate)
        cert.extend(signature_with_type)  # 1 byte type + 64 bytes signature
        
        return bytes(cert)
    
    def __repr__(self) -> str:
        """String representation"""
        return f"<{self.__class__.__name__} type={self.CERT_TYPE} name='{self.CERT_NAME}'>"
