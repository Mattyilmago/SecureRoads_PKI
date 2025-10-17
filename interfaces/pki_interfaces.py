"""
PKI Abstract Interfaces - ETSI ASN.1 OER Only

**SIMPLIFIED VERSION** - Elimina ridondanze con classi esistenti.

Le classi RootCA, TLM, CRLManager GIÀ ESISTONO e implementano queste funzionalità.
Queste interfacce servono SOLO per type hints e duck typing, NON per sostituire classi reali.

Design Pattern: Duck Typing (Python native) invece di ABC formale.

Author: SecureRoad PKI Project
Date: October 2025
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

# ETSI usa SOLO ASN.1 OER (bytes), NON X.509
CertificateType = bytes  # ASN.1 OER encoded certificate


class EnrollmentCertificateValidator(ABC):
    """
    Abstract interface for Enrollment Certificate validation.
    
    Implementations: ECValidator
    
    ETSI TS 102941 Section 6.3.3: AA must validate EC before issuing AT.
    
    **NOTE**: Usa ASN.1 OER (bytes) non X.509
    """
    
    @abstractmethod
    def validate(self, enrollment_cert: Union[CertificateType, Any]) -> None:
        """
        Validate Enrollment Certificate completely.
        
        Performs:
        1. Trust chain verification
        2. Expiry check
        3. Revocation status check
        
        Args:
            enrollment_cert: EC certificate (ASN.1 OER bytes or X.509 for compatibility)
            
        Raises:
            ValueError: If certificate is invalid with reason
        """
        pass
    
    @abstractmethod
    def check_trust_chain(self, certificate: Union[CertificateType, Any]) -> Tuple[bool, str]:
        """
        Verify certificate trust chain.
        
        Args:
            certificate: Certificate to verify
            
        Returns:
            Tuple of (is_trusted: bool, info: str)
        """
        pass
    
    @abstractmethod
    def check_expiry(self, certificate: Union[CertificateType, Any]) -> bool:
        """
        Check if certificate is expired.
        
        Args:
            certificate: Certificate to check
            
        Returns:
            True if valid (not expired), False if expired
        """
        pass
    
    @abstractmethod
    def check_revocation(self, certificate: Union[CertificateType, Any]) -> bool:
        """
        Check if certificate is revoked.
        
        Args:
            certificate: Certificate to check
            
        Returns:
            True if revoked, False if valid
        """
        pass
