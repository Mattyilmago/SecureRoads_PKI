"""
PKI Interfaces Package

**SIMPLIFIED** - Solo interfacce necessarie, senza duplicare classi esistenti.

RootCA, TLM, CRLManager GIÀ ESISTONO - non servono interfacce.
"""

from .pki_interfaces import EnrollmentCertificateValidator

__all__ = [
    "EnrollmentCertificateValidator",
]
