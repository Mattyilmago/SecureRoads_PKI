"""
ETSI Security Operations

This module provides security and cryptographic operations for ETSI ITS PKI:
- Butterfly key expansion for AT batch generation
- ECIES encryption/decryption
- Proof of Possession (PoP) signature generation

Standards Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats

Author: SecureRoad PKI Project
Date: October 2025
"""

from .butterfly import (
    ButterflyExpansion,
    derive_at_keys,
    generate_key_tag,
    derive_ecc_key_pair_from_seed,
    compute_shared_secret_ecdh,
    validate_butterfly_keys,
    compute_key_fingerprint,
    derive_ticket_hmac,
)
from .ecies import ecies_encrypt, ecies_decrypt
from .proof_of_possession import generate_pop_signature, verify_pop_signature

__all__ = [
    # Butterfly key expansion - class interface
    "ButterflyExpansion",
    
    # Butterfly key expansion - functional interface
    "derive_at_keys",
    "generate_key_tag",
    "derive_ecc_key_pair_from_seed",
    "compute_shared_secret_ecdh",
    "validate_butterfly_keys",
    "compute_key_fingerprint",
    "derive_ticket_hmac",
    
    # ECIES encryption
    "ecies_encrypt",
    "ecies_decrypt",
    
    # Proof of Possession
    "generate_pop_signature",
    "verify_pop_signature",
]
