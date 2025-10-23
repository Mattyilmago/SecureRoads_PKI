"""
Proof of Possession (PoP) Signatures

Implements Proof of Possession signature generation and verification for
ETSI enrollment requests.

PoP proves that the requester possesses the private key corresponding to
the public key in the certificate request.

Standards Reference:
- ETSI TS 102941 V2.1.1 Section 6.2.3.2 - InnerEcRequestSignedForPop

Author: SecureRoad PKI Project
Date: October 2025
"""

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from protocols.core import sign_data_ecdsa_sha256, verify_signature_ecdsa_sha256


def generate_pop_signature(
    tbs_data: bytes,
    private_key: EllipticCurvePrivateKey
) -> bytes:
    """
    Generate Proof of Possession signature.
    
    Signs the ToBeSignedData (serialized InnerEcRequest) with the
    private key corresponding to the public key in the request.
    
    Args:
        tbs_data: Serialized InnerEcRequest
        private_key: Private key corresponding to requested public key
        
    Returns:
        bytes: ECDSA signature (64 bytes: r || s)
    """
    return sign_data_ecdsa_sha256(tbs_data, private_key)


def verify_pop_signature(
    tbs_data: bytes,
    signature: bytes,
    public_key: EllipticCurvePublicKey
) -> bool:
    """
    Verify Proof of Possession signature.
    
    Verifies that the signature over ToBeSignedData is valid for the
    provided public key, proving possession of the private key.
    
    Args:
        tbs_data: Serialized InnerEcRequest
        signature: ECDSA signature (64 bytes: r || s)
        public_key: Public key from the request
        
    Returns:
        bool: True if signature is valid (PoP verified)
    """
    return verify_signature_ecdsa_sha256(tbs_data, signature, public_key)
