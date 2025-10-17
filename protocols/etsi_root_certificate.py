"""
ETSI Root Certificate Encoder - ASN.1 OER Implementation

Implements Root CA Certificate (Trust Anchor) encoding/decoding per ETSI TS 103097 V2.1.1
using ASN.1 Octet Encoding Rules (OER) as specified in ISO/IEC 8825-7:2015.

Root certificates are self-signed trust anchors used to verify the entire PKI hierarchy.
They use explicit (complete public key) format instead of implicit reconstruction.

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Standard
- ISO/IEC 8825-7:2015 - ASN.1 OER Encoding Rules

Certificate Structure:
    EtsiTs103097Certificate ::= SEQUENCE {
        version Uint8(3),                    -- ETSI TS 103097 v2.1.1
        type CertificateType(explicit),      -- Type = 0 for Root CA
        issuer IssuerIdentifier,             -- Self for root (own HashedId8)
        toBeSigned ToBeSignedCertificate,
        signature Signature                   -- ECDSA-SHA256
    }

Author: SecureRoad PKI Project
Date: October 2025
"""

import struct
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# Import centralized ETSI utilities from etsi_message_types (DRY compliance)
from protocols.etsi_message_types import (
    CERT_TYPE_EXPLICIT,
    compute_hashed_id8,
    encode_public_key_compressed,
    time32_decode,
    time32_encode,
)


class ETSIRootCertificateEncoder:
    """
    Encoder/Decoder for ETSI Root CA Certificates in ASN.1 OER format.
    
    Implements self-signed trust anchor generation, signing, verification,
    and serialization according to ETSI TS 103097 V2.1.1 standards.
    
    Uses centralized ETSI utilities from etsi_message_types module (DRY compliance).
    """

    def __init__(self):
        """Initialize Root Certificate Encoder"""
        pass

    # Delegate to centralized utilities from etsi_message_types (DRY compliance)
    compute_hashed_id8 = staticmethod(compute_hashed_id8)
    time32_encode = staticmethod(time32_encode)
    time32_decode = staticmethod(time32_decode)
    encode_public_key = staticmethod(encode_public_key_compressed)

    def encode_subject_attributes_root(
        self,
        ca_name: str = "RootCA",
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """
        Encode subject attributes for Root CA.
        
        Args:
            ca_name: Root CA name (Common Name)
            country: Country code (2 letters)
            organization: Organization name
            
        Returns:
            bytes: Encoded subject attributes (variable length)
        """
        encoded = bytearray()
        
        # Country (2 bytes)
        encoded.extend(country.encode('utf-8')[:2].ljust(2, b'\x00'))
        
        # Organization length + value
        org_bytes = organization.encode('utf-8')
        encoded.append(min(len(org_bytes), 255))  # Length (1 byte, max 255)
        encoded.extend(org_bytes[:255])
        
        # CA Name length + value
        ca_name_bytes = ca_name.encode('utf-8')
        encoded.append(min(len(ca_name_bytes), 255))  # Length (1 byte, max 255)
        encoded.extend(ca_name_bytes[:255])
        
        return bytes(encoded)

    def encode_to_be_signed_root(
        self,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_years: int = 10,
        ca_name: str = "RootCA",
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """
        Encode ToBeSignedCertificate for Root CA.
        
        ETSI TS 103097 Section 6.4.3:
        ToBeSignedCertificate ::= SEQUENCE {
            id CertificateId,                -- Subject attributes
            cracaId HashedId3,               -- Always 0 for root
            crlSeries Uint16,                -- CRL series number
            validityPeriod ValidityPeriod,   -- Start + Duration
            region GeographicRegion OPTIONAL,
            assuranceLevel SubjectAssurance OPTIONAL,
            appPermissions SequenceOfPsidSsp OPTIONAL,
            certIssuePermissions SequenceOfPsidGroupPermissions OPTIONAL,
            certRequestPermissions SequenceOfPsidGroupPermissions OPTIONAL,
            canRequestRollover NULL OPTIONAL,
            encryptionKey PublicEncryptionKey OPTIONAL,
            verifyKeyIndicator VerificationKeyIndicator
        }
        
        Args:
            subject_public_key: Public key for Root CA
            start_validity: Certificate start time
            duration_years: Validity duration in years (default 10)
            ca_name: Root CA name
            country: Country code
            organization: Organization name
            
        Returns:
            bytes: ToBeSignedCertificate encoded in ASN.1 OER
        """
        tbs = bytearray()
        
        # 1. Certificate ID (subject attributes)
        subject_attrs = self.encode_subject_attributes_root(ca_name, country, organization)
        tbs.extend(subject_attrs)
        
        # 2. cracaId (3 bytes) - Always 0x000000 for self-signed root
        tbs.extend(b'\x00\x00\x00')
        
        # 3. crlSeries (2 bytes, big-endian) - Initial value 0
        tbs.extend(struct.pack(">H", 0))
        
        # 4. Validity Period
        # Start time (Time32 - 4 bytes)
        start_time32 = self.time32_encode(start_validity)
        tbs.extend(struct.pack(">I", start_time32))
        
        # Duration (Uint16 - hours, 2 bytes)
        duration_hours = duration_years * 365 * 24
        tbs.extend(struct.pack(">H", min(duration_hours, 65535)))
        
        # 5. Geographic Region (OPTIONAL) - Flag: 0 = not present
        tbs.append(0x00)
        
        # 6. Assurance Level (OPTIONAL) - Flag: 0 = not present
        tbs.append(0x00)
        
        # 7. App Permissions (OPTIONAL) - Flag: 0 = not present
        tbs.append(0x00)
        
        # 8. Cert Issue Permissions (OPTIONAL) - Flag: 1 = present (Root can issue)
        tbs.append(0x01)
        # Simple: Allow all PSIDs (0xFFFFFFFF)
        tbs.extend(struct.pack(">I", 0xFFFFFFFF))
        
        # 9. Cert Request Permissions (OPTIONAL) - Flag: 0 = not present
        tbs.append(0x00)
        
        # 10. Can Request Rollover (OPTIONAL) - Flag: 0 = not present
        tbs.append(0x00)
        
        # 11. Encryption Key (OPTIONAL) - Flag: 0 = not present for Root
        tbs.append(0x00)
        
        # 12. Verify Key Indicator (Public Key - Explicit for Root)
        # Type: 0 = verificationKey (explicit public key)
        tbs.append(0x00)
        # Encode public key (compressed format - 33 bytes)
        public_key_bytes = self.encode_public_key(subject_public_key)
        tbs.extend(public_key_bytes)
        
        return bytes(tbs)

    def sign_root_certificate(
        self,
        tbs_cert: bytes,
        private_key: EllipticCurvePrivateKey
    ) -> bytes:
        """
        Sign ToBeSignedCertificate with Root CA private key (self-signed).
        
        ETSI TS 103097 Section 6.3.9:
        Signature ::= CHOICE {
            ecdsaNistP256Signature EcdsaP256Signature,
            ...
        }
        
        EcdsaP256Signature ::= SEQUENCE {
            rSig EccP256CurvePoint,
            sSig OCTET STRING (SIZE(32))
        }
        
        Args:
            tbs_cert: ToBeSignedCertificate bytes
            private_key: Private key for signing
            
        Returns:
            bytes: ECDSA signature (64 bytes: 32 bytes R + 32 bytes S)
        """
        signature_der = private_key.sign(tbs_cert, ec.ECDSA(hashes.SHA256()))
        
        # Convert DER signature to raw R|S format (64 bytes)
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
        )
        r, s = decode_dss_signature(signature_der)
        
        # Encode as fixed 64 bytes (32 + 32)
        signature_bytes = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
        
        return signature_bytes

    def encode_full_root_certificate(
        self,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_years: int,
        root_private_key: EllipticCurvePrivateKey,
        ca_name: str = "RootCA",
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """
        Encode complete Root Certificate (TBS + Signature).
        
        ETSI TS 103097 Section 6.4.1:
        EtsiTs103097Certificate ::= SEQUENCE {
            version Uint8(3),
            type CertificateType,
            issuer IssuerIdentifier,
            toBeSigned ToBeSignedCertificate,
            signature Signature
        }
        
        Args:
            subject_public_key: Public key for Root CA
            start_validity: Certificate start time
            duration_years: Validity duration in years
            root_private_key: Private key for signing (self-signed)
            ca_name: Root CA name
            country: Country code
            organization: Organization name
            
        Returns:
            bytes: Complete ASN.1 OER encoded Root Certificate
        """
        # 1. Encode ToBeSignedCertificate
        tbs_cert = self.encode_to_be_signed_root(
            subject_public_key=subject_public_key,
            start_validity=start_validity,
            duration_years=duration_years,
            ca_name=ca_name,
            country=country,
            organization=organization,
        )
        
        # 2. Sign TBS certificate
        signature = self.sign_root_certificate(tbs_cert, root_private_key)
        
        # 3. Build complete certificate
        cert = bytearray()
        
        # Version (1 byte): 3 for ETSI TS 103097 v2.1.1
        cert.append(3)
        
        # Type (1 byte): 0 = explicit (Root CA)
        cert.append(CERT_TYPE_EXPLICIT)
        
        # Issuer Identifier (self-signed, so use placeholder and update later)
        # Type: 0 = self (no issuer info for self-signed)
        cert.append(0x00)
        
        # TBS length (2 bytes, big-endian)
        cert.extend(struct.pack(">H", len(tbs_cert)))
        
        # ToBeSignedCertificate
        cert.extend(tbs_cert)
        
        # Signature (64 bytes)
        cert.extend(signature)
        
        return bytes(cert)

    def decode_root_certificate(self, cert_bytes: bytes) -> Dict:
        """
        Decode Root Certificate from ASN.1 OER bytes.
        
        Args:
            cert_bytes: ASN.1 OER encoded Root Certificate
            
        Returns:
            dict: Decoded certificate data
            
        Raises:
            ValueError: If certificate format is invalid
        """
        if len(cert_bytes) < 100:  # Minimum size check
            raise ValueError(f"Certificate too small: {len(cert_bytes)} bytes")
        
        offset = 0
        decoded = {}
        
        # 1. Version (1 byte)
        decoded['version'] = cert_bytes[offset]
        offset += 1
        
        # 2. Type (1 byte)
        decoded['type'] = cert_bytes[offset]
        offset += 1
        
        if decoded['type'] != CERT_TYPE_EXPLICIT:
            raise ValueError(f"Invalid certificate type for Root CA: {decoded['type']}")
        
        # 3. Issuer Identifier (1 byte for self-signed)
        issuer_type = cert_bytes[offset]
        offset += 1
        decoded['issuer_type'] = 'self' if issuer_type == 0 else 'unknown'
        
        # 4. TBS length (2 bytes)
        tbs_length = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
        offset += 2
        
        # 5. ToBeSignedCertificate
        tbs_cert = cert_bytes[offset:offset+tbs_length]
        offset += tbs_length
        
        # 6. Signature (64 bytes)
        signature = cert_bytes[offset:offset+64]
        offset += 64
        
        decoded['tbs_cert'] = tbs_cert
        decoded['signature'] = signature.hex()
        
        # Decode TBS details
        tbs_decoded = self._decode_tbs_root(tbs_cert)
        decoded.update(tbs_decoded)
        
        return decoded

    def _decode_tbs_root(self, tbs_bytes: bytes) -> Dict:
        """Decode ToBeSignedCertificate for Root CA"""
        offset = 0
        decoded = {}
        
        # Subject attributes (variable length, skip for now)
        # Country (2 bytes)
        country = tbs_bytes[offset:offset+2].decode('utf-8', errors='ignore').rstrip('\x00')
        offset += 2
        decoded['country'] = country
        
        # Organization (length + data)
        org_len = tbs_bytes[offset]
        offset += 1
        organization = tbs_bytes[offset:offset+org_len].decode('utf-8', errors='ignore')
        offset += org_len
        decoded['organization'] = organization
        
        # CA Name (length + data)
        ca_name_len = tbs_bytes[offset]
        offset += 1
        ca_name = tbs_bytes[offset:offset+ca_name_len].decode('utf-8', errors='ignore')
        offset += ca_name_len
        decoded['ca_name'] = ca_name
        
        # cracaId (3 bytes)
        offset += 3
        
        # crlSeries (2 bytes)
        crl_series = struct.unpack(">H", tbs_bytes[offset:offset+2])[0]
        offset += 2
        decoded['crl_series'] = crl_series
        
        # Validity Period
        start_time32 = struct.unpack(">I", tbs_bytes[offset:offset+4])[0]
        offset += 4
        duration_hours = struct.unpack(">H", tbs_bytes[offset:offset+2])[0]
        offset += 2
        
        decoded['start_validity'] = self.time32_decode(start_time32).isoformat()
        decoded['duration_hours'] = duration_hours
        
        return decoded

    def verify_root_certificate(
        self,
        cert_bytes: bytes,
        root_public_key: EllipticCurvePublicKey
    ) -> bool:
        """
        Verify Root Certificate signature (self-signed).
        
        Args:
            cert_bytes: Complete Root Certificate bytes
            root_public_key: Public key to verify (extracted from cert)
            
        Returns:
            bool: True if signature is valid
        """
        decoded = self.decode_root_certificate(cert_bytes)
        tbs_cert = decoded['tbs_cert']
        signature_hex = decoded['signature']
        
        # Convert hex signature to bytes
        signature_bytes = bytes.fromhex(signature_hex)
        
        # Extract R and S (32 bytes each)
        r = int.from_bytes(signature_bytes[:32], byteorder='big')
        s = int.from_bytes(signature_bytes[32:64], byteorder='big')
        
        # Convert to DER format
        from cryptography.hazmat.primitives.asymmetric.utils import (
            encode_dss_signature,
        )
        signature_der = encode_dss_signature(r, s)
        
        # Verify
        try:
            root_public_key.verify(signature_der, tbs_cert, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def export_to_json(self, full_certificate: bytes) -> dict:
        """
        Export Root Certificate to JSON-compatible dict.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded Root Certificate
            
        Returns:
            dict: JSON-serializable certificate data
        """
        decoded = self.decode_root_certificate(full_certificate)
        return {
            'certificate_type': 'RootCertificate',
            'format': 'ASN.1 OER (ETSI TS 103097)',
            'size_bytes': len(full_certificate),
            'data': decoded,
        }


# ============================================================================
# HIGH-LEVEL GENERATION FUNCTIONS
# ============================================================================

def generate_root_certificate(
    root_public_key: EllipticCurvePublicKey,
    root_private_key: EllipticCurvePrivateKey,
    duration_years: int = 10,
    ca_name: str = "RootCA",
    country: str = "IT",
    organization: str = "SecureRoad PKI"
) -> bytes:
    """
    High-level function to generate self-signed Root Certificate.
    
    Args:
        root_public_key: Root CA public key
        root_private_key: Root CA private key (for self-signing)
        duration_years: Certificate validity (default 10 years)
        ca_name: Root CA name (default "RootCA")
        country: Country code (default "IT")
        organization: Organization name (default "SecureRoad PKI")
        
    Returns:
        bytes: Complete Root Certificate (ASN.1 OER)
    """
    encoder = ETSIRootCertificateEncoder()
    
    # Generate certificate
    start_validity = datetime.now(timezone.utc)
    
    return encoder.encode_full_root_certificate(
        subject_public_key=root_public_key,
        start_validity=start_validity,
        duration_years=duration_years,
        root_private_key=root_private_key,
        ca_name=ca_name,
        country=country,
        organization=organization
    )
