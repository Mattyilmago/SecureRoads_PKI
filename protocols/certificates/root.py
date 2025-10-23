
"""
Root Certificate Encoder - ASN.1 OER Implementation

Implements Root CA Certificate (Trust Anchor) encoding/decoding per ETSI TS 103097 V2.1.1
using ASN.1 Octet Encoding Rules (OER) as specified in ISO/IEC 8825-7:2015.

Root certificates are self-signed trust anchors used to verify the entire PKI hierarchy.
They use explicit (complete public key) format instead of implicit reconstruction.

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Standard
- ISO/IEC 8825-7:2015 - ASN.1 OER Encoding Rules

Author: SecureRoad PKI Project
Date: October 2025
"""

import struct
from datetime import datetime, timezone
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

# Import from new modular structure
from protocols.core.types import CERT_TYPE_EXPLICIT
from protocols.core.primitives import (
    compute_hashed_id8,
    encode_public_key_compressed,
    time32_decode,
    time32_encode,
)


class RootCertificate:
    """
    Encoder/Decoder for ETSI Root CA Certificates in ASN.1 OER format.
    
    Implements self-signed trust anchor generation, signing, verification,
    and serialization according to ETSI TS 103097 V2.1.1 standards.
    """

    def __init__(self):
        """Initialize Root Certificate Encoder"""
        pass

    # Delegate to centralized utilities
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
        """Encode subject attributes for Root CA."""
        encoded = bytearray()
        
        # Country (2 bytes)
        encoded.extend(country.encode('utf-8')[:2].ljust(2, b'\x00'))
        
        # Organization length + value
        org_bytes = organization.encode('utf-8')
        encoded.append(min(len(org_bytes), 255))
        encoded.extend(org_bytes[:255])
        
        # CA Name length + value
        ca_name_bytes = ca_name.encode('utf-8')
        encoded.append(min(len(ca_name_bytes), 255))
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
        """Encode ToBeSignedCertificate for Root CA."""
        tbs = bytearray()
        
        # 1. Certificate ID (subject attributes)
        subject_attrs = self.encode_subject_attributes_root(ca_name, country, organization)
        tbs.extend(subject_attrs)
        
        # 2. cracaId (3 bytes) - Always 0x000000 for self-signed root
        tbs.extend(b'\x00\x00\x00')
        
        # 3. crlSeries (2 bytes) - Initial value 0
        tbs.extend(struct.pack(">H", 0))
        
        # 4. Validity Period
        start_time32 = self.time32_encode(start_validity)
        tbs.extend(struct.pack(">I", start_time32))
        
        # Encode Duration as CHOICE (OER tag required)
        # Tag 0x84 = hours (Uint16)
        duration_hours = duration_years * 365 * 24
        tbs.append(0x84)
        tbs.extend(struct.pack(">H", min(duration_hours, 65535)))
        
        # 5-10. Optional fields (flags: 0 = not present)
        tbs.append(0x00)  # Geographic Region
        tbs.append(0x00)  # Assurance Level
        tbs.append(0x00)  # App Permissions
        
        # 8. Cert Issue Permissions (1 = present for Root)
        tbs.append(0x01)
        tbs.extend(struct.pack(">I", 0xFFFFFFFF))  # Allow all PSIDs
        
        tbs.append(0x00)  # Cert Request Permissions
        tbs.append(0x00)  # Can Request Rollover
        tbs.append(0x00)  # Encryption Key
        
        # 12. Verify Key Indicator (Public Key - Explicit)
        tbs.append(0x00)  # Type: verificationKey
        public_key_bytes = self.encode_public_key(subject_public_key)
        tbs.extend(public_key_bytes)
        
        return bytes(tbs)

    def sign_root_certificate(
        self,
        tbs_cert: bytes,
        private_key: EllipticCurvePrivateKey
    ) -> bytes:
        """Sign ToBeSignedCertificate with Root CA private key (self-signed)."""
        signature_der = private_key.sign(tbs_cert, ec.ECDSA(hashes.SHA256()))
        
        # Convert DER to raw R|S format (64 bytes)
        r, s = decode_dss_signature(signature_der)
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
        """Encode complete Root Certificate (TBS + Signature)."""
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
        cert.append(3)  # Version
        cert.append(CERT_TYPE_EXPLICIT)  # Type
        cert.append(0x00)  # Issuer (self)
        cert.extend(struct.pack(">H", len(tbs_cert)))  # TBS length
        cert.extend(tbs_cert)
        cert.extend(signature)
        
        return bytes(cert)

    def decode_root_certificate(self, cert_bytes: bytes) -> Dict:
        """Decode Root Certificate from ASN.1 OER bytes."""
        if len(cert_bytes) < 100:
            raise ValueError(f"Certificate too small: {len(cert_bytes)} bytes")
        
        offset = 0
        decoded = {}
        
        decoded['version'] = cert_bytes[offset]
        offset += 1
        
        decoded['type'] = cert_bytes[offset]
        offset += 1
        
        if decoded['type'] != CERT_TYPE_EXPLICIT:
            raise ValueError(f"Invalid certificate type: {decoded['type']}")
        
        issuer_type = cert_bytes[offset]
        offset += 1
        decoded['issuer_type'] = 'self' if issuer_type == 0 else 'unknown'
        
        tbs_length = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
        offset += 2
        
        tbs_cert = cert_bytes[offset:offset+tbs_length]
        offset += tbs_length
        
        signature = cert_bytes[offset:offset+64]
        offset += 64
        
        decoded['tbs_cert'] = tbs_cert
        decoded['signature'] = signature.hex()
        
        tbs_decoded = self._decode_tbs_root(tbs_cert)
        decoded.update(tbs_decoded)
        
        return decoded

    def _decode_tbs_root(self, tbs_bytes: bytes) -> Dict:
        """Decode ToBeSignedCertificate for Root CA."""
        offset = 0
        decoded = {}
        
        # Country (2 bytes)
        country = tbs_bytes[offset:offset+2].decode('utf-8', errors='ignore').rstrip('\x00')
        offset += 2
        decoded['country'] = country
        
        # Organization
        org_len = tbs_bytes[offset]
        offset += 1
        organization = tbs_bytes[offset:offset+org_len].decode('utf-8', errors='ignore')
        offset += org_len
        decoded['organization'] = organization
        
        # CA Name
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
        """Verify Root Certificate signature (self-signed)."""
        decoded = self.decode_root_certificate(cert_bytes)
        tbs_cert = decoded['tbs_cert']
        signature_hex = decoded['signature']
        
        signature_bytes = bytes.fromhex(signature_hex)
        r = int.from_bytes(signature_bytes[:32], byteorder='big')
        s = int.from_bytes(signature_bytes[32:64], byteorder='big')
        
        signature_der = encode_dss_signature(r, s)
        
        try:
            root_public_key.verify(signature_der, tbs_cert, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False

    def export_to_json(self, full_certificate: bytes) -> dict:
        """Export Root Certificate to JSON-compatible dict."""
        decoded = self.decode_root_certificate(full_certificate)
        return {
            'certificate_type': 'RootCertificate',
            'format': 'ASN.1 OER (ETSI TS 103097)',
            'size_bytes': len(full_certificate),
            'data': decoded,
        }

    @staticmethod
    def generate(
        ca_name: str,
        private_key: EllipticCurvePrivateKey,
        duration_years: int = 10,
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """
        High-level function to generate self-signed Root Certificate using ASN.1 compiler.
        
        🔄 MIGRATO AD ASN.1 COMPILER (October 2025)
        ==========================================
        Usa asn1_compiler invece di encoding manuale per garantire
        conformità ETSI TS 103097 / IEEE 1609.2 completa.
        
        Args:
            ca_name: Root CA name
            private_key: Root CA private key (public key will be derived)
            duration_years: Certificate validity (default 10 years)
            country: Country code
            organization: Organization name
            
        Returns:
            bytes: Complete Root Certificate (ASN.1 OER)
        """
        # Delega al nuovo encoder ASN.1
        from .asn1_encoder import generate_root_certificate
        
        return generate_root_certificate(
            ca_name=ca_name,
            private_key=private_key,
            duration_years=duration_years,
            country=country,
            organization=organization
        )


# Backward compatibility aliases
ETSIRootCertificateEncoder = RootCertificate
generate_root_certificate = RootCertificate.generate

__all__ = ["RootCertificate", "ETSIRootCertificateEncoder", "generate_root_certificate"]
