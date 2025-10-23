"""
Subordinate Certificate Encoder - ASN.1 OER Implementation

Implements Enrollment Authority (EA) and Authorization Authority (AA) certificate 
encoding/decoding per ETSI TS 103097 V2.1.1 using ASN.1 Octet Encoding Rules (OER).

Authority certificates are subordinate certificates signed by Root CA and used to 
issue end-entity certificates (EC for EA, AT for AA).

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Standard

Author: SecureRoad PKI Project
Date: October 2025
"""

import struct
from datetime import datetime, timedelta, timezone
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
from protocols.core.primitives import (
    compute_hashed_id8,
    encode_public_key_compressed,
    decode_public_key_compressed,
    time32_decode,
    time32_encode,
)


class SubordinateCertificate:
    """
    Encoder/Decoder for ETSI Authority Certificates (EA/AA) in ASN.1 OER format.
    
    Implements subordinate certificate generation for Enrollment and Authorization
    Authorities according to ETSI TS 103097 V2.1.1 standards.
    
    **Certificate Type:** Explicit (contains full public key)
    **Issuer:** Root CA (identified by HashedId8)
    **Purpose:** Sign end-entity certificates (EC or AT)
    """

    def __init__(self):
        """Initialize Authority Certificate Encoder"""
        pass

    # Delegate to centralized utilities
    compute_hashed_id8 = staticmethod(compute_hashed_id8)
    time32_encode = staticmethod(time32_encode)
    time32_decode = staticmethod(time32_decode)
    encode_public_key = staticmethod(encode_public_key_compressed)

    def encode_subject_attributes(
        self,
        authority_id: str,
        authority_type: str = "EA",
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """Encode subject attributes for Authority certificate."""
        encoded = bytearray()
        
        encoded.extend(country.encode('utf-8')[:2].ljust(2, b'\x00'))
        
        org_bytes = organization.encode('utf-8')
        encoded.append(min(len(org_bytes), 255))
        encoded.extend(org_bytes[:255])
        
        auth_type_bytes = authority_type.encode('utf-8')
        encoded.append(min(len(auth_type_bytes), 255))
        encoded.extend(auth_type_bytes[:255])
        
        auth_id_bytes = authority_id.encode('utf-8')
        encoded.append(min(len(auth_id_bytes), 255))
        encoded.extend(auth_id_bytes[:255])
        
        return bytes(encoded)

    def encode_to_be_signed_authority_cert(
        self,
        issuer_hashed_id8: bytes,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_years: int,
        authority_id: str,
        authority_type: str = "EA",
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """Encode ToBeSignedCertificate for Authority (EA/AA)."""
        tbs = bytearray()
        
        tbs.append(3)  # Version
        tbs.append(2)  # Type: Authority
        tbs.append(0x02)  # Issuer: HashedId8
        tbs.extend(issuer_hashed_id8)
        
        subject_attrs = self.encode_subject_attributes(
            authority_id=authority_id,
            authority_type=authority_type,
            country=country,
            organization=organization
        )
        tbs.extend(subject_attrs)
        
        start_time32 = self.time32_encode(start_validity)
        duration_hours = duration_years * 365 * 24
        
        tbs.extend(struct.pack(">I", start_time32))
        
        # Encode Duration as CHOICE (OER tag required)
        # Tag 0x84 = hours (Uint16)
        tbs.append(0x84)
        tbs.extend(struct.pack(">H", min(duration_hours, 65535)))
        
        tbs.append(0x00)  # Geographic region
        tbs.append(0x00)  # Assurance level
        tbs.append(0x00)  # App permissions
        
        tbs.append(0x01)  # Cert issue permissions
        if authority_type == "EA":
            tbs.append(0x03)  # Can issue EC
        elif authority_type == "AA":
            tbs.append(0x04)  # Can issue AT
        else:
            tbs.append(0xFF)
        
        tbs.append(0x00)  # Cert request permissions
        tbs.append(0x00)  # Verification key type
        
        public_key_compressed = self.encode_public_key(subject_public_key)
        tbs.extend(public_key_compressed)
        
        return bytes(tbs)

    def encode_full_authority_certificate(
        self,
        issuer_hashed_id8: bytes,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_years: int,
        authority_id: str,
        root_ca_signature: bytes,
        authority_type: str = "EA",
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """Encode complete Authority Certificate (TBS + Signature)."""
        tbs_cert = self.encode_to_be_signed_authority_cert(
            issuer_hashed_id8=issuer_hashed_id8,
            subject_public_key=subject_public_key,
            start_validity=start_validity,
            duration_years=duration_years,
            authority_id=authority_id,
            authority_type=authority_type,
            country=country,
            organization=organization,
        )
        
        cert = bytearray()
        cert.extend(struct.pack(">H", len(tbs_cert)))
        cert.extend(tbs_cert)
        cert.append(0x00)  # Signature type: ECDSA-SHA256
        
        if len(root_ca_signature) != 64:
            raise ValueError(f"Invalid signature length: {len(root_ca_signature)}")
        cert.extend(root_ca_signature)
        
        return bytes(cert)

    def decode_authority_certificate(self, cert_bytes: bytes) -> Dict:
        """Decode Authority Certificate from ASN.1 OER."""
        offset = 0
        
        tbs_length = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
        offset += 2
        
        version = cert_bytes[offset]
        offset += 1
        
        cert_type = cert_bytes[offset]
        offset += 1
        
        issuer_type = cert_bytes[offset]
        offset += 1
        
        issuer_hashed_id8 = cert_bytes[offset:offset+8] if issuer_type == 0x02 else b''
        offset += 8 if issuer_type == 0x02 else 0
        
        country = cert_bytes[offset:offset+2].decode('utf-8').strip('\x00')
        offset += 2
        
        org_len = cert_bytes[offset]
        offset += 1
        organization = cert_bytes[offset:offset+org_len].decode('utf-8')
        offset += org_len
        
        auth_type_len = cert_bytes[offset]
        offset += 1
        authority_type = cert_bytes[offset:offset+auth_type_len].decode('utf-8')
        offset += auth_type_len
        
        auth_id_len = cert_bytes[offset]
        offset += 1
        authority_id = cert_bytes[offset:offset+auth_id_len].decode('utf-8')
        offset += auth_id_len
        
        start_time32 = struct.unpack(">I", cert_bytes[offset:offset+4])[0]
        offset += 4
        
        # Decode Duration CHOICE (OER tag + value)
        duration_tag = cert_bytes[offset]
        offset += 1
        
        # Parse duration based on tag
        if duration_tag == 0x84:  # hours
            duration_value = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
            offset += 2
            duration_hours = duration_value
        elif duration_tag == 0x86:  # years
            duration_value = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
            offset += 2
            duration_hours = duration_value * 365 * 24
        else:
            # Fallback per altri tag (non ancora implementati)
            duration_value = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
            offset += 2
            duration_hours = duration_value  # Assume hours per sicurezza
        
        start_validity = self.time32_decode(start_time32)
        expiry = start_validity + timedelta(hours=duration_hours)
        
        # Skip optional fields
        offset += 1  # region
        offset += 1  # assurance
        offset += 1  # app perms
        offset += 2  # cert issue perms
        offset += 1  # cert request perms
        offset += 1  # key type
        offset += 33  # public key
        
        sig_type_offset = 2 + tbs_length
        signature_offset = sig_type_offset + 1
        signature = cert_bytes[signature_offset:signature_offset+64]
        
        return {
            "tbs_length": tbs_length,
            "version": version,
            "type": cert_type,
            "issuer_hashed_id8": issuer_hashed_id8.hex(),
            "authority_id": authority_id,
            "authority_type": authority_type,
            "country": country,
            "organization": organization,
            "start_validity": start_validity.isoformat(),
            "duration_hours": duration_hours,
            "expiry": expiry.isoformat(),
            "signature_hex": signature.hex(),
        }

    def extract_public_key(self, full_certificate: bytes) -> EllipticCurvePublicKey:
        """
        Extract public key from Authority Certificate using ASN.1 decoder.
        
        Uses the centralized extract_public_key_from_asn1_certificate() function
        to properly decode the certificate structure according to ETSI TS 103097.
        """
        from protocols.certificates.utils import extract_public_key_from_asn1_certificate
        
        try:
            # Use centralized ASN.1 decoder-based extraction (DRY principle)
            return extract_public_key_from_asn1_certificate(full_certificate)
        except Exception as e:
            raise ValueError(f"Failed to extract public key from Authority certificate: {e}")

    def verify_authority_certificate_signature(
        self,
        cert_bytes: bytes,
        root_ca_public_key: EllipticCurvePublicKey
    ) -> bool:
        """
        Verify Authority Certificate signature using centralized function.
        
        Uses verify_asn1_certificate_signature() for consistent ETSI-compliant
        signature verification across all certificate types.
        """
        from protocols.certificates.utils import verify_asn1_certificate_signature
        
        try:
            # Use centralized ASN.1 signature verification (DRY principle)
            return verify_asn1_certificate_signature(cert_bytes, root_ca_public_key)
        except Exception:
            return False

    @staticmethod
    def generate(
        root_ca_cert_asn1: bytes,
        root_ca_private_key: EllipticCurvePrivateKey,
        authority_public_key: EllipticCurvePublicKey,
        authority_id: str,
        authority_type: str = "EA",
        duration_years: int = 5,
        country: str = "IT",
        organization: str = "SecureRoad PKI"
    ) -> bytes:
        """
        High-level function to generate Authority Certificate using ASN.1 compiler.
        
        🔄 MIGRATO AD ASN.1 COMPILER (October 2025)
        ==========================================
        Usa asn1_compiler invece di encoding manuale per garantire
        conformità ETSI TS 103097 / IEEE 1609.2 completa.
        
        Args:
            root_ca_cert_asn1: Root CA certificate
            root_ca_private_key: Root CA signing key
            authority_public_key: Authority public key
            authority_id: Authority identifier (e.g., "EA_001")
            authority_type: "EA" or "AA"
            duration_years: Validity in years
            country: Country code
            organization: Organization name
            
        Returns:
            bytes: Complete Authority Certificate (ASN.1 OER)
        """
        # Delega al nuovo encoder ASN.1
        from .asn1_encoder import generate_subordinate_certificate
        
        return generate_subordinate_certificate(
            root_ca_cert_asn1=root_ca_cert_asn1,
            root_ca_private_key=root_ca_private_key,
            authority_public_key=authority_public_key,
            authority_id=authority_id,
            authority_type=authority_type,
            duration_years=duration_years,
            country=country,
            organization=organization
        )


# Backward compatibility aliases
ETSIAuthorityCertificateEncoder = SubordinateCertificate
generate_authority_certificate = SubordinateCertificate.generate

__all__ = ["SubordinateCertificate", "ETSIAuthorityCertificateEncoder", "generate_authority_certificate"]
