"""
ETSI Authority Certificate Encoder - ASN.1 OER Implementation

Implements Enrollment Authority (EA) and Authorization Authority (AA) certificate 
encoding/decoding per ETSI TS 103097 V2.1.1 using ASN.1 Octet Encoding Rules (OER).

Authority certificates are subordinate certificates signed by Root CA and used to 
issue end-entity certificates (EC for EA, AT for AA).

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Standard
- ISO/IEC 8825-7:2015 - ASN.1 OER Encoding Rules

Certificate Structure:
    EtsiTs103097Certificate ::= SEQUENCE {
        version Uint8(3),                    -- ETSI TS 103097 v2.1.1
        type CertificateType(explicit),      -- Type = 0 for explicit
        issuer IssuerIdentifier,             -- Root CA HashedId8
        toBeSigned ToBeSignedCertificate,
        signature Signature                   -- ECDSA-SHA256 (from Root CA)
    }

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

# Import centralized ETSI utilities from etsi_message_types (DRY compliance)
from protocols.etsi_message_types import (
    CERT_TYPE_EXPLICIT,
    compute_hashed_id8,
    encode_public_key_compressed,
    time32_decode,
    time32_encode,
)


class ETSIAuthorityCertificateEncoder:
    """
    Encoder/Decoder for ETSI Authority Certificates (EA/AA) in ASN.1 OER format.
    
    Implements subordinate certificate generation for Enrollment and Authorization
    Authorities according to ETSI TS 103097 V2.1.1 standards.
    
    **Certificate Type:** Explicit (contains full public key, not reconstructed)
    **Issuer:** Root CA (identified by HashedId8)
    **Purpose:** Sign end-entity certificates (EC or AT)
    
    Uses centralized ETSI utilities from etsi_message_types module (DRY compliance).
    """

    def __init__(self):
        """Initialize Authority Certificate Encoder"""
        pass

    # Delegate to centralized utilities from etsi_message_types (DRY compliance)
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
        """
        Encode subject attributes for Authority certificate.
        
        Format:
            [country(2)] [org_len(1)] [org_data] [auth_type_len(1)] [auth_type] [auth_id_len(1)] [auth_id]
        
        Args:
            authority_id: Authority ID (e.g., "EA_001", "AA_002")
            authority_type: Authority type ("EA" or "AA")
            country: Country code (2 letters)
            organization: Organization name
            
        Returns:
            bytes: Encoded subject attributes (variable length)
        """
        encoded = bytearray()
        
        # Country (2 bytes, fixed)
        encoded.extend(country.encode('utf-8')[:2].ljust(2, b'\x00'))
        
        # Organization length + value (1 + N bytes)
        org_bytes = organization.encode('utf-8')
        encoded.append(min(len(org_bytes), 255))  # Length (1 byte, max 255)
        encoded.extend(org_bytes[:255])
        
        # Authority Type length + value (1 + N bytes)
        auth_type_bytes = authority_type.encode('utf-8')
        encoded.append(min(len(auth_type_bytes), 255))
        encoded.extend(auth_type_bytes[:255])
        
        # Authority ID length + value (1 + N bytes)
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
        """
        Encode ToBeSignedCertificate for Authority (EA/AA).
        
        ETSI TS 103097 Section 6.4.12:
        ToBeSignedCertificate ::= SEQUENCE {
            id CertificateId,              -- Authority ID
            cracaId HashedId3,             -- 0 for authorities
            crlSeries Uint16,              -- CRL series number
            validityPeriod ValidityPeriod,
            region GeographicRegion,       -- Optional
            assuranceLevel SubjectAssurance, -- Optional
            appPermissions SequenceOfPsidSsp,
            certIssuePermissions ...,      -- EA/AA can issue certs
            certRequestPermissions ...,    -- Not used for authorities
            verifyKeyIndicator VerificationKeyIndicator
        }
        
        Args:
            issuer_hashed_id8: HashedId8 of Root CA (8 bytes)
            subject_public_key: Public key for authority
            start_validity: Certificate start time
            duration_years: Validity duration in years (typically 5-10)
            authority_id: Authority identifier (e.g., "EA_001")
            authority_type: "EA" or "AA"
            country: Country code (default "IT")
            organization: Organization name
            
        Returns:
            bytes: ToBeSignedCertificate encoded in ASN.1 OER
        """
        tbs = bytearray()
        
        # 1. Version (1 byte): 3 for ETSI TS 103097 v2.1.1
        tbs.append(3)
        
        # 2. Certificate Type (1 byte): 2 for Authority
        tbs.append(2)  # Authority type (between Root=0 and Enrollment=3)
        
        # 3. Issuer Identifier: HashedId8 of Root CA
        # Type: 2 = HashedId8
        tbs.append(0x02)
        tbs.extend(issuer_hashed_id8)
        
        # 4. Subject Attributes (variable length)
        subject_attrs = self.encode_subject_attributes(
            authority_id=authority_id,
            authority_type=authority_type,
            country=country,
            organization=organization
        )
        tbs.extend(subject_attrs)
        
        # 5. Validity Period (8 bytes: start_time32 + duration)
        start_time32 = self.time32_encode(start_validity)
        duration_hours = duration_years * 365 * 24  # Convert years to hours
        
        tbs.extend(struct.pack(">I", start_time32))  # 4 bytes BE
        tbs.extend(struct.pack(">I", duration_hours))  # 4 bytes BE
        
        # 6. Geographic Region: None (authorities are global)
        tbs.append(0x00)  # No region restriction
        
        # 7. Assurance Level: None
        tbs.append(0x00)
        
        # 8. App Permissions: None (authorities don't send app messages)
        tbs.append(0x00)  # Empty sequence
        
        # 9. Cert Issue Permissions: EA/AA can issue certificates
        # Flag: 1 = can issue subordinate certificates
        tbs.append(0x01)
        
        # Issue permissions details:
        if authority_type == "EA":
            # EA can issue Enrollment Certificates (type 3)
            tbs.append(0x03)  # EC type
        elif authority_type == "AA":
            # AA can issue Authorization Tickets (type 4)
            tbs.append(0x04)  # AT type
        else:
            # Generic authority
            tbs.append(0xFF)  # All types
        
        # 10. Cert Request Permissions: None (authorities don't request certs)
        tbs.append(0x00)
        
        # 11. Verification Key Indicator: explicit public key
        # Type: 0 = ECC-NISTP256 with uncompressed point
        tbs.append(0x00)
        
        # Encode public key (compressed, 33 bytes)
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
        """
        Encode complete Authority Certificate (TBS + Signature from Root CA).
        
        ETSI TS 103097 Section 6.4.1:
        EtsiTs103097Certificate ::= SEQUENCE {
            version Uint8(3),
            type CertificateType,
            issuer IssuerIdentifier,
            toBeSigned ToBeSignedCertificate,
            signature Signature
        }
        
        Args:
            issuer_hashed_id8: Root CA HashedId8 (8 bytes)
            subject_public_key: Authority public key
            start_validity: Certificate start time
            duration_years: Validity duration in years
            authority_id: Authority identifier
            root_ca_signature: Signature from Root CA (64 bytes)
            authority_type: "EA" or "AA"
            country: Country code
            organization: Organization name
            
        Returns:
            bytes: Complete ASN.1 OER encoded Authority Certificate
        """
        # 1. Encode ToBeSignedCertificate
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
        
        # 2. Build complete certificate
        cert = bytearray()
        
        # TBS length (2 bytes, big-endian)
        cert.extend(struct.pack(">H", len(tbs_cert)))
        
        # ToBeSignedCertificate
        cert.extend(tbs_cert)
        
        # Signature type (1 byte): 0 = ECDSA-SHA256
        cert.append(0x00)
        
        # Signature (64 bytes: R || S)
        if len(root_ca_signature) != 64:
            raise ValueError(f"Invalid signature length: {len(root_ca_signature)} (expected 64)")
        cert.extend(root_ca_signature)
        
        return bytes(cert)

    def decode_authority_certificate(self, cert_bytes: bytes) -> Dict:
        """
        Decode Authority Certificate from ASN.1 OER to dictionary.
        
        Args:
            cert_bytes: ASN.1 OER encoded certificate
            
        Returns:
            dict: Decoded certificate data with fields:
                - tbs_length: ToBeSignedCertificate length
                - version: Certificate version
                - type: Certificate type
                - issuer_type: Issuer identifier type
                - issuer_hashed_id8: Root CA HashedId8 (hex)
                - authority_id: Authority identifier
                - authority_type: "EA" or "AA"
                - country: Country code
                - organization: Organization name
                - start_validity: Start time (ISO format)
                - duration_hours: Validity duration
                - expiry: Expiry time (ISO format)
                - public_key_hex: Public key (compressed, hex)
                - signature_hex: Signature (hex)
        """
        offset = 0
        
        # 1. TBS Length (2 bytes)
        tbs_length = struct.unpack(">H", cert_bytes[offset:offset+2])[0]
        offset += 2
        
        # 2. Version (1 byte)
        version = cert_bytes[offset]
        offset += 1
        
        # 3. Certificate Type (1 byte)
        cert_type = cert_bytes[offset]
        offset += 1
        
        # 4. Issuer Identifier
        issuer_type = cert_bytes[offset]
        offset += 1
        
        if issuer_type == 0x02:  # HashedId8
            issuer_hashed_id8 = cert_bytes[offset:offset+8]
            offset += 8
        else:
            issuer_hashed_id8 = b''
        
        # 5. Subject Attributes
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
        
        # 6. Validity Period
        start_time32 = struct.unpack(">I", cert_bytes[offset:offset+4])[0]
        offset += 4
        duration_hours = struct.unpack(">I", cert_bytes[offset:offset+4])[0]
        offset += 4
        
        start_validity = self.time32_decode(start_time32)
        expiry = start_validity + timedelta(hours=duration_hours)
        
        # 7. Skip optional fields (region, assurance, permissions)
        # Geographic region
        offset += 1
        # Assurance level
        offset += 1
        # App permissions
        offset += 1
        # Cert issue permissions
        offset += 2
        # Cert request permissions
        offset += 1
        
        # 8. Verification Key
        key_type = cert_bytes[offset]
        offset += 1
        
        public_key_compressed = cert_bytes[offset:offset+33]
        offset += 33
        
        # 9. Signature
        # Skip to signature (after TBS)
        sig_type_offset = 2 + tbs_length
        signature_offset = sig_type_offset + 1
        
        signature = cert_bytes[signature_offset:signature_offset+64]
        
        return {
            "tbs_length": tbs_length,
            "version": version,
            "type": cert_type,
            "issuer_type": issuer_type,
            "issuer_hashed_id8": issuer_hashed_id8.hex(),
            "authority_id": authority_id,
            "authority_type": authority_type,
            "country": country,
            "organization": organization,
            "start_validity": start_validity.isoformat(),
            "duration_hours": duration_hours,
            "expiry": expiry.isoformat(),
            "public_key_hex": public_key_compressed.hex(),
            "signature_hex": signature.hex(),
        }

    def extract_public_key(
        self,
        full_certificate: bytes,
    ) -> EllipticCurvePublicKey:
        """
        Extract public key from Authority Certificate.
        
        Parses the ASN.1 OER encoded certificate and extracts the compressed
        public key, then decompresses it to return a usable EllipticCurvePublicKey.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded Authority certificate
            
        Returns:
            EllipticCurvePublicKey: Extracted and decompressed public key
            
        Raises:
            ValueError: If certificate is malformed or key cannot be extracted
        """
        from protocols.etsi_message_types import decode_public_key_compressed
        
        try:
            # Read TBS length
            tbs_len = struct.unpack('>H', full_certificate[0:2])[0]
            tbs_cert = full_certificate[2:2+tbs_len]
            
            # Parse TBS certificate to find verification key
            offset = 0
            
            # Skip: Version (1), Type (1), Issuer type (1), Issuer hash (8)
            offset += 1 + 1 + 1 + 8
            
            # Skip: Subject attributes (variable)
            # Country (2 bytes)
            offset += 2
            # Organization length + value
            org_len = tbs_cert[offset]
            offset += 1 + org_len
            # Authority type length + value
            auth_type_len = tbs_cert[offset]
            offset += 1 + auth_type_len
            # Authority ID length + value
            auth_id_len = tbs_cert[offset]
            offset += 1 + auth_id_len
            
            # Skip: Validity period (8 bytes: start_time32 + duration)
            offset += 8
            
            # Skip: Geographic region (1 byte presence flag)
            has_region = tbs_cert[offset]
            offset += 1
            if has_region:
                offset += 10  # Lat (4) + Lon (4) + Radius (2)
            
            # Skip: Assurance level (1 byte)
            has_assurance = tbs_cert[offset]
            offset += 1
            
            # Skip: App permissions (1 byte count, should be 0 for authorities)
            offset += 1
            
            # Skip: Cert issue permissions (2 bytes: flag + cert type)
            # Always 2 bytes: 0x01 (flag) + 0x03/0x04/0xFF (cert type)
            offset += 2
            
            # Skip: Cert request permissions (1 byte: always 0x00 for authorities)
            offset += 1
            
            # Verification Key Indicator (1 byte: should be 0x00 for explicit key)
            key_indicator = tbs_cert[offset]
            offset += 1
            
            if key_indicator != 0x00:  # Must be verificationKey
                raise ValueError(f"Unexpected key indicator: 0x{key_indicator:02x}")
            
            # Extract compressed public key (33 bytes)
            compressed_key = tbs_cert[offset:offset+33]
            
            if len(compressed_key) != 33:
                raise ValueError(f"Invalid compressed key length: {len(compressed_key)}")
            
            # Decompress and return public key
            return decode_public_key_compressed(compressed_key)
            
        except Exception as e:
            raise ValueError(f"Failed to extract public key from Authority certificate: {e}")

    def verify_authority_certificate_signature(
        self,
        cert_bytes: bytes,
        root_ca_public_key: EllipticCurvePublicKey
    ) -> bool:
        """
        Verify Authority Certificate signature using Root CA public key.
        
        Args:
            cert_bytes: Complete ASN.1 OER encoded certificate
            root_ca_public_key: Root CA public key for verification
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Extract TBS and signature
        tbs_length = struct.unpack(">H", cert_bytes[0:2])[0]
        tbs_cert = cert_bytes[2:2+tbs_length]
        
        sig_type_offset = 2 + tbs_length
        signature_offset = sig_type_offset + 1
        signature = cert_bytes[signature_offset:signature_offset+64]
        
        # Convert raw signature to DER format for cryptography library
        r = int.from_bytes(signature[:32], byteorder='big')
        s = int.from_bytes(signature[32:], byteorder='big')
        
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        der_signature = encode_dss_signature(r, s)
        
        # Verify signature
        try:
            root_ca_public_key.verify(
                der_signature,
                tbs_cert,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False


# ============================================================================
# HIGH-LEVEL HELPER FUNCTIONS (DRY - Reusable across entities)
# ============================================================================

def generate_authority_certificate(
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
    High-level function to generate Authority Certificate.
    
    This function orchestrates the complete flow:
    1. Compute Root CA HashedId8
    2. Encode ToBeSignedCertificate
    3. Sign with Root CA
    4. Assemble complete certificate
    
    Args:
        root_ca_cert_asn1: Root CA certificate in ASN.1 OER (for HashedId8)
        root_ca_private_key: Root CA signing key
        authority_public_key: Authority public key
        authority_id: Authority identifier (e.g., "EA_001")
        authority_type: "EA" or "AA"
        duration_years: Validity in years (default 5)
        country: Country code (default "IT")
        organization: Organization name
        
    Returns:
        bytes: Complete Authority Certificate (ASN.1 OER)
    """
    encoder = ETSIAuthorityCertificateEncoder()
    
    # Compute Root CA HashedId8
    root_ca_hashed_id8 = encoder.compute_hashed_id8(root_ca_cert_asn1)
    
    # Start validity: now
    start_validity = datetime.now(timezone.utc)
    
    # Encode TBS
    tbs_cert = encoder.encode_to_be_signed_authority_cert(
        issuer_hashed_id8=root_ca_hashed_id8,
        subject_public_key=authority_public_key,
        start_validity=start_validity,
        duration_years=duration_years,
        authority_id=authority_id,
        authority_type=authority_type,
        country=country,
        organization=organization,
    )
    
    # Sign with Root CA (ECDSA-SHA256, raw format)
    signature_der = root_ca_private_key.sign(
        tbs_cert,
        ec.ECDSA(hashes.SHA256())
    )
    
    # Convert DER signature to raw R||S format (64 bytes)
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(signature_der)
    signature_raw = r.to_bytes(32, byteorder='big') + s.to_bytes(32, byteorder='big')
    
    # Assemble complete certificate
    authority_certificate = encoder.encode_full_authority_certificate(
        issuer_hashed_id8=root_ca_hashed_id8,
        subject_public_key=authority_public_key,
        start_validity=start_validity,
        duration_years=duration_years,
        authority_id=authority_id,
        root_ca_signature=signature_raw,
        authority_type=authority_type,
        country=country,
        organization=organization,
    )
    
    return authority_certificate
