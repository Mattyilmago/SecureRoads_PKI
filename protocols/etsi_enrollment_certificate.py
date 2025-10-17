"""
ETSI Enrollment Certificate Encoder - ASN.1 OER Implementation

Implements Enrollment Certificate (EC) encoding/decoding per ETSI TS 103097 V2.1.1
using ASN.1 Octet Encoding Rules (OER) as specified in ISO/IEC 8825-7:2015.

Enrollment Certificates are long-lived certificates used by ITS Stations to obtain
Authorization Tickets from Authorization Authorities.

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Standard
- ISO/IEC 8825-7:2015 - ASN.1 OER Encoding Rules

Certificate Structure:
    EtsiTs103097Certificate ::= SEQUENCE {
        version Uint8(3),                    -- ETSI TS 103097 v2.1.1
        type CertificateType(enrollment),    -- Type = 2 for EC
        issuer IssuerIdentifier,             -- HashedId8 of EA
        toBeSigned ToBeSignedCertificate,
        signature Signature                   -- ECDSA-SHA256
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
    CERT_TYPE_ENROLLMENT,
    compute_hashed_id8,
    encode_public_key_compressed,
    time32_decode,
    time32_encode,
)


class ETSIEnrollmentCertificateEncoder:
    """
    Encoder/Decoder for ETSI Enrollment Certificates in ASN.1 OER format.
    
    Implements certificate generation, signing, verification, and serialization
    according to ETSI TS 103097 V2.1.1 standards.
    
    Uses centralized ETSI utilities from etsi_message_types module (DRY compliance).
    """

    def __init__(self):
        """Initialize Enrollment Certificate Encoder"""
        pass

    # Delegate to centralized utilities from etsi_message_types (DRY compliance)
    compute_hashed_id8 = staticmethod(compute_hashed_id8)
    time32_encode = staticmethod(time32_encode)
    time32_decode = staticmethod(time32_decode)
    encode_public_key = staticmethod(encode_public_key_compressed)

    def encode_subject_attributes(
        self,
        its_id: str,
        country: str = "IT",
        organization: str = "ITS-S"
    ) -> bytes:
        """
        Encode subject attributes for EC.
        
        Args:
            its_id: ITS Station ID (Common Name)
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
        
        # ITS ID length + value
        its_id_bytes = its_id.encode('utf-8')
        encoded.append(min(len(its_id_bytes), 255))  # Length (1 byte, max 255)
        encoded.extend(its_id_bytes[:255])
        
        return bytes(encoded)

    def encode_to_be_signed_ec(
        self,
        issuer_hashed_id8: bytes,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_days: int,
        its_id: str,
        country: str = "IT",
        organization: str = "ITS-S"
    ) -> bytes:
        """
        Encode ToBeSignedCertificate for Enrollment Certificate.
        
        ETSI TS 103097 Section 6.4.12:
        ToBeSignedCertificate ::= SEQUENCE {
            id CertificateId,              -- ITS ID
            cracaId HashedId3,             -- Optional
            crlSeries Uint16,              -- Optional
            validityPeriod ValidityPeriod,
            region GeographicRegion,       -- Optional (not used for EC)
            assuranceLevel SubjectAssurance, -- Optional
            appPermissions SequenceOfPsidSsp, -- Not used for EC
            certIssuePermissions ...,      -- Not used for EC
            certRequestPermissions ...,    -- Used for EC
            verifyKeyIndicator VerificationKeyIndicator
        }
        
        Args:
            issuer_hashed_id8: HashedId8 of issuing EA (8 bytes)
            subject_public_key: Public key for EC
            start_validity: Certificate start time
            duration_days: Validity duration in days (typically 90)
            its_id: ITS Station ID
            country: Country code (default "IT")
            organization: Organization name (default "ITS-S")
            
        Returns:
            bytes: ToBeSignedCertificate encoded in ASN.1 OER
        """
        tbs = bytearray()
        
        # 1. Version (1 byte) - ETSI TS 103097 v2.1.1 = version 3
        tbs.append(3)
        
        # 2. Certificate Type (1 byte) - Enrollment Certificate
        tbs.append(CERT_TYPE_ENROLLMENT)
        
        # 3. Issuer (1 + 8 bytes) - HashedId8 of EA
        if len(issuer_hashed_id8) != 8:
            raise ValueError(f"issuer_hashed_id8 must be 8 bytes, got {len(issuer_hashed_id8)}")
        tbs.append(0x00)  # IssuerIdentifier choice: sha256AndDigest
        tbs.extend(issuer_hashed_id8)
        
        # 4. Validity Period (4 + 4 bytes) - start Time32 + duration seconds
        start_time32 = self.time32_encode(start_validity)
        duration_seconds = duration_days * 86400  # days to seconds
        tbs.extend(struct.pack('>II', start_time32, duration_seconds))
        
        # 5. Geographic Region (optional) - NOT PRESENT for EC
        tbs.append(0x00)  # Not present
        
        # 6. Subject Assurance Level (optional) - NOT PRESENT for EC
        tbs.append(0x00)  # Not present
        
        # 7. Application Permissions - NOT PRESENT for EC (used by AT)
        tbs.append(0x00)  # Not present (0 permissions)
        
        # 8. Certificate Issue Permissions - NOT PRESENT for EC
        tbs.append(0x00)
        
        # 9. Certificate Request Permissions - PRESENT for EC (can request AT)
        # Simplified: just a flag indicating EC can request AT
        tbs.append(0x01)  # Present
        tbs.append(0x01)  # Can request Authorization Tickets
        
        # 10. Subject Attributes (ITS ID, country, org)
        subject_attrs = self.encode_subject_attributes(its_id, country, organization)
        tbs.extend(subject_attrs)
        
        # 11. Verification Key Indicator (1 + 33 bytes) - Public Key
        tbs.append(0x00)  # VerificationKeyIndicator: verificationKey
        compressed_key = self.encode_public_key(subject_public_key)
        tbs.extend(compressed_key)
        
        return bytes(tbs)

    def sign_enrollment_certificate(
        self,
        tbs_certificate: bytes,
        ea_private_key: EllipticCurvePrivateKey,
    ) -> bytes:
        """
        Sign ToBeSignedCertificate with EA private key.
        
        Uses ECDSA-SHA256 with raw signature format (r || s, 64 bytes).
        
        ETSI TS 103097 Section 5.3.1:
        Signature ::= CHOICE {
            ecdsaNistP256Signature EcdsaP256Signature,  -- 64 bytes
            ...
        }
        
        EcdsaP256Signature ::= SEQUENCE {
            rSig EccP256CurvePoint,  -- r value (32 bytes)
            sSig OCTET STRING (SIZE(32))  -- s value (32 bytes)
        }
        
        Args:
            tbs_certificate: ToBeSignedCertificate bytes
            ea_private_key: EA's ECDSA private key
            
        Returns:
            bytes: Raw ECDSA signature (64 bytes: r || s)
        """
        # Sign using ECDSA-SHA256
        der_signature = ea_private_key.sign(
            tbs_certificate,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Convert DER signature to raw format (r || s)
        # DER format: 0x30 [len] 0x02 [len_r] [r] 0x02 [len_s] [s]
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
        r, s = decode_dss_signature(der_signature)
        
        # Convert to 32-byte big-endian format
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')
        
        return r_bytes + s_bytes

    def encode_full_enrollment_certificate(
        self,
        issuer_hashed_id8: bytes,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_days: int,
        its_id: str,
        ea_private_key: EllipticCurvePrivateKey,
        country: str = "IT",
        organization: str = "ITS-S"
    ) -> bytes:
        """
        Encode complete signed Enrollment Certificate.
        
        Full Certificate Structure:
            [ToBeSigned Length (2)] [ToBeSigned] [Signature Type (1)] [Signature (64)]
        
        Args:
            issuer_hashed_id8: HashedId8 of EA (8 bytes)
            subject_public_key: EC public key
            start_validity: Start time
            duration_days: Validity period (typically 90 days)
            its_id: ITS Station ID
            ea_private_key: EA signing key
            country: Country code (default "IT")
            organization: Organization name (default "ITS-S")
            
        Returns:
            bytes: Complete ASN.1 OER encoded Enrollment Certificate
        """
        # 1. Encode ToBeSignedCertificate
        tbs_cert = self.encode_to_be_signed_ec(
            issuer_hashed_id8=issuer_hashed_id8,
            subject_public_key=subject_public_key,
            start_validity=start_validity,
            duration_days=duration_days,
            its_id=its_id,
            country=country,
            organization=organization,
        )
        
        # 2. Sign TBS certificate
        signature = self.sign_enrollment_certificate(tbs_cert, ea_private_key)
        
        # 3. Build full certificate: [TBS_LEN(2)] [TBS] [SIG_TYPE(1)] [SIG(64)]
        full_cert = bytearray()
        
        # TBS length (2 bytes, big-endian)
        full_cert.extend(struct.pack('>H', len(tbs_cert)))
        
        # TBS certificate
        full_cert.extend(tbs_cert)
        
        # Signature type (1 byte) - 0x00 = ecdsaNistP256Signature
        full_cert.append(0x00)
        
        # Signature (64 bytes)
        if len(signature) != 64:
            raise ValueError(f"Invalid signature length: {len(signature)} bytes")
        full_cert.extend(signature)
        
        return bytes(full_cert)

    def verify_enrollment_certificate_signature(
        self,
        full_certificate: bytes,
        ea_public_key: EllipticCurvePublicKey,
    ) -> bool:
        """
        Verify Enrollment Certificate signature.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded EC
            ea_public_key: EA's public key for verification
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # 1. Extract TBS and signature
            if len(full_certificate) < 67:  # Minimum: 2 + 1 + 1 + 64
                return False
            
            # Read TBS length (2 bytes)
            tbs_len = struct.unpack('>H', full_certificate[0:2])[0]
            
            # Extract TBS
            tbs_cert = full_certificate[2:2+tbs_len]
            
            # Extract signature type (1 byte)
            sig_type = full_certificate[2+tbs_len]
            if sig_type != 0x00:  # Only ECDSA-P256 supported
                return False
            
            # Extract signature (64 bytes)
            signature_raw = full_certificate[2+tbs_len+1:2+tbs_len+1+64]
            if len(signature_raw) != 64:
                return False
            
            # 2. Convert raw signature to DER format
            r_bytes = signature_raw[:32]
            s_bytes = signature_raw[32:64]
            r_int = int.from_bytes(r_bytes, byteorder='big')
            s_int = int.from_bytes(s_bytes, byteorder='big')
            
            from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
            der_signature = encode_dss_signature(r_int, s_int)
            
            # 3. Verify signature
            ea_public_key.verify(
                der_signature,
                tbs_cert,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        
        except Exception as e:
            print(f"[EC VERIFICATION] Signature verification failed: {e}")
            return False

    def decode_enrollment_certificate(
        self,
        full_certificate: bytes,
    ) -> Dict[str, any]:
        """
        Decode Enrollment Certificate to human-readable dict.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded EC
            
        Returns:
            dict: Decoded certificate fields
        """
        try:
            # Read TBS length
            tbs_len = struct.unpack('>H', full_certificate[0:2])[0]
            tbs_cert = full_certificate[2:2+tbs_len]
            
            # Parse TBS certificate
            offset = 0
            result = {}
            
            # Version (1 byte)
            result['version'] = tbs_cert[offset]
            offset += 1
            
            # Certificate Type (1 byte)
            result['type'] = 'Enrollment' if tbs_cert[offset] == 2 else 'Unknown'
            offset += 1
            
            # Issuer (1 + 8 bytes)
            issuer_type = tbs_cert[offset]
            offset += 1
            result['issuer_hashed_id8'] = tbs_cert[offset:offset+8].hex()
            offset += 8
            
            # Validity Period (8 bytes)
            start_time32, duration_sec = struct.unpack('>II', tbs_cert[offset:offset+8])
            offset += 8
            result['start_validity'] = self.time32_decode(start_time32).isoformat()
            result['duration_days'] = duration_sec // 86400
            result['expiry'] = (self.time32_decode(start_time32) + timedelta(seconds=duration_sec)).isoformat()
            
            # Geographic region (optional) - skip if present
            has_region = tbs_cert[offset]
            offset += 1
            
            # Subject assurance (optional) - skip if present
            has_assurance = tbs_cert[offset]
            offset += 1
            
            # App permissions - skip (0 for EC)
            num_perms = tbs_cert[offset]
            offset += 1
            
            # Cert issue permissions - skip
            has_issue = tbs_cert[offset]
            offset += 1
            
            # Cert request permissions - skip but note
            has_request = tbs_cert[offset]
            offset += 1
            if has_request:
                result['can_request_at'] = bool(tbs_cert[offset])
                offset += 1
            
            # Signature
            sig_start = 2 + tbs_len + 1
            result['signature'] = full_certificate[sig_start:sig_start+64].hex()
            
            # HashedId8 of this certificate
            result['hashed_id8'] = self.compute_hashed_id8(full_certificate).hex()
            
            return result
        
        except Exception as e:
            return {'error': f'Decoding failed: {e}'}

    def extract_public_key(
        self,
        full_certificate: bytes,
    ) -> EllipticCurvePublicKey:
        """
        Extract public key from Enrollment Certificate.
        
        Parses the ASN.1 OER encoded certificate and extracts the compressed
        public key, then decompresses it to return a usable EllipticCurvePublicKey.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded EC
            
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
            
            # Skip: Validity period (8 bytes)
            offset += 8
            
            # Skip: Geographic region (1 byte presence flag + optional data)
            has_region = tbs_cert[offset]
            offset += 1
            if has_region:
                offset += 10  # Lat (4) + Lon (4) + Radius (2)
            
            # Skip: Subject assurance (1 byte presence flag)
            has_assurance = tbs_cert[offset]
            offset += 1
            
            # Skip: App permissions (1 byte count)
            num_perms = tbs_cert[offset]
            offset += 1
            # Skip permission entries (simplified - assume 2 bytes each)
            offset += num_perms * 2
            
            # Skip: Cert issue permissions (1 byte)
            has_issue = tbs_cert[offset]
            offset += 1
            
            # Skip: Cert request permissions (1 + optional 1 byte)
            has_request = tbs_cert[offset]
            offset += 1
            if has_request:
                offset += 1
            
            # Skip: Subject attributes (variable length)
            # Country (2 bytes)
            offset += 2
            # Organization length + value
            org_len = tbs_cert[offset]
            offset += 1 + org_len
            # ITS ID length + value
            its_id_len = tbs_cert[offset]
            offset += 1 + its_id_len
            
            # Now at Verification Key Indicator
            key_indicator = tbs_cert[offset]
            offset += 1
            
            if key_indicator != 0x00:  # Must be verificationKey (not reconstructionValue)
                raise ValueError(f"Unexpected key indicator: 0x{key_indicator:02x}")
            
            # Extract compressed public key (33 bytes)
            compressed_key = tbs_cert[offset:offset+33]
            
            if len(compressed_key) != 33:
                raise ValueError(f"Invalid compressed key length: {len(compressed_key)}")
            
            # Decompress and return public key
            return decode_public_key_compressed(compressed_key)
            
        except Exception as e:
            raise ValueError(f"Failed to extract public key from certificate: {e}")

    def export_to_json(
        self,
        full_certificate: bytes,
    ) -> dict:
        """
        Export Enrollment Certificate to JSON-compatible dict.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded EC
            
        Returns:
            dict: JSON-serializable certificate data
        """
        decoded = self.decode_enrollment_certificate(full_certificate)
        return {
            'certificate_type': 'EnrollmentCertificate',
            'format': 'ASN.1 OER (ETSI TS 103097)',
            'size_bytes': len(full_certificate),
            'data': decoded,
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def generate_enrollment_certificate(
    ea_certificate_oer: bytes,
    ea_private_key: EllipticCurvePrivateKey,
    subject_public_key: EllipticCurvePublicKey,
    its_id: str,
    duration_days: int = 90,
    country: str = "IT",
    organization: str = "ITS-S"
) -> bytes:
    """
    High-level function to generate Enrollment Certificate.
    
    Args:
        ea_certificate_oer: EA certificate in ASN.1 OER (for HashedId8)
        ea_private_key: EA signing key
        subject_public_key: ITS-S public key for EC
        its_id: ITS Station ID
        duration_days: EC validity (default 90 days)
        country: Country code (default "IT")
        organization: Organization name (default "ITS-S")
        
    Returns:
        bytes: Complete Enrollment Certificate (ASN.1 OER)
    """
    encoder = ETSIEnrollmentCertificateEncoder()
    
    # Compute EA's HashedId8
    ea_hashed_id8 = encoder.compute_hashed_id8(ea_certificate_oer)
    
    # Start validity: now
    start_validity = datetime.now(timezone.utc)
    
    # Generate EC
    ec_certificate = encoder.encode_full_enrollment_certificate(
        issuer_hashed_id8=ea_hashed_id8,
        subject_public_key=subject_public_key,
        start_validity=start_validity,
        duration_days=duration_days,
        its_id=its_id,
        ea_private_key=ea_private_key,
        country=country,
        organization=organization,
    )
    
    return ec_certificate
