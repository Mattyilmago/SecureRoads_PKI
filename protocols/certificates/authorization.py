"""
ETSI Authorization Ticket Encoder - ASN.1 OER Implementation

Implements Authorization Ticket (AT) certificate encoding/decoding per ETSI TS 103097 V2.1.1
using ASN.1 Octet Encoding Rules (OER) as specified in ISO/IEC 8825-7:2015.

Authorization Tickets are short-lived certificates used by ITS Stations for V2X communication.
They provide pseudonymity and unlinkability while maintaining security and privacy.

Standards Reference:
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- IEEE 1609.2 - WAVE Security Standard
- ISO/IEC 8825-7:2015 - ASN.1 OER Encoding Rules

Certificate Structure:
    EtsiTs103097Certificate ::= SEQUENCE {
        version Uint8(3),                    -- ETSI TS 103097 v2.1.1
        type CertificateType(authorization), -- Type = 1 for AT
        issuer IssuerIdentifier,             -- HashedId8 of AA
        toBeSigned ToBeSignedCertificate,
        signature Signature                   -- ECDSA-SHA256
    }

Author: SecureRoad PKI Project
Date: October 2025
"""

import struct
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

# Import from new modular structure
from protocols.core.types import CERT_TYPE_AUTHORIZATION
from protocols.core.primitives import (
    compute_hashed_id8,
    encode_public_key_compressed,
    decode_public_key_compressed,
    time32_decode,
    time32_encode,
)
from protocols.core.crypto import sign_data_ecdsa_sha256


class AuthorizationTicket:
    """
    Encoder/Decoder for ETSI Authorization Tickets in ASN.1 OER format.
    
    Implements certificate generation, signing, verification, and serialization
    according to ETSI TS 103097 V2.1.1 standards.
    
    Uses centralized ETSI utilities from etsi_message_types module (DRY compliance).
    """

    # ITS Application IDs (ETSI TS 102965)
    # Solo CAM e DENM supportati per questo progetto
    ITS_APP_IDS = {
        'CAM': 36,   # Cooperative Awareness Message (ETSI EN 302 637-2)
        'DENM': 37,  # Decentralized Environmental Notification Message (ETSI EN 302 637-3)
    }

    def __init__(self):
        """Initialize Authorization Ticket Encoder"""
        pass

    # Delegate to centralized utilities from etsi_message_types (DRY compliance)
    compute_hashed_id8 = staticmethod(compute_hashed_id8)
    time32_encode = staticmethod(time32_encode)
    time32_decode = staticmethod(time32_decode)
    encode_public_key = staticmethod(encode_public_key_compressed)

    def encode_app_permissions(
        self, 
        app_permissions: List[str],
        priority: Optional[int] = None
    ) -> bytes:
        """
        Encode ITS application permissions (PSIDs).
        
        ETSI TS 102965 - ITS Application Identifiers
        
        Args:
            app_permissions: List of ITS app names (e.g., ['CAM', 'DENM'])
            priority: Optional traffic priority (0-7)
            
        Returns:
            bytes: Encoded permissions (variable length)
        """
        encoded = bytearray()
        
        # Number of permissions (1 byte)
        encoded.append(len(app_permissions))
        
        for app_name in app_permissions:
            if app_name not in self.ITS_APP_IDS:
                raise ValueError(f"Unknown ITS application: {app_name}")
            
            psid = self.ITS_APP_IDS[app_name]
            # PSID as varint (simplified: 1-2 bytes for values < 128)
            if psid < 128:
                encoded.append(psid)
            else:
                encoded.append(0x80 | (psid >> 8))
                encoded.append(psid & 0xFF)
        
        # Priority (optional, 1 byte)
        if priority is not None:
            encoded.append(min(max(priority, 0), 7))  # Clamp 0-7
        
        return bytes(encoded)

    def encode_geographic_region(
        self, 
        latitude: float, 
        longitude: float, 
        radius_m: int = 1000
    ) -> bytes:
        """
        Encode geographic region as circular region.
        
        ETSI TS 103097 Section 6.4.30:
        CircularRegion ::= SEQUENCE {
            center TwoDLocation,
            radius Uint16  -- meters
        }
        
        TwoDLocation ::= SEQUENCE {
            latitude Latitude,   -- 1/10 microdegree (-900000000..900000001)
            longitude Longitude  -- 1/10 microdegree (-1800000000..1800000001)
        }
        
        Args:
            latitude: Latitude in degrees (-90.0 to 90.0)
            longitude: Longitude in degrees (-180.0 to 180.0)
            radius_m: Radius in meters (default 1000m = 1km)
            
        Returns:
            bytes: Encoded geographic region (12 bytes)
        """
        # Convert to 1/10 microdegree (ETSI format)
        lat_int = int(latitude * 10_000_000)
        lon_int = int(longitude * 10_000_000)
        
        # Validate ranges
        if not (-900_000_000 <= lat_int <= 900_000_001):
            raise ValueError(f"Latitude out of range: {latitude}")
        if not (-1_800_000_000 <= lon_int <= 1_800_000_001):
            raise ValueError(f"Longitude out of range: {longitude}")
        
        # Encode: lat (4 bytes) + lon (4 bytes) + radius (2 bytes)
        encoded = struct.pack('>iih', lat_int, lon_int, radius_m)
        return encoded

    def encode_to_be_signed_at(
        self,
        issuer_hashed_id8: bytes,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_hours: int,
        app_permissions: List[str],
        geographic_region: Optional[Tuple[float, float, int]] = None,
        priority: Optional[int] = None,
    ) -> bytes:
        """
        Encode ToBeSignedCertificate for Authorization Ticket.
        
        ETSI TS 103097 Section 6.4.12:
        ToBeSignedCertificate ::= SEQUENCE {
            id CertificateId,              -- Optional
            cracaId HashedId3,             -- Optional
            crlSeries Uint16,              -- Optional
            validityPeriod ValidityPeriod,
            region GeographicRegion,       -- Optional
            assuranceLevel SubjectAssurance, -- Optional
            appPermissions SequenceOfPsidSsp, -- ITS apps
            certIssuePermissions ...,      -- Not used for AT
            certRequestPermissions ...,    -- Not used for AT
            verifyKeyIndicator VerificationKeyIndicator
        }
        
        Args:
            issuer_hashed_id8: HashedId8 of issuing AA (8 bytes)
            subject_public_key: Public key for AT
            start_validity: Certificate start time
            duration_hours: Validity duration in hours (1-168 typical)
            app_permissions: ITS applications (e.g., ['CAM', 'DENM'])
            geographic_region: Optional (lat, lon, radius_m) tuple
            priority: Optional traffic priority (0-7)
            
        Returns:
            bytes: ToBeSignedCertificate encoded in ASN.1 OER
        """
        tbs = bytearray()
        
        # 1. Version (1 byte) - ETSI TS 103097 v2.1.1 = version 3
        tbs.append(3)
        
        # 2. Certificate Type (1 byte) - Authorization Ticket
        tbs.append(CERT_TYPE_AUTHORIZATION)
        
        # 3. Issuer (1 + 8 bytes) - HashedId8 of AA
        if len(issuer_hashed_id8) != 8:
            raise ValueError(f"issuer_hashed_id8 must be 8 bytes, got {len(issuer_hashed_id8)}")
        tbs.append(0x00)  # IssuerIdentifier choice: sha256AndDigest
        tbs.extend(issuer_hashed_id8)
        
        # 4. Validity Period (start Time32 + Duration CHOICE)
        start_time32 = self.time32_encode(start_validity)
        tbs.extend(struct.pack('>I', start_time32))
        
        # Encode Duration as CHOICE (OER tag required)
        # Tag 0x84 = hours (Uint16)
        tbs.append(0x84)  # hours
        tbs.extend(struct.pack('>H', min(duration_hours, 65535)))
        
        # 5. Geographic Region (optional, 1 + 12 bytes if present)
        if geographic_region:
            tbs.append(0x01)  # Present flag
            lat, lon, radius = geographic_region
            tbs.extend(self.encode_geographic_region(lat, lon, radius))
        else:
            tbs.append(0x00)  # Not present
        
        # 6. Subject Assurance Level (optional, 1 + 1 byte if present)
        # For AT, typically not present (only for long-term certificates)
        tbs.append(0x00)  # Not present
        
        # 7. Application Permissions (variable length)
        app_perms_bytes = self.encode_app_permissions(app_permissions, priority)
        tbs.extend(app_perms_bytes)
        
        # 8. Certificate Issue Permissions - NOT PRESENT for AT
        tbs.append(0x00)
        
        # 9. Certificate Request Permissions - NOT PRESENT for AT
        tbs.append(0x00)
        
        # 10. Verification Key Indicator (1 + 33 bytes) - Public Key
        tbs.append(0x00)  # VerificationKeyIndicator: verificationKey
        compressed_key = self.encode_public_key(subject_public_key)
        tbs.extend(compressed_key)
        
        return bytes(tbs)

    def sign_authorization_ticket(
        self,
        tbs_certificate: bytes,
        aa_private_key: EllipticCurvePrivateKey,
    ) -> bytes:
        """
        Sign ToBeSignedCertificate with AA private key.
        
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
            aa_private_key: AA's ECDSA private key
            
        Returns:
            bytes: Raw ECDSA signature (64 bytes: r || s)
        """
        # Sign using ECDSA-SHA256
        der_signature = aa_private_key.sign(
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

    def encode_full_authorization_ticket(
        self,
        issuer_hashed_id8: bytes,
        subject_public_key: EllipticCurvePublicKey,
        start_validity: datetime,
        duration_hours: int,
        app_permissions: List[str],
        aa_private_key: EllipticCurvePrivateKey,
        geographic_region: Optional[Tuple[float, float, int]] = None,
        priority: Optional[int] = None,
    ) -> bytes:
        """
        Encode complete signed Authorization Ticket certificate.
        
        Full Certificate Structure:
            [ToBeSigned Length (2)] [ToBeSigned] [Signature Type (1)] [Signature (64)]
        
        Args:
            issuer_hashed_id8: HashedId8 of AA (8 bytes)
            subject_public_key: AT public key
            start_validity: Start time
            duration_hours: Validity period (1-168 hours typical)
            app_permissions: ITS apps (['CAM', 'DENM'])
            aa_private_key: AA signing key
            geographic_region: Optional (lat, lon, radius_m)
            priority: Optional priority (0-7)
            
        Returns:
            bytes: Complete ASN.1 OER encoded Authorization Ticket
        """
        # 1. Encode ToBeSignedCertificate
        tbs_cert = self.encode_to_be_signed_at(
            issuer_hashed_id8=issuer_hashed_id8,
            subject_public_key=subject_public_key,
            start_validity=start_validity,
            duration_hours=duration_hours,
            app_permissions=app_permissions,
            geographic_region=geographic_region,
            priority=priority,
        )
        
        # 2. Sign TBS certificate
        signature = self.sign_authorization_ticket(tbs_cert, aa_private_key)
        
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

    def verify_authorization_ticket_signature(
        self,
        full_certificate: bytes,
        aa_public_key: EllipticCurvePublicKey,
    ) -> bool:
        """
        Verify Authorization Ticket signature using centralized function.
        
        Uses verify_asn1_certificate_signature() for consistent ETSI-compliant
        signature verification across all certificate types.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded AT
            aa_public_key: AA's public key for verification
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        from protocols.certificates.utils import verify_asn1_certificate_signature
        
        try:
            # Use centralized ASN.1 signature verification (DRY principle)
            return verify_asn1_certificate_signature(full_certificate, aa_public_key)
        except Exception:
            return False

    def decode_authorization_ticket(
        self,
        full_certificate: bytes,
    ) -> Dict[str, any]:
        """
        Decode Authorization Ticket to human-readable dict.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded AT
            
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
            result['type'] = 'Authorization' if tbs_cert[offset] == 1 else 'Unknown'
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
            result['duration_hours'] = duration_sec // 3600
            result['expiry'] = (self.time32_decode(start_time32) + timedelta(seconds=duration_sec)).isoformat()
            
            # Geographic region (optional)
            has_region = tbs_cert[offset]
            offset += 1
            if has_region:
                lat_int, lon_int, radius = struct.unpack('>iih', tbs_cert[offset:offset+10])
                result['geographic_region'] = {
                    'latitude': lat_int / 10_000_000,
                    'longitude': lon_int / 10_000_000,
                    'radius_m': radius
                }
                offset += 10
            
            # Subject assurance (optional)
            has_assurance = tbs_cert[offset]
            offset += 1
            
            # App permissions (simplified parsing)
            num_perms = tbs_cert[offset]
            offset += 1
            result['app_permissions'] = []
            for _ in range(num_perms):
                psid = tbs_cert[offset]
                offset += 1
                # Reverse lookup
                for app_name, app_id in self.ITS_APP_IDS.items():
                    if app_id == psid:
                        result['app_permissions'].append(app_name)
                        break
            
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
        Extract public key from Authorization Ticket using ASN.1 decoder.
        
        Uses the centralized extract_public_key_from_asn1_certificate() function
        to properly decode the certificate structure according to ETSI TS 103097.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded AT
            
        Returns:
            EllipticCurvePublicKey: Extracted and decompressed public key
            
        Raises:
            ValueError: If certificate is malformed or key cannot be extracted
        """
        from protocols.certificates.utils import extract_public_key_from_asn1_certificate
        
        try:
            # Use centralized ASN.1 decoder-based extraction (DRY principle)
            return extract_public_key_from_asn1_certificate(full_certificate)
        except Exception as e:
            raise ValueError(f"Failed to extract public key from AT certificate: {e}")

    def export_to_json(
        self,
        full_certificate: bytes,
    ) -> dict:
        """
        Export Authorization Ticket to JSON-compatible dict.
        
        Args:
            full_certificate: Complete ASN.1 OER encoded AT
            
        Returns:
            dict: JSON-serializable certificate data
        """
        decoded = self.decode_authorization_ticket(full_certificate)
        return {
            'certificate_type': 'AuthorizationTicket',
            'format': 'ASN.1 OER (ETSI TS 103097)',
            'size_bytes': len(full_certificate),
            'data': decoded,
        }


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def generate_authorization_ticket(
    aa_certificate_oer: bytes,
    aa_private_key: EllipticCurvePrivateKey,
    subject_public_key: EllipticCurvePublicKey,
    duration_hours: int = 24,
    app_permissions: Optional[List[str]] = None,
    geographic_region: Optional[Tuple[float, float, int]] = None,
) -> bytes:
    """
    High-level function to generate Authorization Ticket.
    
    Args:
        aa_certificate_oer: AA certificate in ASN.1 OER (for HashedId8)
        aa_private_key: AA signing key
        subject_public_key: ITS-S public key for AT
        duration_hours: AT validity (default 24h)
        app_permissions: ITS apps (default ['CAM', 'DENM'])
        geographic_region: Optional (lat, lon, radius_m)
        
    Returns:
        bytes: Complete Authorization Ticket (ASN.1 OER)
    """
    encoder = AuthorizationTicket()
    
    # Compute AA's HashedId8
    aa_hashed_id8 = encoder.compute_hashed_id8(aa_certificate_oer)
    
    # Default permissions: CAM e DENM (messaggi V2X standard)
    if app_permissions is None:
        app_permissions = ['CAM', 'DENM']
    
    # Start validity: now
    start_validity = datetime.now(timezone.utc)
    
    # Generate AT
    at_certificate = encoder.encode_full_authorization_ticket(
        issuer_hashed_id8=aa_hashed_id8,
        subject_public_key=subject_public_key,
        start_validity=start_validity,
        duration_hours=duration_hours,
        app_permissions=app_permissions,
        aa_private_key=aa_private_key,
        geographic_region=geographic_region,
    )
    
    return at_certificate


# Backward compatibility
ETSIAuthorizationTicketEncoder = AuthorizationTicket
__all__ = ['AuthorizationTicket', 'ETSIAuthorizationTicketEncoder']
