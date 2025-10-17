"""
ETSI TS 102941 Link Certificate Encoding (ASN.1 OER)

Implementa la codifica ASN.1 OER per Link Certificates secondo lo standard
ETSI TS 102941 V2.1.1 Section 6.4.

Standard Reference:
- ETSI TS 102941 V2.1.1 (2023-11) - Trust and Privacy Management
- ETSI TS 103097 V2.1.1 (2023-08) - Security Header and Certificate Formats
- IEEE 1609.2 - Wireless Access in Vehicular Environments (WAVE)

ASN.1 Schema:
    ToBeSignedLinkCertificate ::= SEQUENCE {
        certificateHash HashedId8,
        issuerCertificate Certificate,
        expiryTime Time32,
        ...
    }

    LinkCertificate ::= SEQUENCE {
        content ToBeSignedLinkCertificate,
        signature Signature
    }

Author: SecureRoad PKI Project
Date: October 2025
"""

import json
import struct
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Import centralized ETSI utilities from etsi_message_types (DRY compliance)
from protocols.etsi_message_types import compute_hashed_id8, time32_decode, time32_encode


class ETSILinkCertificateEncoder:
    """
    Codifica e decodifica Link Certificates in formato ASN.1 OER ETSI-compliant.

    Supporta:
    - Codifica ToBeSignedLinkCertificate
    - Firma ECDSA con curve NIST P-256
    - HashedId8 computation
    - Time32 encoding (Unix timestamp 32-bit)
    
    Uses centralized ETSI utilities from etsi_message_types module (DRY compliance).
    """

    # ETSI TS 102941 constants
    LINK_CERTIFICATE_VERSION = 1
    SIGNATURE_ALGORITHM_ECDSA_SHA256 = 0

    # Delegate to centralized utilities from etsi_message_types (DRY compliance)
    compute_hashed_id8 = staticmethod(compute_hashed_id8)
    time32_encode = staticmethod(time32_encode)
    time32_decode = staticmethod(time32_decode)

    def encode_to_be_signed_link_certificate(
        self,
        issuer_cert_der: bytes,
        subject_cert_der: bytes,
        expiry_time: datetime,
    ) -> bytes:
        """
        Codifica ToBeSignedLinkCertificate in ASN.1 OER.

        ETSI TS 102941 Section 6.4:
        ToBeSignedLinkCertificate ::= SEQUENCE {
            certificateHash HashedId8,      -- 8 bytes
            issuerCertificate Certificate,  -- DER-encoded issuer cert
            expiryTime Time32,              -- 4 bytes
        }

        Args:
            issuer_cert_der: Certificato issuer (RootCA) in DER
            subject_cert_der: Certificato subject (EA/AA) in DER
            expiry_time: Scadenza del link certificate

        Returns:
            bytes: ToBeSignedLinkCertificate codificato
        """
        # 1. HashedId8 del certificato subject
        cert_hash = self.compute_hashed_id8(subject_cert_der)

        # 2. Time32 per expiry
        time32 = self.time32_encode(expiry_time)

        # 3. Costruisci struttura ASN.1 OER
        # Formato semplificato: [hash(8) | issuer_len(2) | issuer_cert | time32(4)]
        encoded = bytearray()

        # HashedId8 (8 bytes)
        encoded.extend(cert_hash)

        # Issuer Certificate length (2 bytes, big-endian)
        encoded.extend(struct.pack(">H", len(issuer_cert_der)))

        # Issuer Certificate (variable length)
        encoded.extend(issuer_cert_der)

        # Time32 (4 bytes, big-endian)
        encoded.extend(struct.pack(">I", time32))

        return bytes(encoded)

    def decode_to_be_signed_link_certificate(self, encoded: bytes) -> Dict:
        """
        Decodifica ToBeSignedLinkCertificate da ASN.1 OER.

        Args:
            encoded: Bytes codificati

        Returns:
            Dict con campi decodificati
        """
        offset = 0

        # HashedId8 (8 bytes)
        cert_hash = encoded[offset : offset + 8]
        offset += 8

        # Issuer Certificate length (2 bytes)
        issuer_len = struct.unpack(">H", encoded[offset : offset + 2])[0]
        offset += 2

        # Issuer Certificate
        issuer_cert_der = encoded[offset : offset + issuer_len]
        offset += issuer_len

        # Time32 (4 bytes)
        time32 = struct.unpack(">I", encoded[offset : offset + 4])[0]
        offset += 4

        expiry_time = self.time32_decode(time32)

        return {
            "cert_hash_id8": cert_hash.hex(),
            "issuer_cert_der": issuer_cert_der.hex(),
            "expiry_time": expiry_time,
            "time32": time32,
        }

    def sign_link_certificate(
        self, to_be_signed: bytes, private_key, algorithm="ECDSA-SHA256"
    ) -> bytes:
        """
        Firma ToBeSignedLinkCertificate con ECDSA.

        ETSI TS 103097: Signature using ECDSA-SHA256 on curve NIST P-256

        Args:
            to_be_signed: Bytes da firmare
            private_key: Chiave privata ECC
            algorithm: Algoritmo firma (default: ECDSA-SHA256)

        Returns:
            bytes: Firma ECDSA (64 bytes: r + s, 32 bytes each)
        """
        if algorithm != "ECDSA-SHA256":
            raise ValueError(f"Unsupported signature algorithm: {algorithm}")

        # Firma con ECDSA-SHA256
        signature_der = private_key.sign(to_be_signed, ec.ECDSA(hashes.SHA256()))

        # ETSI richiede formato raw (r || s) non DER
        # Converti da DER a raw 64 bytes
        from cryptography.hazmat.primitives.asymmetric.utils import (
            decode_dss_signature,
        )

        r, s = decode_dss_signature(signature_der)

        # 32 bytes per r, 32 bytes per s (NIST P-256)
        signature_raw = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

        return signature_raw

    def verify_link_certificate_signature(
        self, to_be_signed: bytes, signature: bytes, public_key
    ) -> bool:
        """
        Verifica firma ECDSA di un Link Certificate.

        Args:
            to_be_signed: Dati firmati
            signature: Firma raw (64 bytes)
            public_key: Chiave pubblica ECC

        Returns:
            bool: True se firma valida
        """
        try:
            # Converti signature da raw (r || s) a DER
            if len(signature) != 64:
                raise ValueError(f"Invalid signature length: {len(signature)}")

            r = int.from_bytes(signature[:32], byteorder="big")
            s = int.from_bytes(signature[32:], byteorder="big")

            from cryptography.hazmat.primitives.asymmetric.utils import (
                encode_dss_signature,
            )

            signature_der = encode_dss_signature(r, s)

            # Verifica con ECDSA-SHA256
            public_key.verify(signature_der, to_be_signed, ec.ECDSA(hashes.SHA256()))

            return True

        except Exception as e:
            print(f"[ETSI] Signature verification failed: {e}")
            return False

    def encode_full_link_certificate(
        self,
        issuer_cert_der: bytes,
        subject_cert_der: bytes,
        expiry_time: datetime,
        private_key,
    ) -> bytes:
        """
        Codifica LinkCertificate completo (ToBeSignedLinkCertificate + Signature).

        ETSI TS 102941 Section 6.4:
        LinkCertificate ::= SEQUENCE {
            content ToBeSignedLinkCertificate,
            signature Signature
        }

        Args:
            issuer_cert_der: Certificato issuer (RootCA) in DER
            subject_cert_der: Certificato subject (EA/AA) in DER
            expiry_time: Scadenza del link certificate
            private_key: Chiave privata per firma

        Returns:
            bytes: LinkCertificate completo codificato
        """
        # 1. Codifica ToBeSignedLinkCertificate
        to_be_signed = self.encode_to_be_signed_link_certificate(
            issuer_cert_der, subject_cert_der, expiry_time
        )

        # 2. Firma
        signature = self.sign_link_certificate(to_be_signed, private_key)

        # 3. Combina: [to_be_signed_len(2) | to_be_signed | signature(64)]
        encoded = bytearray()

        # ToBeSignedLinkCertificate length (2 bytes)
        encoded.extend(struct.pack(">H", len(to_be_signed)))

        # ToBeSignedLinkCertificate
        encoded.extend(to_be_signed)

        # Signature (64 bytes)
        encoded.extend(signature)

        return bytes(encoded)

    def decode_full_link_certificate(self, encoded: bytes) -> Dict:
        """
        Decodifica LinkCertificate completo.

        Args:
            encoded: Bytes del LinkCertificate

        Returns:
            Dict con contenuto e firma
        """
        offset = 0

        # ToBeSignedLinkCertificate length (2 bytes)
        to_be_signed_len = struct.unpack(">H", encoded[offset : offset + 2])[0]
        offset += 2

        # ToBeSignedLinkCertificate
        to_be_signed = encoded[offset : offset + to_be_signed_len]
        offset += to_be_signed_len

        # Signature (64 bytes)
        signature = encoded[offset : offset + 64]
        offset += 64

        # Decodifica contenuto
        content = self.decode_to_be_signed_link_certificate(to_be_signed)

        return {
            "content": content,
            "signature": signature.hex(),
            "to_be_signed": to_be_signed.hex(),
        }

    def export_to_json(self, link_cert_data: Dict) -> str:
        """
        Esporta Link Certificate in formato JSON leggibile (per debugging).

        Args:
            link_cert_data: Dati del link certificate

        Returns:
            str: JSON formattato
        """
        json_data = {
            "version": "1.0",
            "format": "ETSI_TS_102941_ASN1_OER",
            "content": {
                "cert_hash_id8": link_cert_data["content"]["cert_hash_id8"],
                "issuer_cert_der_hex": link_cert_data["content"]["issuer_cert_der"],
                "expiry_time": link_cert_data["content"]["expiry_time"].isoformat(),
                "time32": link_cert_data["content"]["time32"],
            },
            "signature": link_cert_data["signature"],
            "signature_algorithm": "ECDSA-SHA256-P256",
        }

        return json.dumps(json_data, indent=2)


# Utility functions per conversione tra formati


def convert_json_to_asn1_link_certificate(
    json_link_cert: Dict, root_ca_private_key, root_ca_cert, subject_cert
) -> bytes:
    """
    Converte un Link Certificate da formato JSON a ASN.1 OER binario.

    Args:
        json_link_cert: Link certificate in formato JSON/dict
        root_ca_private_key: Chiave privata RootCA per ri-firmare
        root_ca_cert: Certificato RootCA
        subject_cert: Certificato subordinato (EA/AA)

    Returns:
        bytes: Link certificate in formato ASN.1 OER
    """
    encoder = ETSILinkCertificateEncoder()

    # Estrai certificati in DER
    issuer_cert_der = root_ca_cert.public_bytes(serialization.Encoding.DER)
    subject_cert_der = subject_cert.public_bytes(serialization.Encoding.DER)

    # Estrai expiry time
    expiry_time = datetime.fromisoformat(json_link_cert["expiry_time"])

    # Codifica in ASN.1 OER
    asn1_bytes = encoder.encode_full_link_certificate(
        issuer_cert_der, subject_cert_der, expiry_time, root_ca_private_key
    )

    return asn1_bytes


def convert_asn1_to_json_link_certificate(asn1_bytes: bytes) -> Dict:
    """
    Converte un Link Certificate da ASN.1 OER a formato JSON leggibile.

    Args:
        asn1_bytes: Link certificate in formato ASN.1 OER

    Returns:
        Dict: Link certificate in formato JSON
    """
    encoder = ETSILinkCertificateEncoder()
    decoded = encoder.decode_full_link_certificate(asn1_bytes)

    return {
        "format": "ETSI_TS_102941_ASN1_OER",
        "cert_hash_id8": decoded["content"]["cert_hash_id8"],
        "expiry_time": decoded["content"]["expiry_time"].isoformat(),
        "signature": decoded["signature"],
        "signature_algorithm": "ECDSA-SHA256-P256",
    }


def decode_link_certificates_bundle(bundle_bytes: bytes) -> list[Dict]:
    """
    Decodifica un bundle ASN.1 OER contenente multipli Link Certificates.

    Formato bundle:
    - [count: 2 bytes] numero di link certificates
    - Per ogni link certificate:
      - [length: 2 bytes] lunghezza del link certificate
      - [data: length bytes] link certificate ASN.1 OER

    Args:
        bundle_bytes: Bundle in formato ASN.1 OER

    Returns:
        List[Dict]: Lista di link certificates decodificati

    Raises:
        ValueError: Se il bundle è malformato o corrotto
    """
    import struct

    if len(bundle_bytes) < 2:
        raise ValueError("Bundle troppo corto: mancano header")

    offset = 0

    # Leggi numero di link certificates (2 bytes, big-endian)
    count = struct.unpack(">H", bundle_bytes[offset : offset + 2])[0]
    offset += 2

    link_certificates = []
    encoder = ETSILinkCertificateEncoder()

    for i in range(count):
        # Leggi lunghezza link certificate (2 bytes)
        if offset + 2 > len(bundle_bytes):
            raise ValueError(f"Bundle corrotto: manca lunghezza per link {i + 1}")

        link_len = struct.unpack(">H", bundle_bytes[offset : offset + 2])[0]
        offset += 2

        # Leggi link certificate data
        if offset + link_len > len(bundle_bytes):
            raise ValueError(f"Bundle corrotto: dati incompleti per link {i + 1}")

        link_data = bundle_bytes[offset : offset + link_len]
        offset += link_len

        # Decodifica link certificate
        try:
            decoded = encoder.decode_full_link_certificate(link_data)
            link_certificates.append(decoded)
        except Exception as e:
            raise ValueError(f"Errore decodifica link {i + 1}: {e}")

    return link_certificates
