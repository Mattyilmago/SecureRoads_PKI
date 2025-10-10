"""
Test per ETSI Link Certificate ASN.1 OER Encoder

Testa la codifica/decodifica ETSI-compliant dei Link Certificates.
"""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from entities.enrollment_authority import EnrollmentAuthority
from entities.root_ca import RootCA
from managers.trust_list_manager import TrustListManager
from protocols.etsi_link_certificate import (
    ETSILinkCertificateEncoder,
    convert_asn1_to_json_link_certificate,
    convert_json_to_asn1_link_certificate,
)


@pytest.fixture(scope="module")
def root_ca_link(root_ca):
    """Use shared RootCA instance"""
    return root_ca


@pytest.fixture(scope="module")
def ea(root_ca_link, test_base_dir):
    """Create EA instance"""
    return EnrollmentAuthority(root_ca=root_ca_link, ea_id="EA_ETSI_TEST", base_dir=os.path.join(test_base_dir, "ea_etsi"))


@pytest.fixture
def encoder():
    """Create encoder instance"""
    return ETSILinkCertificateEncoder()


class TestETSILinkCertificateEncoder:
    """Test ETSI Link Certificate encoding/decoding"""

    def test_compute_hashed_id8(self, encoder, ea):
        """Test HashedId8 computation"""
        cert_der = ea.certificate.public_bytes(serialization.Encoding.DER)
        hashed_id8 = encoder.compute_hashed_id8(cert_der)
        
        assert len(hashed_id8) == 8
        assert isinstance(hashed_id8, bytes)

    def test_time32_encode_decode(self, encoder):
        """Test Time32 encoding/decoding"""
        now = datetime.now(timezone.utc)
        
        # Encode
        time32 = encoder.time32_encode(now)
        assert 0 <= time32 <= 0xFFFFFFFF
        
        # Decode
        decoded = encoder.time32_decode(time32)
        assert abs((decoded - now).total_seconds()) < 1  # Max 1 second diff

    def test_encode_to_be_signed_link_certificate(self, encoder, root_ca, ea):
        """Test ToBeSignedLinkCertificate encoding"""
        issuer_der = root_ca.certificate.public_bytes(serialization.Encoding.DER)
        subject_der = ea.certificate.public_bytes(serialization.Encoding.DER)
        expiry = datetime.now(timezone.utc) + timedelta(days=365)
        
        encoded = encoder.encode_to_be_signed_link_certificate(
            issuer_der, subject_der, expiry
        )
        
        assert isinstance(encoded, bytes)
        assert len(encoded) > 8  # At least HashedId8

    def test_decode_to_be_signed_link_certificate(self, encoder, root_ca, ea):
        """Test ToBeSignedLinkCertificate decoding"""
        issuer_der = root_ca.certificate.public_bytes(serialization.Encoding.DER)
        subject_der = ea.certificate.public_bytes(serialization.Encoding.DER)
        expiry = datetime.now(timezone.utc) + timedelta(days=365)
        
        # Encode
        encoded = encoder.encode_to_be_signed_link_certificate(
            issuer_der, subject_der, expiry
        )
        
        # Decode
        decoded = encoder.decode_to_be_signed_link_certificate(encoded)
        
        assert "cert_hash_id8" in decoded
        assert "issuer_cert_der" in decoded
        assert "expiry_time" in decoded
        assert len(decoded["cert_hash_id8"]) == 16  # 8 bytes in hex

    def test_sign_link_certificate(self, encoder, root_ca):
        """Test ECDSA signature generation"""
        data = b"test data to sign"
        
        signature = encoder.sign_link_certificate(data, root_ca.private_key)
        
        assert len(signature) == 64  # 32 bytes r + 32 bytes s
        assert isinstance(signature, bytes)

    def test_verify_link_certificate_signature(self, encoder, root_ca):
        """Test ECDSA signature verification"""
        data = b"test data to sign"
        
        # Sign
        signature = encoder.sign_link_certificate(data, root_ca.private_key)
        
        # Verify
        is_valid = encoder.verify_link_certificate_signature(
            data, signature, root_ca.certificate.public_key()
        )
        
        assert is_valid is True

    def test_verify_invalid_signature(self, encoder, root_ca):
        """Test signature verification with wrong data"""
        data = b"test data to sign"
        wrong_data = b"wrong data"
        
        # Sign correct data
        signature = encoder.sign_link_certificate(data, root_ca.private_key)
        
        # Verify with wrong data
        is_valid = encoder.verify_link_certificate_signature(
            wrong_data, signature, root_ca.certificate.public_key()
        )
        
        assert is_valid is False

    def test_encode_full_link_certificate(self, encoder, root_ca, ea):
        """Test full LinkCertificate encoding"""
        issuer_der = root_ca.certificate.public_bytes(serialization.Encoding.DER)
        subject_der = ea.certificate.public_bytes(serialization.Encoding.DER)
        expiry = datetime.now(timezone.utc) + timedelta(days=365)
        
        full_cert = encoder.encode_full_link_certificate(
            issuer_der, subject_der, expiry, root_ca.private_key
        )
        
        assert isinstance(full_cert, bytes)
        assert len(full_cert) > 64  # At least signature

    def test_decode_full_link_certificate(self, encoder, root_ca, ea):
        """Test full LinkCertificate decoding"""
        issuer_der = root_ca.certificate.public_bytes(serialization.Encoding.DER)
        subject_der = ea.certificate.public_bytes(serialization.Encoding.DER)
        expiry = datetime.now(timezone.utc) + timedelta(days=365)
        
        # Encode
        full_cert = encoder.encode_full_link_certificate(
            issuer_der, subject_der, expiry, root_ca.private_key
        )
        
        # Decode
        decoded = encoder.decode_full_link_certificate(full_cert)
        
        assert "content" in decoded
        assert "signature" in decoded
        assert len(decoded["signature"]) == 128  # 64 bytes in hex

    def test_export_to_json(self, encoder, root_ca, ea):
        """Test JSON export"""
        issuer_der = root_ca.certificate.public_bytes(serialization.Encoding.DER)
        subject_der = ea.certificate.public_bytes(serialization.Encoding.DER)
        expiry = datetime.now(timezone.utc) + timedelta(days=365)
        
        # Encode and decode
        full_cert = encoder.encode_full_link_certificate(
            issuer_der, subject_der, expiry, root_ca.private_key
        )
        decoded = encoder.decode_full_link_certificate(full_cert)
        
        # Export to JSON
        json_str = encoder.export_to_json(decoded)
        
        assert isinstance(json_str, str)
        assert "ETSI_TS_102941" in json_str
        assert "ECDSA-SHA256" in json_str


class TestTrustListManagerETSI:
    """Test TLM with ETSI-compliant Link Certificates"""

    def test_tlm_generates_asn1_link_certificates(self, root_ca, ea):
        """Test TLM generates both JSON and ASN.1 formats"""
        import glob
        
        tlm = TrustListManager(root_ca=root_ca, base_dir="data/tlm")
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")
        
        # Verifica esistenza file JSON nella sottocartella json/
        json_files = glob.glob("data/tlm/link_certificates/json/*.json")
        assert len(json_files) > 0, f"Nessun file JSON trovato in json/"
        
        # Verifica esistenza file ASN.1 nella sottocartella asn1/
        asn1_files = glob.glob("data/tlm/link_certificates/asn1/*.asn1")
        assert len(asn1_files) > 0, f"Nessun file ASN.1 trovato in asn1/"

    def test_tlm_verify_link_certificate(self, root_ca, ea):
        """Test TLM can verify link certificates"""
        tlm = TrustListManager(root_ca=root_ca, base_dir="data/tlm")
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")
        
        # Verifica link certificate generato
        if len(tlm.link_certificates) > 0:
            link_cert = tlm.link_certificates[0]
            is_valid, message = tlm.verify_link_certificate(link_cert)
            assert is_valid is True


class TestConversionUtilities:
    """Test conversion utilities"""

    def test_convert_json_to_asn1(self, root_ca, ea):
        """Test JSON to ASN.1 conversion"""
        tlm = TrustListManager(root_ca=root_ca, base_dir="data/tlm")
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")
        
        if len(tlm.link_certificates) > 0:
            json_link = tlm.link_certificates[0]
            
            # Convert to ASN.1
            asn1_bytes = convert_json_to_asn1_link_certificate(
                json_link, root_ca.private_key, root_ca.certificate, ea.certificate
            )
            
            assert isinstance(asn1_bytes, bytes)
            assert len(asn1_bytes) > 0


class TestLinkCertificatesBundle:
    """Test Link Certificates Bundle generation and decoding"""

    def test_bundle_generation_and_decode(self, root_ca, ea):
        """Test bundle ASN.1 generation and decoding"""
        from protocols.etsi_link_certificate import decode_link_certificates_bundle
        import os

        tlm = TrustListManager(root_ca=root_ca, base_dir="data/tlm")
        
        # Add multiple trust anchors
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")
        
        # Create 2 more fake EAs for testing
        from entities.enrollment_authority import EnrollmentAuthority
        ea2 = EnrollmentAuthority(root_ca, "EA_002")
        ea3 = EnrollmentAuthority(root_ca, "EA_003")
        tlm.add_trust_anchor(ea2.certificate, authority_type="EA")
        tlm.add_trust_anchor(ea3.certificate, authority_type="EA")
        
        # Publish link certificates (genera bundle ASN.1)
        tlm.publish_link_certificates()
        
        # Verifica che il bundle ASN.1 esista nella sottocartella asn1/
        bundle_path = os.path.join(tlm.link_certs_asn1_dir, "link_certificates_bundle.asn1")
        assert os.path.exists(bundle_path), "Bundle ASN.1 non generato"
        
        # Leggi e decodifica bundle
        with open(bundle_path, "rb") as f:
            bundle_bytes = f.read()
        
        assert len(bundle_bytes) > 0, "Bundle vuoto"
        
        # Decodifica bundle
        links = decode_link_certificates_bundle(bundle_bytes)
        
        # Verifica numero link certificates
        assert len(links) == 3, f"Expected 3 links, got {len(links)}"
        
        # Verifica struttura link certificates
        for link in links:
            assert "content" in link
            assert "signature" in link
            assert "cert_hash_id8" in link["content"]
            assert "expiry_time" in link["content"]
            assert len(link["signature"]) == 128  # 64 bytes hex = 128 chars

    def test_bundle_empty(self):
        """Test decoding empty bundle"""
        from protocols.etsi_link_certificate import decode_link_certificates_bundle
        import struct
        
        # Bundle vuoto (count = 0)
        empty_bundle = struct.pack(">H", 0)
        
        links = decode_link_certificates_bundle(empty_bundle)
        assert len(links) == 0, "Bundle vuoto dovrebbe ritornare lista vuota"

    def test_bundle_corrupted(self):
        """Test decoding corrupted bundle"""
        from protocols.etsi_link_certificate import decode_link_certificates_bundle
        
        # Bundle corrotto (header incompleto)
        corrupted = b"\x00"
        
        with pytest.raises(ValueError, match="Bundle troppo corto"):
            decode_link_certificates_bundle(corrupted)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
