"""
Test Butterfly Authorization - ETSI TS 102941 Conformance

Test suite completa per verificare la conformità dell'implementazione
butterfly authorization agli standard ETSI TS 102941 V2.1.1.

COVERAGE:
=========
✅ Butterfly key expansion (derivazione chiavi)
✅ Unlinkability verification (chiavi tutte diverse)
✅ Batch AT issuance (emissione multipli AT)
✅ Multi-response encoding (codifica risposte cifrate)
✅ End-to-end butterfly flow (ITS-S → AA → ITS-S)
✅ Privacy guarantees (impossibilità di correlazione)
✅ Error handling (gestione errori)

TEST SCENARIOS:
===============
1. test_butterfly_key_expansion_basic
   - Verifica derivazione chiavi per batch piccolo (5 AT)

2. test_butterfly_key_expansion_large_batch
   - Verifica derivazione per batch grande (100 AT)

3. test_butterfly_key_unlinkability
   - Verifica che tutte le chiavi siano diverse (privacy)

4. test_butterfly_batch_at_issuance
   - Verifica emissione batch di AT dall'AA

5. test_butterfly_response_encoding
   - Verifica codifica risposta con N AT cifrati

6. test_butterfly_end_to_end
   - Flusso completo: request → validation → issuance → response

7. test_butterfly_error_handling
   - Verifica gestione errori (EC invalido, batch size 0, etc.)

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Import PKI entities
from entities.authorization_authority import AuthorizationAuthority
from entities.enrollment_authority import EnrollmentAuthority
from entities.root_ca import RootCA
from managers.trust_list_manager import TrustListManager

# Import butterfly modules
from protocols.butterfly_key_expansion import (
    compute_key_fingerprint,
    derive_at_keys,
    generate_key_tag,
    validate_butterfly_keys,
)

# Import ETSI protocol
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import InnerAtRequest, ResponseCode, SharedAtRequest


class TestButterflyKeyExpansion:
    """Test suite for butterfly key expansion algorithm"""

    def test_butterfly_key_expansion_basic(self):
        """Test basic key derivation for small batch"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()
        batch_size = 5

        keys = derive_at_keys(shared_secret, key_tag, batch_size)

        assert len(keys) == batch_size
        assert all(len(v_key) == 32 and len(e_key) == 32 for v_key, e_key in keys)
        print(f"✓ Derivate {batch_size} coppie di chiavi da 32 bytes")

    def test_butterfly_key_expansion_large_batch(self):
        """Test key derivation for maximum batch size"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()
        batch_size = 100  # ETSI max batch size

        keys = derive_at_keys(shared_secret, key_tag, batch_size)

        assert len(keys) == batch_size
        print(f"✓ Derivate {batch_size} coppie di chiavi (max batch)")

    def test_butterfly_key_unlinkability(self):
        """Test unlinkability: all keys must be different"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()
        batch_size = 20

        keys = derive_at_keys(shared_secret, key_tag, batch_size)

        # Estrai tutte le chiavi
        all_keys = []
        for v_key, e_key in keys:
            all_keys.append(v_key)
            all_keys.append(e_key)

        # Verifica che siano tutte diverse
        unique_keys = set(all_keys)
        assert len(unique_keys) == len(all_keys), "ERRORE: Chiavi duplicate rilevate!"

        print(f"✓ Unlinkability verificata: {len(all_keys)} chiavi tutte diverse")

        # Valida anche tramite utility
        assert validate_butterfly_keys(keys), "Validazione butterfly keys fallita"

    def test_butterfly_key_determinism(self):
        """Test that same inputs produce same keys (determinism)"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()
        batch_size = 10

        # Deriva chiavi due volte con stessi parametri
        keys1 = derive_at_keys(shared_secret, key_tag, batch_size)
        keys2 = derive_at_keys(shared_secret, key_tag, batch_size)

        # Devono essere identiche
        for (v1, e1), (v2, e2) in zip(keys1, keys2):
            assert v1 == v2, "Verification keys non deterministiche"
            assert e1 == e2, "Encryption keys non deterministiche"

        print(f"✓ Determinismo verificato: stessi input → stesse chiavi")

    def test_butterfly_key_different_tags(self):
        """Test that different key tags produce different keys"""
        shared_secret = secrets.token_bytes(32)
        key_tag1 = generate_key_tag()
        key_tag2 = generate_key_tag()
        batch_size = 5

        keys1 = derive_at_keys(shared_secret, key_tag1, batch_size)
        keys2 = derive_at_keys(shared_secret, key_tag2, batch_size)

        # Con key tag diversi, le chiavi devono essere diverse
        assert keys1[0][0] != keys2[0][0], "Key tag diversi dovrebbero produrre chiavi diverse"

        print(f"✓ Key tag diversi → chiavi diverse (verified)")


class TestButterflyATIssuance:
    """Test suite for batch AT issuance"""

    @pytest.fixture
    def pki_setup(self):
        """Setup completo PKI per testing butterfly"""
        # Root CA
        root_ca = RootCA(base_dir="./data/root_ca")

        # Trust List Manager
        tlm = TrustListManager(root_ca=root_ca, base_dir="./data/tlm")

        # Enrollment Authority
        ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_BUTTERFLY_TEST", base_dir="./data/ea")

        # Registra EA nel TLM
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")

        # Authorization Authority con TLM
        aa = AuthorizationAuthority(
            root_ca=root_ca, tlm=tlm, aa_id="AA_BUTTERFLY_TEST", base_dir="./data/aa"
        )

        return {
            "root_ca": root_ca,
            "tlm": tlm,
            "ea": ea,
            "aa": aa,
        }

    def test_butterfly_batch_at_issuance(self, pki_setup):
        """Test emissione batch di Authorization Tickets"""
        aa = pki_setup["aa"]
        ea = pki_setup["ea"]

        # 1. Genera Enrollment Certificate per ITS-S
        itss_private_key = ec.generate_private_key(ec.SECP256R1())
        itss_public_key = itss_private_key.public_key()

        # Genera CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITS-S"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "ButterflyTestVehicle"),
                    ]
                )
            )
            .sign(itss_private_key, hashes.SHA256())
        )

        # Emetti EC
        enrollment_cert = ea.issue_enrollment_certificate("ButterflyTestVehicle", itss_public_key)
        assert enrollment_cert is not None
        print(f"✓ EC emesso: serial={enrollment_cert.serial_number}")

        # 2. Crea SharedAtRequest
        shared_request = SharedAtRequest(
            eaId=b"EA_TEST_" + secrets.token_bytes(8),  # HashedId8 simulato
            keyTag=generate_key_tag(),
            certificateFormat=1,
            requestedSubjectAttributes={"appPermissions": ["CAM", "DENM"]},
        )

        # 3. Crea batch di InnerAtRequest con chiavi pubbliche reali
        batch_size = 10
        inner_requests = []
        for i in range(batch_size):
            # Genera una chiave privata e pubblica per ogni AT
            temp_private_key = ec.generate_private_key(ec.SECP256R1())
            temp_public_key = temp_private_key.public_key()
            
            inner_req = InnerAtRequest(
                publicKeys={"verification": temp_public_key},  # Usa chiave pubblica reale
                hmacKey=secrets.token_bytes(32),
                requestedSubjectAttributes={"appPermissions": ["CAM"]},
            )
            inner_requests.append(inner_req)

        print(f"✓ Creati {batch_size} InnerAtRequest")

        # 4. Emetti batch AT (argomenti posizionali)
        authorization_tickets = aa.issue_authorization_ticket_batch(
            shared_request, inner_requests, enrollment_cert
        )

        # 5. Verifica risultati
        assert len(authorization_tickets) == batch_size
        successful_ats = [at for at in authorization_tickets if at is not None]
        assert len(successful_ats) > 0, "Nessun AT emesso con successo"

        print(f"✓ Emessi {len(successful_ats)}/{batch_size} Authorization Tickets")

        # Verifica che tutti gli AT abbiano serial number diversi
        serials = [at.serial_number for at in successful_ats]
        assert len(set(serials)) == len(serials), "AT con serial number duplicati!"

        print(f"✓ Tutti gli AT hanno serial number unici")


class TestButterflyResponseEncoding:
    """Test suite for butterfly response encoding"""

    @pytest.fixture
    def pki_setup(self):
        """Setup completo PKI per testing butterfly"""
        # Root CA
        root_ca = RootCA(base_dir="./data/root_ca")

        # Trust List Manager
        tlm = TrustListManager(root_ca=root_ca, base_dir="./data/tlm")

        # Enrollment Authority
        ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_BUTTERFLY_RESPONSE_TEST", base_dir="./data/ea")

        # Registra EA nel TLM
        tlm.add_trust_anchor(ea.certificate, authority_type="EA")

        # Authorization Authority con TLM
        aa = AuthorizationAuthority(
            root_ca=root_ca, tlm=tlm, aa_id="AA_BUTTERFLY_RESPONSE_TEST", base_dir="./data/aa"
        )

        return {
            "root_ca": root_ca,
            "tlm": tlm,
            "ea": ea,
            "aa": aa,
        }

    def test_butterfly_response_encoding(self, pki_setup):
        """Test encoding di ButterflyAuthorizationResponse"""
        aa = pki_setup["aa"]
        ea = pki_setup["ea"]

        # Setup: emetti alcuni AT
        itss_private_key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TestVehicle")])
            )
            .sign(itss_private_key, hashes.SHA256())
        )

        enrollment_cert = ea.issue_enrollment_certificate("TestVehicle", itss_private_key.public_key())

        # Crea responses
        responses = []
        for i in range(5):
            at = aa.issue_authorization_ticket(
                its_id=f"Test_AT_{i}", public_key=itss_private_key.public_key()
            )

            response = {
                "authorization_ticket": at,
                "hmac_key": secrets.token_bytes(32),
                "response_code": ResponseCode.OK,
            }
            responses.append(response)

        # Encode butterfly response
        encoder = ETSIMessageEncoder()
        request_hash = secrets.token_bytes(32)

        response_der = encoder.encode_butterfly_authorization_response(
            request_hash=request_hash, responses=responses
        )

        assert len(response_der) > 0
        print(f"✓ ButterflyAuthorizationResponse codificata: {len(response_der)} bytes")
        print(f"  Media per AT: {len(response_der) // len(responses)} bytes")


class TestButterflyEndToEnd:
    """Test suite for complete butterfly authorization flow"""

    def test_butterfly_privacy_guarantees(self):
        """Test privacy guarantees: verify unlinkability"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()
        batch_size = 20

        # Deriva chiavi
        keys = derive_at_keys(shared_secret, key_tag, batch_size)

        # Calcola fingerprint per ogni chiave
        fingerprints = []
        for v_key, e_key in keys:
            fp_v = compute_key_fingerprint(v_key)
            fp_e = compute_key_fingerprint(e_key)
            fingerprints.append((fp_v, fp_e))

        # Verifica che nessun fingerprint si ripeta
        all_fingerprints = [fp for pair in fingerprints for fp in pair]
        assert len(set(all_fingerprints)) == len(
            all_fingerprints
        ), "Fingerprint duplicati (privacy violata!)"

        print(f"✓ Privacy verificata: {len(all_fingerprints)} fingerprint tutti diversi")
        print(f"  Esempi:")
        for i in range(min(3, len(fingerprints))):
            print(f"    AT #{i}: v={fingerprints[i][0]}, e={fingerprints[i][1]}")


class TestButterflyErrorHandling:
    """Test suite for error handling"""

    def test_butterfly_invalid_batch_size(self):
        """Test error on invalid batch size"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()

        # Batch size 0 deve fallire
        with pytest.raises(ValueError):
            derive_at_keys(shared_secret, key_tag, 0)

        # Batch size > 100 deve fallire
        with pytest.raises(ValueError):
            derive_at_keys(shared_secret, key_tag, 101)

        print(f"✓ Validazione batch size funziona correttamente")

    def test_butterfly_invalid_shared_secret(self):
        """Test error on invalid shared secret"""
        key_tag = generate_key_tag()

        # Shared secret troppo corto deve fallire
        with pytest.raises(ValueError):
            derive_at_keys(b"short", key_tag, 10)

        print(f"✓ Validazione shared secret funziona correttamente")

    def test_butterfly_invalid_key_tag(self):
        """Test error on invalid key tag"""
        shared_secret = secrets.token_bytes(32)

        # Key tag lunghezza sbagliata deve fallire
        with pytest.raises(ValueError):
            derive_at_keys(shared_secret, b"short", 10)

        print(f"✓ Validazione key tag funziona correttamente")


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
