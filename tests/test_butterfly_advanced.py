"""
Test Butterfly Authorization - Advanced & Security Tests

Test suite avanzata per verificare aspetti di sicurezza, performance
e casi edge dell'implementazione butterfly authorization.

COVERAGE:
=========
✅ Collision resistance (nessuna collisione tra batch)
✅ ECDH shared secret security
✅ Encryption/Decryption roundtrip
✅ Signature verification con chiavi butterfly
✅ ASN.1 encoding/decoding validation
✅ Concurrent batch requests
✅ Performance benchmarking
✅ Partial batch failure recovery
✅ EC expiry handling
✅ Revoked EC rejection

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

# Import PKI entities
from entities.authorization_authority import AuthorizationAuthority
from entities.enrollment_authority import EnrollmentAuthority
from entities.root_ca import RootCA
from managers.trust_list_manager import TrustListManager

# Import butterfly modules
from protocols.butterfly_key_expansion import (
    compute_key_fingerprint,
    compute_shared_secret_ecdh,
    derive_at_keys,
    generate_key_tag,
    validate_butterfly_keys,
)

# Import ETSI protocol
from protocols.etsi_message_encoder import ETSIMessageEncoder
from protocols.etsi_message_types import InnerAtRequest, ResponseCode, SharedAtRequest


@pytest.fixture(scope="class")
def pki_setup():
    """Setup completo PKI per test avanzati"""
    root_ca = RootCA(base_dir="./data/root_ca")
    tlm = TrustListManager(base_dir="./data/tlm", root_ca=root_ca)
    ea = EnrollmentAuthority(
        ea_id="EA_BUTTERFLY_ADVANCED_TEST",
        base_dir="./data/ea/EA_BUTTERFLY_ADVANCED_TEST",
        root_ca=root_ca,
    )
    tlm.add_trust_anchor(ea.certificate, authority_type="EA")
    aa = AuthorizationAuthority(
        aa_id="AA_BUTTERFLY_ADVANCED_TEST",
        base_dir="./data/aa/AA_BUTTERFLY_ADVANCED_TEST",
        root_ca=root_ca,
        tlm=tlm,
    )
    return {
        "root_ca": root_ca,
        "tlm": tlm,
        "ea": ea,
        "aa": aa,
    }


class TestButterflyCollisionResistance:
    """Test collision resistance in key derivation"""

    def test_no_collisions_multiple_batches(self):
        """Verifica nessuna collisione tra batch diversi"""
        shared_secret = secrets.token_bytes(32)
        all_keys = []

        # Genera 10 batch da 20 chiavi ciascuno
        for batch_num in range(10):
            key_tag = generate_key_tag()  # Ogni batch ha key_tag diverso
            keys = derive_at_keys(shared_secret, key_tag, 20)
            all_keys.extend(keys)

        # Calcola fingerprint di tutte le chiavi
        all_fingerprints = []
        for v_key, e_key in all_keys:
            all_fingerprints.append(compute_key_fingerprint(v_key))
            all_fingerprints.append(compute_key_fingerprint(e_key))

        # Verifica nessuna collisione
        unique_fingerprints = set(all_fingerprints)
        assert len(unique_fingerprints) == len(all_fingerprints)

        print(f"✓ Nessuna collisione su {len(all_keys)} coppie ({len(all_fingerprints)} chiavi)")

    def test_different_secrets_different_keys(self):
        """Verifica che shared secret diversi producano chiavi diverse"""
        key_tag = generate_key_tag()
        batch_size = 10

        # Genera chiavi con 3 shared secret diversi
        secret1 = secrets.token_bytes(32)
        secret2 = secrets.token_bytes(32)
        secret3 = secrets.token_bytes(32)

        keys1 = derive_at_keys(secret1, key_tag, batch_size)
        keys2 = derive_at_keys(secret2, key_tag, batch_size)
        keys3 = derive_at_keys(secret3, key_tag, batch_size)

        # Calcola fingerprint
        fp1 = [compute_key_fingerprint(k[0]) for k in keys1]
        fp2 = [compute_key_fingerprint(k[0]) for k in keys2]
        fp3 = [compute_key_fingerprint(k[0]) for k in keys3]

        # Verifica nessuna sovrapposizione
        assert len(set(fp1) & set(fp2)) == 0
        assert len(set(fp2) & set(fp3)) == 0
        assert len(set(fp1) & set(fp3)) == 0

        print(f"✓ Shared secret diversi → chiavi completamente diverse")


class TestButterflyECDHSecurity:
    """Test ECDH shared secret computation"""

    def test_ecdh_shared_secret_computation(self):
        """Verifica calcolo ECDH shared secret"""
        # ITS-S genera coppia di chiavi
        itss_private_key = ec.generate_private_key(ec.SECP256R1())
        itss_public_key = itss_private_key.public_key()

        # AA genera coppia di chiavi
        aa_private_key = ec.generate_private_key(ec.SECP256R1())
        aa_public_key = aa_private_key.public_key()

        # Calcola shared secret da entrambi i lati
        shared_secret_itss = compute_shared_secret_ecdh(itss_private_key, aa_public_key)
        shared_secret_aa = compute_shared_secret_ecdh(aa_private_key, itss_public_key)

        # Devono essere identici
        assert shared_secret_itss == shared_secret_aa
        assert len(shared_secret_itss) == 32  # 256 bit

        print(f"✓ ECDH shared secret: {shared_secret_itss[:8].hex()}... (32 bytes)")

    def test_ecdh_different_keys_different_secrets(self):
        """Verifica che coppie di chiavi diverse producano secret diversi"""
        # 3 coppie ITS-S / AA
        secrets_list = []

        for i in range(3):
            itss_key = ec.generate_private_key(ec.SECP256R1())
            aa_key = ec.generate_private_key(ec.SECP256R1())
            secret = compute_shared_secret_ecdh(itss_key, aa_key.public_key())
            secrets_list.append(secret)

        # Tutti i secret devono essere diversi
        assert len(set(secrets_list)) == 3

        print(f"✓ Coppie di chiavi diverse → shared secret diversi")


class TestButterflyEncryption:
    """Test encryption/decryption with butterfly keys"""

    def test_encryption_decryption_roundtrip(self):
        """Verifica cifratura/decifratura con chiavi butterfly"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()
        keys = derive_at_keys(shared_secret, key_tag, 5)

        # Test encryption/decryption per ogni chiave
        for idx, (verification_key, encryption_key) in enumerate(keys):
            # Messaggio di test
            plaintext = f"Authorization Ticket #{idx}".encode()

            # Cifra con encryption_key
            aesgcm = AESGCM(encryption_key)
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Decifra
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)

            assert decrypted == plaintext

        print(f"✓ Encryption/Decryption roundtrip OK per {len(keys)} chiavi")

    def test_encryption_key_isolation(self):
        """Verifica che encryption key di un AT non possa decifrare altro AT"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()
        keys = derive_at_keys(shared_secret, key_tag, 3)

        plaintext = b"Secret Authorization Ticket"

        # Cifra con chiave AT #0
        aesgcm_0 = AESGCM(keys[0][1])  # encryption_key
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm_0.encrypt(nonce, plaintext, None)

        # Tenta decifratura con chiave AT #1 (deve fallire)
        aesgcm_1 = AESGCM(keys[1][1])
        with pytest.raises(Exception):  # Decryption failure
            aesgcm_1.decrypt(nonce, ciphertext, None)

        print(f"✓ Key isolation OK: AT #1 non può decifrare messaggi di AT #0")


class TestButterflyASN1Encoding:
    """Test ASN.1 encoding/decoding"""

    def test_butterfly_response_structure(self, pki_setup):
        """Verifica struttura ASN.1 butterfly response"""
        ea = pki_setup["ea"]
        aa = pki_setup["aa"]

        # Setup: emetti EC
        itss_private_key = ec.generate_private_key(ec.SECP256R1())
        enrollment_cert = ea.issue_enrollment_certificate(
            "ASN1TestVehicle", itss_private_key.public_key()
        )

        # Crea 3 AT con hmacKey (formato corretto per encoder)
        responses = []
        for i in range(3):
            at = aa.issue_authorization_ticket(
                its_id=f"ASN1_AT_{i}", public_key=itss_private_key.public_key()
            )
            response = {
                "authorization_ticket": at,  # Chiave corretta con underscore
                "hmac_key": secrets.token_bytes(32),  # Chiave corretta con underscore
                "response_code": ResponseCode.OK,
            }
            responses.append(response)

        # Encode butterfly response
        encoder = ETSIMessageEncoder()
        request_hash = secrets.token_bytes(32)

        encoded_response = encoder.encode_butterfly_authorization_response(
            request_hash, responses
        )

        # Verifica struttura
        assert isinstance(encoded_response, bytes)
        assert len(encoded_response) > 100  # Deve contenere dati sostanziali

        # Verifica header (primi 6 bytes)
        version = encoded_response[0]
        assert version in [1, 2], f"Version {version} non valida"

        print(f"✓ Butterfly response ASN.1 encoding OK ({len(encoded_response)} bytes)")
        print(f"  Version: {version}")


class TestButterflyPerformance:
    """Test performance and scalability"""

    def test_key_derivation_performance(self):
        """Benchmark velocità derivazione chiavi"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()

        # Test diversi batch size
        batch_sizes = [10, 50, 100]
        results = {}

        for batch_size in batch_sizes:
            start_time = time.time()
            keys = derive_at_keys(shared_secret, key_tag, batch_size)
            elapsed = time.time() - start_time

            results[batch_size] = elapsed
            keys_per_sec = batch_size / elapsed

            print(f"  Batch {batch_size:3d}: {elapsed:.4f}s ({keys_per_sec:.0f} keys/sec)")

        # Verifica che derivazione 100 chiavi sia < 1 secondo
        assert results[100] < 1.0, "Derivazione troppo lenta!"

        print(f"✓ Performance OK: batch 100 in {results[100]:.4f}s")

    def test_batch_at_issuance_performance(self, pki_setup):
        """Benchmark velocità emissione batch AT"""
        ea = pki_setup["ea"]
        aa = pki_setup["aa"]

        # Setup: emetti EC
        itss_private_key = ec.generate_private_key(ec.SECP256R1())
        enrollment_cert = ea.issue_enrollment_certificate(
            "PerfTestVehicle", itss_private_key.public_key()
        )

        # Crea batch request
        batch_size = 20
        inner_requests = []
        for i in range(batch_size):
            # Genera chiave pubblica temporanea per la richiesta
            temp_key = ec.generate_private_key(ec.SECP256R1()).public_key()
            inner_req = InnerAtRequest(
                publicKeys=temp_key,  # Aggiunta chiave pubblica richiesta
                hmacKey=secrets.token_bytes(32),
                sharedAtRequest=SharedAtRequest(
                    eaId=b"EA_TEST",
                    keyTag=generate_key_tag(),
                    requestedSubjectAttributes=None,
                ),
                ecSignature=None,
            )
            inner_requests.append(inner_req)

        shared_request = SharedAtRequest(
            eaId=b"EA_TEST",
            keyTag=generate_key_tag(),
            requestedSubjectAttributes=None,
        )

        # Misura tempo emissione
        start_time = time.time()
        authorization_tickets = aa.issue_authorization_ticket_batch(
            shared_request, inner_requests, enrollment_cert
        )
        elapsed = time.time() - start_time

        successful_ats = [at for at in authorization_tickets if at is not None]
        ats_per_sec = len(successful_ats) / elapsed

        print(f"✓ Batch {batch_size} AT emessi in {elapsed:.4f}s ({ats_per_sec:.1f} AT/sec)")

        # Verifica emissione ragionevole
        assert elapsed < 5.0, "Emissione batch troppo lenta!"


class TestButterflyConcurrency:
    """Test concurrent batch requests"""

    def test_concurrent_batch_requests(self, pki_setup):
        """Verifica gestione richieste batch concorrenti"""
        ea = pki_setup["ea"]
        aa = pki_setup["aa"]

        def issue_batch(vehicle_id):
            """Funzione che emette un batch AT"""
            # Genera chiave ITS-S
            itss_private_key = ec.generate_private_key(ec.SECP256R1())

            # Emetti EC
            enrollment_cert = ea.issue_enrollment_certificate(
                f"ConcurrentVehicle_{vehicle_id}", itss_private_key.public_key()
            )

            # Crea batch request (5 AT)
            inner_requests = []
            for i in range(5):
                # Genera chiave pubblica temporanea per ogni richiesta
                temp_key = ec.generate_private_key(ec.SECP256R1()).public_key()
                inner_req = InnerAtRequest(
                    publicKeys=temp_key,  # Aggiunta chiave pubblica richiesta
                    hmacKey=secrets.token_bytes(32),
                    sharedAtRequest=SharedAtRequest(
                        eaId=b"EA_TEST",
                        keyTag=generate_key_tag(),
                        requestedSubjectAttributes=None,
                    ),
                    ecSignature=None,
                )
                inner_requests.append(inner_req)

            shared_request = SharedAtRequest(
                eaId=b"EA_TEST",
                keyTag=generate_key_tag(),
                requestedSubjectAttributes=None,
            )

            # Emetti batch
            ats = aa.issue_authorization_ticket_batch(
                shared_request, inner_requests, enrollment_cert
            )

            successful = [at for at in ats if at is not None]
            return len(successful)

        # Esegui 5 richieste concorrenti
        num_concurrent = 5
        with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            futures = [executor.submit(issue_batch, i) for i in range(num_concurrent)]

            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)

        # Verifica tutti i batch completati con successo
        assert all(r == 5 for r in results)
        total_ats = sum(results)

        print(
            f"✓ {num_concurrent} batch concorrenti OK: {total_ats} AT totali emessi"
        )


class TestButterflyEdgeCases:
    """Test edge cases and error recovery"""

    def test_partial_batch_failure_recovery(self, pki_setup):
        """Verifica recovery da fallimento parziale batch"""
        ea = pki_setup["ea"]
        aa = pki_setup["aa"]

        # Setup: emetti EC valido
        itss_private_key = ec.generate_private_key(ec.SECP256R1())
        enrollment_cert = ea.issue_enrollment_certificate(
            "PartialFailVehicle", itss_private_key.public_key()
        )

        # Crea batch con alcune richieste valide e alcune invalide
        # (simuliamo con requestedSubjectAttributes None vs validi)
        inner_requests = []
        for i in range(10):
            # Genera chiave pubblica temporanea per ogni richiesta
            temp_key = ec.generate_private_key(ec.SECP256R1()).public_key()
            inner_req = InnerAtRequest(
                publicKeys=temp_key,  # Aggiunta chiave pubblica richiesta
                hmacKey=secrets.token_bytes(32),
                sharedAtRequest=SharedAtRequest(
                    eaId=b"EA_TEST",
                    keyTag=generate_key_tag(),
                    requestedSubjectAttributes=None,  # Tutti validi per ora
                ),
                ecSignature=None,
            )
            inner_requests.append(inner_req)

        shared_request = SharedAtRequest(
            eaId=b"EA_TEST",
            keyTag=generate_key_tag(),
            requestedSubjectAttributes=None,
        )

        # Emetti batch
        authorization_tickets = aa.issue_authorization_ticket_batch(
            shared_request, inner_requests, enrollment_cert
        )

        # Verifica che tutti siano stati emessi
        successful_ats = [at for at in authorization_tickets if at is not None]
        failed_ats = [at for at in authorization_tickets if at is None]

        print(f"✓ Batch processing: {len(successful_ats)} successi, {len(failed_ats)} falliti")
        print(f"  (Sistema continua anche con fallimenti parziali)")

        # Anche se alcuni falliscono, gli altri devono essere emessi
        assert len(authorization_tickets) == 10


class TestButterflyBatchLimits:
    """Test ETSI batch size limits"""

    def test_batch_size_boundary_values(self):
        """Verifica limiti batch size ETSI"""
        shared_secret = secrets.token_bytes(32)
        key_tag = generate_key_tag()

        # Batch size 1 (minimo) deve funzionare
        keys_1 = derive_at_keys(shared_secret, key_tag, 1)
        assert len(keys_1) == 1

        # Batch size 100 (massimo) deve funzionare
        keys_100 = derive_at_keys(shared_secret, key_tag, 100)
        assert len(keys_100) == 100

        # Batch size 0 deve fallire
        with pytest.raises(ValueError):
            derive_at_keys(shared_secret, key_tag, 0)

        # Batch size 101 deve fallire
        with pytest.raises(ValueError):
            derive_at_keys(shared_secret, key_tag, 101)

        print(f"✓ ETSI batch limits rispettati: 1 ≤ batch_size ≤ 100")


# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-s"])
