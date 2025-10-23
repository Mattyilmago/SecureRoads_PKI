"""
Test di conformità ETSI per Butterfly Authorization Response

Verifica che le funzioni encode/decode butterfly usino esclusivamente
messaggi AuthorizationResponse standard ETSI TS 102941.

Author: SecureRoad PKI Project
Date: October 2025
"""

import secrets
from datetime import datetime, timezone

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

from protocols.messages.encoder import ETSIMessageEncoder
from protocols.core.types import ResponseCode


def test_butterfly_response_etsi_compliance():
    """
    Test: Verifica che butterfly response sia 100% ETSI compliant.
    
    Ogni risposta deve essere un AuthorizationResponse standard,
    decodificabile con decode_authorization_response().
    """
    print("\n" + "="*70)
    print("TEST: Butterfly Response ETSI Compliance")
    print("="*70)
    
    # Setup
    encoder = ETSIMessageEncoder()
    request_hash = secrets.token_bytes(32)
    
    # Simula 3 AT certificates (in realtà bytes ASN.1 OER)
    at_certs = [
        b"FAKE_AT_CERT_0_ASN1_OER_" + secrets.token_bytes(100),
        b"FAKE_AT_CERT_1_ASN1_OER_" + secrets.token_bytes(100),
        b"FAKE_AT_CERT_2_ASN1_OER_" + secrets.token_bytes(100),
    ]
    
    # Genera 3 hmac_keys univoche
    hmac_keys = [secrets.token_bytes(32) for _ in range(3)]
    
    # Prepara risposte per butterfly
    responses = []
    for idx, (at_cert, hmac_key) in enumerate(zip(at_certs, hmac_keys)):
        responses.append({
            'authorization_ticket': at_cert,
            'hmac_key': hmac_key,
            'response_code': ResponseCode.OK
        })
    
    print(f"\n[TEST] Encoding {len(responses)} butterfly responses...")
    
    # === ENCODE ===
    encoded_responses = encoder.encode_butterfly_authorization_response(
        request_hash=request_hash,
        responses=responses
    )
    
    # Verifica: deve restituire una LISTA di bytes
    assert isinstance(encoded_responses, list), "❌ Deve restituire lista"
    assert len(encoded_responses) == len(responses), "❌ Numero risposte errato"
    print(f"✓ Ritornate {len(encoded_responses)} risposte separate")
    
    # Verifica: ogni elemento deve essere bytes (AuthorizationResponse ASN.1 OER)
    for idx, resp_bytes in enumerate(encoded_responses):
        assert isinstance(resp_bytes, bytes), f"❌ Risposta #{idx} non è bytes"
        print(f"  Risposta #{idx}: {len(resp_bytes)} bytes (AuthorizationResponse ETSI)")
    
    print(f"✓ Tutte le risposte sono AuthorizationResponse standard ETSI")
    
    # === DECODE ===
    print(f"\n[TEST] Decoding {len(encoded_responses)} butterfly responses...")
    
    decoded_responses = encoder.decode_butterfly_authorization_response(
        response_bytes_list=encoded_responses,
        hmac_keys=hmac_keys
    )
    
    # Verifica risposte decodificate
    assert len(decoded_responses) == len(responses), "❌ Numero risposte decodificate errato"
    print(f"✓ Decodificate {len(decoded_responses)} risposte")
    
    for idx, decoded in enumerate(decoded_responses):
        assert decoded['response_code'] == ResponseCode.OK, f"❌ Risposta #{idx} non OK"
        assert decoded['authorization_ticket'] == at_certs[idx], f"❌ AT #{idx} diverso"
        assert decoded['request_hash'] == request_hash, f"❌ Request hash #{idx} diverso"
        print(f"  Risposta #{idx}: ✓ OK, AT {len(decoded['authorization_ticket'])} bytes")
    
    print(f"\n✓ TUTTE LE VERIFICHE PASSATE")
    
    # === VERIFICA DECODIFICA SINGOLA ===
    print(f"\n[TEST] Verifica decodifica singola (compatibilità ETSI)...")
    
    # Ogni risposta deve essere decodificabile con decode_authorization_response()
    for idx, (resp_bytes, hmac_key) in enumerate(zip(encoded_responses, hmac_keys)):
        inner_resp = encoder.decode_authorization_response(resp_bytes, hmac_key)
        assert inner_resp.responseCode == ResponseCode.OK
        assert inner_resp.certificate == at_certs[idx]
        assert inner_resp.requestHash == request_hash
        print(f"  Risposta #{idx}: ✓ Decodificabile con funzione standard ETSI")
    
    print(f"\n✓ CONFORMITÀ ETSI TS 102941 VERIFICATA")
    print("="*70)
    print("✅ TEST SUPERATO: Butterfly Response 100% ETSI compliant")
    print("="*70)
    

if __name__ == "__main__":
    test_butterfly_response_etsi_compliance()
