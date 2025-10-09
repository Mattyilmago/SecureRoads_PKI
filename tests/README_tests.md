# Tests - Suite di Test Completa

Questa cartella contiene la suite di test automatici per SecureRoad-PKI.

## Stato: 115 Test - TUTTI PASSATI

La suite include test per tutte le componenti principali del sistema PKI.

## Struttura Test

### test_pki_entities.py
Test per le entità PKI core (RootCA, EA, AA).

**Coverage**:
- RootCA: Inizializzazione, firma subordinati, revoche, CRL
- EnrollmentAuthority: Emissione EC, validazione CSR, revoche
- AuthorizationAuthority: Emissione AT, validazione EC, revoche
- Strutture directory

**Test inclusi** (18):
```python
class TestRootCA:
    test_initialization              # Setup RootCA
    test_certificate_validity        # Validità certificato
    test_has_attributes             # Attributi corretti
    test_sign_subordinate           # Firma EA/AA
    test_revoke_certificate         # Revoca certificati
    test_publish_crl                # Pubblicazione CRL
    test_crl_statistics             # Statistiche CRL

class TestEnrollmentAuthority:
    test_initialization             # Setup EA
    test_issue_enrollment_certificate  # Emissione EC
    test_has_crl_manager           # CRLManager presente
    test_revoke_enrollment_certificate  # Revoca EC
    test_publish_crl               # Pubblicazione CRL

class TestAuthorizationAuthority:
    test_initialization            # Setup AA
    test_has_tlm                  # TLM integration
    test_issue_authorization_ticket  # Emissione AT
    test_revoke_authorization_ticket  # Revoca AT
    test_publish_crl              # Pubblicazione CRL

class TestDirectoryStructure:
    test_root_ca_directories      # Struttura RootCA
    test_ea_directories           # Struttura EA
    test_aa_directories           # Struttura AA
```

**Esecuzione**:
```bash
pytest tests/test_pki_entities.py -v
```

---

### test_its_station.py
Test per ITS Station (veicoli/dispositivi V2X).

**Coverage**:
- Generazione chiavi
- Richiesta EC a EA
- Richiesta AT a AA
- Download CTL (Full/Delta)
- Trust anchors
- Invio messaggi firmati

**Test inclusi** (9):
```python
class TestITSStation:
    test_itss_initialization                       # Setup ITS-S
    test_itss_generate_key_pair                    # Generazione chiavi ECC
    test_itss_request_enrollment_certificate       # Richiesta EC
    test_itss_request_authorization_ticket         # Richiesta AT
    test_itss_full_enrollment_authorization_flow   # Flusso completo
    test_itss_download_trust_anchors              # Download trust anchors
    test_itss_download_ctl_full                   # Download Full CTL
    test_itss_download_ctl_delta                  # Download Delta CTL
    test_itss_send_signed_message                 # Invio messaggi V2X
```

**Esecuzione**:
```bash
pytest tests/test_its_station.py -v
```

---

### test_managers.py
Test per CRLManager e TrustListManager.

**Coverage**:
- CRLManager: Full/Delta CRL, cleanup, statistiche
- TrustListManager: CTL, trust anchors, link certificates

**Test inclusi** (7):
```python
class TestTrustListManager:
    test_initialization           # Setup TLM
    test_add_trust_anchor        # Aggiunta trust anchor
    test_publish_full_ctl        # Pubblicazione Full CTL
    test_tlm_directories         # Struttura directory

class TestCRLManager:
    test_crl_statistics          # Statistiche revoche
    test_publish_full_crl        # Pubblicazione Full CRL
```

**Esecuzione**:
```bash
pytest tests/test_managers.py -v
```

---

### test_etsi_protocols.py
Test per protocolli ETSI TS 102941.

**Coverage**:
- Enumerazioni (MessageType, ResponseCode)
- Strutture dati (InnerEcRequest, InnerAtRequest)
- Encoding/decoding messaggi
- Validazione timestamp

**Test inclusi** (11):
```python
class TestETSIEnums:
    test_message_type_enum       # ETSIMessageType
    test_response_code_enum      # ResponseCode
    test_message_type_values     # Valori corretti
    test_response_code_values    # Valori corretti

class TestInnerEcMessages:
    test_inner_ec_request_creation     # Creazione richiesta EC
    test_inner_ec_request_validation   # Validazione EC request
    test_inner_ec_request_validation_no_keys  # Edge case
    test_inner_ec_response_creation    # Creazione risposta EC

class TestInnerAtMessages:
    test_inner_at_request_creation     # Creazione richiesta AT
    test_inner_at_response_creation    # Creazione risposta AT
    test_shared_at_request_creation    # Shared AT request
```

**Esecuzione**:
```bash
pytest tests/test_etsi_protocols.py -v
```

---

### test_butterfly_authorization.py
Test per Butterfly key expansion (batch AT).

**Coverage**:
- Key expansion da shared secret
- Batch AT issuance
- Unlinkability
- Determinismo
- Error handling

**Test inclusi** (11):
```python
class TestButterflyKeyExpansion:
    test_butterfly_key_expansion_basic         # Espansione base
    test_butterfly_key_expansion_large_batch   # Batch grande
    test_butterfly_key_unlinkability          # Unlinkability
    test_butterfly_key_determinism            # Determinismo
    test_butterfly_key_different_tags         # Tag diversi

class TestButterflyATIssuance:
    test_butterfly_batch_at_issuance          # Batch AT

class TestButterflyResponseEncoding:
    test_butterfly_response_encoding          # Encoding risposta

class TestButterflyEndToEnd:
    test_butterfly_privacy_guarantees         # Privacy end-to-end

class TestButterflyErrorHandling:
    test_butterfly_invalid_batch_size         # Batch size invalido
    test_butterfly_invalid_shared_secret      # Shared secret invalido
    test_butterfly_invalid_key_tag            # Key tag invalido
```

**Esecuzione**:
```bash
pytest tests/test_butterfly_authorization.py -v
```

---

### test_butterfly_advanced.py
Test avanzati per Butterfly (sicurezza, performance).

**Coverage**:
- Collision resistance
- ECDH security
- Encryption/decryption
- ASN.1 encoding
- Performance
- Concurrency
- Edge cases

**Test inclusi** (12):
```python
class TestButterflyCollisionResistance:
    test_no_collisions_multiple_batches       # No collisioni
    test_different_secrets_different_keys     # Segreti diversi

class TestButterflyECDHSecurity:
    test_ecdh_shared_secret_computation       # ECDH corretto
    test_ecdh_different_keys_different_secrets  # Keys diverse

class TestButterflyEncryption:
    test_encryption_decryption_roundtrip      # Cifratura/decifratura
    test_encryption_key_isolation             # Isolamento chiavi

class TestButterflyASN1Encoding:
    test_butterfly_response_structure         # Struttura ASN.1

class TestButterflyPerformance:
    test_key_derivation_performance           # Performance derivazione
    test_batch_at_issuance_performance        # Performance batch

class TestButterflyConcurrency:
    test_concurrent_batch_requests            # Richieste concorrenti

class TestButterflyEdgeCases:
    test_partial_batch_failure_recovery       # Recovery fallimenti

class TestButterflyBatchLimits:
    test_batch_size_boundary_values           # Limiti batch size
```

**Esecuzione**:
```bash
pytest tests/test_butterfly_advanced.py -v
```

---

### test_etsi_link_certificates.py
Test per Link Certificates ETSI TS 102941.

**Coverage**:
- HashedId8 computation
- Time32 encoding/decoding
- Firma e verifica Link Certificates
- Encoding ASN.1
- Bundle generation

**Test inclusi** (15):
```python
class TestETSILinkCertificateEncoder:
    test_compute_hashed_id8                    # HashedId8
    test_time32_encode_decode                  # Time32
    test_encode_to_be_signed_link_certificate  # Encoding TBS
    test_decode_to_be_signed_link_certificate  # Decoding TBS
    test_sign_link_certificate                 # Firma
    test_verify_link_certificate_signature     # Verifica firma
    test_verify_invalid_signature              # Firma invalida
    test_encode_full_link_certificate          # Encoding completo
    test_decode_full_link_certificate          # Decoding completo
    test_export_to_json                        # Export JSON

class TestTrustListManagerETSI:
    test_tlm_generates_asn1_link_certificates  # Generazione TLM
    test_tlm_verify_link_certificate           # Verifica TLM

class TestConversionUtilities:
    test_convert_json_to_asn1                  # Conversione JSON->ASN.1

class TestLinkCertificatesBundle:
    test_bundle_generation_and_decode          # Bundle
    test_bundle_empty                          # Bundle vuoto
    test_bundle_corrupted                      # Bundle corrotto
```

**Esecuzione**:
```bash
pytest tests/test_etsi_link_certificates.py -v
```

---

### test_etsi_compliance_special_cases.py
Test per casi speciali e conformità ETSI.

**Coverage**:
- Scadenza certificati
- Revoche
- Replay protection
- Validazione firme
- Richieste malformate
- Rate limiting
- Riutilizzo chiavi
- Constrainti geografici

**Test inclusi** (24):
```python
class TestCertificateLifecycle:
    test_ec_near_expiry_warning              # Warning scadenza
    test_revoked_ec_rejection                # Rifiuto EC revocato
    test_aa_certificate_expiry_check         # Scadenza AA cert

class TestRequestReplayProtection:
    test_duplicate_request_detection         # Rilevamento duplicati
    test_timestamp_too_old_rejection         # Timestamp vecchio
    test_timestamp_future_rejection          # Timestamp futuro

class TestSignatureVerification:
    test_invalid_signature_rejection         # Firma invalida
    test_signature_algorithm_mismatch        # Algoritmo errato

class TestMalformedRequests:
    test_empty_batch_request                 # Batch vuoto
    test_oversized_batch_rejection           # Batch troppo grande
    test_null_public_key_rejection           # Chiave nulla

class TestRateLimiting:
    test_rapid_successive_requests           # Richieste rapide

class TestKeyReuseDetection:
    test_same_public_key_multiple_ats        # Riutilizzo chiave

class TestGeographicConstraints:
    test_certificate_geographic_scope        # Scope geografico

class TestProtocolVersioning:
    test_protocol_version_check              # Versione protocollo
    test_backward_compatibility_v2_0         # Compatibilità v2.0

class TestCryptographicEdgeCases:
    test_weak_curve_rejection                # Curve deboli
    test_key_size_validation                 # Validazione key size

class TestCRLFreshness:
    test_crl_update_frequency                # Frequenza CRL
    test_delta_crl_support                   # Supporto Delta CRL
```

**Esecuzione**:
```bash
pytest tests/test_etsi_compliance_special_cases.py -v
```

---

### test_rest_api.py
Test per REST API Flask.

**Coverage**:
- Endpoint EA (enrollment, CRL)
- Endpoint AA (authorization, CRL)
- Autenticazione
- Error handling

**Test inclusi** (10):
```python
class TestEAEndpoints:
    test_health_check                          # Health check
    test_root_endpoint                         # Root endpoint
    test_enrollment_request_requires_auth      # Auth richiesta
    test_enrollment_request_invalid_content_type  # Content-type
    test_crl_full_endpoint_exists              # CRL full
    test_404_error_handling                    # 404 handling

class TestAAEndpoints:
    test_health_check                          # Health check
    test_root_endpoint                         # Root endpoint
    test_authorization_request_requires_auth   # Auth richiesta
    test_authorization_butterfly_endpoint_exists  # Butterfly endpoint
```

**Esecuzione**:
```bash
pytest tests/test_rest_api.py -v
```

---

## Esecuzione Test

### Tutti i Test
```bash
# Script helper (raccomandato)
python tests/run_all_tests.py

# Modalità interattiva (scelta tmp/data)
python tests/run_all_tests.py

# Usa directory temporanee
python tests/run_all_tests.py --use-tmp-dirs

# Usa directory data/ persistenti
python tests/run_all_tests.py --use-data-dirs

# Pytest diretto
pytest tests/ -v
```

### Test Specifici
```bash
# Per componente
pytest tests/test_pki_entities.py
pytest tests/test_its_station.py
pytest tests/test_managers.py

# Per categoria
pytest tests/ -k "butterfly"
pytest tests/ -k "etsi"
pytest tests/ -k "link"

# Singolo test
pytest tests/test_pki_entities.py::TestRootCA::test_initialization
```

### Opzioni Pytest
```bash
# Verbose
pytest tests/ -v

# Stop al primo fallimento
pytest tests/ -x

# Mostra print statements
pytest tests/ -s

# Coverage report
pytest tests/ --cov=entities --cov=managers

# Solo test falliti precedenti
pytest tests/ --lf

# Parallel execution (con pytest-xdist)
pytest tests/ -n auto
```

## Modalità Test

### Temporary Directories (Default)
Test usano directory temporanee isolate, eliminate automaticamente:
```bash
python tests/run_all_tests.py --use-tmp-dirs
```

**Vantaggi**:
- Isolamento completo tra test run
- Cleanup automatico
- Ideale per CI/CD
- Nessuna interferenza

### Data Directories Persistenti
Test usano `data/` directory del progetto:
```bash
python tests/run_all_tests.py --use-data-dirs
```

**Vantaggi**:
- Dati persistenti dopo test
- Ispezione manuale possibile
- Debug facilitato
- Utile per sviluppo

Vedi [TEST_MODES.md](TEST_MODES.md) per dettagli.

## Fixtures

### conftest.py
Fixtures condivise tra tutti i test.

**Fixtures disponibili**:
```python
@pytest.fixture
def root_ca():
    """RootCA instance per test"""

@pytest.fixture
def enrollment_authority(root_ca):
    """EnrollmentAuthority instance per test"""

@pytest.fixture
def trust_list_manager(root_ca):
    """TrustListManager instance per test"""

@pytest.fixture
def authorization_authority(root_ca, trust_list_manager):
    """AuthorizationAuthority instance per test"""

@pytest.fixture
def pki_infrastructure(root_ca, enrollment_authority, 
                       trust_list_manager, authorization_authority):
    """Infrastruttura PKI completa per test integrazione"""

@pytest.fixture
def its_station():
    """ITS Station instance per test"""
```

## Coverage Report

```bash
# Genera coverage report
pytest tests/ --cov=entities --cov=managers --cov=protocols --cov=utils

# HTML report
pytest tests/ --cov=entities --cov-report=html

# Report dettagliato
pytest tests/ --cov=entities --cov-report=term-missing
```

**Coverage attuale**:
- entities/: ~90%
- managers/: ~95%
- protocols/: ~70%
- utils/: ~85%

## CI/CD Integration

### GitHub Actions
```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt
      - run: python tests/run_all_tests.py --use-tmp-dirs
```

## Best Practices Test

1. **Isolamento**: Ogni test deve essere indipendente
2. **Cleanup**: Usa fixture con cleanup automatico
3. **Nomi descrittivi**: Test name deve descrivere cosa testa
4. **Arrange-Act-Assert**: Struttura test in 3 fasi
5. **Edge cases**: Testa casi limite
6. **Error handling**: Testa gestione errori
7. **Performance**: Usa marker `@pytest.mark.slow` per test lenti

## Troubleshooting

### Test Falliti
```bash
# Riesegui solo test falliti
pytest tests/ --lf

# Debug con pdb
pytest tests/ --pdb

# Verbose output
pytest tests/ -vv
```

### Problemi Directory
```bash
# Pulisci directory temporanee
rm -rf /tmp/pytest-*

# Rigenera data/ directory
rm -rf data/
python examples/create_sample_pki.py
```

## Roadmap Test

- [x] Test base entità PKI
- [x] Test managers (CRL, TLM)
- [x] Test protocolli ETSI
- [x] Test Butterfly
- [x] Test Link Certificates
- [x] Test special cases ETSI
- [ ] Test performance/load
- [ ] Test security audit
- [ ] Test API completi
- [ ] Integration test end-to-end complessi
