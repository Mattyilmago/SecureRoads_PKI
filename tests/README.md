# Test Suite - SecureRoad PKI

Suite completa di test per il progetto SecureRoad PKI.

## Struttura Test

### 📁 test_entities_pki.py
Test per le entità PKI principali:
- **RootCA**: Root Certificate Authority
  - Inizializzazione
  - Emissione certificati subordinati
  - Revoca certificati
  - Generazione CRL
- **EnrollmentAuthority (EA)**: Autorità di Enrollment
  - Inizializzazione
  - Emissione Enrollment Certificates
  - Revoca EC
- **AuthorizationAuthority (AA)**: Autorità di Authorization
  - Inizializzazione
  - Emissione Authorization Tickets
  - Revoca AT

### 📁 test_its_station.py
Test per ITS Station (veicoli/dispositivi):
- Inizializzazione ITS-S
- Generazione chiavi
- Richiesta Enrollment Certificate
- Richiesta Authorization Ticket
- Flusso completo enrollment + authorization

### 📁 test_managers.py
Test per i manager:
- **CRLManager**: Gestione Certificate Revocation Lists
  - Inizializzazione
  - Aggiunta revoche
  - Generazione Full CRL
  - Generazione Delta CRL
- **TrustListManager (TLM)**: Gestione Certificate Trust Lists
  - Inizializzazione
  - Aggiunta EA/AA trusted
  - Generazione Full CTL
  - Generazione Delta CTL

### 📁 test_protocols.py
Test per protocolli ETSI:
- **ETSI Message Types**: Strutture dati messaggi
  - Enum types
  - InnerEcRequest/Response
  - InnerAtRequest/Response
  - PublicKeys
- **ETSI Message Encoder/Decoder**: Encoding ASN.1 OER
  - Inizializzazione encoder
  - Encoding/Decoding EnrollmentRequest
  - Encoding/Decoding EnrollmentResponse
  - Encoding/Decoding AuthorizationRequest
  - Encoding/Decoding AuthorizationResponse
  - Crittografia ECIES
  - Crittografia HMAC-based
  - HashedId8 calculation
  - Test integrazione flussi completi

## Installazione

```powershell
# Installa pytest e dipendenze
pip install pytest pytest-cov
```

## Esecuzione Test

### Tutti i test
```powershell
pytest tests/ -v
```

### Test specifici
```powershell
# Solo test entities
pytest tests/test_entities_pki.py -v

# Solo test ITS-S
pytest tests/test_its_station.py -v

# Solo test managers
pytest tests/test_managers.py -v

# Solo test protocols
pytest tests/test_protocols.py -v
```

### Con coverage
```powershell
# Coverage report
pytest tests/ --cov=entities --cov=managers --cov=protocols --cov-report=html

# Apri report HTML
start htmlcov/index.html
```

### Test specifico
```powershell
# Singola classe
pytest tests/test_entities_pki.py::TestRootCA -v

# Singolo test
pytest tests/test_entities_pki.py::TestRootCA::test_root_ca_initialization -v
```

## Opzioni Utili

```powershell
# Verbose con output completo
pytest tests/ -v -s

# Stop al primo fallimento
pytest tests/ -x

# Solo ultimi test falliti
pytest tests/ --lf

# Esecuzione parallela (richiede pytest-xdist)
pytest tests/ -n auto

# Marker specifici (se configurati)
pytest tests/ -m "slow"
pytest tests/ -m "not slow"
```

## Coverage Atteso

- **entities/**: >80% coverage
- **managers/**: >75% coverage
- **protocols/**: >85% coverage

## Note

- I test usano directory temporanee (`test_data_*`) che vengono pulite automaticamente
- Ogni test è indipendente e può essere eseguito singolarmente
- I test di integrazione verificano flussi completi end-to-end
- Fixtures pytest condivise in `conftest.py`

## Troubleshooting

### Import errors
Se vedi errori di import, verifica che:
```powershell
# Il progetto sia nel PYTHONPATH
$env:PYTHONPATH = "C:\Users\moscu\OneDrive\Desktop\SecureRoad-PKI"
pytest tests/ -v
```

### Test lenti
Alcuni test (es. generazione certificati) possono richiedere qualche secondo. Usa `-v` per vedere il progresso.

### Cleanup issues
Se le directory di test non vengono pulite:
```powershell
# Manuale cleanup
Remove-Item -Recurse -Force test_data_*
```

## Continuous Integration

Per integrare in CI/CD:
```yaml
# .github/workflows/test.yml
- name: Run tests
  run: |
    pip install -r requirements.txt
    pip install pytest pytest-cov
    pytest tests/ --cov --cov-report=xml
```
