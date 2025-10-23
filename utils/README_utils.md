# Utils - Utility e Strumenti di Supporto

Questa cartella contiene utility e funzioni di supporto utilizzate da tutte le componenti del sistema PKI.

## Moduli Disponibili

### cert_utils
**File**: `cert_utils.py`

Utility per manipolazione e analisi di certificati X.509.

**Funzioni Principali**:

#### Identificazione Certificati
```python
def get_certificate_identifier(certificate: x509.Certificate) -> str:
    """
    Genera identificatore unico per certificato.
    Formato: CERT_{TIMESTAMP}_{SERIAL_SHORT}
    
    Esempio: "CERT_20251009_ABC123"
    """

def get_short_identifier(certificate: x509.Certificate) -> str:
    """
    Genera identificatore breve (primi 6 hex del serial number).
    
    Esempio: "ABC123"
    """

def get_certificate_ski(certificate: x509.Certificate) -> str:
    """
    Estrae Subject Key Identifier (SKI) dal certificato.
    Ritorna stringa hex del SKI o genera uno nuovo se assente.
    """
```

#### Validazione Certificati
```python
def validate_certificate_dates(certificate: x509.Certificate) -> dict:
    """
    Valida le date di validità del certificato.
    
    Returns:
        {
            'is_valid': bool,
            'not_before': datetime,
            'not_after': datetime,
            'days_until_expiry': int,
            'is_expired': bool,
            'is_not_yet_valid': bool
        }
    """

def check_certificate_chain(
    certificate: x509.Certificate,
    issuer_certificate: x509.Certificate
) -> bool:
    """
    Verifica che certificate sia firmato da issuer_certificate.
    Valida la firma crittografica.
    """
```

#### Estrazione Informazioni
```python
def get_certificate_info(certificate: x509.Certificate) -> dict:
    """
    Estrae informazioni complete dal certificato.
    
    Returns:
        {
            'subject': str,
            'issuer': str,
            'serial_number': int,
            'not_valid_before': datetime,
            'not_valid_after': datetime,
            'is_ca': bool,
            'ski': str,
            'aki': str (se presente),
            'key_usage': list,
            'extended_key_usage': list (se presente)
        }
    """

def extract_public_key_info(public_key) -> dict:
    """
    Estrae informazioni dalla chiave pubblica.
    
    Returns:
        {
            'key_type': str,      # 'EC', 'RSA', etc.
            'key_size': int,      # bits
            'curve': str          # per chiavi EC
        }
    """
```

#### Conversioni
```python
def certificate_to_pem(certificate: x509.Certificate) -> bytes:
    """Converte certificato X.509 in formato PEM"""

def certificate_to_der(certificate: x509.Certificate) -> bytes:
    """Converte certificato X.509 in formato DER"""

def pem_to_certificate(pem_bytes: bytes) -> x509.Certificate:
    """Carica certificato da bytes PEM"""

def der_to_certificate(der_bytes: bytes) -> x509.Certificate:
    """Carica certificato da bytes DER"""
```

**Utilizzo**:
```python
from utils.cert_utils import (
    get_certificate_identifier,
    validate_certificate_dates,
    get_certificate_info
)

# Identificazione
cert_id = get_certificate_identifier(certificate)
print(f"Certificato: {cert_id}")

# Validazione date
validation = validate_certificate_dates(certificate)
if validation['is_valid']:
    print(f"Valido, scade tra {validation['days_until_expiry']} giorni")
else:
    print("Certificato non valido!")

# Estrazione informazioni
info = get_certificate_info(certificate)
print(f"Subject: {info['subject']}")
print(f"Issuer: {info['issuer']}")
print(f"Is CA: {info['is_ca']}")
```

---

### pki_io
**File**: `pki_io.py`

Gestore I/O per file PKI (certificati, chiavi, CRL, CTL).

**Classe**: `PKIFileHandler`

**Metodi Statici**:

#### Gestione Directory
```python
@staticmethod
def ensure_directories(*paths):
    """
    Crea directory se non esistono (equivalente mkdir -p).
    Accetta multipli path come argomenti.
    """

@staticmethod
def cleanup_directory(path: str, keep_files: int = 0):
    """
    Pulisce directory rimuovendo file vecchi.
    keep_files: numero di file più recenti da mantenere.
    """
```

#### Certificati
```python
@staticmethod
def save_certificate(certificate: x509.Certificate, path: str):
    """Salva certificato X.509 in formato PEM"""

@staticmethod
def load_certificate(path: str) -> x509.Certificate:
    """Carica certificato X.509 da file PEM"""

@staticmethod
def save_certificate_der(certificate: x509.Certificate, path: str):
    """Salva certificato in formato DER"""

@staticmethod
def load_certificate_der(path: str) -> x509.Certificate:
    """Carica certificato da file DER"""
```

#### Chiavi Private
```python
@staticmethod
def save_private_key(private_key, path: str, password: bytes = None):
    """
    Salva chiave privata in formato PEM.
    Se password fornita, cifra con AES-256.
    """

@staticmethod
def load_private_key(path: str, password: bytes = None):
    """
    Carica chiave privata da file PEM.
    Se password fornita, decifra.
    """
```

#### CRL
```python
@staticmethod
def save_crl(crl: x509.CertificateRevocationList, path: str):
    """Salva CRL in formato PEM"""

@staticmethod
def load_crl(path: str) -> x509.CertificateRevocationList:
    """Carica CRL da file PEM"""
```

#### JSON
```python
@staticmethod
def save_json(data: dict, path: str):
    """Salva dizionario in JSON (pretty-printed)"""

@staticmethod
def load_json(path: str) -> dict:
    """Carica dizionario da file JSON"""
```

**Utilizzo**:
```python
from utils.pki_io import PKIFileHandler

# Crea directory
PKIFileHandler.ensure_directories(
    "pki_data/certificates",
    "pki_data/private_keys",
    "pki_data/crl"
)

# Salva certificato
PKIFileHandler.save_certificate(cert, "pki_data/certificates/cert.pem")

# Carica certificato
cert = PKIFileHandler.load_certificate("pki_data/certificates/cert.pem")

# Salva chiave privata (cifrata)
PKIFileHandler.save_private_key(
    private_key,
    "pki_data/private_keys/key.pem",
    password=b"my_secret_password"
)

# Salva JSON
metadata = {"version": 1, "count": 42}
PKIFileHandler.save_json(metadata, "pki_data/metadata.json")
```

---

### certificate_maker
**File**: `certificate_maker.py`

Builder per creazione certificati X.509 con configurazioni predefinite.

**Classi**:

#### CertificateBuilder
Builder fluent per costruzione certificati:
```python
builder = CertificateBuilder()
certificate = (builder
    .set_subject("CN=Test,O=Organization")
    .set_issuer("CN=IssuerCA")
    .set_public_key(public_key)
    .set_validity(days=365)
    .set_serial_number()  # Random
    .add_basic_constraints(ca=False)
    .add_key_usage(['digital_signature', 'key_encipherment'])
    .sign(issuer_private_key)
)
```

#### CertificateMaker
Factory per certificati predefiniti:
```python
class CertificateMaker:
    @staticmethod
    def create_root_ca_certificate(
        subject_name: str,
        private_key,
        validity_years: int = 10
    ) -> x509.Certificate:
        """Crea certificato Root CA self-signed"""
    
    @staticmethod
    def create_subordinate_ca_certificate(
        subject_name: str,
        subject_public_key,
        issuer_certificate: x509.Certificate,
        issuer_private_key,
        validity_years: int = 3
    ) -> x509.Certificate:
        """Crea certificato CA subordinata (EA/AA)"""
    
    @staticmethod
    def create_end_entity_certificate(
        subject_name: str,
        subject_public_key,
        issuer_certificate: x509.Certificate,
        issuer_private_key,
        validity_days: int = 365
    ) -> x509.Certificate:
        """Crea certificato end-entity (EC/AT)"""
```

**Utilizzo**:
```python
from utils.certificate_maker import CertificateMaker

# Root CA
root_cert = CertificateMaker.create_root_ca_certificate(
    subject_name="CN=RootCA,O=PKI",
    private_key=root_private_key,
    validity_years=10
)

# Subordinata EA
ea_cert = CertificateMaker.create_subordinate_ca_certificate(
    subject_name="CN=EA_001,O=PKI",
    subject_public_key=ea_public_key,
    issuer_certificate=root_cert,
    issuer_private_key=root_private_key,
    validity_years=3
)

# End-entity EC
ec_cert = CertificateMaker.create_end_entity_certificate(
    subject_name="CN=Vehicle_001",
    subject_public_key=vehicle_public_key,
    issuer_certificate=ea_cert,
    issuer_private_key=ea_private_key,
    validity_days=365
)
```

---

### certificate_validator
**File**: `certificate_validator.py`

Validatore completo per certificati X.509 con verifiche conformità ETSI.

**Funzioni**:
```python
def validate_certificate_signature(
    certificate: x509.Certificate,
    issuer_public_key
) -> bool:
    """Verifica firma crittografica del certificato"""

def validate_certificate_chain(
    certificate: x509.Certificate,
    intermediate_certs: List[x509.Certificate],
    trust_anchors: List[x509.Certificate]
) -> dict:
    """
    Valida catena completa di certificati.
    
    Returns:
        {
            'is_valid': bool,
            'chain': List[x509.Certificate],
            'trust_anchor': x509.Certificate,
            'errors': List[str]
        }
    """

def check_certificate_revocation(
    certificate: x509.Certificate,
    crl: x509.CertificateRevocationList
) -> dict:
    """
    Verifica se certificato è revocato.
    
    Returns:
        {
            'is_revoked': bool,
            'revocation_date': datetime (se revocato),
            'reason': str (se revocato)
        }
    """

def validate_etsi_compliance(
    certificate: x509.Certificate
) -> dict:
    """
    Verifica conformità ETSI TS 103097.
    
    Controlla:
    - Algoritmi supportati (ECC secp256r1)
    - Estensioni obbligatorie
    - Formato campi
    
    Returns:
        {
            'is_compliant': bool,
            'warnings': List[str],
            'errors': List[str]
        }
    """
```

**Utilizzo**:
```python
from utils.certificate_validator import (
    validate_certificate_chain,
    check_certificate_revocation,
    validate_etsi_compliance
)

# Valida catena
chain_validation = validate_certificate_chain(
    certificate=vehicle_cert,
    intermediate_certs=[ea_cert],
    trust_anchors=[root_cert]
)

if chain_validation['is_valid']:
    print("Catena valida!")
else:
    print(f"Errori: {chain_validation['errors']}")

# Verifica revoca
revocation_check = check_certificate_revocation(
    certificate=vehicle_cert,
    crl=ea_crl
)

if revocation_check['is_revoked']:
    print(f"Certificato revocato il {revocation_check['revocation_date']}")

# Verifica conformità ETSI
compliance = validate_etsi_compliance(vehicle_cert)
if not compliance['is_compliant']:
    print(f"Non conforme: {compliance['errors']}")
```

---

### logger
**File**: `logger.py`

Logger centralizzato per audit e diagnostica conforme ETSI.

**Classe**: `PKILogger`

**Metodi**:
```python
class PKILogger:
    def __init__(self, log_dir: str, component_name: str):
        """
        Inizializza logger per componente.
        
        Args:
            log_dir: Directory per file di log
            component_name: Nome componente (es. "RootCA", "EA_001")
        """
    
    def log_certificate_issuance(
        self,
        certificate: x509.Certificate,
        recipient: str
    ):
        """Log emissione certificato"""
    
    def log_certificate_revocation(
        self,
        certificate: x509.Certificate,
        reason: str
    ):
        """Log revoca certificato"""
    
    def log_crl_publication(self, crl_type: str, crl_number: int):
        """Log pubblicazione CRL"""
    
    def log_error(self, operation: str, error: str):
        """Log errore"""
    
    def log_security_event(self, event: str, details: dict):
        """Log evento di sicurezza"""
```

**Utilizzo**:
```python
from utils.logger import PKILogger
from config import PKI_PATHS

logger = PKILogger(log_dir=str(PKI_PATHS.LOGS), component_name="EA_001")

# Log emissione
logger.log_certificate_issuance(ec_cert, "Vehicle_001")

# Log revoca
logger.log_certificate_revocation(
    ec_cert,
    reason="key_compromise"
)

# Log security event
logger.log_security_event(
    "INVALID_SIGNATURE",
    {"its_id": "Vehicle_001", "timestamp": "2025-10-09T10:00:00"}
)
```

---

### pki_entity_base
**File**: `pki_entity_base.py`

Classe base astratta per entità PKI (implementazione futura).

**Classe**: `PKIEntityBase`

Fornisce interfaccia comune per RootCA, EA, AA, ITSStation:
```python
class PKIEntityBase(ABC):
    @abstractmethod
    def initialize(self):
        """Inizializza entità"""
    
    @abstractmethod
    def generate_keypair(self):
        """Genera coppia di chiavi"""
    
    @abstractmethod
    def save_to_disk(self):
        """Salva stato su disco"""
    
    @abstractmethod
    def load_from_disk(self):
        """Carica stato da disco"""
```

---

## Pattern Comuni

### Gestione Errori
```python
try:
    certificate = PKIFileHandler.load_certificate(path)
except FileNotFoundError:
    print(f"Certificato non trovato: {path}")
except ValueError as e:
    print(f"Certificato non valido: {e}")
```

### Validazione Completa
```python
from utils.cert_utils import validate_certificate_dates
from utils.certificate_validator import (
    validate_certificate_chain,
    check_certificate_revocation
)

# 1. Valida date
date_check = validate_certificate_dates(cert)
if not date_check['is_valid']:
    return False

# 2. Valida catena
chain_check = validate_certificate_chain(cert, intermediates, anchors)
if not chain_check['is_valid']:
    return False

# 3. Verifica revoca
revocation_check = check_certificate_revocation(cert, crl)
if revocation_check['is_revoked']:
    return False

return True
```

## Standard di Riferimento

- **RFC 5280**: X.509 Certificate and CRL Profile
- **ETSI TS 103097**: Certificate Formats
- **NIST SP 800-57**: Key Management Recommendations

## Testing

Test utility:
```bash
pytest tests/ -k "utils or cert"
```
