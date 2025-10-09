# Protocols - Protocolli Messaggistica ETSI

Questa cartella contiene l'implementazione dei protocolli di messaggistica conformi agli standard ETSI TS 102941 per sistemi ITS.

## Classi e Moduli Disponibili

### ETSIMessageTypes
**File**: `etsi_message_types.py`

Definisce le strutture dati e i tipi di messaggi conformi a ETSI TS 102941.

**Enumerazioni**:

#### ETSIMessageType
Tipi di messaggio supportati nel protocollo:
```python
class ETSIMessageType(Enum):
    ENROLLMENT_REQUEST = "EnrollmentRequest"
    ENROLLMENT_RESPONSE = "EnrollmentResponse"
    AUTHORIZATION_REQUEST = "AuthorizationRequest"
    AUTHORIZATION_RESPONSE = "AuthorizationResponse"
    AUTHORIZATION_VALIDATION_REQUEST = "AuthorizationValidationRequest"
    AUTHORIZATION_VALIDATION_RESPONSE = "AuthorizationValidationResponse"
    CTL_REQUEST = "CtlRequest"
    CTL_RESPONSE = "CtlResponse"
    CRL_REQUEST = "CrlRequest"
    CRL_RESPONSE = "CrlResponse"
    BUTTERFLY_AUTHORIZATION_REQUEST = "ButterflyAuthorizationRequest"
```

#### ResponseCode
Codici di risposta standard ETSI:
```python
class ResponseCode(Enum):
    OK = 0                          # Successo
    INVALID_REQUEST = 1             # Richiesta malformata
    INVALID_SIGNATURE = 2           # Firma non valida
    INVALID_ENCRYPTION = 3          # Crittografia non valida
    CERTIFICATE_EXPIRED = 4         # Certificato scaduto
    CERTIFICATE_REVOKED = 5         # Certificato revocato
    UNAUTHORIZED = 6                # Non autorizzato
    INTERNAL_ERROR = 99             # Errore interno server
```

**Strutture Dati Principali**:

#### InnerEcRequest
Richiesta di Enrollment Certificate (parte interna, non cifrata):
```python
@dataclass
class InnerEcRequest:
    its_id: str                     # ID ITS Station
    public_key: bytes               # Chiave pubblica ITS-S (DER)
    requested_subject_attributes: dict
    timestamp: datetime
    
    def to_dict(self) -> dict
    @classmethod
    def from_dict(cls, data: dict)
```

#### EnrollmentRequest
Richiesta completa di EC (cifrata):
```python
@dataclass
class EnrollmentRequest:
    inner_request: InnerEcRequest   # Parte interna
    encrypted_data: bytes           # Dati cifrati con chiave EA
    signature: bytes                # Firma ITS-S (Proof of Possession)
```

#### InnerEcResponse
Risposta EC (parte interna):
```python
@dataclass
class InnerEcResponse:
    response_code: ResponseCode
    request_hash: bytes             # Hash richiesta originale
    certificate: Optional[bytes]    # Certificato EC emesso (PEM)
    
    def is_success(self) -> bool
```

#### InnerAtRequest
Richiesta di Authorization Ticket:
```python
@dataclass
class InnerAtRequest:
    its_id: str
    ec_certificate: bytes           # EC per validazione
    public_key_at: bytes            # Chiave pubblica per AT
    requested_permissions: list     # Permessi richiesti
    region: Optional[str]
    timestamp: datetime
```

#### SharedAtRequest
Richiesta AT condivisa (Butterfly):
```python
@dataclass
class SharedAtRequest:
    hmac: bytes                     # HMAC shared secret
    key_tag: int                    # Tag per batch
    ecdh_public_key: bytes          # Chiave pubblica ECDH
    encrypted_data: bytes
    timestamp: datetime
```

**Utility Functions**:
```python
def compute_request_hash(request_bytes: bytes) -> bytes
    """Calcola hash SHA256 della richiesta"""

def verify_timestamp(timestamp: datetime, max_age_seconds: int = 300) -> bool
    """Verifica validità timestamp (finestra 5 minuti)"""
```

**Utilizzo**:
```python
from protocols.etsi_message_types import (
    InnerEcRequest,
    ResponseCode,
    compute_request_hash
)

# Crea richiesta EC
request = InnerEcRequest(
    its_id="Vehicle_001",
    public_key=public_key_der,
    requested_subject_attributes={"region": "EU"},
    timestamp=datetime.now(timezone.utc)
)

# Serializza a dict
request_dict = request.to_dict()

# Calcola hash
request_bytes = json.dumps(request_dict).encode()
request_hash = compute_request_hash(request_bytes)

# Crea risposta
response = InnerEcResponse(
    response_code=ResponseCode.OK,
    request_hash=request_hash,
    certificate=ec_cert_pem
)
```

---

### ETSIMessageEncoder
**File**: `etsi_message_encoder.py`

Encoder/decoder per messaggi ETSI in formato ASN.1 OER (Octet Encoding Rules).

**Responsabilità**:
- Serializzazione messaggi in ASN.1 OER
- Deserializzazione messaggi ASN.1 OER
- Validazione conformità ETSI TS 102941
- Gestione crittografia messaggi

**Metodi Principali**:
```python
class ETSIMessageEncoder:
    def encode_enrollment_request(
        self,
        inner_request: InnerEcRequest,
        ea_public_key: PublicKey
    ) -> bytes:
        """
        Codifica EnrollmentRequest in ASN.1 OER.
        Cifra inner_request con chiave pubblica EA.
        """
    
    def decode_enrollment_request(
        self,
        request_bytes: bytes,
        ea_private_key: PrivateKey
    ) -> InnerEcRequest:
        """
        Decodifica EnrollmentRequest da ASN.1 OER.
        Decifra con chiave privata EA.
        """
    
    def encode_enrollment_response(
        self,
        response_code: ResponseCode,
        request_hash: bytes,
        certificate: Optional[bytes],
        itss_public_key: PublicKey
    ) -> bytes:
        """
        Codifica EnrollmentResponse in ASN.1 OER.
        Cifra risposta con chiave pubblica ITS-S.
        """
    
    def decode_enrollment_response(
        self,
        response_bytes: bytes,
        itss_private_key: PrivateKey
    ) -> InnerEcResponse:
        """
        Decodifica EnrollmentResponse da ASN.1 OER.
        Decifra con chiave privata ITS-S.
        """
```

**Utilizzo**:
```python
from protocols.etsi_message_encoder import ETSIMessageEncoder

encoder = ETSIMessageEncoder()

# EA: Decodifica richiesta ricevuta
inner_request = encoder.decode_enrollment_request(
    request_bytes=received_data,
    ea_private_key=ea.private_key
)

# EA: Codifica risposta
response_bytes = encoder.encode_enrollment_response(
    response_code=ResponseCode.OK,
    request_hash=compute_request_hash(received_data),
    certificate=ec_cert_pem,
    itss_public_key=inner_request.public_key
)

# ITS-S: Decodifica risposta
response = encoder.decode_enrollment_response(
    response_bytes=response_data,
    itss_private_key=vehicle.private_key
)

if response.is_success():
    print("EC ricevuto con successo!")
```

---

### Schema ASN.1
**File**: `etsi_ts_102941.asn`

Schema ASN.1 formale conforme a ETSI TS 102941 v2.1.1.

Definisce le strutture dati standard per:
- EnrollmentRequest/Response
- AuthorizationRequest/Response
- AuthorizationValidationRequest/Response
- CtlRequest/Response
- CrlRequest/Response

**Nota**: Lo schema è utilizzato come riferimento per l'implementazione. L'encoding/decoding effettivo è gestito da `ETSIMessageEncoder`.

---

### ButterflyKeyExpansion
**File**: `butterfly_key_expansion.py`

Implementa il protocollo Butterfly per generazione batch di Authorization Tickets preservando la privacy.

**Concetti Chiave**:
- **Unlinkability**: Gli AT nel batch non sono collegabili tra loro
- **Key Expansion**: Da un shared secret si derivano N chiavi diverse
- **ECDH**: Scambio chiavi Diffie-Hellman su curve ellittiche
- **HMAC-based KDF**: Key Derivation Function basata su HMAC

**Funzioni Principali**:
```python
def butterfly_key_expansion(
    shared_secret: bytes,
    key_tag: int,
    batch_size: int
) -> List[bytes]:
    """
    Espande shared secret in batch_size chiavi diverse.
    Ogni chiave è derivata da HMAC(shared_secret, key_tag || index).
    """

def generate_butterfly_batch(
    aa: AuthorizationAuthority,
    its_id: str,
    batch_size: int,
    ecdh_public_key: bytes,
    hmac_value: bytes,
    key_tag: int
) -> List[Certificate]:
    """
    Genera batch di AT usando Butterfly key expansion.
    Ogni AT usa una chiave pubblica diversa derivata dal protocollo.
    """
```

**Utilizzo**:
```python
from protocols.butterfly_key_expansion import (
    butterfly_key_expansion,
    generate_butterfly_batch
)

# ITS-S: Genera shared secret ECDH
itss_private = ec.generate_private_key(ec.SECP256R1())
itss_public = itss_private.public_key()

# ITS-S: Calcola shared secret con AA public key
shared_secret = itss_private.exchange(ec.ECDH(), aa_public_key)

# ITS-S: Calcola HMAC
key_tag = random.randint(0, 2**16)
hmac_value = hmac.new(shared_secret, key_tag.to_bytes(2, 'big'), sha256).digest()

# AA: Genera batch AT
at_batch = generate_butterfly_batch(
    aa=authorization_authority,
    its_id="Vehicle_001",
    batch_size=20,
    ecdh_public_key=itss_public_bytes,
    hmac_value=hmac_value,
    key_tag=key_tag
)

# ITS-S: Deriva chiavi localmente
derived_keys = butterfly_key_expansion(
    shared_secret=shared_secret,
    key_tag=key_tag,
    batch_size=20
)

# Ogni derived_key corrisponde a un AT nel batch
```

---

### ETSILinkCertificateEncoder
**File**: `etsi_link_certificate.py`

Encoder per Link Certificates conformi a ETSI TS 102941.

**Responsabilità**:
- Codifica/decodifica Link Certificates in ASN.1 OER
- Calcolo HashedId8 per identificazione certificati
- Encoding Time32 ETSI
- Firma e verifica Link Certificates

**Strutture**:
```python
@dataclass
class ToBeSignedLinkCertificate:
    version: int
    expiryTime: int                 # Time32 ETSI format
    certificateHash: bytes          # HashedId8
    linkCertificateName: str

@dataclass  
class LinkCertificate:
    toBeSigned: ToBeSignedLinkCertificate
    signature: bytes
```

**Funzioni**:
```python
def compute_hashed_id8(certificate_der: bytes) -> bytes:
    """Calcola HashedId8 da certificato (primi 8 byte di SHA256)"""

def encode_time32(dt: datetime) -> int:
    """Converte datetime a Time32 ETSI (secondi da epoch)"""

def decode_time32(time32: int) -> datetime:
    """Converte Time32 ETSI a datetime"""

def sign_link_certificate(
    tbs_cert: ToBeSignedLinkCertificate,
    private_key: PrivateKey
) -> LinkCertificate:
    """Firma ToBeSignedLinkCertificate"""

def verify_link_certificate_signature(
    link_cert: LinkCertificate,
    public_key: PublicKey
) -> bool:
    """Verifica firma Link Certificate"""
```

---

## Flussi Protocollo ETSI

### Enrollment Flow
```
ITS-S                          EA
  |                             |
  | 1. EnrollmentRequest        |
  |  (cifrato con EA pub key)   |
  |---------------------------->|
  |                             | 2. Verifica PoP
  |                             | 3. Emette EC
  | 4. EnrollmentResponse       |
  |  (cifrato con ITS-S pub key)|
  |<----------------------------|
  |                             |
  | 5. Salva EC                 |
```

### Authorization Flow (Standard)
```
ITS-S                          AA
  |                             |
  | 1. AuthorizationRequest     |
  |  (include EC)               |
  |---------------------------->|
  |                             | 2. Valida EC
  |                             | 3. Emette AT
  | 4. AuthorizationResponse    |
  |  (include AT)               |
  |<----------------------------|
  |                             |
```

### Authorization Flow (Butterfly)
```
ITS-S                          AA
  |                             |
  | 1. ButterflyAuthRequest     |
  |  (ECDH pub key + HMAC)      |
  |---------------------------->|
  |                             | 2. Calcola shared secret
  |                             | 3. Key expansion
  |                             | 4. Genera batch AT
  | 5. ButterflyAuthResponse    |
  |  (batch N AT cifrati)       |
  |<----------------------------|
  |                             |
  | 6. Deriva chiavi localmente |
  | 7. Usa AT del batch         |
```

## Standard di Riferimento

- **ETSI TS 102941 v2.1.1**: Trust and Privacy Management
- **ETSI TS 103097**: Security header and certificate formats
- **IEEE 1609.2**: Security Services
- **RFC 5280**: X.509 Certificate and CRL Profile

## Note Implementative

### Crittografia
- **Algoritmo**: AES-128-CCM (futuro)
- **Curve**: secp256r1 (NIST P-256)
- **Hash**: SHA256
- **KDF**: HMAC-based (Butterfly)

### Encoding
- **Formato**: ASN.1 OER (Octet Encoding Rules)
- **Schema**: ETSI TS 102941 v2.1.1
- **Compatibilità**: ETSI TS 103097

### Sicurezza
- Tutte le richieste includono timestamp (anti-replay)
- Finestra validità timestamp: 5 minuti
- Proof of Possession obbligatorio per EC
- Cifratura end-to-end per dati sensibili

## Testing

Test specifici per i protocolli:
```bash
pytest tests/test_etsi_protocols.py          # Test protocolli base
pytest tests/test_butterfly_authorization.py # Test Butterfly
pytest tests/test_etsi_link_certificates.py  # Test Link Certificates
```

## Roadmap

- [ ] Completamento encoding ASN.1 OER
- [ ] Implementazione AES-128-CCM encryption
- [ ] Butterfly batch AT completo
- [ ] Validazione schema ASN.1 formale
- [ ] Performance optimization encoding/decoding
