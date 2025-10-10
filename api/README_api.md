# API - REST API per Comunicazione Inter-Authority

Questa cartella contiene l'implementazione delle REST API per la comunicazione tra entità PKI e distribuzione di certificati/CRL/CTL.

## Stato: IN SVILUPPO (10%)

Le API sono attualmente in fase iniziale di sviluppo. La struttura Flask base è implementata ma gli endpoint sono parzialmente funzionanti.

## Componenti

### flask_app_factory
**File**: `flask_app_factory.py`

Factory per creazione applicazioni Flask per EA, AA e TLM.

**Funzioni**:
```python
def create_ea_app(enrollment_authority: EnrollmentAuthority) -> Flask:
    """
    Crea applicazione Flask per Enrollment Authority.
    
    Endpoint disponibili:
    - GET  /health              - Health check
    - POST /api/v1/enrollment   - Richiesta EC
    - GET  /api/v1/crl/full     - Download Full CRL
    - GET  /api/v1/crl/delta    - Download Delta CRL
    """

def create_aa_app(authorization_authority: AuthorizationAuthority) -> Flask:
    """
    Crea applicazione Flask per Authorization Authority.
    
    Endpoint disponibili:
    - GET  /health                    - Health check
    - POST /api/v1/authorization      - Richiesta AT standard
    - POST /api/v1/authorization/butterfly - Richiesta AT butterfly batch
    - GET  /api/v1/crl/full           - Download Full CRL
    - GET  /api/v1/crl/delta          - Download Delta CRL
    """

def create_tlm_app(trust_list_manager: TrustListManager) -> Flask:
    """
    Crea applicazione Flask per Trust List Manager.
    
    Endpoint disponibili:
    - GET /health                     - Health check
    - GET /api/v1/ctl/full            - Download Full CTL
    - GET /api/v1/ctl/delta           - Download Delta CTL
    - GET /api/v1/trust-anchors       - Lista trust anchors
    - GET /api/v1/link-certificates   - Link certificates
    """
```

## Blueprint Disponibili

### enrollment_bp (ETSI Conforme) ✅
**File**: `blueprints/enrollment_bp.py`

Gestisce le richieste di enrollment certificate secondo lo standard ETSI TS 102941.

**Endpoint ETSI Conforme**:
```
POST /api/enrollment/request
Content-Type: application/octet-stream
X-API-Key: <api_key>

Body: ASN.1 OER encoded EtsiTs102941Data-Encrypted {
  version: 2,
  encryptedData: OCTET STRING (contiene InnerEcRequest),
  recipientId: HashedId8,
  timestamp: Time32
}

Response:
  200 OK: ASN.1 OER encoded EtsiTs102941Data {
    version: 2,
    content: InnerEcResponse {
      requestHash: OCTET STRING (SHA-256),
      responseCode: EnrolmentResponseCode,
      certificate: EtsiTs103097Certificate (se OK)
    }
  }
  400 Bad Request: Richiesta malformata
  401 Unauthorized: Autenticazione fallita
  500 Internal Server Error: Errore server
```

### enrollment_simple_bp (Solo Testing) ⚠️
**File**: `blueprints/enrollment_simple_bp.py`

**⚠️ NON CONFORME ALLO STANDARD - SOLO PER TESTING/DEBUG**

**Endpoint Semplificato**:
```
POST /api/enrollment/request/simple
Content-Type: application/json
X-API-Key: <api_key>

Body:
{
  "its_id": "VEHICLE_001",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
  "requested_attributes": {
    "region": "EU",
    "validity_period": "P3Y"
  }
}

Response:
{
  "response_code": "OK",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "request_hash": "<hex_hash>"
}
```

**Note**:
- ✅ Usare `/api/enrollment/request` per produzione (conforme ETSI)
- ⚠️ Usare `/api/enrollment/request/simple` solo per testing manuale con Swagger UI

### authorization_bp
**File**: `blueprints/authorization_bp.py`

Gestisce le richieste di authorization tickets.

**Endpoint Standard**:
```
POST /api/v1/authorization
Content-Type: application/json
Authorization: Bearer <api_key>

Body:
{
  "its_id": "Vehicle_001",
  "ec_certificate": "<base64_encoded_pem>",
  "permissions": ["CAM", "DENM"],
  "region": "EU"
}

Response:
{
  "response_code": "OK",
  "at_certificate": "<base64_encoded_pem>"
}
```

**Endpoint Butterfly**:
```
POST /api/v1/authorization/butterfly
Content-Type: application/octet-stream
Authorization: Bearer <api_key>

Body: ASN.1 OER encoded ButterflyAuthorizationRequest

Response: ASN.1 OER encoded ButterflyAuthorizationResponse (batch AT)
```

### crl_bp
**File**: `blueprints/crl_bp.py`

Distribuzione Certificate Revocation Lists.

**Endpoint**:
```
GET /api/v1/crl/full
Response: PEM encoded Full CRL

GET /api/v1/crl/delta
Response: PEM encoded Delta CRL

GET /api/v1/crl/info
Response:
{
  "last_full_number": 5,
  "last_delta_number": 42,
  "total_revoked": 15,
  "last_update": "2025-10-09T10:00:00Z"
}
```

### trust_list_bp
**File**: `blueprints/trust_list_bp.py`

Distribuzione Certificate Trust Lists e trust anchors.

**Endpoint**:
```
GET /api/v1/ctl/full
Response: JSON encoded Full CTL

GET /api/v1/ctl/delta
Response: JSON encoded Delta CTL

GET /api/v1/trust-anchors
Response:
{
  "trust_anchors": [
    {
      "identifier": "CERT_ROOT_001",
      "type": "ROOT",
      "subject": "CN=RootCA",
      "certificate": "<pem>"
    }
  ]
}

GET /api/v1/link-certificates
Response: Array di Link Certificates JSON
```

## Middleware

### auth.py
**File**: `middleware/auth.py`

Autenticazione richieste API.

**Modalità**:
1. **API Key**: Header `Authorization: Bearer <key>`
2. **mTLS**: Mutual TLS con certificati client (futuro)

**Funzioni**:
```python
def require_api_key(f):
    """Decorator per richiedere API key valida"""

def validate_client_certificate(f):
    """Decorator per validare certificato client mTLS"""
```

### rate_limiting.py
**File**: `middleware/rate_limiting.py`

Rate limiting per prevenire abusi.

**Configurazione**:
```python
RATE_LIMITS = {
    'enrollment': '10 per minute',
    'authorization': '50 per minute',
    'crl_download': '100 per hour',
    'ctl_download': '100 per hour'
}
```

## Utilizzo

### Avvio Server EA
```python
from api.flask_app_factory import create_ea_app
from entities.enrollment_authority import EnrollmentAuthority

# Crea EA
ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_001")

# Crea app Flask
app = create_ea_app(ea)

# Avvia server
app.run(host='0.0.0.0', port=5000, ssl_context='adhoc')
```

### Avvio Server AA
```python
from api.flask_app_factory import create_aa_app
from entities.authorization_authority import AuthorizationAuthority

# Crea AA
aa = AuthorizationAuthority(root_ca=root_ca, aa_id="AA_001", tlm=tlm)

# Crea app Flask
app = create_aa_app(aa)

# Avvia server
app.run(host='0.0.0.0', port=5001, ssl_context='adhoc')
```

### Client: Richiesta EC
```python
import requests

# Prepara richiesta
enrollment_request = encoder.encode_enrollment_request(
    inner_request=inner_ec_request,
    ea_public_key=ea.certificate.public_key()
)

# Invia richiesta
response = requests.post(
    'https://ea.example.com:5000/api/v1/enrollment',
    headers={
        'Content-Type': 'application/octet-stream',
        'Authorization': f'Bearer {api_key}'
    },
    data=enrollment_request,
    verify='ca-bundle.pem'  # Verifica certificato server
)

if response.status_code == 200:
    # Decodifica risposta
    ec_response = encoder.decode_enrollment_response(
        response.content,
        vehicle.private_key
    )
    
    if ec_response.is_success():
        print("EC ricevuto!")
```

### Client: Download CRL
```python
import requests

response = requests.get(
    'https://ea.example.com:5000/api/v1/crl/delta',
    headers={'Authorization': f'Bearer {api_key}'}
)

if response.status_code == 200:
    # Salva CRL
    with open('ea_delta_crl.pem', 'wb') as f:
        f.write(response.content)
```

## Configurazione

### Certificati SSL/TLS
```python
# Genera certificati self-signed per testing
from werkzeug.serving import make_ssl_devcert
make_ssl_devcert('./ssl', host='localhost')

# Usa certificati in produzione
app.run(
    host='0.0.0.0',
    port=5000,
    ssl_context=('./ssl/cert.pem', './ssl/key.pem')
)
```

### API Keys
```python
# Genera API key
import secrets
api_key = secrets.token_urlsafe(32)

# Salva in configurazione
API_KEYS = {
    'ea_client_1': 'key_abc123...',
    'vehicle_001': 'key_xyz789...'
}
```

## Sicurezza

### Best Practices
1. **Sempre HTTPS**: Mai HTTP in produzione
2. **API Keys robuste**: Almeno 32 bytes random
3. **Rate Limiting**: Prevenire DoS
4. **Input Validation**: Validare tutti gli input
5. **Error Messages**: Non esporre dettagli interni
6. **Logging**: Log tutte le richieste (audit)
7. **mTLS**: Usare mutual TLS in produzione

### Autenticazione Produzione
```python
# mTLS configuration
app.config.update(
    SSL_CLIENT_AUTH='required',
    SSL_CLIENT_CA='ca-bundle.pem'
)

@app.before_request
def verify_client_cert():
    cert = request.environ.get('SSL_CLIENT_CERT')
    if not cert:
        abort(401)
    
    # Valida certificato client
    client_cert = x509.load_pem_x509_certificate(cert.encode())
    if not is_trusted(client_cert):
        abort(403)
```

## Testing API

### Test con curl
```bash
# Health check
curl https://localhost:5000/health

# Enrollment (con file binario)
curl -X POST https://localhost:5000/api/v1/enrollment \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @enrollment_request.bin \
  -o enrollment_response.bin

# Download CRL
curl https://localhost:5000/api/v1/crl/delta \
  -H "Authorization: Bearer ${API_KEY}" \
  -o delta_crl.pem
```

### Test automatici
```bash
pytest tests/test_rest_api.py
```

## Roadmap API

- [x] Struttura Flask base
- [x] Blueprint enrollment (parziale)
- [x] Blueprint authorization (parziale)
- [ ] Completare tutti gli endpoint
- [ ] Implementare autenticazione mTLS
- [ ] Rate limiting completo
- [ ] Logging strutturato
- [ ] Documentazione OpenAPI/Swagger
- [ ] Client SDK Python
- [ ] Container Docker

## Riferimenti

- [Flask Documentation](https://flask.palletsprojects.com/)
- [REST API Best Practices](https://restfulapi.net/)
- ETSI TS 102941 - Trust and Privacy Management
