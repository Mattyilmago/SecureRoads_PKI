# 🔒 Security Best Practices - SecureRoad PKI

## ⚠️ ATTENZIONE: Configurazione Produzione

Questo documento contiene le raccomandazioni di sicurezza **CRITICHE** per deployment in produzione.

---

## 1. 🔑 API Keys Management

### ❌ MAI FARE:
```python
# ❌ HARDCODED API KEYS
EA_API_KEY = "ea-secret-key-12345"  # VULNERABILITÀ!
```

### ✅ BEST PRACTICE:
```bash
# Use environment variables
export EA_API_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
export AA_API_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(32))")
```

```python
# In your code
import os
api_key = os.getenv("EA_API_KEY")
if not api_key:
    raise ValueError("EA_API_KEY environment variable not set!")
```

### 🔧 Configurazione Server:
```python
# start_production_server.py già genera API keys sicure
python start_production_server.py --entity EA --config config.json

# config.json
{
    "api_keys": ["<generated-secure-key>"],  # ✅ Usa secrets.token_urlsafe(32)
    "log_level": "INFO"
}
```

---

## 2. 🛡️ mTLS Authentication (Production)

### Setup mTLS per Inter-Authority Communication:

```python
from api.middleware.mtls_auth import MTLSAuthenticator, require_mtls

# Initialize mTLS authenticator
mtls_auth = MTLSAuthenticator(
    root_ca=root_ca,
    crl_manager=crl_manager,
    allowed_authority_types=['EA', 'AA'],
    cache_ttl=300  # 5 minutes
)

# Protect endpoints
@bp.route('/api/enrollment/request', methods=['POST'])
@require_mtls(['EA'])  # Only EA can call this
def enrollment_request():
    # Client certificate already validated
    return process_request()
```

### Configurazione Flask con mTLS:
```python
app = create_app(
    entity_type="EA",
    entity_instance=ea,
    config={
        "tls_enabled": True,
        "tls_cert": "certs/ea_cert.pem",
        "tls_key": "certs/ea_key.pem",
        "tls_ca_cert": "certs/root_ca.pem",  # For client verification
        "mtls_required": True
    }
)
```

---

## 3. 🔐 TLS/HTTPS Configuration

### ❌ NEVER in Production:
```python
app.run(host='0.0.0.0', port=5000)  # ❌ HTTP only!
```

### ✅ ALWAYS Use HTTPS:
```python
# Development (self-signed)
from werkzeug.serving import make_ssl_devcert
make_ssl_devcert('./ssl', host='localhost')

app.run(
    host='0.0.0.0',
    port=5000,
    ssl_context=('./ssl/cert.pem', './ssl/key.pem')
)
```

### ✅ Production (Let's Encrypt or CA-signed):
```python
# Use gunicorn + nginx reverse proxy
# gunicorn.conf.py
bind = "0.0.0.0:5000"
certfile = "/etc/letsencrypt/live/your-domain/fullchain.pem"
keyfile = "/etc/letsencrypt/live/your-domain/privkey.pem"
ssl_version = 5  # TLS 1.2+
ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
```

---

## 4. 🚦 Rate Limiting

### Current Implementation (Token Bucket):
```python
# api/middleware/rate_limiting.py
# ✅ Già implementato!

from api.middleware import custom_rate_limit

@bp.route('/api/enrollment/request', methods=['POST'])
@custom_rate_limit(requests_per_second=10, burst_size=20)
def enrollment_request():
    return process_request()
```

### Configurazione Consigliata:
```python
RATE_LIMITS = {
    'enrollment': (10, 20),      # 10 req/s, burst 20
    'authorization': (50, 100),  # 50 req/s, burst 100
    'crl_download': (100, 200),  # 100 req/s, burst 200
    'butterfly': (5, 10)         # 5 req/s, burst 10 (expensive)
}
```

---

## 5. 🔍 Input Validation

### ✅ Già implementato in blueprints:
```python
# api/blueprints/enrollment_bp.py
def validate_content_type():
    if request.content_type != 'application/octet-stream':
        return jsonify({
            "error": "Invalid Content-Type",
            "responseCode": ResponseCode.BAD_REQUEST.value
        }), 415
```

### Best Practice - Size Limits:
```python
# flask_app_factory.py
app.config.update({
    'MAX_CONTENT_LENGTH': 10 * 1024 * 1024,  # 10 MB max
})
```

---

## 6. 🪵 Secure Logging

### ❌ Non Loggare Dati Sensibili:
```python
# ❌ WRONG
logger.info(f"API Key: {api_key}")  # Espone credenziali!
logger.debug(f"Private key: {private_key}")  # Mai loggare chiavi!
```

### ✅ Logging Sicuro:
```python
# ✅ CORRECT
from utils.logger import PKILogger

logger = PKILogger.setup_logger("api_server")
logger.info(f"Authentication attempt from {request.remote_addr}")
logger.info(f"Certificate issued for ITS-S: {its_id}")  # OK
logger.debug(f"Certificate SKI: {get_certificate_ski(cert)}")  # OK
```

### ✅ Audit Logging (già implementato):
```python
# entities/enrollment_authority.py - Già usa PKILogger
self.logger.info(
    f"Issued enrollment certificate to ITS-S {its_id}, "
    f"serial={cert.serial_number}"
)
```

---

## 7. 🧪 Exception Handling

### ❌ Exception Troppo Generiche:
```python
# ❌ FIXED in questo code review
try:
    validate_signature()
except Exception:  # Nasconde errori!
    return False
```

### ✅ Specific Exceptions:
```python
# ✅ UPDATED
try:
    validate_signature()
except InvalidSignature:
    logger.warning("Invalid signature")
    return False
except (ValueError, TypeError) as e:
    logger.error(f"Validation error: {e}")
    return False
```

---

## 8. 📦 Dependency Security

### Check Dependencies Regularly:
```bash
# Check for vulnerabilities
pip install safety
safety check --json

# Update dependencies
pip list --outdated
pip install --upgrade cryptography flask
```

### Current Critical Dependencies:
- ✅ `cryptography>=46.0.2` - Latest, secure
- ✅ `flask>=3.0.0` - Latest, secure
- ✅ `werkzeug>=3.0.0` - Latest, secure

---

## 9. 🔒 Private Key Storage

### ❌ NEVER Store Private Keys in Git:
```bash
# Add to .gitignore
data/*/private_key.pem
*.key
*.p12
*.pfx
```

### ✅ Production - Use HSM:
```python
# For production, integrate Hardware Security Module
from cryptography.hazmat.primitives import serialization
from pkcs11 import PKCS11

# Example: Load key from HSM
session = pkcs11_lib.get_session()
private_key = session.get_key(label="EA_SIGNING_KEY")
```

---

## 10. 🌐 CORS Configuration

### ✅ Development (già configurato):
```python
# api/flask_app_factory.py
CORS(app, resources={r"/*": {"origins": "*"}})  # OK per dev
```

### ⚠️ Production - Restrict Origins:
```python
# Production config
CORS(app, resources={
    r"/api/*": {
        "origins": [
            "https://your-frontend.com",
            "https://admin.your-domain.com"
        ],
        "allow_headers": ["Content-Type", "Authorization"],
        "methods": ["GET", "POST"]
    }
})
```

---

## 🎯 Quick Security Checklist

Prima di andare in produzione:

- [ ] ✅ API keys generate con `secrets.token_urlsafe(32)`
- [ ] ✅ mTLS abilitato per inter-authority communication
- [ ] ✅ HTTPS/TLS 1.3 con certificati CA-signed
- [ ] ✅ Rate limiting configurato e testato
- [ ] ✅ CORS origins limitati (non `*`)
- [ ] ✅ MAX_CONTENT_LENGTH configurato (10MB)
- [ ] ✅ Logging configurato senza dati sensibili
- [ ] ✅ Exception handling specifico (no bare `except Exception`)
- [ ] ✅ Private keys in HSM o storage sicuro
- [ ] ✅ Dependencies aggiornate (security patches)
- [ ] ✅ `.gitignore` configurato per escludere chiavi
- [ ] ✅ Monitoring e alerting configurati
- [ ] ✅ Backup automatici configurati
- [ ] ✅ Disaster recovery plan definito

---

## 📚 Riferimenti

- ETSI TS 102941 - Section 6.2: Security Considerations
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- Flask Security Best Practices: https://flask.palletsprojects.com/en/3.0.x/security/
- Cryptography Library Docs: https://cryptography.io/

---

**Autore**: SecureRoad PKI Project  
**Data**: October 2025  
**Versione**: 1.0
