# Examples Directory

Examples and demonstrations for SecureRoad PKI REST API.

## Available Examples

### `api_client_example.py`

Comprehensive examples showing how to interact with the REST API from a client perspective.

**Features:**
- ✅ Health check endpoints
- ✅ Enrollment flow structure
- ✅ Authorization flow structure  
- ✅ Butterfly authorization (batch)
- ✅ CRL distribution
- ✅ CTL distribution
- ✅ Error handling with ETSI response codes

**Usage:**
```powershell
# Make sure servers are running first
python run_ea_server.py  # Terminal 1
python run_aa_server.py  # Terminal 2

# Then run examples
python examples/api_client_example.py  # Terminal 3
```

**Note:** This example shows the API call structure but doesn't include actual ASN.1 OER encoding. For real implementation:
1. Use `ETSIMessageEncoder` from `entities/`
2. Implement proper ASN.1 encoding/decoding
3. Handle encryption/decryption correctly
4. Follow ETSI TS 102941 Section 6 specifications

## Creating Your Own Client

### Basic Structure

```python
import requests
from entities.its_station import ITSStation

# Configuration
EA_URL = "http://localhost:5001"
API_KEY = "ea-secret-key-12345"

# Create ITS-S
itss = ITSStation(vehicle_id="MyVehicle", base_dir="data/itss")

# Prepare request (pseudo-code)
# inner_ec_request = create_inner_ec_request()
# encrypted_request = encrypt_for_ea(inner_ec_request)
# der_encoded = encode_asn1_oer(encrypted_request)

# Send request
response = requests.post(
    f"{EA_URL}/enrollment/request",
    headers={
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/octet-stream'
    },
    data=der_encoded,
    timeout=30
)

# Handle response
if response.status_code == 200:
    # Decode and process
    response_der = response.content
    # decrypted = decrypt_with_canonical_key(response_der)
    # enrollment_cert = extract_certificate(decrypted)
    print("✅ Enrollment successful!")
else:
    error = response.json()
    print(f"❌ Error: {error['error']}")
    print(f"Response Code: {error['responseCode']}")
```

### Key Points

1. **Always use ASN.1 OER encoding** (not JSON)
   - Use `asn1tools` library
   - Follow ETSI TS 103097 for message structure
   - Follow ISO/IEC 8825-7:2015 for encoding rules

2. **Authentication**
   - Use Bearer token in Authorization header
   - Keep API keys secure
   - Consider mTLS for production

3. **Error Handling**
   - Check HTTP status codes
   - Parse ETSI response codes (0-15)
   - Implement retry logic with exponential backoff

4. **Encryption/Decryption**
   - Enrollment: Encrypt with EA public key, decrypt with canonical private key
   - Authorization: Encrypt with AA public key, decrypt with **hmacKey** (not canonical!)
   - Follow ETSI TS 103097 Section 5 for encryption

## Testing Workflow

### 1. Setup Environment

```powershell
# Install dependencies
pip install -r requirements.txt

# Start servers
python run_ea_server.py  # Port 5001
python run_aa_server.py  # Port 5002
```

### 2. Test Health Checks

```powershell
curl http://localhost:5001/health
curl http://localhost:5002/health
```

### 3. Run Example Suite

```powershell
python examples/api_client_example.py
```

### 4. Implement Real Client

Use the examples as reference and implement:
- ASN.1 OER encoding/decoding
- Cryptographic operations
- Certificate storage and management

## Integration with Existing Tests

The existing test suite in `example_test/` can be adapted to use REST API:

```python
# Before: Direct class usage
ea = EnrollmentAuthority(...)
cert = ea.issue_enrollment_certificate(...)

# After: REST API usage
import requests
response = requests.post(
    "http://localhost:5001/enrollment/request",
    headers=headers,
    data=encoded_request
)
```

See `tests/test_api_basic.py` for examples of testing REST API endpoints.

## Production Considerations

### Security

- ✅ Change default API keys
- ✅ Use HTTPS/TLS 1.3
- ✅ Implement mTLS for mutual authentication
- ✅ Enable rate limiting (configured in server)
- ✅ Use secure key storage (HSM in production)

### Performance

- ✅ Connection pooling with `requests.Session()`
- ✅ Retry logic with exponential backoff
- ✅ Timeout configuration
- ✅ Async requests for batch operations

### Monitoring

- ✅ Log all API interactions
- ✅ Monitor response times
- ✅ Track error rates
- ✅ Alert on authentication failures

## ETSI Compliance Checklist

When implementing your client, ensure:

- ✅ ASN.1 OER encoding (ISO/IEC 8825-7:2015)
- ✅ ETSI TS 103097 message structure
- ✅ ETSI TS 102941 Section 6 protocol flows
- ✅ Proper Proof of Possession in enrollment
- ✅ hmacKey usage for authorization unlinkability
- ✅ Certificate chain validation
- ✅ CRL checking before trust
- ✅ CTL validation with TLM

## Common Issues

### "requests module not found"

```powershell
pip install requests
```

### "Connection refused"

Make sure servers are running:
```powershell
python run_ea_server.py
python run_aa_server.py
```

### "Invalid response code"

Server returned ETSI error code. Check:
- Request format (ASN.1 OER)
- Content-Type header
- Authentication token
- Request body structure

### "Decryption failed"

For authorization, remember:
- Response encrypted with **hmacKey** (not canonical private key)
- hmacKey must be stored from request
- Don't confuse enrollment and authorization decryption

## Resources

- **API Documentation**: `api/README.md`
- **Setup Guide**: `docs/API_IMPLEMENTATION_COMPLETE.md`
- **Quick Start**: `docs/QUICK_START_API.md`
- **ETSI Standards**:
  - TS 102941 V2.1.1: Trust and Privacy Management
  - TS 103097: Security Header and Certificate Formats
- **ISO Standards**:
  - ISO/IEC 8825-7:2015: ASN.1 OER encoding rules

---

**Author**: SecureRoad PKI Project  
**Date**: October 2025  
**Conformity**: ETSI TS 102941 V2.1.1, ETSI TS 103097, ISO/IEC 8825-7:2015
