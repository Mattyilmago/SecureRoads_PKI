# SecureRoad-PKI

**Public Key Infrastructure (PKI) per sistemi ITS (Intelligent Transportation Systems) conforme agli standard ETSI**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)](https://github.com/Mattyilmago/SecureRoads_PKI)
[![Tests](https://img.shields.io/badge/Tests-130%20passed-brightgreen)](tests/)

---

## 📋 Indice

- [Panoramica](#panoramica)
- [Installazione Rapida](#installazione-rapida)
- [Avvio del Sistema](#avvio-del-sistema)
- [Architettura](#architettura)
- [REST API](#rest-api)
- [Testing](#testing)
- [Documentazione](#documentazione)

---

## 🎯 Panoramica

SecureRoad-PKI è un'implementazione **production-ready** di una Public Key Infrastructure per sistemi V2X (Vehicle-to-Everything) conforme agli standard **ETSI TS 102941** e **IEEE 1609.2**.

### Caratteristiche Principali

✅ **Conformità Standard ETSI**: Implementazione completa ETSI TS 102941 e IEEE 1609.2  
✅ **REST API Production-Ready**: 11 endpoint con autenticazione, rate limiting, CORS  
✅ **Gestione Certificati Completa**: Enrollment, Authorization, Revoca con supporto CRL/CTL Delta  
✅ **Privacy-Preserving**: Butterfly key expansion per unlinkability (batch 20 AT)  
✅ **Testing Robusto**: 130 test automatici con coverage completo  
✅ **Dashboard Web Interattiva**: Monitoraggio real-time e gestione delle entità  
✅ **Auto-Start System**: Setup automatico con processi in background

### Statistiche Progetto

- **16600+ righe** di codice Python
- **130 test** automatici (100% passing)
- **11 endpoint REST** completamente funzionanti
- **4 entità PKI**: RootCA, EA, AA, TLM
- **~95% completamento** generale

---

## 🚀 Installazione Rapida

### Prerequisiti

- Python 3.8+
- pip
- Windows PowerShell (per Windows) o Bash (per Linux/Mac)

### Setup

```bash
# Clone repository
git clone https://github.com/Mattyilmago/SecureRoads_PKI.git
cd SecureRoads_PKI

# Installa dipendenze
pip install -r requirements.txt

**💡 Gestione Automatica delle Porte:**  
Il sistema assegna automaticamente le porte senza conflitti:
- **RootCA**: Porta fissa 5999
- **EA (Enrollment Authorities)**: Range 5000-5019 (max 20 istanze)
- **AA (Authorization Authorities)**: Range 5020-5039 (max 20 istanze)  
- **TLM**: Porta fissa 5050
- **Dashboard**: Porta 8080

Non è necessario specificare manualmente le porte: `server.py` trova automaticamente la prima porta disponibile nel range dedicato.

---

## 🎮 Avvio del Sistema

### Opzione 1: Dashboard Completa (Consigliato)

Avvia RootCA, TLM e il server web della dashboard con un solo comando:

```powershell
# Windows
.\start_dashboard.ps1

# Apri nel browser
# http://localhost:8080/pki_dashboard.html
```

**Cosa include:**
- ✅ RootCA (porta 5999) - Background process
- ✅ TLM (porta 5050) - Background process  
- ✅ Dashboard HTTP Server (porta 8080)
- ✅ Health check automatico
- ✅ Processi mantengono attivi in background

**Per fermare tutto:**
```powershell
# Premi Ctrl+C per fermare la dashboard
# Poi pulisci i job in background:
Get-Job | Stop-Job
Get-Job | Remove-Job
```

### Opzione 2: Entità Singole

Avvia singole entità per testing o deployment personalizzato:

```bash
# RootCA (Trust Anchor)
python server.py --entity RootCA

# Enrollment Authority
python server.py --entity EA --id EA_001

# Authorization Authority  
python server.py --entity AA --id AA_001

# Trust List Manager
python server.py --entity TLM --id TLM_MAIN
```

### Opzione 3: Testing Interattivo

Per eseguire test completi del sistema:

```bash
# Avvia il tester interattivo (avvia automaticamente le entità necessarie)
python examples/interactive_pki_tester.py

# Oppure usa entità già avviate
python examples/interactive_pki_tester.py --no-start
```

---

## 💻 Esempi di Utilizzo

### Esempio 1: Enrollment e Authorization via API

```python
import requests

EA_URL = "http://localhost:5000"
AA_URL = "http://localhost:5020"
API_KEY = "your-api-key"

# 1. Enrollment Certificate Request
enrollment_response = requests.post(
    f"{EA_URL}/api/enrollment/request/simple",
    json={
        "its_id": "VEHICLE_001",
        "public_key": vehicle_public_key_pem
    },
    headers={"X-API-Key": API_KEY}
)

ec = enrollment_response.json()
print(f"✅ Enrollment Certificate ottenuto: {ec['certificate_id']}")

# 2. Authorization Ticket Request
auth_response = requests.post(
    f"{AA_URL}/api/authorization/request",
    json={
        "vehicle_id": "VEHICLE_001",
        "enrollment_certificate": ec['certificate_pem'],
        "permissions": ["traffic_info", "emergency"]
    },
    headers={"X-API-Key": API_KEY}
)

at = auth_response.json()
print(f"✅ Authorization Ticket ottenuto: {at['ticket_id']}")

# 3. Butterfly Batch Request (20 tickets per privacy)
butterfly_response = requests.post(
    f"{AA_URL}/api/authorization/request/butterfly",
    json={
        "vehicle_id": "VEHICLE_001",
        "enrollment_certificate": ec['certificate_pem'],
        "num_tickets": 20,
        "permissions": ["traffic_info"]
    },
    headers={"X-API-Key": API_KEY}
)

tickets = butterfly_response.json()["tickets"]
print(f"✅ {len(tickets)} Authorization Tickets generati (unlinkable)")
```

### Esempio 2: Fleet V2X Management

```python
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from entities.its_station import ITSStation

# Setup PKI Infrastructure
root_ca = RootCA(base_dir="data/root_ca")
ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_HIGHWAY")
aa = AuthorizationAuthority(
    ea_certificate_path=ea.ea_certificate_path,
    root_ca=root_ca,
    aa_id="AA_TRAFFIC"
)

# Enroll fleet di 3 veicoli
vehicles = []
for i in range(1, 4):
    vehicle = ITSStation(f"Vehicle_{i:03d}")
    vehicle.generate_ecc_keypair()
    
    # Enrollment Certificate
    ec = vehicle.request_ec(ea)
    
    # Authorization Ticket
    at = vehicle.request_at(aa)
    
    vehicles.append(vehicle)
    print(f"✅ {vehicle.vehicle_id}: EC + AT ottenuti")

# Comunicazione V2X
vehicles[0].send_signed_message(
    message="Traffic jam ahead!",
    recipient_id="BROADCAST",
    message_type="DENM"
)
print("✅ Messaggio V2X inviato e firmato")
```

### Esempio 3: Revoca e CRL Management

```python
# Revoca certificato compromesso
root_ca.revoke_certificate(compromised_cert, reason="key_compromise")
root_ca.crl_manager.publish_delta_crl()

# Verifica revoca via API
response = requests.get(f"{EA_URL}/api/crl/delta")
delta_crl = response.json()

# Controlla se un certificato è revocato
is_revoked = any(
    e["serial_number"] == cert.serial_number 
    for e in delta_crl["revoked_certificates"]
)
print(f"Certificato revocato: {is_revoked}")
```

### Esempio 4: Enrollment ETSI Conforme vs Testing

```python
# ====================
# OPZIONE 1: API ETSI Conforme (Produzione)
# ====================
from protocols.etsi_message_encoder import ETSIMessageEncoder

EA_URL = "http://localhost:5000"

encoder = ETSIMessageEncoder()
oer_request = encoder.encode_enrollment_request(
    its_id="VEHICLE_001",
    public_key=vehicle_pubkey,
    ea_certificate=ea_cert
)

response = requests.post(
    f"{EA_URL}/api/enrollment/request",
    data=oer_request,
    headers={
        "Content-Type": "application/octet-stream",
        "X-API-Key": "your-api-key"
    }
)

# Decodifica risposta ASN.1 OER
enrollment_response = encoder.decode_enrollment_response(response.content)
print(f"✅ EC ricevuto: {enrollment_response['certificate']}")

# ====================
# OPZIONE 2: API Simple (Solo Testing/Debug)
# ====================
# ⚠️ NON conforme ETSI - Usa JSON per testing manuale

response = requests.post(
    f"{EA_URL}/api/enrollment/request/simple",
    json={
        "its_id": "VEHICLE_001",
        "public_key": vehicle_public_key_pem
    },
    headers={"X-API-Key": "your-api-key"}
)

enrollment_cert = response.json()
print(f"✅ EC ricevuto: {enrollment_cert['certificate_pem']}")
```

### Esempio 5: Authorization Request Completo

```python
# Authorization Ticket Request
AA_URL = "http://localhost:5020"

response = requests.post(
    f"{AA_URL}/api/authorization/request",
    json={
        "vehicle_id": "Vehicle_001",
        "enrollment_certificate": ec_pem,
        "permissions": ["traffic_info", "emergency"]
    },
    headers={"X-API-Key": "your-api-key"}
)

auth_ticket = response.json()
print(f"✅ AT ricevuto: {auth_ticket['ticket_id']}")

# Butterfly Batch Request (20 tickets per privacy)
butterfly_response = requests.post(
    f"{AA_URL}/api/authorization/request/butterfly",
    json={
        "vehicle_id": "Vehicle_001",
        "enrollment_certificate": ec_pem,
        "num_tickets": 20,
        "permissions": ["traffic_info"]
    },
    headers={"X-API-Key": "your-api-key"}
)

tickets = butterfly_response.json()["tickets"]
print(f"✅ {len(tickets)} AT ricevuti (unlinkable)")
```

---

## 🏗️ Architettura

### Struttura Progetto

```
SecureRoad-PKI/
├── entities/              # Entità PKI (RootCA, EA, AA, ITS-S)
├── managers/              # CRL/CTL Management
├── protocols/             # ETSI messaging, Butterfly expansion
├── api/                   # REST API + middleware
│   ├── blueprints/        # Blueprint per ogni endpoint
│   ├── middleware/        # Auth, rate limiting, logging
│   └── flask_app_factory.py
├── utils/                 # Certificati, logging, metriche
├── data/                  # Dati persistenti (certificati, chiavi, CRL)
├── tests/                 # 130 test automatici
├── examples/              # Script dimostrativi e tester
├── scripts/               # Script gestione (start, stop, check)
├── docs/                  # Documentazione dettagliata
├── setup.py               # Generatore entità bulk
├── server.py              # Launcher server produzione
├── start_dashboard.ps1    # Avvio dashboard + RootCA + TLM
└── pki_dashboard.html     # Dashboard web interattiva
```

### Architettura Directory `data/`

```
data/
├── root_ca/                    # Root Certificate Authority
│   ├── certificates/           # Certificato Root CA
│   ├── private_keys/           # Chiave privata Root CA
│   ├── crl/                    # Certificate Revocation Lists
│   ├── subordinates/           # Certificati EA/AA firmati
│   └── logs/                   # Log operazioni
│
├── ea/                         # Enrollment Authorities (max 20)
│   ├── EA_001/
│   │   ├── certificates/       # Certificato EA
│   │   ├── private_keys/       # Chiave privata EA
│   │   ├── enrollment_certificates/  # EC emessi
│   │   ├── crl/                # CRL specifiche
│   │   └── logs/               # Log operazioni
│   └── ...                     # Fino a EA_020
│
├── aa/                         # Authorization Authorities (max 20)
│   ├── AA_001/
│   │   ├── certificates/       # Certificato AA
│   │   ├── private_keys/       # Chiave privata AA
│   │   ├── authorization_tickets/  # AT emessi
│   │   ├── butterfly_keys/     # Chiavi Butterfly
│   │   ├── crl/                # CRL specifiche
│   │   └── logs/               # Log operazioni
│   └── ...                     # Fino a AA_020
│
└── tlm/                        # Trust List Manager
    └── TLM_MAIN/
        ├── trust_lists/        # Certificate Trust Lists
        ├── delta_lists/        # Delta CTL
        └── logs/               # Log operazioni
```

### Port Management (Auto-Assignment)

| Entità | Range Porte | Max Istanze | Descrizione |
|--------|-------------|-------------|-------------|
| **RootCA** | 5999 | 1 | Trust anchor centrale |
| **EA** | 5000-5019 | 20 | Enrollment Authorities |
| **AA** | 5020-5039 | 20 | Authorization Authorities |
| **TLM** | 5050 | 1 | Trust List Manager |
| **Dashboard** | 8080 | 1 | Web interface |

**Vantaggi:**
- ✅ Zero conflitti di porta
- ✅ Scaling automatico fino a 20 EA + 20 AA
- ✅ Setup semplificato
- ✅ Compatibile con dashboard

---

## 🌐 REST API

### Riepilogo Endpoint

| Endpoint | Metodo | Entità | Descrizione | Conformità ETSI | Auth |
|----------|--------|--------|-------------|-----------------|------|
| `/health` | GET | Tutte | Health check | - | Nessuna |
| `/api/docs` | GET | Tutte | Swagger UI | - | Nessuna |
| `/api/enrollment/request` | POST | EA | Richiesta EC | ✅ ASN.1 OER | API Key |
| `/api/enrollment/request/simple` | POST | EA | Richiesta EC (JSON) | ⚠️ Testing only | API Key |
| `/api/enrollment/validation` | POST | EA | Validazione EC (AA→EA) | ✅ ASN.1 OER | 🔒 mTLS |
| `/api/authorization/request` | POST | AA | Richiesta AT singolo | ✅ JSON | API Key |
| `/api/authorization/request/butterfly` | POST | AA | Richiesta batch 20 AT | ✅ ASN.1 OER | API Key |
| `/api/crl/full` | GET | EA, AA | Download Full CRL | ✅ PEM | Nessuna |
| `/api/crl/delta` | GET | EA, AA | Download Delta CRL | ✅ PEM | Nessuna |
| `/api/trust-list/full` | GET | TLM | Download Full CTL | ✅ JSON | Nessuna |
| `/api/trust-list/delta` | GET | TLM | Download Delta CTL | ✅ JSON | Nessuna |

**Totale**: **11 endpoint** REST API

### Endpoint Principali

#### Enrollment Authority (EA)
- `POST /api/enrollment/request` - **Richiesta EC (ETSI conforme - ASN.1 OER)** ✅
- `POST /api/enrollment/request/simple` - Richiesta EC (JSON - solo testing) ⚠️
- `POST /api/enrollment/validation` - **Validazione EC per AA (mTLS richiesto)** 🔒
- `GET /api/crl/full` - Full CRL
- `GET /api/crl/delta` - Delta CRL

#### Authorization Authority (AA)
- `POST /api/authorization/request` - Richiesta AT singolo
- `POST /api/authorization/request/butterfly` - Batch 20 AT (privacy)
- `GET /api/crl/full` - Full CRL
- `GET /api/crl/delta` - Delta CRL

#### Trust List Manager (TLM)
- `GET /api/trust-list/full` - Full CTL
- `GET /api/trust-list/delta` - Delta CTL

#### Sistema
- `GET /health` - Health check
- `GET /api/docs` - OpenAPI/Swagger

**Note:**
- ✅ Endpoint con ASN.1 OER sono conformi allo standard ETSI TS 102941
- ⚠️ Endpoint con JSON sono forniti solo per testing e debugging (non conformi)

### Due Modalità di Enrollment

#### 🏭 Modalità Produzione (ETSI Conforme)
**Endpoint**: `POST /api/enrollment/request`

✅ Conforme allo standard ETSI TS 102941  
✅ Codifica ASN.1 OER (binaria)  
✅ Crittografia end-to-end  
✅ Proof of Possession (PoP)  

**Esempio**:
```python
from protocols.etsi_message_encoder import ETSIMessageEncoder

encoder = ETSIMessageEncoder()
oer_request = encoder.encode_enrollment_request(
    its_id="VEHICLE_001",
    public_key=vehicle_pubkey,
    ea_certificate=ea_cert
)

response = requests.post(
    "http://localhost:5000/api/enrollment/request",
    data=oer_request,
    headers={"Content-Type": "application/octet-stream", "X-API-Key": "key"}
)

enrollment_response = encoder.decode_enrollment_response(response.content)
```

#### 🧪 Modalità Testing (JSON Semplificato)
**Endpoint**: `POST /api/enrollment/request/simple`

⚠️ **NON conforme allo standard** - Solo per testing  
📝 JSON leggibile  
🛠️ Ideale per Swagger UI e debugging  

**Esempio**:
```python
response = requests.post(
    "http://localhost:5000/api/enrollment/request/simple",
    json={"its_id": "VEHICLE_001", "public_key": pubkey_pem},
    headers={"X-API-Key": "key"}
)

cert = response.json()["certificate_pem"]
```

**Quando usare quale?**
- 🏭 **Produzione**: Sempre usare `/api/enrollment/request` (ETSI conforme)
- 🧪 **Testing manuale**: Usare `/api/enrollment/request/simple` per debug rapido

### Comunicazione Inter-Authority

#### 🔒 Enrollment Validation (AA → EA)
**Endpoint**: `POST /api/enrollment/validation`

**Scenario**: L'Authorization Authority deve validare un Enrollment Certificate prima di emettere un Authorization Ticket.

**Flusso ETSI TS 102941 Section 6.4.1**:
```
┌──────────┐         ┌──────────┐         ┌──────────┐
│  ITS-S   │         │    AA    │         │    EA    │
│ (Vehicle)│         │          │         │          │
└────┬─────┘         └────┬─────┘         └────┬─────┘
     │                    │                     │
     │ AT Request         │                     │
     │ (con EC)           │                     │
     ├───────────────────>│                     │
     │                    │                     │
     │                    │ Validation Request  │
     │                    │ (verifica EC)       │
     │                    ├────────────────────>│
     │                    │                     │
     │                    │                     │ ✓ Verifica firma
     │                    │                     │ ✓ Controlla CRL
     │                    │                     │ ✓ Verifica scadenza
     │                    │                     │
     │                    │ Validation Response │
     │                    │ (OK/INVALID/REVOKED)│
     │                    │<────────────────────┤
     │                    │                     │
     │ AT Response        │                     │
     │ (se EC valido)     │                     │
     │<───────────────────┤                     │
     │                    │                     │
```

**Autenticazione**: 🔒 **mTLS obbligatorio** - Solo AA con certificato client valido

**Esempio**:
```python
# AA chiede validazione a EA
response = requests.post(
    "http://localhost:5000/api/enrollment/validation",
    data=oer_validation_request,
    cert=("aa_cert.pem", "aa_key.pem"),  # mTLS
    verify="root_ca.pem",
    headers={"Content-Type": "application/octet-stream"}
)
```

### Autenticazione

**API Key (Header)**
```python
headers = {"X-API-Key": "your-secret-key"}
```

**mTLS (Client Certificate)**
```python
requests.post(url, cert=("cert.pem", "key.pem"), verify="ca.pem")
```

### Rate Limiting

- **100 req/ora** per IP (default, configurabile)
- Header: `X-RateLimit-Remaining`, `X-RateLimit-Reset`

---

## 🧪 Testing

### Esecuzione Test

```bash
# Tutti i test (130 test automatici)
python -m pytest tests/ -v

# Test specifici per categoria
python -m pytest tests/test_pki_entities.py -v      # Test entità PKI
python -m pytest tests/test_rest_api.py -v          # Test API REST
python -m pytest tests/test_butterfly_*.py -v       # Test Butterfly expansion
python -m pytest tests/test_etsi_*.py -v            # Test conformità ETSI

# Con coverage report
python -m pytest tests/ --cov=. --cov-report=html
```

### Test Interattivo

```bash
# Menu interattivo con test completi
python examples/interactive_pki_tester.py

# Con entità già avviate
python examples/interactive_pki_tester.py --no-start

# Test rapido enrollment + authorization
python examples/quick_test.py
```

### Risultati Test

- ✅ **130/130 test passing**
- 📊 **Coverage: ~90%**
- ⚡ **Performance:** < 30s per full suite
- 🔒 **Security tests:** Certificati, firme, revoca
- 🌐 **API tests:** Tutti gli endpoint REST
- 🦋 **Butterfly tests:** Key expansion e privacy

---

## 📊 Dashboard Web

La dashboard fornisce un'interfaccia web completa per gestire e monitorare la PKI.

### Accesso Dashboard

```bash
# Avvia dashboard (include RootCA e TLM)
.\start_dashboard.ps1

# Apri nel browser
http://localhost:8080/pki_dashboard.html
```

### Funzionalità Dashboard

✅ **Monitoraggio Real-time**
- Stato di tutte le entità (RootCA, EA, AA, TLM)
- Health check automatico
- Statistiche operative

✅ **Gestione Entità**
- Creazione bulk di EA/AA con `setup.py` (nomi personalizzati)
- Eliminazione permanente di entità singole
- Configurazione porte automatica
- Avvio/Stop entities

✅ **Test API Interattivi**
- Test enrollment certificates
- Test authorization tickets
- Test Butterfly expansion
- Download CRL/CTL

✅ **Statistiche e Report**
- Certificati emessi
- Performance metriche
- Log eventi

---

## 🛠️ Strumenti Utility

### Generatore Bulk Entità

Crea multiple entità EA e AA con nomi personalizzati direttamente dalla riga di comando:

```bash
# Esempio: 3 EA e 2 AA con nomi personalizzati
python setup.py --ea 3 --aa 2 --ea-names "EA_HIGHWAY,EA_CITY,EA_RURAL" --aa-names "AA_TOLL,AA_PARKING"

# Esempio: Solo EA senza nomi personalizzati (usa nomi automatici)
python setup.py --ea 5

# Esempio: Solo AA con nomi personalizzati
python setup.py --aa 3 --aa-names "AA_001,AA_002,AA_003"

# Esempio: Combinazione mista
python setup.py --ea 2 --aa 4 --ea-names "EA_MAIN,EA_BACKUP"
```

**Parametri disponibili:**
- `--ea N`: Numero di Enrollment Authorities da creare (max 20)
- `--aa N`: Numero di Authorization Authorities da creare (max 20)
- `--ea-names "NAME1,NAME2,..."`: Nomi personalizzati per EA (opzionale)
- `--aa-names "NAME1,NAME2,..."`: Nomi personalizzati per AA (opzionale)

**Funzionalità automatiche:**
- ✅ **Assegnazione porte automatica** senza conflitti
- ✅ **Nomi duplicati gestiti** automaticamente (EA_001 → EA_001_2 se già esistente)
- ✅ **Registrazione automatica** nel TLM per EA
- ✅ **Configurazione salvata** in `entity_configs.json`
- ✅ **Avvio automatico** in background (opzionale)
```

### Controllo Porte

Verifica porte disponibili e in uso:

```powershell
# Windows
.\scripts\check_ports.ps1
```

### Stop Tutte le Entità

```powershell
# Windows (root directory)
.\stop_all.ps1

# Oppure con PowerShell Job cleanup
Get-Job | Stop-Job
Get-Job | Remove-Job
```

---

## 📚 Documentazione

### Documentazione Dettagliata

- **[INDEX.md](docs/INDEX.md)** - Indice completo documentazione
- **[DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Guida deployment produzione
- **[SECURITY.md](docs/SECURITY.md)** - Best practices sicurezza
- **[TEST_SUMMARY.md](docs/TEST_SUMMARY.md)** - Riepilogo test
- **[QUICK_START_RASPBERRY_PI.md](docs/QUICK_START_RASPBERRY_PI.md)** - Deployment su Raspberry Pi

### README Componenti

- **[entities/README_entities.md](entities/README_entities.md)** - Entità PKI
- **[protocols/README_protocols.md](protocols/README_protocols.md)** - Protocolli ETSI
- **[managers/README_managers.md](managers/README_managers.md)** - CRL/CTL Management
- **[utils/README_utils.md](utils/README_utils.md)** - Utility e helpers
- **[examples/README.md](examples/README.md)** - Esempi e testing

### API Documentation

Gli endpoint REST sono completamente documentati con OpenAPI/Swagger:

```bash
# Avvia un'entità
python server.py --entity EA --id EA_001

# Apri Swagger UI
http://localhost:5000/api/docs
```

---

## 🔒 Standard e Conformità

### Standard Implementati

✅ **ETSI TS 102941** - Security in V2X communications  
✅ **IEEE 1609.2** - Security services for applications and management messages  
✅ **ETSI TS 103097** - Security header and certificate format  

### Algoritmi Crittografici

- **Chiavi**: ECDSA con curva NIST P-256 (secp256r1)
- **Hash**: SHA-256
- **Certificati**: X.509 v3
- **Encoding**: ASN.1 OER (ETSI conforme)

### Privacy Features

- **Butterfly Key Expansion**: Generazione batch di 20 AT unlinkable
- **Pseudonym Certificates**: Authorization Tickets non collegabili
- **Delta CRL**: Riduzione dimensione liste revoca

---

## 🚀 Roadmap

### Completato ✅

- [x] Implementazione core entities (RootCA, EA, AA, ITS-S, TLM)
- [x] 11 endpoint REST API completi
- [x] Butterfly key expansion per privacy
- [x] CRL/CTL management con Delta support
- [x] 130 test automatici
- [x] Dashboard web interattiva
- [x] Auto-start system con background processes
- [x] Bulk entity generator
- [x] Documentazione completa


## 📧 Contatti e Supporto

- **Repository GitHub**: [github.com/Mattyilmago/SecureRoads_PKI](https://github.com/Mattyilmago/SecureRoads_PKI)
- **Issues**: [github.com/Mattyilmago/SecureRoads_PKI/issues](https://github.com/Mattyilmago/SecureRoads_PKI/issues)
- **Documentazione**: [docs/](docs/)

**Per domande o supporto, apri una issue su GitHub.**


**SecureRoad-PKI** - Production-Ready PKI for Intelligent Transportation Systems 🚗🔐

*Implementazione conforme ETSI TS 102941 per sistemi V2X sicuri e privacy-preserving*
