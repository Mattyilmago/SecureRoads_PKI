# SecureRoad-PKI 🔐

**Public Key Infrastructure (PKI) per sistemi ITS (Intelligent Transportation Systems) conforme agli standard ETSI**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Status](https://img.shields.io/badge/Status-In%20Development-yellow)](https://github.com/Mattyilmago/SecureRoads_PKI)

---

## 📋 Indice

- [Panoramica](#panoramica)
- [Architettura](#architettura)
- [Componenti Implementati](#componenti-implementati)
- [Installazione](#installazione)
- [Uso Rapido](#uso-rapido)
- [Documentazione](#documentazione)
- [Roadmap](#roadmap)
- [Testing](#testing)
- [Contribuire](#contribuire)

---

## 🎯 Panoramica

SecureRoad-PKI è un'implementazione completa di una Public Key Infrastructure (PKI) per sistemi di trasporto intelligente (ITS) seguendo gli standard **ETSI TS 102941** e **IEEE 1609.2**.

Il sistema gestisce:
- ✅ Certificati di enrollment (EC) per veicoli
- ✅ Authorization tickets (AT) per messaggi V2X
- ✅ Certificate Revocation Lists (CRL) con supporto Delta
- ✅ Certificate Trust Lists (CTL) per gestione trust anchors
- ✅ Link certificates per validazione catene di fiducia
- 🚧 Butterfly key expansion per privacy
- 🚧 Messaggistica ASN.1 OER secondo ETSI

---

## 🏗️ Architettura

```
SecureRoad-PKI/
│
├── 📁 entities/                    # Entità PKI core
│   ├── root_ca.py                  # Root Certificate Authority
│   ├── enrollment_authority.py     # Enrollment Authority (EA)
│   ├── authorization_authority.py  # Authorization Authority (AA)
│   └── its_station.py              # ITS Station (veicoli)
│
├── 📁 managers/                    # Manager componenti
│   ├── crl_manager.py              # Certificate Revocation List Manager
│   └── trust_list_manager.py       # Certificate Trust List Manager
│
├── 📁 protocols/                   # Protocolli messaggistica ETSI
│   ├── etsi_message_encoder.py     # Serializzazione ASN.1 OER
│   ├── etsi_message_types.py       # Strutture dati ETSI TS 102941
│   └── etsi_ts_102941.asn          # Schema ASN.1 ETSI
│
├── 📁 utils/                       # Utilities
│   └── cert_utils.py               # Funzioni utilità certificati
│
├── 📁 tests/                       # Test suite
│   ├── test_entities_pki.py        # Test Root CA, EA, AA
│   ├── test_its_station.py         # Test ITS Station
│   ├── test_managers.py            # Test CRL/TLM Manager
│   ├── test_integration.py         # Test integrazione end-to-end
│   ├── test_protocols.py           # Test protocolli ETSI
│   └── test_protocols_simple.py    # Test protocolli semplificati
│
├── 📁 docs/                        # Documentazione
│   ├── DELTA_CRL_DOCUMENTATION.md
│   ├── TRUST_LIST_MANAGER_DOCUMENTATION.md
│   └── ... (altre guide)
│
├── 📁 data/                        # Dati runtime
│   ├── root_ca/                    # Root Certificate Authority
│   │   ├── certificates/           # Certificato root self-signed
│   │   ├── private_keys/           # Chiave privata root
│   │   ├── crl/                    # CRL pubblicate
│   │   │   ├── full/               # Full CRL (lista completa)
│   │   │   └── delta/              # Delta CRL (modifiche incrementali)
│   │   ├── logs/                   # Log audit ETSI-compliant
│   │   ├── backup/                 # Backup disaster recovery
│   │   └── subordinates/           # Certificati EA/AA firmati
│   │
│   ├── ea/                         # Enrollment Authorities
│   │   └── EA_XXX/                 # Una cartella per ogni EA
│   │       ├── certificates/       # Certificato EA firmato da Root
│   │       ├── private_keys/       # Chiave privata EA
│   │       ├── crl/                # CRL pubblicate
│   │       │   ├── full/           # Full CRL
│   │       │   └── delta/          # Delta CRL
│   │       ├── enrollment_certificates/ # EC emessi ai veicoli
│   │       ├── logs/               # Log audit
│   │       └── backup/             # Backup
│   │
│   ├── aa/                         # Authorization Authorities
│   │   └── AA_XXX/                 # Una cartella per ogni AA
│   │       ├── certificates/       # Certificato AA firmato da Root
│   │       ├── private_keys/       # Chiave privata AA
│   │       ├── crl/                # CRL pubblicate
│   │       │   ├── full/           # Full CRL
│   │       │   └── delta/          # Delta CRL
│   │       ├── authorization_tickets/ # AT emessi ai veicoli
│   │       ├── logs/               # Log audit
│   │       └── backup/             # Backup
│   │
│   ├── itss/                       # ITS Stations (veicoli)
│   │   └── Vehicle_XXX/            # Una cartella per ogni veicolo
│   │       ├── own_certificates/   # EC e AT del veicolo
│   │       ├── trust_anchors/      # CTL ricevute (Root, EA, AA)
│   │       ├── ctl_full/           # Full CTL ricevute
│   │       ├── ctl_delta/          # Delta CTL ricevute
│   │       ├── inbox/              # Messaggi V2X ricevuti
│   │       ├── outbox/             # Messaggi V2X inviati
│   │       ├── authorization_tickets/  # AT ricevuti da altri veicoli
│   │       ├── logs/               # Log audit ETSI-compliant
│   │       └── backup/             # Backup certificati e chiavi
│   │
│   └── tlm/                        # Trust List Manager
│       ├── ctl/                    # CTL Full e Delta pubblicate
│       ├── link_certificates/      # Link certificates per catene fiducia
│       │   ├── json/               # Formato JSON (debug)
│       │   └── asn1/               # Formato ASN.1 OER (production)
│       ├── logs/                   # Log audit
│       └── backup/                 # Backup
│
├── 📁 crypto/                      # Crittografia avanzata (TODO)
│   └── crypto_manager.py           # Gestione AES-CCM, HashedId8, Butterfly
│
├── 📁 api/                         # REST API (TODO)
│   └── flask_app_factory.py        # API per comunicazione inter-authority
│
└── 📁 storage/                     # Gestione storage (TODO)
    └── filesystem_manager.py       # Gestione unificata filesystem
```

---

## ✅ Componenti Implementati

### **Livello Base (ENTITIES)** - 90% Completo

#### 1. **RootCA** ✅
- ✅ Generazione chiavi ECC (secp256r1)
- ✅ Certificato self-signed
- ✅ Firma certificati subordinati (EA, AA)
- ✅ Pubblicazione CRL (Full + Delta)
- ✅ Gestione revoche
- ⚠️ TODO: Firma messaggi CTL

#### 2. **EnrollmentAuthority (EA)** ✅
- ✅ Ricezione e validazione CSR da ITS-S
- ✅ Proof of possession
- ✅ Emissione Enrollment Certificates (EC)
- ✅ Gestione revoca EC
- ✅ Pubblicazione CRL Delta

#### 3. **AuthorizationAuthority (AA)** ✅
- ✅ Ricezione richieste AT standard
- ✅ Validazione EC tramite EA
- ✅ Emissione Authorization Tickets (AT)
- ✅ Gestione revoca AT
- ✅ Pubblicazione CRL Delta
- ⚠️ TODO: Batch AT butterfly

#### 4. **ITSStation** ✅
- ✅ Generazione chiavi ECC proprie
- ✅ Richiesta EC a EA
- ✅ Richiesta AT a AA (standard)
- ✅ Aggiornamento trust anchors
- ✅ Invio/ricezione messaggi firmati
- ⚠️ TODO: Richiesta AT butterfly

#### 5. **CRLManager** ✅ - COMPLETO!
*(Spostato in `managers/crl_manager.py`)*
- ✅ Generazione Full CRL (tutti i revocati)
- ✅ Generazione Delta CRL (solo nuove revoche)
- ✅ Sincronizzazione Full/Delta
- ✅ Cleanup automatico certificati scaduti
- ✅ Metadata persistence
- ✅ Statistiche e monitoraggio

#### 6. **TrustListManager** ✅
*(Spostato in `managers/trust_list_manager.py`)*
- ✅ Gestione Certificate Trust Lists (CTL)
- ✅ Full CTL (tutte le CA fidate)
- ✅ Delta CTL (modifiche aggiunte/rimozioni)
- ✅ Link Certificates generation
- ✅ Distribuzione trust anchors a ITS-S
- ✅ Verifica certificati fidati
- ✅ Cleanup automatico trust scaduti
- ⚠️ TODO: ASN.1 OER encoding (ETSI TS 102941)

---

### **Livello Protocollo/Messaggistica** - 50% Completo

#### ETSIMessageEncoder ⚠️
- ✅ Struttura base implementata
- ✅ Schema ASN.1 ETSI TS 102941
- ⚠️ Serializzazione ASN.1 OER (parziale)
- ⚠️ Parsing messaggi ETSI (in sviluppo)

#### ETSIMessageTypes ⚠️
- ✅ Strutture dati base
- ⚠️ EnrollmentRequest, AuthorizationRequest (parziale)
- ❌ ButterflyRequest structures

---

### **Livello Crittografia** - 30% Completo

#### CryptoManager ⚠️
- ✅ Generazione chiavi ECC (via cryptography)
- ✅ Firma/verifica (via cryptography)
- ❌ AES-CCM per messaggi cifrati
- ❌ Generazione HashedId8
- ❌ Butterfly key expansion

---

### **Livello REST API** - 0% Completo

#### FlaskAppFactory ❌
- API REST per comunicazione inter-authority
- Autenticazione (API key/mTLS)
- Blueprint per ogni entità

---

### **Livello Storage** - 40% Completo

#### FileSystemManager ⚠️
- ✅ Gestione base file (implementato nelle singole classi)
- ❌ Classe unificata FileSystemManager
- ❌ Rotazione automatica certificati scaduti
- ❌ Supporto ASN.1 OER files

---

## 📦 Installazione

### Prerequisiti

- Python 3.8+
- pip

### Setup

```bash
# Clone repository
git clone https://github.com/Mattyilmago/SecureRoads_PKI.git
cd SecureRoads_PKI

# Crea virtual environment (consigliato)
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Installa dipendenze
pip install -r requirements.txt
```

### Dipendenze

```
cryptography>=41.0.0
flask>=2.3.0 (per API REST, futuro)
asn1tools>=0.166.0 (per ASN.1 OER, futuro)
```

---

## 🚀 Uso Rapido

### Esempio Base: Enrollment e Authorization

```python
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from entities.its_station import ITSStation
from managers.trust_list_manager import TrustListManager

# 1. Setup PKI Infrastructure
root_ca = RootCA(base_dir="data/root_ca")
ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_001")
aa = AuthorizationAuthority(
    ea_certificate_path=ea.ea_certificate_path,
    root_ca=root_ca,
    aa_id="AA_001"
)

# 2. Setup Trust List Manager
tlm = TrustListManager(root_ca=root_ca, tlm_id="TLM_001")
tlm.add_trust_anchor(ea.certificate, authority_type="EA")
tlm.add_trust_anchor(aa.certificate, authority_type="AA")
tlm.publish_full_ctl(validity_days=30)

# 3. Veicolo richiede Enrollment Certificate
vehicle = ITSStation("Vehicle_001")
vehicle.generate_ecc_keypair()
ec = vehicle.request_ec(ea)

# 4. Veicolo richiede Authorization Ticket
at = vehicle.request_at(aa)

# 5. Veicolo invia messaggio firmato
vehicle.send_signed_message(
    message="Emergency brake!",
    recipient_id="Vehicle_002",
    message_type="DENM"
)

print("✅ Enrollment e Authorization completati!")
```

### Esempio: Gestione Revoche

```python
# Scenario: EA compromessa

# 1. Root CA revoca certificato EA
root_ca.revoke_certificate(
    ea.certificate,
    reason=ReasonFlags.key_compromise
)

# 2. Pubblica Delta CRL
root_ca.crl_manager.publish_delta_crl()

# 3. Rimuovi da trust anchors
tlm.remove_trust_anchor(ea.certificate, reason="key_compromise")

# 4. Pubblica Delta CTL
tlm.publish_delta_ctl()

# 5. Distribuisci aggiornamenti a veicoli
vehicles = [vehicle1, vehicle2, vehicle3]
tlm.distribute_to_itss(vehicles)

print("✅ EA revocata e trust aggiornato!")
```

---

## 📚 Documentazione

### Guide Complete

- [**Delta CRL Documentation**](docs/DELTA_CRL_DOCUMENTATION.md) - Guida completa alle CRL incrementali
- [**Trust List Manager Documentation**](docs/TRUST_LIST_MANAGER_DOCUMENTATION.md) - Guida completa al TLM

### Concetti Chiave

#### CRL vs CTL

| Aspetto | **CRL (Revocation)** | **CTL (Trust)** |
|---------|---------------------|-----------------|
| Scopo | Blacklist (chi NON fidarsi) | Whitelist (di chi fidarsi) |
| Contenuto | Certificati revocati | CA fidate (trust anchors) |
| Gestito da | CRLManager | TrustListManager |
| Operazioni | `add_revoked()` | `add_trust_anchor()` |
| Uso | Validare che cert NON sia revocato | Validare catene di fiducia |

#### Full vs Delta

**Full CRL/CTL**:
- Contiene TUTTI i dati (revoche o trust anchors)
- Pubblicazione mensile
- Base di riferimento per Delta

**Delta CRL/CTL**:
- Contiene SOLO modifiche dall'ultima Full
- Pubblicazione settimanale/oraria
- Molto più piccola e veloce

---

## 🧪 Testing

### Esegui Test Completi

```bash
# Test PKI Entities (Root CA, EA, AA)
pytest tests/test_entities_pki.py

# Test ITS Station
pytest tests/test_its_station.py

# Test Managers (CRL, TLM)
pytest tests/test_managers.py

# Test Integrazione end-to-end
pytest tests/test_integration.py

# Test Protocolli ETSI
pytest tests/test_protocols.py

# Esegui TUTTI i test in batch
python run_all_tests.py
# oppure
pytest tests/
```

### Test Coverage


### Stato Test Suite

- Tutti i test ora usano i parametri costruttore aggiornati
- Gli errori dovuti a parametri obsoleti sono stati risolti
- Alcuni test potrebbero fallire per mismatch API/metodi: vedi changelog

---

## 🗺️ Roadmap

### ✅ Phase 1: Core PKI (COMPLETATO - 90%)
- [x] RootCA, EA, AA, ITSStation
- [x] CRLManager con Delta CRL
- [x] TrustListManager con Delta CTL
- [x] Test suite base

### 🚧 Phase 2: Protocollo e Messaggistica (50%)
- [x] ETSIMessageEncoder (struttura base)
- [x] ETSIMessageTypes (strutture base)
- [x] Schema ASN.1 ETSI TS 102941
- [ ] Completamento serializzazione ASN.1 OER
- [ ] CryptoManager completo
  - [ ] AES-CCM encryption
  - [ ] HashedId8 generation
  - [ ] Butterfly key expansion

### 🔜 Phase 3: API e Storage (0%)
- [ ] FlaskAppFactory REST API
- [ ] FileSystemManager unificato
- [ ] Autenticazione inter-authority (mTLS)
- [ ] Rotazione automatica certificati

### 🔜 Phase 4: Advanced Features (0%)
- [ ] Batch AT butterfly
- [ ] ConfigLoader
- [ ] TestScenarioManager
- [ ] Production-grade error handling
- [ ] Logging strutturato

### 🔜 Phase 5: Production Ready (0%)
- [ ] Performance optimization
- [ ] Security audit
- [ ] Load testing
- [ ] Documentation completa
- [ ] Docker deployment

---

## 📊 Stato Progetto

**Completamento totale: ~35%**

| Componente | Stato | Completamento |
|------------|-------|---------------|
| RootCA | ✅ | 95% |
| EnrollmentAuthority | ✅ | 95% |
| AuthorizationAuthority | ✅ | 90% |
| ITSStation | ✅ | 90% |
| CRLManager | ✅ | 100% |
| TrustListManager | ✅ | 95% |
| ETSIMessageEncoder | ⚠️ | 50% |
| ETSIMessageTypes | ⚠️ | 50% |
| CertUtils | ✅ | 80% |
| CryptoManager | ❌ | 0% (TODO) |
| FlaskAppFactory | ❌ | 0% (TODO) |
| FileSystemManager | ❌ | 0% (TODO) |

---

## 🤝 Contribuire

Contributi benvenuti! Per favore:

1. Fork il repository
2. Crea un branch per la feature (`git checkout -b feature/AmazingFeature`)
3. Commit le modifiche (`git commit -m 'Add AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Apri una Pull Request

### Guidelines

- Segui lo stile di codice esistente
- Aggiungi test per nuove features
- Aggiorna la documentazione
- Usa commit messages descrittivi

---

## 📄 Licenza

Distribuito sotto licenza MIT. Vedi `LICENSE` per maggiori informazioni.

---

## 🔗 Riferimenti

### Standard

- **ETSI TS 102941** - Trust and Privacy Management for ITS
- **ETSI TS 103097** - Security Header and Certificate Format
- **IEEE 1609.2** - Security Services for Applications and Management Messages
- **RFC 5280** - X.509 Certificate and CRL Profile

### Librerie

- [cryptography](https://cryptography.io/) - Crittografia Python
- [asn1tools](https://github.com/eerimoq/asn1tools) - ASN.1 encoding/decoding
- [Flask](https://flask.palletsprojects.com/) - Web framework per API

---

## 👥 Autori

- **Mattyilmago** - *Initial work* - [GitHub](https://github.com/Mattyilmago)

---

## 📧 Contatti

Per domande o supporto, apri una issue su GitHub.

---

**🚗 Buona strada sicura con SecureRoad-PKI! 🔐**
