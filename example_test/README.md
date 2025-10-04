# 📁 TEST SUITE - Sistema PKI V2X

**Ultimo aggiornamento**: 4 Ottobre 2025

---

## 🎯 TEST DISPONIBILI

Questa cartella contiene i test essenziali per il sistema PKI V2X conforme agli standard ETSI TS 102 941 e TS 103 097.

### ⭐ Test Principale

#### `test_complete_system.py`
**Test completo del sistema PKI V2X**

**Copertura**: 13 test integrati (100%)
- ✅ Root CA initialization
- ✅ Enrollment Authority (EA)
- ✅ Authorization Authority (AA)
- ✅ Trust List Manager (TLM)
- ✅ Enrollment Certificate (EC)
- ✅ Authorization Ticket (AT)
- ✅ Messaggi V2X (CAM/DENM)
- ✅ Validazione messaggi
- ✅ Revoca certificati
- ✅ Verifica CRL
- ✅ Delta CRL
- ✅ Delta CTL
- ✅ Conformità ETSI

**Esecuzione**:
```bash
python example_test/test_complete_system.py
```

**Output atteso**:
```
>> Risultati: 13/13 test superati (100.0%)
*** TUTTI I TEST SUPERATI! ***
```

**Usa questo test per**:
- ✅ Demo completa del sistema
- ✅ Validazione funzionalità
- ✅ Presentazione tesi
- ✅ Verifica dopo modifiche

---

### 🔬 Test Specializzati

#### `test_crl_freshness.py`
**Test conformità ETSI sulla freshness CRL**

**Scopo**: Verifica che le ITS-S aggiornino automaticamente le CRL quando sono più vecchie di 10 minuti

**Standard**: ETSI TS 102 941 (Section 6.2.3.10.2)

**Test inclusi**:
- Validazione messaggio con CRL recente (OK)
- Validazione messaggio con CRL obsoleta (>10 min) → aggiornamento automatico
- Verifica download automatico da TLM

**Esecuzione**:
```bash
python example_test/test_crl_freshness.py
```

**Usa questo test per**:
- ✅ Dimostrare conformità ETSI TS 102 941
- ✅ Validare meccanismo freshness CRL
- ✅ Verificare sincronizzazione automatica

---

#### `test_aa_with_tlm.py`
**Test Authorization Authority con modalità TLM multi-EA**

**Scopo**: Verifica che l'AA possa validare EC emessi da multiple EA tramite Trust List Manager

**Architettura**: Multi-EA con TLM centralizzato

**Test inclusi**:
- Setup PKI con 2 Enrollment Authority (EA_001, EA_002)
- Trust List Manager con entrambe le EA
- Validazione cross-EA tramite TLM
- Emissione AT per veicoli registrati presso EA diverse

**Esecuzione**:
```bash
python example_test/test_aa_with_tlm.py
```

**Usa questo test per**:
- ✅ Dimostrare scalabilità sistema
- ✅ Validare architettura multi-EA
- ✅ Verificare TLM in scenario reale

---

## 📚 DOCUMENTAZIONE CORRELATA

### API Reference
**File**: `docs/API_DOCUMENTATION.md`

Documentazione completa delle classi del sistema:
- Costruttori con parametri corretti
- Attributi e tipi
- Metodi principali con esempi
- Pattern di utilizzo comuni
- Errori comuni da evitare

**Usa questa documentazione quando**:
- Scrivi nuovi test
- Modifichi il codice
- Hai dubbi sui parametri delle funzioni

### Scenari Reali
**File**: `docs/SCENARI_REALI.md`

Documentazione dettagliata di scenari realistici:

**Scenario 1**: Incidente stradale con allerta DENM
- Timeline completa (T+0s → T+3.10s)
- 5 veicoli coinvolti
- Validazione messaggi in tempo reale
- **Risultato**: 5 vite salvate, €150,000 danni prevenuti

**Scenario 2**: Attacco hacker con veicolo compromesso
- Timeline completa (T+0s → T+50s)
- IDS detection (15 secondi)
- Revoca certificato (2 secondi)
- **Risultato**: 93% attacchi bloccati (14/15 messaggi)

**Usa questa documentazione per**:
- ✅ Capitolo scenari nella tesi
- ✅ Presentazione casi d'uso
- ✅ Dimostrare valore del sistema

---

## 🎯 COME USARE I TEST

### Per Demo Sistema Completo
```bash
python example_test/test_complete_system.py
```
**Output**: 13/13 test superati (100%)
**Tempo**: ~30 secondi
**Usa per**: Presentazione tesi, validazione completa

### Per Conformità ETSI
```bash
python example_test/test_crl_freshness.py
```
**Standard**: ETSI TS 102 941 (6.2.3.10.2)
**Usa per**: Dimostrare conformità standard

### Per Scalabilità Multi-EA
```bash
python example_test/test_aa_with_tlm.py
```
**Architettura**: 2 EA + 1 TLM + 1 AA
**Usa per**: Dimostrare architettura avanzata

---

## 📊 COVERAGE

### Entità Testate
- ✅ RootCA (Root Certificate Authority)
- ✅ EnrollmentAuthority (EA)
- ✅ AuthorizationAuthority (AA)
- ✅ TrustListManager (TLM)
- ✅ ITSStation (Veicolo)
- ✅ CRLManager (Revoca certificati)

### Funzionalità Testate
- ✅ Generazione certificati (EC, AT)
- ✅ Firma messaggi V2X (CAM, DENM)
- ✅ Validazione messaggi (3 livelli)
- ✅ Revoca certificati (CRL)
- ✅ Delta CRL incrementale
- ✅ Trust List (CTL)
- ✅ Delta CTL incrementale
- ✅ Freshness CRL (10 minuti)
- ✅ Multi-EA con TLM
- ✅ Conformità ETSI completa

### Standard Conformità
- ✅ ETSI TS 102 941 (Trust Management)
- ✅ ETSI TS 103 097 (Security Header)
- ✅ ECDSA-SHA256 (Firma digitale)
- ✅ ECC NIST P-256 (Crittografia)

---

