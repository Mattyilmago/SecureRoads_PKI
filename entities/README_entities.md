# Entities - Entità PKI Core

Questa cartella contiene le entità principali dell'infrastruttura PKI per sistemi ITS.

## Classi Disponibili

### RootCA
**File**: `root_ca.py`

Root Certificate Authority - Autorità di certificazione radice del sistema PKI.

**Responsabilità**:
- Generazione e gestione del certificato root self-signed
- Firma dei certificati subordinati (EA e AA)
- Gestione delle revoche tramite CRLManager
- Pubblicazione di Full CRL e Delta CRL
- Archiviazione dei certificati firmati

**Utilizzo base**:
```python
from entities.root_ca import RootCA

# Inizializzazione
root_ca = RootCA(base_dir="data/root_ca")

# Firma certificato subordinato
subordinate_cert = root_ca.sign_certificate(
    subject_public_key=public_key,
    subject_name="EnrollmentAuthority_001",
    is_ca=True
)

# Revoca certificato
root_ca.revoke_certificate(certificate, reason=ReasonFlags.key_compromise)

# Pubblica CRL
root_ca.crl_manager.publish_full_crl(validity_days=30)
root_ca.crl_manager.publish_delta_crl(validity_days=7)
```

**Struttura directory**:
```
data/root_ca/
├── certificates/       # Certificato root self-signed
├── private_keys/       # Chiave privata root (protetta)
├── subordinates/       # Certificati EA/AA firmati
├── crl/
│   ├── full/          # Full CRL
│   └── delta/         # Delta CRL
├── logs/              # Log audit
└── backup/            # Backup
```

---

### EnrollmentAuthority
**File**: `enrollment_authority.py`

Enrollment Authority - Autorità che gestisce l'emissione di Enrollment Certificates (EC) per le ITS Station.

**Responsabilità**:
- Ricezione e validazione di Certificate Signing Requests (CSR)
- Proof of Possession verification
- Emissione di Enrollment Certificates (EC)
- Gestione revoche EC tramite CRLManager integrato
- Pubblicazione CRL (Full e Delta)
- Processamento richieste ETSI TS 102941 (ASN.1 OER)

**Utilizzo base**:
```python
from entities.enrollment_authority import EnrollmentAuthority

# Inizializzazione
ea = EnrollmentAuthority(
    root_ca=root_ca,
    ea_id="EA_001",
    base_dir="data/ea"
)

# Processamento CSR
ec_certificate = ea.process_csr(
    csr_pem=csr_bytes,
    its_id="Vehicle_001",
    attributes={"region": "EU"}
)

# Emissione diretta EC
ec_cert = ea.issue_enrollment_certificate(
    its_id="Vehicle_001",
    public_key=vehicle_public_key
)

# Revoca EC
ea.revoke_enrollment_certificate(
    certificate=ec_cert,
    reason=ReasonFlags.key_compromise
)

# Pubblica CRL
ea.crl_manager.publish_delta_crl()
```

**Struttura directory**:
```
data/ea/EA_001/
├── certificates/            # Certificato EA firmato da Root
├── private_keys/            # Chiave privata EA
├── enrollment_certificates/ # EC emessi ai veicoli
├── crl/
│   ├── full/               # Full CRL
│   └── delta/              # Delta CRL
├── logs/                   # Log audit
└── backup/                 # Backup
```

---

### AuthorizationAuthority
**File**: `authorization_authority.py`

Authorization Authority - Autorità che gestisce l'emissione di Authorization Tickets (AT) per messaggi V2X.

**Responsabilità**:
- Validazione Enrollment Certificates
- Emissione Authorization Tickets (AT) per periodi brevi
- Validazione tramite TrustListManager o certificato EA diretto
- Gestione revoche AT
- Pubblicazione CRL
- Supporto Butterfly key expansion (in sviluppo)

**Utilizzo base**:
```python
from entities.authorization_authority import AuthorizationAuthority

# Inizializzazione con TLM (raccomandato)
aa = AuthorizationAuthority(
    root_ca=root_ca,
    tlm=trust_list_manager,
    aa_id="AA_001",
    base_dir="data/aa"
)

# Processamento richiesta AT
at_certificate = aa.process_authorization_request(
    ec_pem=enrollment_cert_bytes,
    its_id="Vehicle_001",
    attributes={"permissions": ["CAM", "DENM"]}
)

# Revoca AT
aa.revoke_authorization_ticket(
    certificate=at_cert,
    reason=ReasonFlags.privilege_withdrawn
)

# Pubblica CRL
aa.crl_manager.publish_delta_crl()
```

**Modalità operative**:
1. **TLM Mode** (raccomandato): Validazione EC tramite TrustListManager
2. **Legacy Mode**: Validazione EC tramite certificato EA specifico

**Struttura directory**:
```
data/aa/AA_001/
├── certificates/          # Certificato AA firmato da Root
├── private_keys/          # Chiave privata AA
├── authorization_tickets/ # AT emessi ai veicoli
├── crl/
│   ├── full/             # Full CRL
│   └── delta/            # Delta CRL
├── logs/                 # Log audit
└── backup/               # Backup
```

---

### ITSStation
**File**: `its_station.py`

ITS Station - Rappresenta un veicolo o dispositivo V2X nel sistema.

**Responsabilità**:
- Generazione chiavi ECC proprie
- Creazione Certificate Signing Requests (CSR)
- Richiesta Enrollment Certificate (EC) a EA
- Richiesta Authorization Ticket (AT) a AA
- Gestione trust anchors ricevuti dal TLM
- Validazione catene di certificati
- Download e gestione CTL (Full e Delta)
- Invio e ricezione messaggi V2X firmati

**Utilizzo base**:
```python
from entities.its_station import ITSStation

# Inizializzazione
vehicle = ITSStation(
    its_id="Vehicle_001",
    base_dir="data/itss"
)

# 1. Genera chiavi proprie
vehicle.generate_ecc_keypair()

# 2. Richiedi Enrollment Certificate
ec_cert = vehicle.request_ec(enrollment_authority)

# 3. Richiedi Authorization Ticket
at_cert = vehicle.request_at(
    authorization_authority,
    permissions=["CAM", "DENM"],
    region="EU"
)

# 4. Aggiorna trust anchors
vehicle.update_trust_anchors([root_ca_cert, ea_cert, aa_cert])

# 5. Valida certificato
is_valid = vehicle.validate_certificate_chain(some_certificate)

# 6. Invia messaggio firmato
vehicle.send_signed_message(
    message="Emergency brake!",
    recipient_id="Vehicle_002",
    message_type="DENM"
)

# 7. Download CTL
vehicle.download_ctl_full(trust_list_manager)
vehicle.download_ctl_delta(trust_list_manager)
```

**Struttura directory**:
```
data/itss/Vehicle_001/
├── own_certificates/      # Chiavi, EC, AT propri
├── trust_anchors/         # Trust anchors (Root, EA, AA)
├── ctl_full/             # Full CTL ricevute
├── ctl_delta/            # Delta CTL ricevute
├── inbox/                # Messaggi V2X ricevuti
├── outbox/               # Messaggi V2X inviati
├── authorization_tickets/ # AT di altri veicoli
└── logs/                 # Log
```

---

## Standard di Riferimento

- **ETSI TS 102941**: Trust and Privacy Management
- **ETSI TS 103097**: Security Header and Certificate Formats
- **IEEE 1609.2**: Security Services for Applications
- **RFC 5280**: X.509 Certificate and CRL Profile

## Note Implementative

### Gestione Chiavi
- Tutte le chiavi usano curve ellittica **secp256r1** (NIST P-256)
- Le chiavi private sono salvate in formato PEM cifrato
- Le chiavi pubbliche sono distribuite tramite certificati X.509

### Validità Certificati
- **Root CA**: 10 anni
- **EA/AA**: 3 anni
- **EC**: 1-3 anni (configurabile)
- **AT**: ore/giorni (configurabile, tipicamente 1 settimana)

### CRL e CTL
- Le entità usano `CRLManager` per gestire le revoche
- Le pubblicazioni CRL seguono il pattern Full + Delta
- Le CTL sono gestite da `TrustListManager` (vedi `managers/`)

## Esempi Completi

Vedi `examples/create_sample_pki.py` per un esempio completo di setup PKI.

## Testing

Test specifici per le entità:
```bash
pytest tests/test_pki_entities.py    # Test RootCA, EA, AA
pytest tests/test_its_station.py     # Test ITS Station
```
