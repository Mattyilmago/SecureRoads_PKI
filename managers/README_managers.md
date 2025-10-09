# Managers - Gestori PKI

Questa cartella contiene i manager specializzati per la gestione di Certificate Revocation Lists (CRL) e Certificate Trust Lists (CTL).

## Classi Disponibili

### CRLManager
**File**: `crl_manager.py`

Certificate Revocation List Manager - Gestisce la creazione e pubblicazione di CRL conformi a X.509 e ETSI.

**Responsabilità**:
- Gestione lista certificati revocati
- Generazione Full CRL (lista completa)
- Generazione Delta CRL (solo modifiche incrementali)
- Sincronizzazione automatica Full/Delta
- Cleanup certificati scaduti
- Statistiche e monitoraggio
- Persistenza metadata su JSON

**Caratteristiche**:
- Supporto Full CRL: contiene tutti i certificati revocati attivi
- Supporto Delta CRL: contiene solo le modifiche dall'ultima Full CRL
- Gestione automatica numeri CRL sequenziali
- Cleanup automatico certificati scaduti dalle CRL
- Metadata persistence per tracking revoche

**Utilizzo base**:
```python
from managers.crl_manager import CRLManager

# Inizializzazione
crl_manager = CRLManager(
    authority_id="EA_001",
    base_dir="data/ea/EA_001",
    issuer_certificate=ea_certificate,
    issuer_private_key=ea_private_key
)

# Aggiungi certificato revocato
crl_manager.add_revoked_certificate(
    certificate=cert_to_revoke,
    reason=ReasonFlags.key_compromise
)

# Pubblica Full CRL
full_crl_path = crl_manager.publish_full_crl(validity_days=30)

# Pubblica Delta CRL
delta_crl_path = crl_manager.publish_delta_crl(validity_days=7)

# Ottieni statistiche
stats = crl_manager.get_statistics()
print(f"Certificati revocati: {stats['total_revoked']}")
print(f"Ultima Full CRL: {stats['last_full_crl_number']}")
print(f"Ultima Delta CRL: {stats['last_delta_crl_number']}")

# Cleanup certificati scaduti
removed = crl_manager.cleanup_expired_certificates()
print(f"Rimossi {removed} certificati scaduti dalle CRL")
```

**Metadata persistenti**:
Il CRLManager salva automaticamente i metadata in `crl_metadata.json`:
```json
{
  "last_full_crl_number": 5,
  "last_delta_crl_number": 42,
  "last_full_crl_date": "2025-10-09T10:30:00",
  "revoked_certificates": [
    {
      "serial_number": "123456789",
      "identifier": "CERT_ABC123",
      "ski": "1A2B3C...",
      "revocation_date": "2025-10-09T08:00:00",
      "expiry_date": "2026-10-09T00:00:00",
      "reason": "key_compromise"
    }
  ]
}
```

**Struttura directory**:
```
base_dir/
├── crl/
│   ├── full/
│   │   ├── crl_full_001.pem
│   │   ├── crl_full_002.pem
│   │   └── ...
│   ├── delta/
│   │   ├── crl_delta_001.pem
│   │   ├── crl_delta_002.pem
│   │   └── ...
│   └── crl_metadata.json
```

**Best Practices**:
1. **Pubblicazione Full CRL**: Mensile o quando Delta CRL diventa troppo grande
2. **Pubblicazione Delta CRL**: Settimanale o giornaliera
3. **Cleanup**: Eseguire periodicamente per rimuovere certificati scaduti
4. **Monitoraggio**: Controllare statistiche per pianificare pubblicazioni

---

### TrustListManager
**File**: `trust_list_manager.py`

Certificate Trust List Manager - Gestisce la lista delle autorità di certificazione fidate (trust anchors).

**Responsabilità**:
- Gestione trust anchors (Root CA, EA, AA)
- Generazione Full CTL (lista completa trust anchors)
- Generazione Delta CTL (modifiche: aggiunte/rimozioni)
- Generazione Link Certificates conformi ETSI TS 102941
- Distribuzione trust anchors alle ITS Stations
- Verifica appartenenza certificati a CA fidate
- Cleanup trust anchors scaduti

**Caratteristiche**:
- Supporto Full CTL e Delta CTL
- Link Certificates in formato JSON e ASN.1 OER
- Tracking aggiunte e rimozioni trust anchors
- Validazione automatica certificati contro trust list
- Metadata persistence su JSON

**Utilizzo base**:
```python
from managers.trust_list_manager import TrustListManager

# Inizializzazione
tlm = TrustListManager(
    root_ca=root_ca,
    tlm_id="TLM_001",
    base_dir="data/tlm"
)

# Aggiungi trust anchor
tlm.add_trust_anchor(
    certificate=ea_certificate,
    authority_type="EA",
    description="Enrollment Authority 001"
)

tlm.add_trust_anchor(
    certificate=aa_certificate,
    authority_type="AA",
    description="Authorization Authority 001"
)

# Pubblica Full CTL
full_ctl_path = tlm.publish_full_ctl(validity_days=30)

# Pubblica Delta CTL
delta_ctl_path = tlm.publish_delta_ctl(validity_days=7)

# Genera Link Certificate ETSI
link_cert_json = tlm.generate_link_certificate(
    root_cert=root_ca.certificate,
    authority_cert=ea_certificate,
    authority_type="EA"
)

# Verifica se certificato è fidato
is_trusted = tlm.is_certificate_in_trust_list(some_certificate)

# Ottieni trust anchors per tipo
ea_anchors = tlm.get_trust_anchors_by_type("EA")

# Distribuisci a veicoli
vehicles = [vehicle1, vehicle2, vehicle3]
tlm.distribute_to_itss(vehicles)

# Rimuovi trust anchor
tlm.remove_trust_anchor(
    certificate=compromised_ea_cert,
    reason="key_compromise"
)

# Cleanup trust anchors scaduti
removed = tlm.cleanup_expired_trust_anchors()
```

**Link Certificates ETSI**:
Il TLM genera Link Certificates conformi a ETSI TS 102941 che collegano la Root CA alle autorità subordinate:

```json
{
  "version": 1,
  "expiryTime": 1696838400,
  "certificateHash": "1A2B3C4D...",
  "linkCertificateName": "Root-to-EA_001",
  "issuerCertificate": "-----BEGIN CERTIFICATE-----...",
  "subordinateCertificate": "-----BEGIN CERTIFICATE-----..."
}
```

**Struttura directory**:
```
data/tlm/TLM_001/
├── ctl/
│   ├── full/
│   │   ├── ctl_full_001.json
│   │   ├── ctl_full_002.json
│   │   └── ...
│   ├── delta/
│   │   ├── ctl_delta_001.json
│   │   ├── ctl_delta_002.json
│   │   └── ...
│   └── ctl_metadata.json
├── link_certificates/
│   ├── json/              # Link certificates JSON (debug)
│   │   ├── Root-to-EA_001.json
│   │   ├── Root-to-AA_001.json
│   │   └── ...
│   └── asn1/              # Link certificates ASN.1 (production)
│       ├── Root-to-EA_001.oer
│       └── ...
├── logs/
└── backup/
```

**CTL Metadata**:
```json
{
  "last_full_ctl_number": 3,
  "last_delta_ctl_number": 15,
  "last_full_ctl_date": "2025-10-09T10:00:00",
  "trust_anchors": [
    {
      "identifier": "CERT_ROOT_001",
      "ski": "9F8E7D...",
      "subject": "CN=RootCA",
      "authority_type": "ROOT",
      "added_date": "2025-09-01T00:00:00",
      "expiry_date": "2035-09-01T00:00:00",
      "status": "active"
    }
  ],
  "removed_trust_anchors": [
    {
      "identifier": "CERT_EA_BAD",
      "removal_date": "2025-10-01T10:00:00",
      "reason": "key_compromise"
    }
  ]
}
```

**Best Practices**:
1. **Pubblicazione Full CTL**: Mensile
2. **Pubblicazione Delta CTL**: Settimanale
3. **Link Certificates**: Rigenerare quando cambiano le autorità
4. **Distribuzione**: Automatizzare la distribuzione alle ITS Stations
5. **Monitoraggio**: Verificare scadenze trust anchors

---

## Differenze CRL vs CTL

| Aspetto | CRL (Revocation) | CTL (Trust) |
|---------|------------------|-------------|
| **Scopo** | Blacklist - chi NON fidarsi | Whitelist - di chi fidarsi |
| **Contenuto** | Certificati revocati | CA fidate (trust anchors) |
| **Gestito da** | CRLManager | TrustListManager |
| **Operazioni** | `add_revoked_certificate()` | `add_trust_anchor()` |
| **Validazione** | Verifica che cert NON sia revocato | Verifica catena di fiducia |
| **Frequenza** | Alta (settimanale/giornaliera) | Media (mensile) |
| **Dimensione** | Cresce con revoche | Piccola (poche CA) |

## Pattern Full + Delta

Entrambi i manager usano il pattern **Full + Delta** per distribuzione efficiente:

**Full CRL/CTL**:
- Contiene TUTTI i dati (revoche o trust anchors)
- Pubblicazione mensile
- Base di riferimento per Delta
- File più grande ma completo

**Delta CRL/CTL**:
- Contiene SOLO modifiche dall'ultima Full
- Pubblicazione frequente (settimanale/giornaliera)
- Molto più piccola e veloce da scaricare
- Richiede Full come riferimento

**Workflow tipico**:
```python
# Giorno 1: Pubblica Full
manager.publish_full_crl(validity_days=30)

# Giorni 2-30: Pubblica Delta
for day in range(2, 31):
    manager.add_revoked_certificate(cert, reason)
    manager.publish_delta_crl(validity_days=7)

# Giorno 31: Nuova Full (reset)
manager.publish_full_crl(validity_days=30)
```

## Standard di Riferimento

- **RFC 5280**: X.509 Certificate and CRL Profile
- **ETSI TS 102941**: Trust and Privacy Management (CTL, Link Certificates)
- **ETSI TS 103097**: Certificate formats

## Esempi Completi

Vedi la documentazione dettagliata:
- `docs/DELTA_CRL_DOCUMENTATION.md` - Guida completa CRL
- `docs/TRUST_LIST_MANAGER_DOCUMENTATION.md` - Guida completa TLM

## Testing

Test specifici per i manager:
```bash
pytest tests/test_managers.py
```
