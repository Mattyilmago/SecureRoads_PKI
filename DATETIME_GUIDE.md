# 📅 Guida Definitiva: Gestione Datetime nei Certificati

## ⚠️ REGOLA D'ORO - LEGGERE PRIMA DI TOCCARE CODICE!

**La libreria `cryptography` (versione 39.0.0+) restituisce datetime NAIVE (senza timezone) dai certificati.**

```python
# ❌ SBAGLIATO - Genera TypeError!
cert = some_certificate()
expiry = cert.not_valid_after  # ← datetime NAIVE (no timezone)
if expiry < datetime.now(timezone.utc):  # ← datetime AWARE (con UTC)
    # TypeError: can't compare offset-naive and offset-aware datetimes
    pass
```

## ✅ SOLUZIONE CORRETTA - USA SEMPRE LE UTILITY

```python
from utils.cert_utils import get_certificate_expiry_time, get_certificate_not_before

# ✅ CORRETTO - Restituiscono datetime UTC-aware normalizzati
cert = some_certificate()
expiry = get_certificate_expiry_time(cert)  # ← UTC-aware automatico
start = get_certificate_not_before(cert)     # ← UTC-aware automatico

# Ora puoi confrontare tranquillamente
if expiry < datetime.now(timezone.utc):
    print("Certificato scaduto")
```

## 📖 Documentazione Tecnica

### Comportamento `cryptography` Library

| Proprietà Certificate | Tipo Restituito | Note |
|----------------------|-----------------|------|
| `cert.not_valid_before` | `datetime` NAIVE | ⚠️ NO timezone |
| `cert.not_valid_after` | `datetime` NAIVE | ⚠️ NO timezone |
| ~~`cert.not_valid_before_utc`~~ | ❌ **NON ESISTE** | Rimosso in cryptography 39.0+ |
| ~~`cert.not_valid_after_utc`~~ | ❌ **NON ESISTE** | Rimosso in cryptography 39.0+ |

### Funzioni Utility Disponibili

File: `utils/cert_utils.py`

```python
def get_certificate_expiry_time(certificate: x509.Certificate) -> datetime:
    """
    Estrae data di scadenza certificato (timezone-aware UTC).
    
    Normalizza automaticamente:
    - Se datetime è NAIVE → aggiunge timezone UTC
    - Se datetime è AWARE → ritorna così com'è
    
    Returns:
        datetime con timezone UTC
    """
    expiry = certificate.not_valid_after
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry


def get_certificate_not_before(certificate: x509.Certificate) -> datetime:
    """
    Estrae data di inizio validità certificato (timezone-aware UTC).
    
    Returns:
        datetime con timezone UTC
    """
    not_before = certificate.not_valid_before
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    return not_before


def is_certificate_valid_at(certificate: x509.Certificate, timestamp=None) -> bool:
    """
    Verifica validità certificato in un momento specifico.
    
    Args:
        certificate: Certificato X.509
        timestamp: Momento da verificare (default: ora corrente UTC)
    
    Returns:
        True se valido, False altrimenti
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc)
    
    not_before = get_certificate_not_before(certificate)
    not_after = get_certificate_expiry_time(certificate)
    
    return not_before <= timestamp <= not_after
```

## 🎯 Pattern Comuni - Copia/Incolla Questi

### 1. Verificare Scadenza Certificato

```python
from utils.cert_utils import get_certificate_expiry_time
from datetime import datetime, timezone

# ✅ CORRETTO
expiry = get_certificate_expiry_time(certificate)
if expiry < datetime.now(timezone.utc):
    logger.error("Certificato scaduto!")
    return None
```

### 2. Calcolare Giorni Rimanenti

```python
from utils.cert_utils import get_certificate_expiry_time
from datetime import datetime, timezone

# ✅ CORRETTO
expiry = get_certificate_expiry_time(certificate)
remaining_days = (expiry - datetime.now(timezone.utc)).days

if remaining_days < 30:
    logger.warning(f"Certificato scade tra {remaining_days} giorni!")
```

### 3. Verificare Validità Completa

```python
from utils.cert_utils import is_certificate_valid_at

# ✅ CORRETTO
if not is_certificate_valid_at(certificate):
    logger.error("Certificato non valido (scaduto o non ancora valido)")
    return None
```

### 4. Stampare Info Validità

```python
from utils.cert_utils import get_certificate_not_before, get_certificate_expiry_time

# ✅ CORRETTO
start = get_certificate_not_before(certificate)
expiry = get_certificate_expiry_time(certificate)
logger.info(f"Validità: dal {start} al {expiry}")
```

### 5. Confrontare Date tra Certificati

```python
from utils.cert_utils import get_certificate_expiry_time

# ✅ CORRETTO
cert1_expiry = get_certificate_expiry_time(cert1)
cert2_expiry = get_certificate_expiry_time(cert2)

# Usa quello che scade prima
link_expiry = min(cert1_expiry, cert2_expiry)
```

## 🚫 Pattern da EVITARE

### ❌ NON fare mai questo:

```python
# ❌ SBAGLIATO - TypeError garantito!
if certificate.not_valid_after < datetime.now(timezone.utc):
    pass

# ❌ SBAGLIATO - Proprietà non esiste!
expiry = certificate.not_valid_after_utc

# ❌ SBAGLIATO - Confronto naive vs aware
expiry = certificate.not_valid_after
remaining = (expiry - datetime.now(timezone.utc)).days
```

### ✅ Fai sempre così:

```python
# ✅ CORRETTO - Usa utility
from utils.cert_utils import get_certificate_expiry_time

expiry = get_certificate_expiry_time(certificate)
if expiry < datetime.now(timezone.utc):
    pass
```

## 🔍 Debugging DateTime Issues

Se ottieni `TypeError: can't compare offset-naive and offset-aware datetimes`:

1. **Verifica** che stai usando le funzioni utility:
   ```python
   # Cerca nel file
   grep "certificate.not_valid" file.py
   
   # Dovrebbe mostrare get_certificate_expiry_time(), NON .not_valid_after
   ```

2. **Controlla** gli import:
   ```python
   # All'inizio del file DEVE esserci:
   from utils.cert_utils import get_certificate_expiry_time, get_certificate_not_before
   ```

3. **Sostituisci** il codice vecchio:
   ```python
   # TROVA:
   cert.not_valid_after
   
   # SOSTITUISCI CON:
   get_certificate_expiry_time(cert)
   ```

## 📝 Checklist per Nuove Funzioni

Quando aggiungi codice che gestisce certificati:

- [ ] Import delle utility certificate in alto
- [ ] Uso di `get_certificate_expiry_time()` invece di `.not_valid_after`
- [ ] Uso di `get_certificate_not_before()` invece di `.not_valid_before`
- [ ] Tutti i confronti datetime usano `datetime.now(timezone.utc)`
- [ ] Test aggiunto per verificare gestione datetime

## 🎓 Perché Questo Casino?

**Storia breve:**
- **cryptography < 39.0**: Aveva `.not_valid_after_utc` (UTC-aware)
- **cryptography ≥ 39.0**: Rimosso! Solo `.not_valid_after` (NAIVE)
- **Motivo**: Maggiore controllo al programmatore sulla gestione timezone
- **Soluzione**: Utility functions che normalizzano in UTC-aware

## 📚 Riferimenti

- **File utility**: `utils/cert_utils.py`
- **Logger setup**: `utils/logger.py`
- **Test esempi**: `tests/test_pki_entities.py`
- **Versione cryptography**: 39.0.0 (vedi `requirements.txt`)

---

**ULTIMA REVISIONE**: 2025-10-09  
**STATO TEST**: ✅ 115/115 test passano con questa implementazione
