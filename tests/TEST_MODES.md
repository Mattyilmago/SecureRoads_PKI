# 🧪 SecureRoad PKI - Test Modes

Questa guida spiega le due modalità di esecuzione dei test disponibili.

---

## 📋 Modalità Disponibili

### 1. 🔒 **Temporary Directories** (Default - Raccomandato)

**Comportamento:**
- Crea directory temporanee isolate per ogni sessione di test
- Path tipo: `C:\Users\...\AppData\Local\Temp\pytest-of-user\pytest-XX\pki_test_data0\`
- **I dati vengono eliminati automaticamente** dopo i test
- Garantisce isolamento completo tra esecuzioni

**Quando usare:**
- ✅ Sviluppo quotidiano
- ✅ CI/CD pipeline
- ✅ Test automatizzati
- ✅ Quando vuoi test puliti e isolati

**Come eseguire:**
```bash
# Modalità default (nessun flag necessario)
python tests/run_all_tests.py

# Con opzioni pytest
python tests/run_all_tests.py -v
python tests/run_all_tests.py -k "butterfly"
python tests/run_all_tests.py --failed
```

**Output esempio:**
```
================================================================================
  SecureRoad PKI - Test Suite
  🔒 MODALITÀ: TEMPORARY DIRECTORIES (isolate)
================================================================================
✅ I test useranno directory temporanee
✅ I dati verranno eliminati automaticamente dopo i test
================================================================================
```

---

### 2. 📂 **Data Directories** (Persistenti)

**Comportamento:**
- Usa le directory `data/` del progetto
- Path: `./data/root_ca/`, `./data/ea/EA_TEST/`, ecc.
- **I dati NON vengono eliminati** dopo i test
- Permette ispezione manuale dei file generati

**Quando usare:**
- 🔍 Debug e troubleshooting
- 📊 Analisi dei certificati generati
- 🧪 Testing manuale con dati persistenti
- 📝 Documentazione e screenshot

**Come eseguire:**
```bash
# Con flag --use-data-dirs
python tests/run_all_tests.py --use-data-dirs

# Con opzioni pytest
python tests/run_all_tests.py --use-data-dirs -v
python tests/run_all_tests.py --use-data-dirs -k "etsi"
```

**Output esempio:**
```
================================================================================
  SecureRoad PKI - Test Suite
  📂 MODALITÀ: DATA DIRECTORIES PERSISTENTI
================================================================================
⚠️  I test useranno le directory data/ esistenti
⚠️  I dati NON verranno eliminati dopo i test
================================================================================
```

**⚠️ Nota:** Dopo l'esecuzione, puoi ispezionare i file in:
```
data/
├── root_ca/
│   ├── certificates/
│   │   └── root_ca_certificate.pem
│   └── private_keys/
│       └── root_ca_key.pem
├── ea/
│   └── EA_TEST/
│       ├── certificates/
│       └── enrollment_certificates/
├── aa/
│   └── AA_TEST/
│       ├── certificates/
│       └── authorization_tickets/
└── itss/
    └── TEST_VEHICLE/
        └── own_certificates/
```

---

## 🎯 Esempi di Utilizzo

### Sviluppo Normale
```bash
# Modalità interattiva (chiede quale usare)
python tests/run_all_tests.py

# Con flag esplicito (salta la scelta)
python tests/run_all_tests.py --use-tmp-dirs -v

# Test specifici
python tests/run_all_tests.py -k "test_root_ca"
```

### Debug Approfondito
```bash
# Genera dati persistenti per ispezione
python tests/run_all_tests.py --use-data-dirs -v

# Dopo i test, ispeziona i certificati generati
openssl x509 -in data/root_ca/certificates/root_ca_certificate.pem -text -noout

# Verifica le CRL
openssl crl -in data/ea/EA_TEST/crl/full/ea_full_crl_0.pem -text -noout
```

### Test Specifici con Dati Persistenti
```bash
# Solo test ETSI con dati salvati
python tests/run_all_tests.py --use-data-dirs -k "etsi"

# Solo test Butterfly con dati salvati
python tests/run_all_tests.py --use-data-dirs -k "butterfly"
```

---

## 🔧 Configurazione Tecnica

### Environment Variable
Il sistema usa la variabile d'ambiente `PKI_USE_DATA_DIRS`:
- `PKI_USE_DATA_DIRS=0` (default): temporary directories
- `PKI_USE_DATA_DIRS=1`: data directories persistenti

### File Coinvolti
1. **`run_all_tests.py`**: Gestisce il flag `--use-data-dirs` e setta la variabile d'ambiente
2. **`conftest.py`**: Legge la variabile e configura le fixture di conseguenza
   - `test_base_dir()`: Sceglie tra tmp_path o data/
   - `cleanup_data_folder()`: Salta il cleanup se modalità persistente

---

## 📊 Confronto Rapido

| Caratteristica | Temporary Dirs | Data Dirs |
|----------------|----------------|-----------|
| **Isolamento** | ✅ Completo | ⚠️ Condiviso |
| **Cleanup** | ✅ Automatico | ❌ Manuale |
| **Path** | `/tmp/pytest-XX/` | `./data/` |
| **Ispezione** | ❌ Difficile | ✅ Facile |
| **CI/CD** | ✅ Ideale | ❌ Sconsigliato |
| **Debug** | ⚠️ Limitato | ✅ Completo |
| **Performance** | ✅ Veloce | ✅ Veloce |

---

## 💡 Best Practices

### ✅ DO
- Usa **temporary directories** per sviluppo quotidiano
- Usa **data directories** solo per debug specifici
- Pulisci manualmente `data/` dopo debug con data directories
- Usa `-k` per test selettivi quando serve debug

### ❌ DON'T
- Non usare data directories in CI/CD
- Non committare la cartella `data/` dopo test manuali
- Non lanciare test in parallelo con data directories

---

## 🧹 Pulizia Manuale

Se hai usato `--use-data-dirs` e vuoi pulire:

### Windows PowerShell
```powershell
Remove-Item -Path data\root_ca -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path data\ea\EA_TEST -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path data\aa\AA_TEST -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path data\tlm -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path data\itss\TEST_VEHICLE -Recurse -Force -ErrorAction SilentlyContinue
```

### Linux/Mac
```bash
rm -rf data/root_ca
rm -rf data/ea/EA_TEST
rm -rf data/aa/AA_TEST
rm -rf data/tlm
rm -rf data/itss/TEST_VEHICLE
```

O usa lo script di esempio per rigenerare una PKI pulita:
```bash
python examples/create_sample_pki.py
```

---

## 🎓 Note Tecniche

### Temporary Directories (pytest tmp_path_factory)
- Creato da pytest nel sistema di temp del OS
- Path univoco per ogni sessione (`pytest-XX`)
- Eliminato automaticamente da pytest alla fine
- Supporta test in parallelo (xdist)

### Data Directories
- Usa le stesse directory del codice di produzione
- Fixture condividono stato (session scope)
- Richiede cleanup manuale tra esecuzioni
- Permette debugging con strumenti esterni (openssl, browser, ecc.)

---

**Ultima modifica:** Ottobre 2025  
**Autore:** SecureRoad PKI Project
