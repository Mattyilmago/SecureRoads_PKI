# Daily Use PKI Test Scripts

Script interattivi per testare quotidianamente la PKI SecureRoad.

## 📋 Script Disponibili

### 1. Interactive PKI Tester

**File:** `examples/interactive_pki_tester.py`

Script con menu interattivo per eseguire test completi sulla PKI.

**Utilizzo:**
```powershell
python examples/interactive_pki_tester.py
```

**Con integrazione dashboard:**
```powershell
python examples/interactive_pki_tester.py --dashboard
```

**Test Disponibili:**
1. ✈️ **Enrollment singolo veicolo** - Test base di enrollment
2. 🎫 **Authorization Ticket** - Richiesta AT per veicolo enrollato
3. 🚗 **Fleet Enrollment** - Enrollment di 5 veicoli contemporaneamente
4. 📡 **V2V Communication** - Simulazione comunicazione tra veicoli
5. ✔️ **Certificate Validation** - Verifica validità certificati
6. ⚡ **Performance Test** - Test di carico con 10 enrollment
7. 🔄 **Full Suite** - Esegui tutti i test in sequenza
8. 📊 **Show Results** - Visualizza risultati salvati
9. 🗑️ **Cleanup** - Rimuovi stazioni di test

**Caratteristiche:**
- Menu interattivo user-friendly
- Salvataggio automatico risultati in `data/test_results.json`
- Integrazione con dashboard
- Statistiche dettagliate
- Gestione flotta veicoli

---

### 2. Quick Test

**File:** `examples/quick_test.py`

Script veloce per test rapidi senza menu interattivo.

**Utilizzo:**

```powershell
# Test singolo enrollment
python examples/quick_test.py --test enrollment

# Test authorization
python examples/quick_test.py --test authorization

# Test enrollment multipli
python examples/quick_test.py --test multiple --count 5

# Esegui tutti i test
python examples/quick_test.py --test all
```

**Opzioni:**
- `--test` - Tipo di test: `enrollment`, `authorization`, `multiple`, `all`
- `--ea-url` - URL Enrollment Authority (default: http://localhost:5000, EA range: 5000-5019)
- `--aa-url` - URL Authorization Authority (default: http://localhost:5020, AA range: 5020-5039)
- `--count` - Numero di enrollment per test multiple (default: 3)

**Caratteristiche:**
- Esecuzione veloce
- Output compatto
- Exit code per CI/CD
- Senza dipendenze dalla dashboard

---

## 🎯 Scenari di Test Comuni

### Scenario 1: Test Completo del Sistema

```powershell
# 1. Verifica che le entità siano attive
.\check_ports.ps1

# 2. Esegui test completi
python examples/interactive_pki_tester.py --dashboard

# 3. Scegli opzione 7 (Full Suite) dal menu
```

### Scenario 2: Test Rapido Enrollment

```powershell
python examples/quick_test.py --test enrollment
```

### Scenario 3: Test Performance

```powershell
# Opzione A: Menu interattivo
python examples/interactive_pki_tester.py
# Scegli opzione 6 (Performance Test)

# Opzione B: Quick test multiple
python examples/quick_test.py --test multiple --count 10
```

### Scenario 4: Verifica Giornaliera

```powershell
# Test veloce di enrollment e authorization
python examples/quick_test.py --test all
```

---

## 📊 Dashboard Integration

I risultati dei test eseguiti con `interactive_pki_tester.py` vengono automaticamente salvati in `data/test_results.json` e possono essere visualizzati nella dashboard.

**Per visualizzare i risultati:**

1. Apri `pki_dashboard.html` nel browser
2. Scorri fino alla sezione "Daily Use Test Scripts"
3. Clicca su "Refresh Results" per aggiornare
4. Clicca su "View Details" per vedere i dettagli completi

**Formato Risultati:**
```json
{
  "timestamp": "2025-10-09T22:45:00.000Z",
  "test": "vehicle_enrollment",
  "status": "success",
  "details": {
    "vehicle_id": "VEHICLE_1728509100",
    "ec_serial": "123456789",
    "ec_ski": "ABCDEF01"
  }
}
```

---

## 🔧 Configurazione

### URL delle Entità

Entrambi gli script supportano configurazione custom:

```powershell
# Usa porte diverse
# Se le entities usano porte diverse dai default
python examples/interactive_pki_tester.py --ea-url http://localhost:5001 --aa-url http://localhost:5021

python examples/quick_test.py --ea-url http://localhost:5001 --aa-url http://localhost:5021
```

### Configurazione Entity Config

Se usi configurazioni custom, assicurati che corrispondano a `entity_configs.json`:

```json
{
  "entities": [
    {"type": "EA", "id": "EA_001", "port": "auto"},
    {"type": "AA", "id": "AA_001", "port": "auto"}
  ]
}
```

**Note**: Ports are auto-assigned from configured ranges:
- **EA**: 5000-5019 (up to 20 instances)
- **AA**: 5020-5039 (up to 20 instances)
- **TLM**: 5050 (1 instance)
- **RootCA**: 5999 (1 instance)

---

## 📖 Esempi Dettagliati

### Esempio 1: Test Enrollment Completo

```powershell
PS> python examples/interactive_pki_tester.py

======================================================================
  PKI TESTER - Menu Interattivo
======================================================================

  Test Disponibili:
  1. ✈️  Enrollment singolo veicolo
  2. 🎫 Richiesta Authorization Ticket
  ...

  Scegli test (0-9): 1

======================================================================
  TEST 1: Enrollment Veicolo
======================================================================

ℹ️  Creazione ITS Station: VEHICLE_1728509100
✅ ITS Station VEHICLE_1728509100 creata
ℹ️  Chiave pubblica generata: 256 bit
ℹ️  Richiesta Enrollment Certificate a http://localhost:5000 (EA range: 5000-5019)
✅ Enrollment Certificate ottenuto!
ℹ️    Serial: 241224130540609952107986729182435911934044412977
ℹ️    Valido fino: 2026-10-09 20:37:52+00:00
ℹ️    SKI: 0A1A2209

  Premi ENTER per continuare...
```

### Esempio 2: Quick Test con Output

```powershell
PS> python examples/quick_test.py --test enrollment

🚀 Quick PKI Tester
   EA URL: http://localhost:5000 (EA range: 5000-5019)
   AA URL: http://localhost:5020 (AA range: 5020-5039)

============================================================
  TEST: Enrollment
============================================================

1. Creazione ITS Station: QUICK_TEST_1728509200
   ✅ Station creata

2. Richiesta Enrollment Certificate a http://localhost:5000 (EA range: 5000-5019)
   ✅ Enrollment riuscito!
   Serial: 397891247975812256609797316525704181229033810220
   SKI: 1B2C3D4E

============================================================
  ✅ TEST SUPERATO
============================================================
```

### Esempio 3: Performance Test

```powershell
PS> python examples/interactive_pki_tester.py

  Scegli test (0-9): 6

======================================================================
  TEST 6: Performance Test
======================================================================

ℹ️  Esecuzione di 10 enrollment consecutivi...

✅ Test completato in 4.52s
ℹ️    Richieste riuscite: 10/10
ℹ️    Tempo medio: 0.445s
ℹ️    Tempo minimo: 0.412s
ℹ️    Tempo massimo: 0.489s
ℹ️    Throughput: 2.21 req/s
```

---

## 🐛 Troubleshooting

### Errore: "Connection refused"

**Causa:** Entità PKI non avviate.

**Soluzione:**
```powershell
# Verifica porte attive
.\check_ports.ps1

# Avvia le entità
.\start_all_entities.ps1
```

### Errore: "Enrollment failed"

**Causa:** EA non risponde o configurazione errata.

**Soluzione:**
```powershell
# Verifica che EA sia raggiungibile (default first EA port)
curl http://localhost:5000/health

# Se non risponde, riavvia EA (auto port assignment)
python server.py --entity EA --id EA_001
```

### Test Results non visibili in Dashboard

**Causa:** File `data/test_results.json` non esiste.

**Soluzione:**
```powershell
# Esegui almeno un test con interactive_pki_tester
python examples/interactive_pki_tester.py --dashboard

# Il file verrà creato automaticamente
```

### Cleanup Test Stations

Se hai molte test stations:

```powershell
# Opzione A: Usa menu cleanup
python examples/interactive_pki_tester.py
# Scegli opzione 9 (Cleanup)

# Opzione B: Rimuovi manualmente
Remove-Item -Recurse -Force .\data\its_stations\VEHICLE_*
Remove-Item -Recurse -Force .\data\its_stations\FLEET_*
Remove-Item -Recurse -Force .\data\its_stations\QUICK_*
```

---

## 📈 Metriche e Benchmarks

### Tempi Tipici (su hardware medio)

| Operazione | Tempo Medio | Note |
|-----------|-------------|------|
| Single Enrollment | 0.4-0.6s | Dipende dal carico EA |
| Authorization Request | 0.5-0.7s | Include enrollment + AT |
| Fleet Enrollment (5) | 2-3s | Sequenziale |
| Performance Test (10) | 4-5s | Sequenziale |
| V2V Message Sign+Verify | <0.1s | Operazione locale |

### Throughput Atteso

- **Enrollment:** ~2-3 req/s (sequenziale)
- **Authorization:** ~1.5-2 req/s (sequenziale)
- **Firma Messaggi:** >100 msg/s (locale)

---

## 🎓 Best Practices

1. **Esegui test completi dopo ogni modifica**
   ```powershell
   python examples/interactive_pki_tester.py --dashboard
   # Scegli opzione 7 (Full Suite)
   ```

2. **Usa quick_test per CI/CD**
   ```powershell
   python examples/quick_test.py --test all
   if ($LASTEXITCODE -ne 0) { exit 1 }
   ```

3. **Monitora risultati dalla dashboard**
   - Apri `pki_dashboard.html`
   - Controlla sezione "Daily Use Test Scripts"
   - Verifica trend successi/fallimenti

4. **Pulisci regolarmente test stations**
   ```powershell
   # Ogni settimana
   python examples/interactive_pki_tester.py
   # Opzione 9 (Cleanup)
   ```

5. **Salva logs importanti**
   ```powershell
   python examples/quick_test.py --test all > test_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt
   ```

---

## 🔗 Link Utili

- [API Examples](./api_client_example.py) - Esempi chiamate API dirette
- [Entity README](../entities/README_entities.md) - Documentazione entità
- [Port Management](../docs/PORT_MANAGEMENT.md) - Gestione porte
- [Dashboard](../pki_dashboard.html) - Control Panel web

---

## 📝 Note

- I risultati sono salvati in `data/test_results.json`
- Le test stations sono create in `data/its_stations/`
- Usa `--dashboard` per integrazione automatica con dashboard
- Gli script supportano Ctrl+C per interruzione pulita
