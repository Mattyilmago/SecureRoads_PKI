# 🎯 Test delle Nuove Funzionalità

## ✅ Modifiche Implementate

### 1. **DELETE ALL EA/AA ora ferma i processi** 💥
   - **File modificato:** `api/blueprints/management_bp.py`
   - **Nuovo import:** `psutil` per killare processi Python
   - **Comportamento:**
     1. Scansiona tutti i processi Python in esecuzione
     2. Identifica EA/AA tramite cmdline (e.g., "EA_001", "AA_001")
     3. Killa i processi con `proc.kill()`
     4. Rimuove entità da `entity_configs.json`
     5. Elimina directory `data/ea/` e `data/aa/`
   - **Response JSON aggiornata:**
     ```json
     {
       "success": true,
       "message": "Deleted 2 entities and killed 2 processes",
       "deleted": ["EA_001", "AA_001"],
       "processes_killed": [
         {"pid": 12345, "cmdline": "python -m entities.enrollment_authority"},
         {"pid": 12346, "cmdline": "python -m entities.authorization_authority"}
       ],
       "failed": []
     }
     ```

### 2. **START NOW avvia processi in background** 🚀
   - **File modificato:** `pki_dashboard.html` (funzione `executeSetupDirectly`)
   - **Nuovo endpoint:** `POST /api/management/start-entities`
   - **Workflow:**
     1. Chiama `POST /api/management/setup` con `auto_start: false`
     2. Setup.py crea entità e config (senza avviare processi)
     3. Chiama `POST /api/management/start-entities` con lista entità
     4. Processi avviati in background con `subprocess.Popen`
   - **Windows:** Usa `PowerShell Start-Process -WindowStyle Hidden`
   - **Linux/Mac:** Usa `start_new_session=True` per detach

### 3. **UI migliorata** 🎨
   - **DELETE ALL button:** Testo aggiornato da "DELETE ALL EA/AA FROM CONFIG" a "DELETE ALL EA/AA (INSTANT)"
   - **Warning box:** Rimossa sezione con `.\stop_all.ps1` (non più necessaria!)
   - **Success box verde:** Spiega che il bottone fa tutto automaticamente
   - **Dashboard logs:** Messaggi migliorati con conteggio processi killati

---

## 🧪 Come Testare

### Test 1: Delete All con Kill Processi

1. **Avvia dashboard:**
   ```powershell
   .\start_dashboard.ps1
   ```

2. **Crea 2 EA + 2 AA:**
   ```powershell
   python setup.py --ea 2 --aa 2
   ```

3. **Verifica nel dashboard:**
   - Dovresti vedere "2 EA" e "2 AA" in Running Instances
   - Controlla anche Task Manager → 4 processi Python attivi

4. **Clicca "DELETE ALL EA/AA (INSTANT)"**
   - Logs dovrebbero mostrare:
     ```
     💥 Deleting ALL EA and AA entities AND stopping processes...
     ✅ Successfully deleted 4 entities and stopped processes!
       ✓ Removed from config: EA_001, EA_002, AA_001, AA_002
       ✓ Killed 4 Python processes
     🔄 Dashboard will update in 3 seconds...
     ```

5. **Attendi 3 secondi:**
   - Dashboard si aggiorna automaticamente
   - Dovresti vedere "0 EA" e "0 AA"
   - Task Manager → processi Python terminati

---

### Test 2: START NOW con Processi Background

1. **Dashboard già attivo** (da test precedente)

2. **Clicca "🏗️ Generate Multiple Entities"**

3. **Compila form:**
   - Numero EA: 2
   - Numero AA: 1
   - Nomi custom: "EA_TEST_A", "EA_TEST_B", "AA_TEST_X"

4. **Clicca "➕ Generate Entities with Names"**

5. **Clicca "▶️ START NOW"**
   - Logs dovrebbero mostrare:
     ```
     🚀 Creating 2 EA and 1 AA entities...
     ✅ Entities created successfully!
     🚀 Starting 3 entities in background...
     ✅ Successfully started 3 entities!
       ✓ EA_TEST_A started
       ✓ EA_TEST_B started
       ✓ AA_TEST_X started
     🔄 Refreshing dashboard in 5 seconds...
     ```

6. **Attendi 5 secondi:**
   - Dashboard mostra "2 EA" e "1 AA"
   - Task Manager → 3 nuovi processi Python

7. **Verifica porte attive:**
   ```powershell
   netstat -ano | findstr "LISTENING" | findstr "500"
   ```
   - Dovresti vedere porte 5000, 5001, 5020

---

### Test 3: Ciclo Completo (Create → Delete → Create)

1. **Crea entità:** START NOW → 3 EA, 2 AA
2. **Verifica:** Dashboard mostra "3 EA" e "2 AA"
3. **Elimina:** DELETE ALL EA/AA (INSTANT)
4. **Verifica:** Dashboard mostra "0 EA" e "0 AA"
5. **Ricrea:** START NOW → 1 EA, 1 AA
6. **Verifica finale:** Dashboard mostra "1 EA" e "1 AA"

---

## ✅ Checklist Funzionalità

- [x] `psutil` importato in `management_bp.py`
- [x] Funzione `delete_all_ea_aa()` killa processi prima di eliminare
- [x] Nuovo endpoint `POST /api/management/start-entities`
- [x] `executeSetupDirectly()` chiama setup + start entities
- [x] Dashboard UI aggiornata (bottone + messaggi)
- [x] Timeout aumentato a 3 secondi per process cleanup
- [x] Logs migliorati con conteggio processi killati

---

## 🐛 Troubleshooting

### Se DELETE ALL non funziona:

1. **Verifica psutil installato:**
   ```powershell
   python -c "import psutil; print(psutil.__version__)"
   ```

2. **Controlla processi manualmente:**
   ```powershell
   Get-Process python | Where-Object {$_.CommandLine -like "*entities*"}
   ```

3. **Fallback manuale:**
   ```powershell
   .\stop_all.ps1
   ```

### Se START NOW non avvia processi:

1. **Verifica entity_configs.json esistente:**
   ```powershell
   Get-Content entity_configs.json | ConvertFrom-Json | Select-Object -ExpandProperty start_commands
   ```

2. **Controlla porte disponibili:**
   ```powershell
   .\scripts\check_ports.ps1
   ```

3. **Test manuale endpoint:**
   ```powershell
   curl -X POST http://localhost:5999/api/management/start-entities -H "Content-Type: application/json" -d '{"entities":["EA_001"]}'
   ```

---

## 📋 Log Messages da Aspettarsi

### Delete All (Success):
```
💥 Deleting ALL EA and AA entities AND stopping processes...
✅ Successfully deleted 4 entities and stopped processes!
  ✓ Removed from config: EA_001, EA_002, AA_001, AA_002
  ✓ Killed 4 Python processes
🔄 Dashboard will update in 3 seconds...
✅ Dashboard updated - all EA/AA removed!
```

### Start Now (Success):
```
🚀 Creating 2 EA and 1 AA entities...
✅ Entities created successfully!
🚀 Starting 3 entities in background...
✅ Successfully started 3 entities!
  ✓ EA_TEST_A started
  ✓ EA_TEST_B started
  ✓ AA_TEST_X started
🔄 Refreshing dashboard in 5 seconds...
✅ Dashboard updated!
```

---

## 🎉 Risultato Atteso

- **DELETE ALL EA/AA:** Un solo click → Config pulito + Processi fermati + Dashboard aggiornato
- **START NOW:** Un solo click → Entità create + Processi avviati in background + Dashboard aggiornato

Niente più comandi da copiare/incollare in PowerShell! 🚀
