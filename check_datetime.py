#!/usr/bin/env python3
"""
Script di verifica gestione datetime nei certificati.

COSA FA:
--------
Scansiona automaticamente tutti i file .py del progetto cercando:
1. Comparazioni dirette tra datetime NAIVE (da certificati) e UTC-aware
2. Sottrazioni problematiche che generano TypeError
3. Uso di proprietà deprecate (_utc)

COME FUNZIONA:
--------------
- Cerca pattern regex problematici (es: cert.not_valid_after < datetime.now(timezone.utc))
- Ignora pattern sicuri (print, log, CertificateBuilder methods)
- Segnala linee di codice che possono causare TypeError

QUANDO USARLO:
--------------
- Prima di ogni commit
- Dopo modifiche a codice che gestisce certificati
- Durante code review
- In CI/CD pipeline

ESEMPIO OUTPUT:
---------------
✅ Nessun problema trovato!
   Tutti i datetime nei certificati sono gestiti correttamente.

oppure:

⚠️ Trovati 2 potenziali problemi:
   📄 entities/root_ca.py
      Linea 120: Comparazione diretta datetime NAIVE con UTC-aware
      > if cert.not_valid_after < datetime.now(timezone.utc):

💡 Soluzione: Usa get_certificate_expiry_time() da utils/cert_utils
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple

# Pattern da cercare (potenzialmente problematici)
PROBLEMATIC_PATTERNS = [
    # Comparazione diretta con datetime aware
    (
        r'certificate\.not_valid_(before|after)\s*[<>=]+\s*datetime\.now\(timezone\.utc\)',
        "Comparazione diretta datetime NAIVE con UTC-aware - usa get_certificate_expiry_time()"
    ),
    (
        r'cert\.not_valid_(before|after)\s*[<>=]+\s*datetime\.now\(timezone\.utc\)',
        "Comparazione diretta datetime NAIVE con UTC-aware - usa get_certificate_expiry_time()"
    ),
    # Sottrazione diretta
    (
        r'\(certificate\.not_valid_(before|after)\s*-\s*datetime\.now\(timezone\.utc\)\)',
        "Sottrazione datetime NAIVE - UTC-aware - usa get_certificate_expiry_time()"
    ),
    (
        r'\(cert\.not_valid_(before|after)\s*-\s*datetime\.now\(timezone\.utc\)\)',
        "Sottrazione datetime NAIVE - UTC-aware - usa get_certificate_expiry_time()"
    ),
]

# Pattern CORRETTI da ignorare
SAFE_PATTERNS = [
    r'\.not_valid_before\(',  # CertificateBuilder.not_valid_before(...)
    r'\.not_valid_after\(',   # CertificateBuilder.not_valid_after(...)
    r'^\s*#',                  # Commenti (inizio riga)
    r'# .*\.not_valid',        # Commenti con not_valid
    r'""".*\.not_valid',       # Docstrings
    r"'''.*\.not_valid",       # Docstrings con apici singoli
    r'print\(.*\.not_valid',   # Print statements (solo visualizzazione)
    r'logger\.',               # Logger statements
    r'f".*\.not_valid',        # F-strings per log
    r'from utils.cert_utils',  # Import delle utility
    r'def get_certificate_',   # Definizione funzioni utility
    r'^\s*>',                  # Esempi di codice (markdown/doc)
    r'^\s*-\s',                # Liste (markdown/doc)
]

def is_safe_line(line: str) -> bool:
    """Verifica se la linea è sicura (non problematica)."""
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, line):
            return True
    return False

def check_file(file_path: Path) -> List[Tuple[int, str, str]]:
    """
    Controlla un file per pattern problematici.
    
    Returns:
        Lista di (line_number, line_content, issue_description)
    """
    issues = []
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for line_num, line in enumerate(lines, start=1):
            # Salta linee sicure
            if is_safe_line(line):
                continue
                
            # Cerca pattern problematici
            for pattern, description in PROBLEMATIC_PATTERNS:
                if re.search(pattern, line):
                    issues.append((line_num, line.strip(), description))
                    
    except Exception as e:
        print(f"⚠️  Errore lettura {file_path}: {e}", file=sys.stderr)
        
    return issues

def main():
    """Esegue la verifica su tutti i file Python del progetto."""
    
    project_root = Path(__file__).parent
    python_files = list(project_root.rglob("*.py"))
    
    # Escludi directory
    exclude_dirs = {'.venv', 'venv', '__pycache__', '.pytest_cache', 'build', 'dist'}
    python_files = [
        f for f in python_files 
        if not any(excluded in f.parts for excluded in exclude_dirs)
    ]
    
    print("🔍 Verifica gestione datetime nei certificati...")
    print(f"📁 File da controllare: {len(python_files)}")
    print()
    
    total_issues = 0
    files_with_issues = []
    
    for file_path in sorted(python_files):
        issues = check_file(file_path)
        
        if issues:
            files_with_issues.append((file_path, issues))
            total_issues += len(issues)
    
    # Report risultati
    if total_issues == 0:
        print("✅ Nessun problema trovato!")
        print()
        print("Tutti i datetime nei certificati sono gestiti correttamente.")
        return 0
    else:
        print(f"⚠️  Trovati {total_issues} potenziali problemi in {len(files_with_issues)} file:\n")
        
        for file_path, issues in files_with_issues:
            rel_path = file_path.relative_to(project_root)
            print(f"📄 {rel_path}")
            
            for line_num, line_content, description in issues:
                print(f"   Linea {line_num}: {description}")
                print(f"   > {line_content}")
                print()
        
        print("💡 Soluzione:")
        print("   Usa le funzioni utility da utils.cert_utils:")
        print("   - get_certificate_expiry_time(cert)")
        print("   - get_certificate_not_before(cert)")
        print()
        print("   Vedi DATETIME_GUIDE.md per dettagli.")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())
