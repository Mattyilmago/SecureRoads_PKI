"""
Run All Tests - Esegue tutti i test del progetto SecureRoad PKI

Usage:
    python tests/run_all_tests.py                    # Scelta interattiva modalità
    python tests/run_all_tests.py --use-data-dirs    # Usa directory data/ persistenti
    python tests/run_all_tests.py --use-tmp-dirs     # Usa temporary directories
    python tests/run_all_tests.py -v                 # Verbose
    python tests/run_all_tests.py -k etsi            # Solo test ETSI
    python tests/run_all_tests.py --failed           # Solo test falliti precedenti
    
Opzioni modalità test:
    --use-data-dirs    : Usa directory data/ persistenti (non elimina dati dopo test)
    --use-tmp-dirs     : Usa temporary directories isolate (elimina automaticamente)
    (nessun flag)      : Chiede interattivamente quale modalità usare
"""

import sys
import os
import pytest
import argparse

# Aggiungi la directory root del progetto al sys.path per gli import
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


def ask_test_mode():
    """Chiede all'utente quale modalità di test usare"""
    print("=" * 80)
    print("  SecureRoad PKI - Test Suite")
    print("=" * 80)
    print()
    print("Scegli la modalità di esecuzione dei test:")
    print()
    print("  1) [TMP]  Temporary Directories (raccomandato)")
    print("            - Directory temporanee isolate")
    print("            - Dati eliminati automaticamente dopo i test")
    print("            - Ideale per sviluppo e CI/CD")
    print()
    print("  2) [DATA] Data Directories Persistenti")
    print("            - Usa directory data/ del progetto")
    print("            - Dati NON eliminati dopo i test")
    print("            - Utile per debug e ispezione manuale")
    print()
    
    while True:
        choice = input("Scelta [1/2] (default=1): ").strip()
        
        if choice == '' or choice == '1':
            return False  # Temporary directories
        elif choice == '2':
            return True   # Data directories
        else:
            print("[!] Scelta non valida. Inserisci 1 o 2.")


def main():
    """Esegue tutti i test con pytest"""
    
    # Parse argomenti
    parser = argparse.ArgumentParser(
        description='Esegue la test suite di SecureRoad PKI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Esempi:
  python tests/run_all_tests.py                   # Scelta interattiva
  python tests/run_all_tests.py --use-data-dirs   # Test con data/ persistenti
  python tests/run_all_tests.py --use-tmp-dirs    # Test con tmp directories
  python tests/run_all_tests.py -v -k butterfly   # Test butterfly verbose
        """
    )
    
    parser.add_argument(
        '--use-data-dirs',
        action='store_true',
        help='Usa directory data/ persistenti invece di temporary directories'
    )
    
    parser.add_argument(
        '--use-tmp-dirs',
        action='store_true',
        help='Usa temporary directories isolate (default se non specificato)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Output verbose'
    )
    
    parser.add_argument(
        '-k',
        metavar='EXPRESSION',
        help='Esegui solo test che matchano l\'espressione (es: -k "etsi or butterfly")'
    )
    
    parser.add_argument(
        '--failed',
        action='store_true',
        help='Esegui solo i test falliti nell\'ultima esecuzione'
    )
    
    parser.add_argument(
        '--markers',
        action='store_true',
        help='Mostra i markers disponibili e esci'
    )
    
    args, unknown_args = parser.parse_known_args()
    
    # Configurazione pytest base
    pytest_args = [
        "tests/",           # Directory test
        "--tb=short",       # Traceback breve
        "--color=yes",      # Colori output
    ]
    
    # Aggiungi verbose se richiesto
    if args.verbose:
        pytest_args.append("-v")
    else:
        pytest_args.append("-v")  # Default verbose
    
    # Aggiungi filtro test se specificato
    if args.k:
        pytest_args.extend(["-k", args.k])
    
    # Aggiungi flag per failed
    if args.failed:
        pytest_args.append("--lf")  # last-failed
    
    # Aggiungi markers se richiesto
    if args.markers:
        pytest_args = ["--markers"]
    
    # Determina modalità test: interattiva o da flag
    use_data_dirs = False
    
    if args.use_data_dirs and args.use_tmp_dirs:
        print("[!] Errore: non puoi specificare sia --use-data-dirs che --use-tmp-dirs")
        sys.exit(1)
    elif args.use_data_dirs:
        use_data_dirs = True
    elif args.use_tmp_dirs:
        use_data_dirs = False
    else:
        # Nessun flag specificato: chiedi interattivamente
        use_data_dirs = ask_test_mode()
    
    # Modalità: Temporary directories o Data directories persistenti
    if use_data_dirs:
        # Modalità DATA: usa directory data/ persistenti
        os.environ['PKI_USE_DATA_DIRS'] = '1'
        print()
        print("=" * 80)
        print("  SecureRoad PKI - Test Suite")
        print("  [DATA MODE] DATA DIRECTORIES PERSISTENTI")
        print("=" * 80)
        print("[!] I test useranno le directory data/ esistenti")
        print("[!] I dati NON verranno eliminati dopo i test")
        print("=" * 80)
    else:
        # Modalità TMP: temporary directories
        print()
        print("=" * 80)
        print("  SecureRoad PKI - Test Suite")
        print("  [TMP MODE] TEMPORARY DIRECTORIES (isolate)")
        print("=" * 80)
        print("[OK] I test useranno directory temporanee")
        print("[OK] I dati verranno eliminati automaticamente dopo i test")
        print("=" * 80)
    
    # Aggiungi argomenti sconosciuti (passthrough a pytest)
    pytest_args.extend(unknown_args)
    
    print(f"Eseguendo: pytest {' '.join(pytest_args)}")
    print("=" * 80)
    print()
    
    # Esegui pytest
    exit_code = pytest.main(pytest_args)
    
    print()
    print("=" * 80)
    if exit_code == 0:
        print("  [OK] TUTTI I TEST PASSATI!")
    else:
        print(f"  [FAIL] TEST FALLITI (exit code: {exit_code})")
    print("=" * 80)
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
