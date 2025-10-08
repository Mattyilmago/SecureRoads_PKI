"""
Run All Tests - Esegue tutti i test del progetto SecureRoad PKI

Usage:
    python tests/run_all_tests.py              # Tutti i test
    python tests/run_all_tests.py -v           # Verbose
    python tests/run_all_tests.py -k etsi      # Solo test ETSI
    python tests/run_all_tests.py --failed     # Solo test falliti precedenti
"""

import sys
import pytest


def main():
    """Esegue tutti i test con pytest"""
    
    # Configurazione pytest
    args = [
        "tests/",           # Directory test
        "-v",               # Verbose
        "--tb=short",       # Traceback breve
        "--color=yes",      # Colori output
    ]
    
    # Aggiungi argomenti da command line (se presenti)
    if len(sys.argv) > 1:
        # Rimuovi -v di default se utente specifica altri args
        args = ["tests/", "--tb=short", "--color=yes"] + sys.argv[1:]
    
    print("=" * 80)
    print("  SecureRoad PKI - Test Suite")
    print("=" * 80)
    print(f"Eseguendo: pytest {' '.join(args)}")
    print("=" * 80)
    print()
    
    # Esegui pytest
    exit_code = pytest.main(args)
    
    print()
    print("=" * 80)
    if exit_code == 0:
        print("  ✅ TUTTI I TEST PASSATI!")
    else:
        print(f"  ❌ TEST FALLITI (exit code: {exit_code})")
    print("=" * 80)
    
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
