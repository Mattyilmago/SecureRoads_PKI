"""
Script per eseguire tutti i test e generare un report

Usage:
    python run_all_tests.py
    python run_all_tests.py --coverage
    python run_all_tests.py --verbose
"""

import subprocess
import sys
from pathlib import Path


def run_tests(with_coverage=False, verbose=False):
    """Esegue tutti i test con opzioni configurabili"""
    
    # Trova il python del venv
    venv_python = Path(".venv/Scripts/python.exe")
    if not venv_python.exists():
        print("❌ Virtual environment non trovato!")
        print(f"   Cercato in: {venv_python.absolute()}")
        return False
    
    # Base command
    cmd = [str(venv_python), "-m", "pytest", "tests/"]
    
    # Opzioni
    if verbose:
        cmd.append("-v")
    
    if with_coverage:
        cmd.extend([
            "--cov=entities",
            "--cov=managers", 
            "--cov=protocols",
            "--cov-report=term-missing",
            "--cov-report=html",
        ])
    
    cmd.append("--tb=short")
    
    print("="* 80)
    print("🧪 SecureRoad PKI - Test Suite")
    print("="* 80)
    print(f"Comando: {' '.join(cmd)}")
    print("="* 80)
    print()
    
    # Esegui
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        print()
        print("="* 80)
        print("✅ TUTTI I TEST SONO PASSATI!")
        print("="* 80)
        if with_coverage:
            print("\n📊 Coverage report generato in: htmlcov/index.html")
            print("   Apri con: start htmlcov/index.html")
    else:
        print()
        print("="* 80)
        print("❌ ALCUNI TEST SONO FALLITI")
        print("="* 80)
    
    return result.returncode == 0


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Esegui tutti i test del progetto")
    parser.add_argument("--coverage", "-c", action="store_true", 
                       help="Genera coverage report")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Output verbose")
    
    args = parser.parse_args()
    
    success = run_tests(
        with_coverage=args.coverage,
        verbose=args.verbose
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
