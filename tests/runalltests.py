"""
Comprehensive test runner for all PKI tests
Discovers and runs all tests in the tests directory using pytest
"""
import sys
import subprocess
from pathlib import Path
import argparse


# Add parent directory to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def run_tests_with_pytest(test_path=None, pattern=None, verbosity=2, failfast=False, category=None):
    """
    Run tests using pytest
    
    Args:
        test_path: Path to search for tests (default: tests directory)
        pattern: File pattern to match test files (default: None, pytest finds all)
        verbosity: Verbosity level (0, 1, or 2)
        failfast: Stop on first failure
        category: Test category to run
        
    Returns:
        Exit code from pytest
    """
    if test_path is None:
        test_path = Path(__file__).parent
    else:
        test_path = Path(test_path)
    
    if category:
        test_path = test_path / category
        
    print("=" * 70)
    print("  PKI TEST SUITE RUNNER (pytest)")
    print("=" * 70)
    print(f"\n📁 Test Directory: {test_path}")
    if pattern:
        print(f"🔍 Pattern: {pattern}")
    print(f"📊 Verbosity: {verbosity}")
    print(f"⚡ Fail Fast: {failfast}")
    print("\n" + "=" * 70)
    
    # Build pytest command
    pytest_args = [sys.executable, "-m", "pytest", str(test_path)]
    
    # Add verbosity
    if verbosity == 0:
        pytest_args.append("-q")
    elif verbosity == 2:
        pytest_args.append("-v")
    # verbosity 1 is pytest default
    
    # Add failfast
    if failfast:
        pytest_args.append("-x")
    
    # Add pattern if specified
    if pattern:
        pytest_args.extend(["-k", pattern])
    
    # Add color support
    pytest_args.append("--color=yes")
    
    # Show test summary
    pytest_args.append("-ra")
    
    # Run pytest
    try:
        result = subprocess.run(pytest_args, cwd=str(project_root))
        return result.returncode
    except Exception as e:
        print(f"❌ Error running pytest: {e}")
        return 1


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Run all PKI tests using pytest',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python runalltests.py                    # Run all tests
  python runalltests.py -v 1               # Run with minimal verbosity
  python runalltests.py -f                 # Stop on first failure
  python runalltests.py -c unit            # Run only unit tests
  python runalltests.py -c integration     # Run only integration tests
  python runalltests.py -p "butterfly"     # Run tests matching pattern
        """
    )
    
    parser.add_argument(
        '-v', '--verbosity',
        type=int,
        choices=[0, 1, 2],
        default=2,
        help='Verbosity level (0=quiet, 1=normal, 2=verbose)'
    )
    
    parser.add_argument(
        '-f', '--failfast',
        action='store_true',
        help='Stop on first failure'
    )
    
    parser.add_argument(
        '-c', '--category',
        type=str,
        choices=['unit', 'integration', 'api', 'security', 'performance', 'etsi_compliance', 'protocols'],
        help='Run tests from specific category only'
    )
    
    parser.add_argument(
        '-p', '--pattern',
        type=str,
        help='Pattern to match test names (uses pytest -k)'
    )
    
    parser.add_argument(
        '-d', '--directory',
        type=str,
        help='Custom directory to search for tests'
    )
    
    args = parser.parse_args()
    
    # Run tests with pytest
    exit_code = run_tests_with_pytest(
        test_path=args.directory,
        pattern=args.pattern,
        verbosity=args.verbosity,
        failfast=args.failfast,
        category=args.category
    )
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
