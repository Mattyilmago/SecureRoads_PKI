"""
Quick script to run all tests automatically
"""
import sys
import time
from pathlib import Path

# Add parent directory to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import functions and class
from interactive_pki_tester import PKITester, start_pki_entities

def main():
    print("=" * 70)
    print("  ESECUZIONE AUTOMATICA DI TUTTI I TEST")
    print("=" * 70)
    
    # Start entities
    print("\n🚀 Avvio entities PKI...")
    if not start_pki_entities():
        print("❌ Errore avvio entities!")
        return 1
    
    print("✅ Entities avviate!")
    print("⏳ Attesa 5 secondi prima di iniziare i test...")
    time.sleep(5)
    
    # Create tester instance
    tester = PKITester()
    
    try:
        # Run all tests in sequence
        tests = [
            ("Test 1: Enrollment singolo", tester.test_1_vehicle_enrollment),
            ("Test 2: Authorization Ticket", tester.test_2_authorization_ticket),
            ("Test 3: Enrollment flotta", tester.test_3_multiple_vehicles),
            ("Test 4: Comunicazione V2V", tester.test_4_v2v_communication),
            ("Test 5: Validazione certificati", tester.test_5_certificate_validation),
            ("Test 6: Performance test", tester.test_6_performance_test),
            ("Test 7: Butterfly Expansion", tester.test_7_butterfly_expansion),
            ("Test 8: Revoca certificato", tester.test_8_certificate_revocation),
            ("Test 9: Download CRL", tester.test_9_crl_download),
        ]
        
        results = {}
        for test_name, test_func in tests:
            print(f"\n{'=' * 70}")
            print(f"  🚀 Esecuzione: {test_name}")
            print(f"{'=' * 70}")
            try:
                success = test_func()
                results[test_name] = "✅ SUCCESS" if success else "❌ FAILED"
            except Exception as e:
                results[test_name] = f"❌ ERROR: {str(e)[:50]}"
                import traceback
                traceback.print_exc()
            
            # Small delay between tests
            time.sleep(1)
        
        # Print summary
        print("\n" + "=" * 70)
        print("  📊 RIEPILOGO RISULTATI")
        print("=" * 70)
        for test_name, result in results.items():
            print(f"  {result:20} {test_name}")
        
        # Show test results
        print("\n")
        tester.show_results()
        
        return 0
        
    finally:
        # Cleanup
        print("\n🧹 Cleanup...")
        tester.cleanup()

if __name__ == "__main__":
    sys.exit(main())
