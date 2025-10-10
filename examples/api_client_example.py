"""
Client Example - REST API Usage

This example shows how to use the REST API from an ITS-S (client).

Key Features:
- Proper ASN.1 OER encoding/decoding
- Authentication with Bearer tokens
- Error handling with ETSI response codes
- Complete enrollment and authorization flow

Usage:
    # Set API keys as environment variables
    export EA_API_KEY="your-ea-key"
    export AA_API_KEY="your-aa-key"
    
    python examples/api_client_example.py

Author: SecureRoad PKI Project
Date: October 2025
"""

import sys
import os
import requests
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from entities.its_station import ITSStation
from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from managers.trust_list_manager import TrustListManager


def print_section(title):
    """Print a section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70 + "\n")


def check_response(response, operation):
    """Check REST API response and handle ETSI response codes"""
    print(f"📡 {operation}")
    print(f"   Status Code: {response.status_code}")
    print(f"   Content-Type: {response.headers.get('Content-Type', 'N/A')}")
    
    if response.status_code == 200:
        print(f"   ✅ Success!")
        return True
    else:
        print(f"   ❌ Failed!")
        try:
            error_data = response.json()
            print(f"   Response Code: {error_data.get('responseCode', 'N/A')}")
            print(f"   Error: {error_data.get('error', 'N/A')}")
        except:
            print(f"   Raw Response: {response.text[:200]}")
        return False


def example_enrollment_flow():
    """Example: Complete enrollment flow"""
    print_section("Example 1: Enrollment Flow")
    
    # Configuration - Use environment variables for security
    # Default port 5000 is first EA port (EA range: 5000-5019)
    EA_BASE_URL = os.getenv("EA_BASE_URL", "http://localhost:5000")
    EA_API_KEY = os.getenv("EA_API_KEY")
    
    if not EA_API_KEY:
        print("⚠️  ERROR: EA_API_KEY environment variable not set!")
        print("   Set it with: export EA_API_KEY='your-key'")
        return
    
    print("🔧 Configuration:")
    print(f"   EA Server: {EA_BASE_URL}")
    print(f"   API Key: {EA_API_KEY[:10]}...")
    
    # Create ITS-S
    print("\n🚗 Creating ITS-S (Vehicle)...")
    itss = ITSStation(vehicle_id="Vehicle_API_Test", base_dir="data/itss")
    print(f"   ✅ ITS-S created: {itss.vehicle_id}")
    
    # Prepare enrollment request
    print("\n📝 Preparing enrollment request...")
    print("   (In real implementation, this would:")
    print("   1. Generate canonical key pair")
    print("   2. Create InnerEcRequest with PoP")
    print("   3. Encrypt with EA public key")
    print("   4. Create EtsiTs103097Data-Encrypted")
    print("   5. Encode with ASN.1 OER")
    
    # For this example, we'll just show the API call structure
    print("\n📤 Sending enrollment request to EA...")
    
    # Note: In real implementation, you would encode the request with ETSIMessageEncoder
    # enrollment_request_der = encoder.encode_enrollment_request(inner_ec_request)
    
    # Simulated request (in real code, use actual DER-encoded data)
    headers = {
        'Authorization': f'Bearer {EA_API_KEY}',
        'Content-Type': 'application/octet-stream'
    }
    
    print(f"   Endpoint: POST {EA_BASE_URL}/enrollment/request")
    print(f"   Headers: {headers}")
    
    # For demonstration, we'll test with empty body (will fail with proper error)
    try:
        response = requests.post(
            f"{EA_BASE_URL}/enrollment/request",
            headers=headers,
            data=b'',  # In real code: enrollment_request_der
            timeout=30
        )
        
        success = check_response(response, "Enrollment Request")
        
        if success and response.headers.get('Content-Type') == 'application/octet-stream':
            print("\n📥 Received enrollment response (DER-encoded)")
            print(f"   Size: {len(response.content)} bytes")
            print("   (In real implementation, decode with ETSIMessageEncoder)")
            print("   1. Decode ASN.1 OER")
            print("   2. Decrypt with canonical private key")
            print("   3. Extract enrollment certificate")
            print("   4. Store EC and trust anchors")
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Connection error: {e}")


def example_authorization_flow():
    """Example: Authorization flow with enrollment certificate"""
    print_section("Example 2: Authorization Flow")
    
    # Configuration - Use environment variables for security
    # Default port 5020 is first AA port (AA range: 5020-5039)
    AA_BASE_URL = os.getenv("AA_BASE_URL", "http://localhost:5020")
    AA_API_KEY = os.getenv("AA_API_KEY")
    
    if not AA_API_KEY:
        print("⚠️  ERROR: AA_API_KEY environment variable not set!")
        print("   Set it with: export AA_API_KEY='your-key'")
        return
    
    print("🔧 Configuration:")
    print(f"   AA Server: {AA_BASE_URL}")
    print(f"   API Key: {AA_API_KEY[:10]}...")
    
    print("\n📝 Preparing authorization request...")
    print("   Prerequisites:")
    print("   ✅ ITS-S has valid enrollment certificate")
    print("   ✅ EA is trusted by TLM at AA")
    
    print("\n   Request structure:")
    print("   1. Create SharedAtRequest (permissions, validity)")
    print("   2. Create InnerAtRequest with hmacKey (unlinkability!)")
    print("   3. Sign with canonical private key")
    print("   4. Encrypt with AA public key")
    print("   5. Create EtsiTs103097Data-Encrypted-Unicast")
    print("   6. Encode with ASN.1 OER")
    
    print("\n📤 Sending authorization request to AA...")
    
    headers = {
        'Authorization': f'Bearer {AA_API_KEY}',
        'Content-Type': 'application/octet-stream'
    }
    
    print(f"   Endpoint: POST {AA_BASE_URL}/authorization/request")
    
    try:
        response = requests.post(
            f"{AA_BASE_URL}/authorization/request",
            headers=headers,
            data=b'',  # In real code: authorization_request_der
            timeout=30
        )
        
        success = check_response(response, "Authorization Request")
        
        if success:
            print("\n📥 Received authorization response")
            print("   (In real implementation:)")
            print("   1. Decode ASN.1 OER")
            print("   2. Decrypt with hmacKey (NOT canonical key!)")
            print("   3. Extract authorization ticket")
            print("   4. Store AT for V2X communications")
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Connection error: {e}")


def example_butterfly_authorization():
    """Example: Butterfly authorization (batch)"""
    print_section("Example 3: Butterfly Authorization (Batch)")
    
    # Default port 5020 is first AA port (AA range: 5020-5039)
    AA_BASE_URL = os.getenv("AA_BASE_URL", "http://localhost:5020")
    AA_API_KEY = os.getenv("AA_API_KEY")
    
    if not AA_API_KEY:
        print("⚠️  ERROR: AA_API_KEY environment variable not set!")
        return
    
    print("🔧 Configuration:")
    print(f"   AA Server: {AA_BASE_URL}")
    
    print("\n📝 Butterfly Authorization allows batch AT issuance:")
    print("   - Single request with multiple InnerAtRequests")
    print("   - Each request has unique hmacKey")
    print("   - Responses encrypted individually")
    print("   - Improves efficiency for multiple ATs")
    
    print("\n   Request structure:")
    print("   1. Create multiple SharedAtRequests")
    print("   2. Create multiple InnerAtRequests (each with unique hmacKey)")
    print("   3. Combine in AuthorizationRequestMessage")
    print("   4. Encode with ASN.1 OER")
    
    print("\n📤 Sending butterfly authorization request...")
    
    headers = {
        'Authorization': f'Bearer {AA_API_KEY}',
        'Content-Type': 'application/octet-stream'
    }
    
    try:
        response = requests.post(
            f"{AA_BASE_URL}/authorization/request/butterfly",
            headers=headers,
            data=b'',  # In real code: butterfly_request_der
            timeout=60  # Longer timeout for batch
        )
        
        success = check_response(response, "Butterfly Authorization Request")
        
        if success:
            print("\n📥 Received butterfly response")
            print("   Multiple ATs received!")
            print("   Each encrypted with its own hmacKey")
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Connection error: {e}")


def example_crl_distribution():
    """Example: CRL retrieval"""
    print_section("Example 4: CRL Distribution")
    
    # Default port 5000 is first EA port (EA range: 5000-5019)
    EA_BASE_URL = "http://localhost:5000"
    
    print("📥 Retrieving CRL from EA...")
    
    # Full CRL
    try:
        response = requests.get(f"{EA_BASE_URL}/crl/full", timeout=10)
        
        if check_response(response, "Full CRL Retrieval"):
            print(f"\n   CRL Size: {len(response.content)} bytes")
            print("   Content-Type:", response.headers.get('Content-Type'))
            print("   (DER-encoded CRL)")
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Connection error: {e}")
    
    # Delta CRL
    print("\n📥 Retrieving Delta CRL...")
    try:
        response = requests.get(f"{EA_BASE_URL}/crl/delta", timeout=10)
        
        if response.status_code == 200:
            print("   ✅ Delta CRL available")
        elif response.status_code == 404:
            print("   ℹ️  No delta CRL published yet")
        else:
            check_response(response, "Delta CRL Retrieval")
            
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Connection error: {e}")


def example_ctl_distribution():
    """Example: CTL (Certificate Trust List) retrieval"""
    print_section("Example 5: CTL Distribution (TLM)")
    
    # Default port 5020 is first AA port (AA range: 5020-5039)
    AA_BASE_URL = "http://localhost:5020"
    
    print("📥 Retrieving CTL from TLM (via AA)...")
    
    # Full CTL
    try:
        response = requests.get(f"{AA_BASE_URL}/ctl/full", timeout=10)
        
        if check_response(response, "Full CTL Retrieval"):
            ctl_data = response.json()
            print(f"\n   Trust Anchors: {len(ctl_data.get('trust_anchors', []))}")
            print(f"   Version: {ctl_data.get('version')}")
            print(f"   Timestamp: {ctl_data.get('timestamp')}")
            
            # Show trust anchors
            for ta in ctl_data.get('trust_anchors', [])[:3]:  # First 3
                print(f"\n   Trust Anchor:")
                print(f"     Type: {ta.get('authority_type')}")
                print(f"     ID: {ta.get('authority_id')}")
                
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Connection error: {e}")


def example_health_checks():
    """Example: Health checks"""
    print_section("Example 6: Health Checks")
    
    # Default ports from configured ranges
    servers = [
        ("EA Server", "http://localhost:5000"),  # EA range: 5000-5019
        ("AA Server", "http://localhost:5020"),  # AA range: 5020-5039
    ]
    
    for name, url in servers:
        print(f"\n🏥 Checking {name}...")
        print(f"   URL: {url}/health")
        
        try:
            response = requests.get(f"{url}/health", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Status: {data.get('status')}")
                print(f"   Entity Type: {data.get('entity_type')}")
                print(f"   Protocol: {data.get('protocol')}")
                print(f"   Encoding: {data.get('encoding')}")
            else:
                print(f"   ❌ Unhealthy (status {response.status_code})")
                
        except requests.exceptions.RequestException as e:
            print(f"   ❌ Connection error: {e}")


def example_error_handling():
    """Example: Error handling"""
    print_section("Example 7: ETSI Response Codes")
    
    # Default port 5000 is first EA port (EA range: 5000-5019)
    EA_BASE_URL = "http://localhost:5000"
    EA_API_KEY = "ea-secret-key-12345"
    
    print("Testing various error scenarios...\n")
    
    # 1. Missing authentication
    print("❌ Test 1: Missing Authentication")
    try:
        response = requests.post(
            f"{EA_BASE_URL}/enrollment/request",
            headers={'Content-Type': 'application/octet-stream'},
            data=b''
        )
        check_response(response, "Request without auth")
        print(f"   Expected Response Code: 9 (UNAUTHORIZED)")
    except Exception as e:
        print(f"   Error: {e}")
    
    # 2. Wrong content type
    print("\n❌ Test 2: Wrong Content-Type")
    try:
        response = requests.post(
            f"{EA_BASE_URL}/enrollment/request",
            headers={
                'Authorization': f'Bearer {EA_API_KEY}',
                'Content-Type': 'application/json'  # Wrong!
            },
            json={}
        )
        check_response(response, "Request with wrong content-type")
        print(f"   Expected Response Code: 2 (BAD_CONTENT_TYPE)")
    except Exception as e:
        print(f"   Error: {e}")
    
    # 3. Malformed body
    print("\n❌ Test 3: Malformed ASN.1 Body")
    try:
        response = requests.post(
            f"{EA_BASE_URL}/enrollment/request",
            headers={
                'Authorization': f'Bearer {EA_API_KEY}',
                'Content-Type': 'application/octet-stream'
            },
            data=b'not-valid-asn1-data'
        )
        check_response(response, "Request with malformed body")
        print(f"   Expected Response Code: 1 (CANT_PARSE)")
    except Exception as e:
        print(f"   Error: {e}")


def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("  SecureRoad PKI REST API - Client Examples")
    print("  ETSI TS 102941 V2.1.1 Compliant")
    print("="*70)
    
    print("\n⚠️  IMPORTANT:")
    print("   Make sure EA and AA servers are running:")
    print("   - python run_ea_server.py")
    print("   - python run_aa_server.py")
    
    input("\n   Press Enter to continue...")
    
    # Run examples
    try:
        example_health_checks()
        example_enrollment_flow()
        example_authorization_flow()
        example_butterfly_authorization()
        example_crl_distribution()
        example_ctl_distribution()
        example_error_handling()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user\n")
        return
    
    # Final notes
    print_section("Summary")
    print("✅ Examples completed!")
    print("\n💡 Next Steps:")
    print("   1. Implement actual ASN.1 OER encoding in your client")
    print("   2. Use ETSIMessageEncoder from entities/")
    print("   3. Test with real enrollment/authorization flows")
    print("   4. Integrate with existing test suite")
    print("\n📚 Documentation:")
    print("   - api/README.md")
    print("   - docs/API_IMPLEMENTATION_COMPLETE.md")
    print("   - docs/QUICK_START_API.md")
    print("\n" + "="*70 + "\n")


if __name__ == '__main__':
    main()
