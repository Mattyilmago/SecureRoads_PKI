"""
Monitoring Demo - Show how metrics collection works

This script demonstrates the monitoring system by:
1. Starting an EA server with monitoring enabled
2. Making several API requests
3. Displaying collected metrics

Usage:
    python examples/monitoring_demo.py
"""

import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.flask_app_factory import create_app
from entities.enrollment_authority import EnrollmentAuthority
from entities.root_ca import RootCA
from utils.metrics import get_metrics_collector
import requests
import threading


def start_server():
    """Start test server in background"""
    # Create entities
    root_ca = RootCA(base_dir="data/root_ca")
    ea = EnrollmentAuthority(root_ca=root_ca, ea_id="EA_Monitoring_Test")
    
    # Create Flask app
    app = create_app(
        entity_type="EA",
        entity_instance=ea,
        config={
            "api_keys": ["test-api-key-12345"],
            "environment": "development",
            "log_level": "INFO"
        }
    )
    
    # Run server
    app.run(host='127.0.0.1', port=5555, debug=False, use_reloader=False)


def make_test_requests():
    """Make several test requests to generate metrics"""
    base_url = "http://127.0.0.1:5555"
    headers = {
        "Authorization": "Bearer test-api-key-12345",
        "Content-Type": "application/json"
    }
    
    print("\n" + "="*70)
    print("Making test requests to generate metrics...")
    print("="*70 + "\n")
    
    # Give server time to start
    time.sleep(2)
    
    # 1. Health check (should succeed)
    print("1. Health check...")
    try:
        resp = requests.get(f"{base_url}/health", timeout=5)
        print(f"   Status: {resp.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    
    time.sleep(0.5)
    
    # 2. Root endpoint (should succeed)
    print("2. Root endpoint...")
    try:
        resp = requests.get(f"{base_url}/", timeout=5)
        print(f"   Status: {resp.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    
    time.sleep(0.5)
    
    # 3. Enrollment endpoint without auth (should fail 401)
    print("3. Enrollment without auth (should fail 401)...")
    try:
        resp = requests.post(
            f"{base_url}/api/enrollment/request/simple",
            json={"its_id": "test"},
            timeout=5
        )
        print(f"   Status: {resp.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    
    time.sleep(0.5)
    
    # 4. Enrollment endpoint with auth (should fail 400 - incomplete data)
    print("4. Enrollment with auth (should fail 400)...")
    try:
        resp = requests.post(
            f"{base_url}/api/enrollment/request/simple",
            headers=headers,
            json={"its_id": "test"},  # Missing required fields
            timeout=5
        )
        print(f"   Status: {resp.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    
    time.sleep(0.5)
    
    # 5. Non-existent endpoint (should fail 404)
    print("5. Non-existent endpoint (should fail 404)...")
    try:
        resp = requests.get(f"{base_url}/api/nonexistent", headers=headers, timeout=5)
        print(f"   Status: {resp.status_code}")
    except Exception as e:
        print(f"   Error: {e}")
    
    print("\n" + "="*70)
    print("Test requests completed!")
    print("="*70 + "\n")
    
    time.sleep(1)


def display_metrics():
    """Display collected metrics"""
    base_url = "http://127.0.0.1:5555"
    
    print("\n" + "="*70)
    print("MONITORING METRICS")
    print("="*70 + "\n")
    
    # 1. Get JSON metrics
    print("📊 Overall Metrics:")
    print("-" * 70)
    try:
        resp = requests.get(f"{base_url}/api/monitoring/metrics", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            
            overall = data['overall']
            print(f"  Total requests:      {overall['total_requests']}")
            print(f"  Successful:          {overall['successful_requests']}")
            print(f"  Failed:              {overall['failed_requests']}")
            print(f"  Error rate:          {overall['error_rate_percent']}%")
            print(f"  Avg latency:         {overall['avg_latency_ms']:.2f} ms")
            print(f"  Min latency:         {overall['min_latency_ms']:.2f} ms")
            print(f"  Max latency:         {overall['max_latency_ms']:.2f} ms")
            print(f"  Requests/sec:        {overall['requests_per_second']:.2f}")
            print()
            
            print("  Status codes:")
            for code, count in sorted(data['status_codes'].items()):
                print(f"    {code}: {count}")
            print()
            
            print("  Endpoints hit:")
            for endpoint, count in sorted(data['endpoints'].items(), key=lambda x: x[1], reverse=True):
                print(f"    {endpoint}: {count}")
            print()
            
            print("  Counters:")
            for name, value in data['counters'].items():
                if value > 0:
                    print(f"    {name}: {value}")
        else:
            print(f"  Failed to get metrics: {resp.status_code}")
    except Exception as e:
        print(f"  Error: {e}")
    
    print()
    
    # 2. Get recent errors
    print("❌ Recent Errors:")
    print("-" * 70)
    try:
        resp = requests.get(f"{base_url}/api/monitoring/metrics/errors", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            errors = data['errors']
            
            if errors:
                for i, error in enumerate(errors[:5], 1):  # Show only first 5
                    print(f"  {i}. {error['method']} {error['endpoint']}")
                    print(f"     Status: {error['status_code']} | Latency: {error['latency_ms']:.2f}ms")
                    if error['error']:
                        print(f"     Error: {error['error']}")
                    print()
            else:
                print("  No errors recorded")
        else:
            print(f"  Failed to get errors: {resp.status_code}")
    except Exception as e:
        print(f"  Error: {e}")
    
    print()
    
    # 3. Get slowest requests
    print("🐌 Slowest Requests:")
    print("-" * 70)
    try:
        resp = requests.get(f"{base_url}/api/monitoring/metrics/slowest", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            slowest = data['slowest_requests']
            
            if slowest:
                for i, req in enumerate(slowest[:5], 1):  # Show only first 5
                    print(f"  {i}. {req['method']} {req['endpoint']}")
                    print(f"     Latency: {req['latency_ms']:.2f}ms | Status: {req['status_code']}")
                    print()
            else:
                print("  No requests recorded")
        else:
            print(f"  Failed to get slowest requests: {resp.status_code}")
    except Exception as e:
        print(f"  Error: {e}")
    
    print()
    
    # 4. Health check
    print("🏥 Health Check:")
    print("-" * 70)
    try:
        resp = requests.get(f"{base_url}/api/monitoring/health", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            
            print(f"  Status:              {data['status']}")
            print(f"  Uptime:              {data['uptime_seconds']:.1f} seconds")
            print()
            
            entity = data['entity']
            print(f"  Entity type:         {entity['type']}")
            print(f"  Entity ID:           {entity['id']}")
            print(f"  Operational:         {entity['operational']}")
            print()
            
            system = data['system']
            print(f"  CPU usage:           {system['cpu_percent']}%")
            print(f"  Memory usage:        {system['memory_percent']:.1f}%")
            print(f"  Memory available:    {system['memory_available_mb']:.0f} MB")
            print(f"  Disk usage:          {system['disk_percent']:.1f}%")
            print(f"  Disk free:           {system['disk_free_gb']:.1f} GB")
            print()
            
            perf = data['performance']
            print(f"  Performance (last 5min):")
            print(f"    Requests:          {perf['requests_total']}")
            print(f"    Error rate:        {perf['error_rate_percent']}%")
            print(f"    Avg latency:       {perf['avg_latency_ms']:.2f}ms")
            print(f"    Req/sec:           {perf['requests_per_second']:.2f}")
            
            if data.get('issues'):
                print()
                print("  ⚠️ Issues:")
                for issue in data['issues']:
                    print(f"    - {issue}")
        else:
            print(f"  Health check failed: {resp.status_code}")
    except Exception as e:
        print(f"  Error: {e}")
    
    print()
    print("="*70)
    print("Monitoring demo completed!")
    print("="*70 + "\n")


def main():
    """Main entry point"""
    print("\n" + "="*70)
    print("  SecureRoad PKI - Monitoring System Demo")
    print("  ETSI TS 102941 Compliant")
    print("="*70)
    
    # Start server in background thread
    print("\nStarting EA server...")
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Wait for server to be ready
    time.sleep(3)
    
    # Make test requests
    make_test_requests()
    
    # Display metrics
    display_metrics()
    
    print("\n💡 Tip: You can also access metrics at:")
    print("   http://127.0.0.1:5555/api/monitoring/metrics")
    print("   http://127.0.0.1:5555/api/monitoring/health")
    print("   http://127.0.0.1:5555/api/monitoring/metrics/prometheus")
    print()


if __name__ == "__main__":
    main()
