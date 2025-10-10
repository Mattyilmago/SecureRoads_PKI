"""
Analyze Raspberry Pi Test Results

Genera report, grafici e statistiche dai test eseguiti su Raspberry Pi.

Usage:
    python analyze_results.py
    python analyze_results.py --export-csv
    python analyze_results.py --compare Vehicle_001 Vehicle_002
"""

import argparse
import json
import statistics
from pathlib import Path
from typing import Dict, List
from datetime import datetime


RESULTS_DIR = Path("results")


def load_all_results() -> List[Dict]:
    """Load all test results from results directory"""
    all_results = []
    
    if not RESULTS_DIR.exists():
        print("❌ No results directory found")
        return all_results
    
    for json_file in RESULTS_DIR.glob("*.json"):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
                data['_filename'] = json_file.name
                all_results.append(data)
        except Exception as e:
            print(f"⚠️  Failed to load {json_file}: {e}")
    
    return all_results


def print_summary(results: List[Dict]):
    """Print summary of all tests"""
    print("\n" + "="*70)
    print("  TEST RESULTS SUMMARY")
    print("="*70 + "\n")
    
    # Group by test type
    by_test = {}
    for r in results:
        test_name = r.get('test', 'unknown')
        if test_name not in by_test:
            by_test[test_name] = []
        by_test[test_name].append(r)
    
    # Print summary for each test type
    for test_name, test_results in sorted(by_test.items()):
        print(f"\n--- {test_name.upper()} ({len(test_results)} runs) ---")
        
        # Success rate
        success_count = sum(1 for r in test_results if r.get('success', False))
        success_rate = success_count / len(test_results) * 100
        print(f"  Success Rate: {success_rate:.1f}% ({success_count}/{len(test_results)})")
        
        # Extract timing data
        if test_name == 'enrollment':
            times = [
                r.get('timings', {}).get('total_enrollment_ms', 0)
                for r in test_results
                if r.get('success', False)
            ]
            
            if times:
                print(f"  Timing Statistics:")
                print(f"    Average: {statistics.mean(times):.2f}ms")
                print(f"    Min:     {min(times):.2f}ms")
                print(f"    Max:     {max(times):.2f}ms")
                print(f"    Median:  {statistics.median(times):.2f}ms")
                if len(times) > 1:
                    print(f"    StdDev:  {statistics.stdev(times):.2f}ms")
                
                # Check target
                within_target = sum(1 for t in times if t < 1000)
                target_rate = within_target / len(times) * 100
                print(f"  Target (<1000ms): {target_rate:.1f}% ({within_target}/{len(times)})")
        
        elif test_name == 'authorization':
            times = [
                r.get('timings', {}).get('total_authorization_ms', 0)
                for r in test_results
                if r.get('success', False)
            ]
            
            if times:
                print(f"  Timing Statistics:")
                print(f"    Average: {statistics.mean(times):.2f}ms")
                print(f"    Min:     {min(times):.2f}ms")
                print(f"    Max:     {max(times):.2f}ms")
                print(f"    Median:  {statistics.median(times):.2f}ms")
                
                within_target = sum(1 for t in times if t < 1000)
                target_rate = within_target / len(times) * 100
                print(f"  Target (<1000ms): {target_rate:.1f}% ({within_target}/{len(times)})")
        
        elif test_name == 'fleet':
            # Aggregate statistics from all fleet tests
            all_avg_times = [
                r.get('statistics', {}).get('avg_time_ms', 0)
                for r in test_results
                if r.get('success', False)
            ]
            
            if all_avg_times:
                print(f"  Average Times Across Fleets:")
                print(f"    Mean:   {statistics.mean(all_avg_times):.2f}ms")
                print(f"    Min:    {min(all_avg_times):.2f}ms")
                print(f"    Max:    {max(all_avg_times):.2f}ms")


def print_detailed_report(results: List[Dict]):
    """Print detailed report for each test"""
    print("\n" + "="*70)
    print("  DETAILED TEST REPORTS")
    print("="*70)
    
    for r in results:
        print(f"\n{'─'*70}")
        print(f"Test: {r.get('test', 'unknown')}")
        print(f"File: {r.get('_filename', 'unknown')}")
        
        if 'metadata' in r:
            meta = r['metadata']
            print(f"Vehicle: {meta.get('vehicle_id', 'N/A')}")
            print(f"Timestamp: {meta.get('timestamp', 'N/A')}")
            print(f"PKI Server: {meta.get('pki_server', 'N/A')}")
            print(f"Raspberry Pi: {meta.get('raspberry_pi_model', 'N/A')}")
        
        print(f"Success: {'✅ Yes' if r.get('success', False) else '❌ No'}")
        
        # Print timings if available
        if 'timings' in r and r['timings']:
            print("\nTimings:")
            for key, value in r['timings'].items():
                print(f"  {key}: {value}")
        
        # Print statistics if available
        if 'statistics' in r and r['statistics']:
            print("\nStatistics:")
            for key, value in r['statistics'].items():
                print(f"  {key}: {value}")
        
        # Print system metrics if available
        if 'system_metrics_before' in r and r['system_metrics_before']:
            metrics_before = r['system_metrics_before']
            metrics_after = r.get('system_metrics_after', {})
            
            print("\nSystem Metrics:")
            print(f"  CPU:    {metrics_before.get('cpu_percent', 0):.1f}% -> "
                  f"{metrics_after.get('cpu_percent', 0):.1f}%")
            print(f"  Memory: {metrics_before.get('memory_used_mb', 0):.1f}MB -> "
                  f"{metrics_after.get('memory_used_mb', 0):.1f}MB")
            
            if metrics_before.get('cpu_temp_celsius'):
                print(f"  Temp:   {metrics_before['cpu_temp_celsius']:.1f}°C -> "
                      f"{metrics_after.get('cpu_temp_celsius', 0):.1f}°C")


def export_csv(results: List[Dict]):
    """Export results to CSV format"""
    csv_file = RESULTS_DIR / "summary.csv"
    
    print(f"\n📊 Exporting to {csv_file}...")
    
    with open(csv_file, 'w') as f:
        # Header
        f.write("test_name,vehicle_id,timestamp,success,total_time_ms,cpu_percent,memory_mb\n")
        
        # Data rows
        for r in results:
            test_name = r.get('test', 'unknown')
            vehicle_id = r.get('vehicle_id', 'N/A')
            timestamp = r.get('metadata', {}).get('timestamp', 'N/A')
            success = '1' if r.get('success', False) else '0'
            
            # Get timing based on test type
            total_time = 0
            if test_name == 'enrollment':
                total_time = r.get('timings', {}).get('total_enrollment_ms', 0)
            elif test_name == 'authorization':
                total_time = r.get('timings', {}).get('total_authorization_ms', 0)
            
            cpu = r.get('system_metrics_after', {}).get('cpu_percent', 0)
            memory = r.get('system_metrics_after', {}).get('memory_used_mb', 0)
            
            f.write(f"{test_name},{vehicle_id},{timestamp},{success},{total_time},{cpu},{memory}\n")
    
    print(f"✅ Exported {len(results)} results to {csv_file}")


def compare_vehicles(results: List[Dict], vehicle_ids: List[str]):
    """Compare performance between vehicles"""
    print("\n" + "="*70)
    print(f"  VEHICLE COMPARISON: {' vs '.join(vehicle_ids)}")
    print("="*70 + "\n")
    
    for vehicle_id in vehicle_ids:
        vehicle_results = [
            r for r in results 
            if r.get('vehicle_id') == vehicle_id or
               r.get('metadata', {}).get('vehicle_id') == vehicle_id
        ]
        
        print(f"\n--- {vehicle_id} ({len(vehicle_results)} tests) ---")
        
        if not vehicle_results:
            print("  No results found")
            continue
        
        # Enrollment times
        enrollment_times = [
            r.get('timings', {}).get('total_enrollment_ms', 0)
            for r in vehicle_results
            if r.get('test') == 'enrollment' and r.get('success')
        ]
        
        if enrollment_times:
            print(f"  Enrollment:")
            print(f"    Average: {statistics.mean(enrollment_times):.2f}ms")
            print(f"    Min:     {min(enrollment_times):.2f}ms")
            print(f"    Max:     {max(enrollment_times):.2f}ms")
        
        # Authorization times
        auth_times = [
            r.get('timings', {}).get('total_authorization_ms', 0)
            for r in vehicle_results
            if r.get('test') == 'authorization' and r.get('success')
        ]
        
        if auth_times:
            print(f"  Authorization:")
            print(f"    Average: {statistics.mean(auth_times):.2f}ms")
            print(f"    Min:     {min(auth_times):.2f}ms")
            print(f"    Max:     {max(auth_times):.2f}ms")
        
        # System resources
        cpu_samples = [
            r.get('system_metrics_after', {}).get('cpu_percent', 0)
            for r in vehicle_results
            if 'system_metrics_after' in r
        ]
        
        if cpu_samples:
            print(f"  CPU Usage:")
            print(f"    Average: {statistics.mean(cpu_samples):.1f}%")
            print(f"    Max:     {max(cpu_samples):.1f}%")


def generate_ascii_chart(data: List[float], title: str, max_width: int = 50):
    """Generate simple ASCII bar chart"""
    print(f"\n{title}")
    print("─" * max_width)
    
    if not data:
        print("No data")
        return
    
    max_val = max(data)
    
    for i, value in enumerate(data):
        bar_length = int((value / max_val) * max_width)
        bar = "█" * bar_length
        print(f"{i+1:2d} | {bar} {value:.2f}")


def main():
    parser = argparse.ArgumentParser(
        description='Analyze Raspberry Pi PKI test results'
    )
    
    parser.add_argument(
        '--export-csv',
        action='store_true',
        help='Export results to CSV'
    )
    
    parser.add_argument(
        '--compare',
        nargs='+',
        help='Compare performance between vehicles'
    )
    
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed report for each test'
    )
    
    parser.add_argument(
        '--charts',
        action='store_true',
        help='Generate ASCII charts'
    )
    
    args = parser.parse_args()
    
    # Load all results
    print("📂 Loading test results...")
    results = load_all_results()
    
    if not results:
        print("❌ No test results found in ./results/")
        return
    
    print(f"✅ Loaded {len(results)} test results\n")
    
    # Print summary
    print_summary(results)
    
    # Detailed report if requested
    if args.detailed:
        print_detailed_report(results)
    
    # Export CSV if requested
    if args.export_csv:
        export_csv(results)
    
    # Compare vehicles if requested
    if args.compare:
        compare_vehicles(results, args.compare)
    
    # Generate charts if requested
    if args.charts:
        # Enrollment times chart
        enrollment_times = [
            r.get('timings', {}).get('total_enrollment_ms', 0)
            for r in results
            if r.get('test') == 'enrollment' and r.get('success')
        ]
        
        if enrollment_times:
            generate_ascii_chart(
                enrollment_times[:20],  # Show max 20
                "Enrollment Times (ms)",
                max_width=60
            )
        
        # Authorization times chart
        auth_times = [
            r.get('timings', {}).get('total_authorization_ms', 0)
            for r in results
            if r.get('test') == 'authorization' and r.get('success')
        ]
        
        if auth_times:
            generate_ascii_chart(
                auth_times[:20],  # Show max 20
                "Authorization Times (ms)",
                max_width=60
            )
    
    print("\n" + "="*70)
    print("  ANALYSIS COMPLETE")
    print("="*70)


if __name__ == '__main__':
    main()
