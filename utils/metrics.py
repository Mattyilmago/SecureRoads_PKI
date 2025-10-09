"""
Metrics Collection System

Lightweight metrics system for monitoring API performance and usage.
Tracks requests, latency, errors, and entity-specific metrics.

Author: SecureRoad PKI Project
Date: October 2025
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, List, Optional


@dataclass
class MetricsSample:
    """Single metrics sample"""
    timestamp: datetime
    endpoint: str
    method: str
    status_code: int
    latency_ms: float
    entity_type: str
    entity_id: str
    error: Optional[str] = None


@dataclass
class MetricsStats:
    """Aggregated statistics"""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_latency_ms: float = 0.0
    min_latency_ms: float = float('inf')
    max_latency_ms: float = 0.0
    error_rate: float = 0.0
    requests_per_second: float = 0.0
    
    # Per status code
    status_codes: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    
    # Per endpoint
    endpoints: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


class MetricsCollector:
    """
    Collects and aggregates metrics for monitoring.
    
    Thread-safe metrics collection with in-memory storage and periodic aggregation.
    """
    
    def __init__(self, max_samples: int = 10000):
        """
        Initialize metrics collector
        
        Args:
            max_samples: Maximum number of samples to keep in memory
        """
        self.max_samples = max_samples
        self._samples: List[MetricsSample] = []
        self._lock = Lock()
        self._start_time = datetime.now(timezone.utc)
        
        # Real-time counters
        self._counters = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'enrollment_requests': 0,
            'authorization_requests': 0,
            'butterfly_requests': 0,
            'crl_downloads': 0,
            'ctl_downloads': 0,
        }
        
        # Latency tracking
        self._latencies: List[float] = []
        
    def record_request(
        self,
        endpoint: str,
        method: str,
        status_code: int,
        latency_ms: float,
        entity_type: str,
        entity_id: str,
        error: Optional[str] = None
    ):
        """
        Record a single API request
        
        Args:
            endpoint: Request endpoint (e.g., /api/enrollment/request)
            method: HTTP method (GET, POST, etc.)
            status_code: HTTP status code
            latency_ms: Request latency in milliseconds
            entity_type: Entity type (EA, AA, TLM, RootCA)
            entity_id: Entity identifier
            error: Error message if request failed
        """
        with self._lock:
            # Create sample
            sample = MetricsSample(
                timestamp=datetime.now(timezone.utc),
                endpoint=endpoint,
                method=method,
                status_code=status_code,
                latency_ms=latency_ms,
                entity_type=entity_type,
                entity_id=entity_id,
                error=error
            )
            
            # Add to samples (FIFO)
            self._samples.append(sample)
            if len(self._samples) > self.max_samples:
                self._samples.pop(0)
            
            # Update counters
            self._counters['total_requests'] += 1
            if 200 <= status_code < 300:
                self._counters['successful_requests'] += 1
            else:
                self._counters['failed_requests'] += 1
            
            # Track endpoint-specific counters
            if 'enrollment' in endpoint:
                self._counters['enrollment_requests'] += 1
            elif 'authorization' in endpoint:
                if 'butterfly' in endpoint:
                    self._counters['butterfly_requests'] += 1
                else:
                    self._counters['authorization_requests'] += 1
            elif 'crl' in endpoint:
                self._counters['crl_downloads'] += 1
            elif 'trust-list' in endpoint:
                self._counters['ctl_downloads'] += 1
            
            # Track latency
            self._latencies.append(latency_ms)
            if len(self._latencies) > 1000:  # Keep last 1000
                self._latencies.pop(0)
    
    def get_stats(self, last_n_minutes: Optional[int] = None) -> MetricsStats:
        """
        Get aggregated statistics
        
        Args:
            last_n_minutes: Only include samples from last N minutes (None = all)
        
        Returns:
            MetricsStats with aggregated data
        """
        with self._lock:
            samples = self._samples
            
            # Filter by time window if specified
            if last_n_minutes:
                cutoff = datetime.now(timezone.utc).timestamp() - (last_n_minutes * 60)
                samples = [s for s in samples if s.timestamp.timestamp() > cutoff]
            
            if not samples:
                return MetricsStats()
            
            # Calculate stats
            total = len(samples)
            successful = len([s for s in samples if 200 <= s.status_code < 300])
            failed = total - successful
            
            latencies = [s.latency_ms for s in samples]
            avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
            min_latency = min(latencies) if latencies else 0.0
            max_latency = max(latencies) if latencies else 0.0
            
            error_rate = (failed / total * 100) if total > 0 else 0.0
            
            # Calculate requests per second
            if len(samples) > 1:
                time_span = (samples[-1].timestamp - samples[0].timestamp).total_seconds()
                rps = total / time_span if time_span > 0 else 0.0
            else:
                rps = 0.0
            
            # Status code distribution
            status_codes = defaultdict(int)
            for sample in samples:
                status_codes[sample.status_code] += 1
            
            # Endpoint distribution
            endpoints = defaultdict(int)
            for sample in samples:
                endpoints[sample.endpoint] += 1
            
            return MetricsStats(
                total_requests=total,
                successful_requests=successful,
                failed_requests=failed,
                avg_latency_ms=avg_latency,
                min_latency_ms=min_latency,
                max_latency_ms=max_latency,
                error_rate=error_rate,
                requests_per_second=rps,
                status_codes=dict(status_codes),
                endpoints=dict(endpoints)
            )
    
    def get_counters(self) -> Dict[str, int]:
        """Get real-time counters"""
        with self._lock:
            return self._counters.copy()
    
    def get_uptime_seconds(self) -> float:
        """Get server uptime in seconds"""
        return (datetime.now(timezone.utc) - self._start_time).total_seconds()
    
    def get_recent_errors(self, limit: int = 10) -> List[MetricsSample]:
        """Get most recent errors"""
        with self._lock:
            errors = [s for s in self._samples if s.status_code >= 400]
            return list(reversed(errors[-limit:]))  # Most recent first
    
    def get_slowest_requests(self, limit: int = 10) -> List[MetricsSample]:
        """Get slowest requests"""
        with self._lock:
            sorted_samples = sorted(self._samples, key=lambda s: s.latency_ms, reverse=True)
            return sorted_samples[:limit]
    
    def reset(self):
        """Reset all metrics (useful for testing)"""
        with self._lock:
            self._samples.clear()
            self._latencies.clear()
            self._counters = {k: 0 for k in self._counters}
            self._start_time = datetime.now(timezone.utc)
    
    def export_prometheus_format(self) -> str:
        """
        Export metrics in Prometheus text format
        
        Returns:
            Prometheus-compatible metrics string
        """
        stats = self.get_stats()
        counters = self.get_counters()
        
        lines = []
        
        # Counter metrics
        lines.append('# HELP pki_requests_total Total number of requests')
        lines.append('# TYPE pki_requests_total counter')
        lines.append(f'pki_requests_total {counters["total_requests"]}')
        
        lines.append('# HELP pki_requests_successful Total number of successful requests')
        lines.append('# TYPE pki_requests_successful counter')
        lines.append(f'pki_requests_successful {counters["successful_requests"]}')
        
        lines.append('# HELP pki_requests_failed Total number of failed requests')
        lines.append('# TYPE pki_requests_failed counter')
        lines.append(f'pki_requests_failed {counters["failed_requests"]}')
        
        # Gauge metrics
        lines.append('# HELP pki_error_rate Current error rate percentage')
        lines.append('# TYPE pki_error_rate gauge')
        lines.append(f'pki_error_rate {stats.error_rate}')
        
        lines.append('# HELP pki_latency_avg_ms Average request latency in milliseconds')
        lines.append('# TYPE pki_latency_avg_ms gauge')
        lines.append(f'pki_latency_avg_ms {stats.avg_latency_ms}')
        
        lines.append('# HELP pki_latency_max_ms Maximum request latency in milliseconds')
        lines.append('# TYPE pki_latency_max_ms gauge')
        lines.append(f'pki_latency_max_ms {stats.max_latency_ms}')
        
        lines.append('# HELP pki_requests_per_second Current requests per second')
        lines.append('# TYPE pki_requests_per_second gauge')
        lines.append(f'pki_requests_per_second {stats.requests_per_second}')
        
        # Entity-specific counters
        lines.append('# HELP pki_enrollment_requests_total Total enrollment requests')
        lines.append('# TYPE pki_enrollment_requests_total counter')
        lines.append(f'pki_enrollment_requests_total {counters["enrollment_requests"]}')
        
        lines.append('# HELP pki_authorization_requests_total Total authorization requests')
        lines.append('# TYPE pki_authorization_requests_total counter')
        lines.append(f'pki_authorization_requests_total {counters["authorization_requests"]}')
        
        lines.append('# HELP pki_butterfly_requests_total Total butterfly requests')
        lines.append('# TYPE pki_butterfly_requests_total counter')
        lines.append(f'pki_butterfly_requests_total {counters["butterfly_requests"]}')
        
        return '\n'.join(lines) + '\n'


# Global metrics collector instance
_metrics_collector: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create global metrics collector"""
    global _metrics_collector
    if _metrics_collector is None:
        _metrics_collector = MetricsCollector()
    return _metrics_collector


def reset_metrics_collector():
    """Reset global metrics collector (for testing)"""
    global _metrics_collector
    if _metrics_collector:
        _metrics_collector.reset()
