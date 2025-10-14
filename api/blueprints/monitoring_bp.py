"""
Monitoring Blueprint

Endpoints for metrics, health checks, and system status.

Questo blueprint fornisce metriche ETSI TS 102 941 compliant per il monitoraggio
del sistema PKI, utilizzando il CRLManager per la gestione delle revoche
(Full CRL + Delta CRL).

Author: SecureRoad PKI Project
Date: October 2025
"""

import psutil
from datetime import datetime, timezone
from flask import Blueprint, current_app, jsonify
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from utils.metrics import get_metrics_collector


# Create blueprint
monitoring_bp = Blueprint('monitoring', __name__)


@monitoring_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """
    Get current metrics in JSON format
    
    Returns:
        JSON with comprehensive metrics data
    """
    metrics = get_metrics_collector()
    stats_all = metrics.get_stats()
    stats_5min = metrics.get_stats(last_n_minutes=5)
    counters = metrics.get_counters()
    
    # Get entity-specific statistics
    entity = current_app.config.get('ENTITY_INSTANCE')
    entity_type = current_app.config.get('ENTITY_TYPE')
    
    # Add entity-specific counters based on type
    if entity_type == 'TLM' and entity:
        try:
            # Cleanup expired trust anchors before getting stats
            if hasattr(entity, '_cleanup_expired_trust_anchors'):
                entity._cleanup_expired_trust_anchors()
            
            # Get TLM statistics
            if hasattr(entity, 'get_statistics'):
                tlm_stats = entity.get_statistics()
                counters['trust_anchors'] = tlm_stats.get('total_trust_anchors', 0)
                counters['enrolled_entities'] = tlm_stats.get('total_trust_anchors', 0)
                counters['tlm_enrolled'] = tlm_stats.get('total_trust_anchors', 0)
                counters['enrolled_eas'] = tlm_stats.get('trust_anchors_by_type', {}).get('EA', 0)
                counters['enrolled_aas'] = tlm_stats.get('trust_anchors_by_type', {}).get('AA', 0)
                counters['ctl_number'] = tlm_stats.get('ctl_number', 0)
                counters['delta_additions_pending'] = tlm_stats.get('delta_additions_pending', 0)
                counters['delta_removals_pending'] = tlm_stats.get('delta_removals_pending', 0)
                current_app.logger.info(f"✅ TLM stats updated: {counters['trust_anchors']} trust anchors ({counters['enrolled_eas']} EA, {counters['enrolled_aas']} AA)")
            elif hasattr(entity, 'trust_anchors'):
                # Fallback to direct counting
                trust_anchors_count = len(entity.trust_anchors)
                counters['trust_anchors'] = trust_anchors_count
                counters['enrolled_entities'] = trust_anchors_count
                counters['tlm_enrolled'] = trust_anchors_count
                
                # Count by type
                ea_count = sum(1 for a in entity.trust_anchors if a.get('authority_type') == 'EA')
                aa_count = sum(1 for a in entity.trust_anchors if a.get('authority_type') == 'AA')
                counters['enrolled_eas'] = ea_count
                counters['enrolled_aas'] = aa_count
        except Exception as e:
            current_app.logger.error(f"❌ Error getting TLM stats: {e}")
    
    elif entity_type == 'RootCA' and entity:
        try:
            # Get RootCA statistics
            if hasattr(entity, 'get_subordinate_statistics'):
                root_stats = entity.get_subordinate_statistics()
                counters['subordinate_cas'] = root_stats.get('total_subordinates', 0)
                counters['rootca_issued_certificates'] = root_stats.get('total_subordinates', 0)
                counters['issued_certificates'] = root_stats.get('total_subordinates', 0)
                counters['active_certificates'] = root_stats.get('active_subordinates', 0)
                counters['enrolled_eas'] = root_stats.get('ea_count', 0)
                counters['enrolled_aas'] = root_stats.get('aa_count', 0)
                current_app.logger.info(f"✅ RootCA stats updated: {counters['subordinate_cas']} subordinates ({counters['enrolled_eas']} EA, {counters['enrolled_aas']} AA), {counters['active_certificates']} active")
            
            # Get CRL statistics
            if hasattr(entity, 'get_crl_statistics'):
                crl_stats = entity.get_crl_statistics()
                counters['crl_number'] = crl_stats.get('crl_number', 0)
                counters['revoked_certificates'] = crl_stats.get('total_revoked', 0)
        except Exception as e:
            current_app.logger.error(f"❌ Error getting RootCA stats: {e}")
    
    # active_certificates counter is now maintained in real-time (ETSI TS 102 941 compliant)
    
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'uptime_seconds': metrics.get_uptime_seconds(),
        
        # Overall stats
        'overall': {
            'total_requests': stats_all.total_requests,
            'successful_requests': stats_all.successful_requests,
            'failed_requests': stats_all.failed_requests,
            'error_rate_percent': round(stats_all.error_rate, 2),
            'avg_latency_ms': round(stats_all.avg_latency_ms, 2),
            'min_latency_ms': round(stats_all.min_latency_ms, 2),
            'max_latency_ms': round(stats_all.max_latency_ms, 2),
            'requests_per_second': round(stats_all.requests_per_second, 2),
        },
        
        # Last 5 minutes
        'last_5_minutes': {
            'total_requests': stats_5min.total_requests,
            'error_rate_percent': round(stats_5min.error_rate, 2),
            'avg_latency_ms': round(stats_5min.avg_latency_ms, 2),
            'requests_per_second': round(stats_5min.requests_per_second, 2),
        },
        
        # Status code distribution
        'status_codes': stats_all.status_codes,
        
        # Endpoint distribution
        'endpoints': stats_all.endpoints,
        
        # Entity-specific counters (now includes active_certificates)
        'counters': counters,
    }), 200


@monitoring_bp.route('/metrics/prometheus', methods=['GET'])
def get_prometheus_metrics():
    """
    Get metrics in Prometheus text format
    
    Returns:
        Plain text in Prometheus format
    """
    metrics = get_metrics_collector()
    prometheus_text = metrics.export_prometheus_format()
    
    return prometheus_text, 200, {'Content-Type': 'text/plain; charset=utf-8'}


@monitoring_bp.route('/metrics/errors', methods=['GET'])
def get_recent_errors():
    """
    Get recent errors for debugging
    
    Returns:
        JSON with recent error samples
    """
    metrics = get_metrics_collector()
    errors = metrics.get_recent_errors(limit=20)
    
    error_list = []
    for error in errors:
        error_list.append({
            'timestamp': error.timestamp.isoformat(),
            'endpoint': error.endpoint,
            'method': error.method,
            'status_code': error.status_code,
            'latency_ms': round(error.latency_ms, 2),
            'error': error.error,
        })
    
    return jsonify({
        'status': 'ok',
        'count': len(error_list),
        'errors': error_list
    }), 200


@monitoring_bp.route('/metrics/slowest', methods=['GET'])
def get_slowest_requests():
    """
    Get slowest requests for performance analysis
    
    Returns:
        JSON with slowest request samples
    """
    metrics = get_metrics_collector()
    slowest = metrics.get_slowest_requests(limit=20)
    
    slow_list = []
    for sample in slowest:
        slow_list.append({
            'timestamp': sample.timestamp.isoformat(),
            'endpoint': sample.endpoint,
            'method': sample.method,
            'status_code': sample.status_code,
            'latency_ms': round(sample.latency_ms, 2),
        })
    
    return jsonify({
        'status': 'ok',
        'count': len(slow_list),
        'slowest_requests': slow_list
    }), 200


@monitoring_bp.route('/health', methods=['GET'])
def health_check():
    """
    Comprehensive health check endpoint
    
    Checks:
    - Server is running
    - Entity is operational
    - System resources
    - Dependencies
    
    Returns:
        JSON with detailed health status
    """
    entity = current_app.config.get('ENTITY_INSTANCE')
    entity_type = current_app.config.get('ENTITY_TYPE')
    entity_id = current_app.config.get('ENTITY_ID')
    
    # Get system metrics
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('.')
    except Exception:
        cpu_percent = 0
        memory = None
        disk = None
    
    # Get metrics
    metrics = get_metrics_collector()
    stats = metrics.get_stats(last_n_minutes=5)
    counters = metrics.get_counters()
    
    # Determine health status
    health_status = 'healthy'
    issues = []
    
    # Check error rate
    if stats.error_rate > 10:  # More than 10% errors
        health_status = 'degraded'
        issues.append(f'High error rate: {stats.error_rate:.1f}%')
    
    # Check latency
    if stats.avg_latency_ms > 5000:  # More than 5 seconds
        health_status = 'degraded'
        issues.append(f'High latency: {stats.avg_latency_ms:.0f}ms')
    
    # Check system resources
    if memory and memory.percent > 90:
        health_status = 'degraded'
        issues.append(f'High memory usage: {memory.percent:.1f}%')
    
    if disk and disk.percent > 90:
        health_status = 'degraded'
        issues.append(f'Low disk space: {disk.percent:.1f}% used')
    
    # Build response
    health_data = {
        'status': health_status,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'uptime_seconds': metrics.get_uptime_seconds(),
        
        # Entity info
        'entity': {
            'type': entity_type,
            'id': entity_id,
            'operational': entity is not None,
        },
        
        # System resources
        'system': {
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent if memory else None,
            'memory_available_mb': memory.available / (1024**2) if memory else None,
            'disk_percent': disk.percent if disk else None,
            'disk_free_gb': disk.free / (1024**3) if disk else None,
        },
        
        # Performance metrics (last 5 min)
        'performance': {
            'requests_total': stats.total_requests,
            'error_rate_percent': round(stats.error_rate, 2),
            'avg_latency_ms': round(stats.avg_latency_ms, 2),
            'requests_per_second': round(stats.requests_per_second, 2),
        },
        
        # Counters
        'counters': counters,
        
        # Issues (if any)
        'issues': issues if issues else None,
    }
    
    # Return appropriate status code
    status_code = 200 if health_status == 'healthy' else 503
    
    return jsonify(health_data), status_code


@monitoring_bp.route('/health/ready', methods=['GET'])
def readiness_check():
    """
    Kubernetes-style readiness probe
    
    Returns:
        200 if ready to accept traffic, 503 otherwise
    """
    entity = current_app.config.get('ENTITY_INSTANCE')
    
    if entity is None:
        return jsonify({
            'status': 'not_ready',
            'reason': 'Entity not initialized'
        }), 503
    
    return jsonify({
        'status': 'ready'
    }), 200


@monitoring_bp.route('/health/live', methods=['GET'])
def liveness_check():
    """
    Kubernetes-style liveness probe
    
    Returns:
        200 if server is alive, 503 otherwise
    """
    # Simple check - if we can respond, we're alive
    return jsonify({
        'status': 'alive',
        'timestamp': datetime.now(timezone.utc).isoformat()
    }), 200
