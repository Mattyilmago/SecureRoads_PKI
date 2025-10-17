"""
Stats Blueprint - Entity Statistics

Provides endpoints to retrieve statistics about PKI entities.
"""

from flask import Blueprint, jsonify, current_app
from pathlib import Path

from utils.cert_utils import count_active_certificates


def create_stats_blueprint(entity_instance, entity_type):
    """Create Flask blueprint for statistics endpoints."""
    bp = Blueprint("stats", __name__)

    bp.entity = entity_instance
    bp.entity_type = entity_type

    @bp.route("", methods=["GET"])
    def get_stats():
        """
        GET /api/stats
        
        Returns statistics about the entity.
        
        Response Body (JSON):
            {
                "entity_id": "EA_001",
                "entity_type": "EA",
                "certificates_issued": 42,
                "revoked_certificates": 3,
                "active_certificates": 39,
                "uptime": "2h 15m"
            }
        """
        try:
            stats = {}
            
            # Common stats
            stats["entity_type"] = bp.entity_type
            
            if bp.entity_type == "EA":
                stats["entity_id"] = bp.entity.ea_id
                # Count issued Enrollment Certificates from enrollment_certificates directory
                import os
                from pathlib import Path
                
                # EA stores issued ECs in enrollment_certificates/ (ASN.1 OER format .oer)
                ec_dir = Path(bp.entity.base_dir) / "enrollment_certificates"
                if ec_dir.exists():
                    ec_issued = len(list(ec_dir.glob("EC_*.oer")))
                else:
                    ec_issued = 0
                
                # Count revoked certificates from CRL
                ec_revoked = 0
                if hasattr(bp.entity, 'crl_manager'):
                    try:
                        # Get revoked count from CRL metadata
                        metadata_path = bp.entity.crl_manager.metadata_path
                        if os.path.exists(metadata_path):
                            import json
                            with open(metadata_path, 'r') as f:
                                metadata = json.load(f)
                                ec_revoked = metadata.get('revoked_count', 0)
                    except:
                        pass
                
                stats["certificates_issued"] = ec_issued
                stats["revoked_certificates"] = ec_revoked
                # Count truly active certificates (valid + not revoked) using ETSI-compliant logic
                stats["active_certificates"] = count_active_certificates(ec_dir, getattr(bp.entity, 'crl_manager', None))
                stats["certificate_type"] = "Enrollment Certificate (EC)"
                
                # Get CRL info if available
                if hasattr(bp.entity, 'crl_manager'):
                    try:
                        crl_path = bp.entity.crl_manager.full_crl_path
                        if os.path.exists(crl_path):
                            import datetime
                            mtime = os.path.getmtime(crl_path)
                            last_update = datetime.datetime.fromtimestamp(mtime).isoformat()
                            stats["crl_last_update"] = last_update
                            stats["crl_available"] = True
                        else:
                            stats["crl_available"] = False
                    except:
                        stats["crl_available"] = False
                
            elif bp.entity_type == "AA":
                stats["entity_id"] = bp.entity.aa_id
                
                # Count issued Authorization Tickets from tickets directory
                import os
                from pathlib import Path
                
                # AA stores issued ATs in tickets/ (ASN.1 OER format .oer)
                at_dir = Path(bp.entity.base_dir) / "tickets"
                if at_dir.exists():
                    at_issued = len(list(at_dir.glob("AT_*.oer")))
                else:
                    at_issued = 0
                
                # Count revoked certificates from CRL
                at_revoked = 0
                if hasattr(bp.entity, 'crl_manager'):
                    try:
                        # Get revoked count from CRL metadata
                        metadata_path = bp.entity.crl_manager.metadata_path
                        if os.path.exists(metadata_path):
                            import json
                            with open(metadata_path, 'r') as f:
                                metadata = json.load(f)
                                at_revoked = metadata.get('revoked_count', 0)
                    except:
                        pass
                
                stats["certificates_issued"] = at_issued
                stats["revoked_certificates"] = at_revoked
                # Count truly active certificates (valid + not revoked) using ETSI-compliant logic
                stats["active_certificates"] = count_active_certificates(at_dir, getattr(bp.entity, 'crl_manager', None))
                stats["certificate_type"] = "Authorization Ticket (AT)"
                
            elif bp.entity_type == "TLM":
                stats["entity_id"] = "TLM_MAIN"
                
                # Get comprehensive statistics from TLM instance
                import os
                from pathlib import Path
                
                # Use get_statistics() method for accurate, real-time data
                if hasattr(bp.entity, 'get_statistics'):
                    tlm_stats = bp.entity.get_statistics()
                    
                    # First cleanup expired trust anchors to get accurate count
                    if hasattr(bp.entity, '_cleanup_expired_trust_anchors'):
                        bp.entity._cleanup_expired_trust_anchors()
                    
                    # Get updated statistics after cleanup
                    tlm_stats = bp.entity.get_statistics()
                    
                    stats["trust_anchors"] = tlm_stats.get('total_trust_anchors', 0)
                    stats["active_certificates"] = tlm_stats.get('total_trust_anchors', 0)  # For dashboard consistency
                    stats["ctl_number"] = tlm_stats.get('ctl_number', 0)
                    stats["base_ctl_number"] = tlm_stats.get('base_ctl_number', 0)
                    stats["delta_additions_pending"] = tlm_stats.get('delta_additions_pending', 0)
                    stats["delta_removals_pending"] = tlm_stats.get('delta_removals_pending', 0)
                    
                    # Count by type from trust_anchors_by_type
                    anchors_by_type = tlm_stats.get('trust_anchors_by_type', {})
                    stats["enrolled_eas"] = anchors_by_type.get('EA', 0)
                    stats["enrolled_aas"] = anchors_by_type.get('AA', 0)
                    
                    # Last update time
                    last_full_ctl = tlm_stats.get('last_full_ctl')
                    if last_full_ctl:
                        stats["last_update"] = last_full_ctl
                    else:
                        import datetime
                        stats["last_update"] = datetime.datetime.utcnow().isoformat()
                else:
                    # Fallback to direct count if get_statistics not available
                    trust_anchors_count = 0
                    if hasattr(bp.entity, 'trust_anchors'):
                        trust_anchors_count = len(bp.entity.trust_anchors)
                    
                    # Count by type
                    ea_count = 0
                    aa_count = 0
                    if hasattr(bp.entity, 'trust_anchors'):
                        for anchor in bp.entity.trust_anchors:
                            auth_type = anchor.get('authority_type', 'UNKNOWN')
                            if auth_type == 'EA':
                                ea_count += 1
                            elif auth_type == 'AA':
                                aa_count += 1
                    
                    stats["trust_anchors"] = trust_anchors_count
                    stats["active_certificates"] = trust_anchors_count  # For dashboard consistency
                    stats["enrolled_eas"] = ea_count
                    stats["enrolled_aas"] = aa_count
                    
                    import datetime
                    stats["last_update"] = datetime.datetime.utcnow().isoformat()
                
                stats["trust_list_version"] = "v1.0"
                
            elif bp.entity_type == "RootCA":
                stats["entity_id"] = "RootCA"
                
                # Get comprehensive statistics from RootCA instance
                import os
                from pathlib import Path
                
                # Use get_subordinate_statistics() method for accurate, real-time data
                if hasattr(bp.entity, 'get_subordinate_statistics'):
                    sub_stats = bp.entity.get_subordinate_statistics()
                    
                    stats["issued_certificates"] = sub_stats.get('total_subordinates', 0)
                    stats["sub_cas"] = sub_stats.get('total_subordinates', 0)
                    stats["active_certificates"] = sub_stats.get('active_subordinates', 0)
                    stats["enrolled_eas"] = sub_stats.get('ea_count', 0)
                    stats["enrolled_aas"] = sub_stats.get('aa_count', 0)
                else:
                    # Fallback to directory counting
                    cert_dir = Path(bp.entity.base_dir) / "subordinates"
                    sub_ca_count = 0
                    ea_count = 0
                    aa_count = 0
                    
                    if cert_dir.exists():
                        # Count all certificates (ASN.1 OER format .oer)
                        cert_files = list(cert_dir.glob("*.oer"))
                        sub_ca_count = len(cert_files)
                        
                        # Count by type
                        for cert_file in cert_files:
                            if cert_file.name.startswith('EA_'):
                                ea_count += 1
                            elif cert_file.name.startswith('AA_'):
                                aa_count += 1
                    
                    stats["issued_certificates"] = sub_ca_count
                    stats["sub_cas"] = sub_ca_count
                    stats["active_certificates"] = sub_ca_count  # Simplified fallback
                    stats["enrolled_eas"] = ea_count
                    stats["enrolled_aas"] = aa_count
                
                stats["certificate_chain"] = "Root → EA/AA"
                stats["status"] = "Active"
                
                # Get CRL statistics
                if hasattr(bp.entity, 'get_crl_statistics'):
                    crl_stats = bp.entity.get_crl_statistics()
                    stats["crl_number"] = crl_stats.get('crl_number', 0)
                    stats["revoked_certificates"] = crl_stats.get('total_revoked', 0)
                    stats["delta_pending"] = crl_stats.get('delta_pending', 0)
                
                # Get CRL availability info
                if hasattr(bp.entity, 'crl_manager'):
                    try:
                        crl_path = bp.entity.crl_manager.full_crl_path
                        if os.path.exists(crl_path):
                            stats["crl_available"] = True
                        else:
                            stats["crl_available"] = False
                    except:
                        stats["crl_available"] = False
            
            return jsonify(stats), 200
            
        except Exception as e:
            current_app.logger.error(f"Error getting stats: {e}")
            import traceback
            current_app.logger.error(traceback.format_exc())
            return jsonify({
                "error": "Failed to retrieve statistics",
                "message": str(e)
            }), 500

    return bp
