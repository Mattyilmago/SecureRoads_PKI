"""
Stats Blueprint - Entity Statistics

Provides endpoints to retrieve statistics about PKI entities.
"""

from flask import Blueprint, jsonify, current_app


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
                
                # EA stores issued ECs in enrollment_certificates/
                ec_dir = Path(bp.entity.base_dir) / "enrollment_certificates"
                if ec_dir.exists():
                    ec_issued = len(list(ec_dir.glob("EC_*.pem")))
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
                stats["active_certificates"] = ec_issued - ec_revoked
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
                
                # AA stores issued ATs in tickets/
                at_dir = Path(bp.entity.base_dir) / "tickets"
                if at_dir.exists():
                    at_issued = len(list(at_dir.glob("AT_*.pem")))
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
                stats["active_certificates"] = at_issued - at_revoked
                stats["certificate_type"] = "Authorization Ticket (AT)"
                
            elif bp.entity_type == "TLM":
                stats["entity_id"] = "TLM_MAIN"
                
                # Count trust anchors directly from TLM instance
                import os
                from pathlib import Path
                
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
                stats["trust_list_version"] = "v1.0"
                
                # Check CTL (Certificate Trust List) metadata for last update
                ctl_metadata_path = Path(bp.entity.base_dir) / "ctl" / "ctl_metadata.json"
                
                if ctl_metadata_path.exists():
                    import datetime
                    import json
                    try:
                        with open(ctl_metadata_path, 'r') as f:
                            ctl_meta = json.load(f)
                            last_full_time = ctl_meta.get('last_full_ctl_time')
                            if last_full_time:
                                stats["last_update"] = last_full_time
                            stats["ctl_number"] = ctl_meta.get('ctl_number', 0)
                    except:
                        import datetime
                        stats["last_update"] = datetime.datetime.utcnow().isoformat()
                else:
                    import datetime
                    stats["last_update"] = datetime.datetime.utcnow().isoformat()
                
            elif bp.entity_type == "RootCA":
                stats["entity_id"] = "RootCA"
                
                # Count issued Sub-CA certificates (EA, AA)
                import os
                from pathlib import Path
                
                cert_dir = Path(bp.entity.base_dir) / "certificates"
                sub_ca_count = 0
                
                if cert_dir.exists():
                    # Count all certificates except root_ca_certificate.pem
                    for cert_file in cert_dir.glob("*.pem"):
                        if cert_file.name != "root_ca_certificate.pem":
                            sub_ca_count += 1
                
                # If no Sub-CAs issued, check in typical EA/AA directories
                if sub_ca_count == 0:
                    # Check if EA/AA certs were issued by counting their existence
                    data_root = Path(bp.entity.base_dir).parent
                    
                    # Count EA instances
                    ea_dir = data_root / "ea"
                    if ea_dir.exists():
                        ea_instances = [d for d in ea_dir.iterdir() if d.is_dir() and d.name.startswith("EA_")]
                        sub_ca_count += len(ea_instances)
                    
                    # Count AA instances  
                    aa_dir = data_root / "aa"
                    if aa_dir.exists():
                        aa_instances = [d for d in aa_dir.iterdir() if d.is_dir() and d.name.startswith("AA_")]
                        sub_ca_count += len(aa_instances)
                
                stats["issued_certificates"] = sub_ca_count
                stats["sub_cas"] = sub_ca_count
                stats["certificate_chain"] = "Root → EA/AA"
                stats["status"] = "Active"
                
                # Get CRL info
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
