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
                # Count issued certificates from data directory
                import os
                from pathlib import Path
                
                cert_dir = Path(bp.entity.base_dir) / "certificates"
                if cert_dir.exists():
                    cert_count = len(list(cert_dir.glob("*.pem")))
                else:
                    cert_count = 0
                
                stats["certificates_issued"] = cert_count
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
                
                # Count issued AT
                import os
                from pathlib import Path
                
                cert_dir = Path(bp.entity.base_dir) / "certificates"
                if cert_dir.exists():
                    cert_count = len(list(cert_dir.glob("*.pem")))
                else:
                    cert_count = 0
                
                stats["certificates_issued"] = cert_count
                stats["certificate_type"] = "Authorization Ticket (AT)"
                
            elif bp.entity_type == "TLM":
                stats["entity_id"] = "TLM_MAIN"
                
                # Count enrolled EAs and AAs from link certificates
                import os
                from pathlib import Path
                
                # TLM stores link certificates for each EA/AA
                link_cert_dir = Path(bp.entity.base_dir) / "link_certificates"
                ea_count = 0
                aa_count = 0
                
                if link_cert_dir.exists():
                    # Count EA and AA link certificates
                    for cert_file in link_cert_dir.glob("*_link.pem"):
                        if "EA_" in cert_file.name:
                            ea_count += 1
                        elif "AA_" in cert_file.name:
                            aa_count += 1
                
                stats["enrolled_eas"] = ea_count
                stats["enrolled_aas"] = aa_count
                stats["trust_list_version"] = "v1.0"
                
                # Check CTL (Certificate Trust List) file for last update
                ctl_dir = Path(bp.entity.base_dir) / "ctl"
                trust_list_file = None
                
                if ctl_dir.exists():
                    # Look for latest CTL file
                    ctl_files = list(ctl_dir.glob("*.ctl"))
                    if ctl_files:
                        # Get most recent
                        trust_list_file = max(ctl_files, key=lambda p: p.stat().st_mtime)
                
                if trust_list_file and trust_list_file.exists():
                    import datetime
                    mtime = os.path.getmtime(trust_list_file)
                    last_update = datetime.datetime.fromtimestamp(mtime).isoformat()
                    stats["last_update"] = last_update
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
