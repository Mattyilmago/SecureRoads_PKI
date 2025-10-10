"""
Management Blueprint - Entity lifecycle management endpoints
Provides API endpoints for creating, deleting, and managing PKI entities
"""

from flask import Blueprint, jsonify, request
import json
import shutil
import subprocess
import psutil
import os
from pathlib import Path

management_bp = Blueprint('management', __name__, url_prefix='/api/management')


@management_bp.route('/entities', methods=['GET'])
def list_entities():
    """Get list of configured entities from entity_configs.json"""
    try:
        config_path = Path(__file__).parent.parent.parent / "entity_configs.json"
        
        if not config_path.exists():
            return jsonify({
                "success": False,
                "message": "entity_configs.json not found"
            }), 404
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Parse start_commands to get entity list
        entities = []
        for cmd in config.get('start_commands', []):
            entity_id = cmd.get('entity')
            entity_type = None
            
            if entity_id.startswith('EA_'):
                entity_type = 'EA'
            elif entity_id.startswith('AA_'):
                entity_type = 'AA'
            elif entity_id.startswith('TLM_'):
                entity_type = 'TLM'
            elif entity_id == 'ROOT_CA':
                entity_type = 'RootCA'
            
            if entity_type:
                entities.append({
                    'id': entity_id,
                    'type': entity_type,
                    'command': cmd.get('command'),
                    'description': cmd.get('description')
                })
        
        return jsonify({
            "success": True,
            "entities": entities,
            "total": len(entities)
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error listing entities: {str(e)}"
        }), 500


@management_bp.route('/entities/<entity_id>', methods=['DELETE'])
def delete_entity(entity_id):
    """
    Delete an entity: kill process, remove from config, delete data directory
    
    Args:
        entity_id: Entity identifier (e.g., EA_004, AA_005)
    
    Returns:
        JSON response with operation status
    """
    try:
        config_path = Path(__file__).parent.parent.parent / "entity_configs.json"
        data_path = Path(__file__).parent.parent.parent / "data"
        
        # Validate entity_id
        if not entity_id or entity_id in ['ROOT_CA', 'TLM_MAIN']:
            return jsonify({
                "success": False,
                "message": f"Cannot delete system entity: {entity_id}"
            }), 400
        
        # Determine entity type and data directory
        entity_type = None
        data_dir = None
        
        if entity_id.startswith('EA_'):
            entity_type = 'EA'
            data_dir = data_path / 'ea' / entity_id
        elif entity_id.startswith('AA_'):
            entity_type = 'AA'
            data_dir = data_path / 'aa' / entity_id
        else:
            return jsonify({
                "success": False,
                "message": f"Invalid entity type for: {entity_id}"
            }), 400
        
        results = {
            "entity_id": entity_id,
            "process_killed": False,
            "config_removed": False,
            "data_removed": False,
            "rootca_cert_removed": False,
            "errors": []
        }
        
        # Step 0: Kill process if running
        try:
            import re
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and 'python' in proc.info['name'].lower():
                        cmdline_str = ' '.join(cmdline)
                        # Use word boundary regex for exact match
                        pattern = r'\b' + re.escape(entity_id) + r'\b'
                        if re.search(pattern, cmdline_str, re.IGNORECASE):
                            proc.kill()
                            results['process_killed'] = True
                            results['killed_pid'] = proc.info['pid']
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            results['errors'].append(f"Failed to kill process: {str(e)}")
        
        # Step 0.5: Remove certificate from RootCA archive
        # RootCA saves certificates with pattern: EA_{SKI}.pem or AA_{SKI}.pem
        try:
            rootca_subordinates_dir = data_path / 'root_ca' / 'subordinates'
            if rootca_subordinates_dir.exists():
                # Find and remove certificates matching entity type prefix
                prefix = f"{entity_type}_"
                removed_certs = []
                
                for cert_file in rootca_subordinates_dir.glob(f"{prefix}*.pem"):
                    # Read certificate to verify it belongs to this entity
                    try:
                        from cryptography import x509
                        from cryptography.hazmat.backends import default_backend
                        
                        with open(cert_file, 'rb') as f:
                            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                        
                        # Check if CN or O contains entity_id
                        subject = cert.subject
                        cn_attrs = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        org_attrs = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                        
                        cn = cn_attrs[0].value if cn_attrs else ""
                        org = org_attrs[0].value if org_attrs else ""
                        
                        # EXACT match: entity_id must be complete token
                        # Use pattern that allows underscore as separator but prevents partial matches
                        # e.g., EA_002 matches in "EnrollmentAuthority_EA_002" but not in "EA_0021"
                        import re
                        pattern = r'(?:^|_)' + re.escape(entity_id) + r'(?:$|_)'
                        if re.search(pattern, cn) or re.search(pattern, org):
                            cert_file.unlink()
                            removed_certs.append(cert_file.name)
                    except Exception as e:
                        # Skip files that can't be read
                        continue
                
                if removed_certs:
                    results['rootca_cert_removed'] = True
                    results['rootca_certs'] = removed_certs
        except Exception as e:
            results['errors'].append(f"Failed to remove RootCA archived certificate: {str(e)}")
        
        # Step 1: Remove from entity_configs.json
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                # Remove from start_commands
                original_count = len(config.get('start_commands', []))
                config['start_commands'] = [
                    cmd for cmd in config.get('start_commands', [])
                    if cmd.get('entity') != entity_id
                ]
                new_count = len(config['start_commands'])
                
                if original_count > new_count:
                    # Save updated config
                    with open(config_path, 'w') as f:
                        json.dump(config, f, indent=2)
                    
                    results['config_removed'] = True
                    results['message'] = f"Removed {entity_id} from entity_configs.json"
                else:
                    results['errors'].append(f"{entity_id} not found in entity_configs.json")
                    
            except Exception as e:
                results['errors'].append(f"Failed to update entity_configs.json: {str(e)}")
        else:
            results['errors'].append("entity_configs.json not found")
        
        # Step 2: Remove data directory
        if data_dir and data_dir.exists():
            try:
                shutil.rmtree(data_dir)
                results['data_removed'] = True
                results['data_path'] = str(data_dir)
            except Exception as e:
                results['errors'].append(f"Failed to remove data directory: {str(e)}")
        else:
            if not results['config_removed']:
                # Only warn if entity wasn't in config either (might be active-only entity)
                results['errors'].append(f"Data directory not found: {data_dir}")
        
        # Determine overall success (success if at least process killed or config removed)
        success = results['process_killed'] or results['config_removed'] or results['data_removed'] or results['rootca_cert_removed']
        status_code = 200 if success else 404
        
        # Build message
        parts = []
        if results['process_killed']:
            parts.append(f"killed process (PID {results.get('killed_pid')})")
        if results['config_removed']:
            parts.append("removed from config")
        if results['data_removed']:
            parts.append("deleted data directory")
        if results['rootca_cert_removed']:
            parts.append(f"removed {len(results.get('rootca_certs', []))} cert(s) from RootCA archive")
        
        if parts:
            results['message'] = f"Successfully {', '.join(parts)} for {entity_id}"
        else:
            results['message'] = f"Entity {entity_id} not found (not running, not in config, no data)"
        
        return jsonify({
            "success": success,
            **results
        }), status_code
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error deleting entity: {str(e)}"
        }), 500


@management_bp.route('/entities/delete-all-ea-aa', methods=['DELETE'])
def delete_all_ea_aa():
    """
    Delete ALL EA and AA entities at once
    Keeps ROOT_CA and TLM_MAIN
    """
    try:
        config_path = Path(__file__).parent.parent.parent / "entity_configs.json"
        data_path = Path(__file__).parent.parent.parent / "data"
        
        if not config_path.exists():
            return jsonify({
                "success": False,
                "message": "entity_configs.json not found"
            }), 404
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        # Find all EA and AA entities
        ea_aa_entities = [
            cmd.get('entity') for cmd in config.get('start_commands', [])
            if cmd.get('entity', '').startswith(('EA_', 'AA_'))
        ]
        
        if not ea_aa_entities:
            return jsonify({
                "success": False,
                "message": "No EA or AA entities found to delete"
            }), 404
        
        deleted = []
        failed = []
        processes_killed = []
        rootca_certs_removed = []
        
        # Step 1: Kill all EA/AA Python processes
        try:
            import re
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    cmdline = proc.info.get('cmdline', [])
                    if cmdline and 'python' in proc.info['name'].lower():
                        # Check if this is an EA or AA process (EXACT match)
                        cmdline_str = ' '.join(cmdline)
                        for entity_id in ea_aa_entities:
                            pattern = r'\b' + re.escape(entity_id) + r'\b'
                            if re.search(pattern, cmdline_str, re.IGNORECASE):
                                proc.kill()
                                processes_killed.append({
                                    "pid": proc.info['pid'],
                                    "cmdline": ' '.join(cmdline[:3])  # First 3 args
                                })
                                break  # Don't check other entities for this process
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            # Continue even if process killing fails
            pass
            pass
        
        # Step 2: Remove all EA and AA from config
        config['start_commands'] = [
            cmd for cmd in config.get('start_commands', [])
            if not cmd.get('entity', '').startswith(('EA_', 'AA_'))
        ]
        
        # Step 3: Remove all EA/AA certificates from RootCA archive
        try:
            rootca_subordinates_dir = data_path / 'root_ca' / 'subordinates'
            if rootca_subordinates_dir.exists():
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                for cert_file in rootca_subordinates_dir.glob('*.pem'):
                    try:
                        with open(cert_file, 'rb') as f:
                            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
                        
                        subject = cert.subject
                        cn_attrs = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                        org_attrs = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                        
                        cn = cn_attrs[0].value if cn_attrs else ""
                        org = org_attrs[0].value if org_attrs else ""
                        
                        # Check if certificate belongs to any EA/AA entity (EXACT match)
                        # Use pattern that allows underscore as separator but prevents partial matches
                        import re
                        for entity_id in ea_aa_entities:
                            pattern = r'(?:^|_)' + re.escape(entity_id) + r'(?:$|_)'
                            if re.search(pattern, cn) or re.search(pattern, org):
                                cert_file.unlink()
                                rootca_certs_removed.append(cert_file.name)
                                break
                    except Exception:
                        continue
        except Exception as e:
            # Continue even if RootCA cert removal fails
            pass
        
        # Step 4: Delete data directories
        for entity_id in ea_aa_entities:
            try:
                if entity_id.startswith('EA_'):
                    data_dir = data_path / 'ea' / entity_id
                elif entity_id.startswith('AA_'):
                    data_dir = data_path / 'aa' / entity_id
                else:
                    continue
                
                if data_dir.exists():
                    shutil.rmtree(data_dir)
                
                deleted.append(entity_id)
            except Exception as e:
                failed.append({
                    "entity_id": entity_id,
                    "reason": str(e)
                })
        
        # Step 5: Save config
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            return jsonify({
                "success": False,
                "message": f"Failed to save config: {str(e)}"
            }), 500
        
        return jsonify({
            "success": True,
            "message": f"Deleted {len(deleted)} entities and killed {len(processes_killed)} processes",
            "deleted": deleted,
            "failed": failed,
            "processes_killed": processes_killed,
            "rootca_certs_removed": rootca_certs_removed,
            "total": len(ea_aa_entities)
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Failed to delete all EA/AA: {str(e)}"
        }), 500


@management_bp.route('/setup', methods=['POST'])
def run_setup():
    """
    Execute setup.py to create and start entities
    
    Request body:
    {
        "num_ea": 2,
        "num_aa": 2,
        "ea_names": ["EA_001", "EA_002"],  // optional
        "aa_names": ["AA_001", "AA_002"],  // optional
        "auto_start": true  // optional, default true
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "success": False,
                "message": "No JSON data provided"
            }), 400
        
        num_ea = data.get('num_ea', 0)
        num_aa = data.get('num_aa', 0)
        ea_names = data.get('ea_names', [])
        aa_names = data.get('aa_names', [])
        auto_start = data.get('auto_start', True)
        
        # Validate input
        if num_ea == 0 and num_aa == 0:
            return jsonify({
                "success": False,
                "message": "num_ea and num_aa cannot both be 0"
            }), 400
        
        if num_ea < 0 or num_ea > 20:
            return jsonify({
                "success": False,
                "message": "num_ea must be between 0 and 20"
            }), 400
        
        if num_aa < 0 or num_aa > 20:
            return jsonify({
                "success": False,
                "message": "num_aa must be between 0 and 20"
            }), 400
        
        # Build command
        project_root = Path(__file__).parent.parent.parent
        cmd = ['python', 'setup.py', '--ea', str(num_ea), '--aa', str(num_aa)]
        
        # Add custom names if provided
        if ea_names and len(ea_names) > 0:
            cmd.extend(['--ea-names', ','.join(ea_names)])
        
        if aa_names and len(aa_names) > 0:
            cmd.extend(['--aa-names', ','.join(aa_names)])
        
        # Add --no-auto-start if requested
        if not auto_start:
            cmd.append('--no-auto-start')
        
        # Execute setup.py
        result = subprocess.run(
            cmd,
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Parse output
        success = result.returncode == 0
        
        return jsonify({
            "success": success,
            "command": ' '.join(cmd),
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "message": "Setup completed successfully" if success else "Setup failed"
        }), 200 if success else 500
        
    except subprocess.TimeoutExpired:
        return jsonify({
            "success": False,
            "message": "Setup execution timed out (60s)"
        }), 500
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error executing setup: {str(e)}"
        }), 500


@management_bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "management-api"
    }), 200


@management_bp.route('/start-entities', methods=['POST'])
def start_entities():
    """
    Start entities in background processes
    
    Request body:
    {
        "entities": ["EA_001", "EA_002", "AA_001"]  // entity IDs to start
    }
    
    If no entities specified, starts all entities from entity_configs.json
    """
    try:
        data = request.get_json() or {}
        target_entities = data.get('entities', [])
        
        config_path = Path(__file__).parent.parent.parent / "entity_configs.json"
        
        if not config_path.exists():
            return jsonify({
                "success": False,
                "message": "entity_configs.json not found"
            }), 404
        
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        started = []
        failed = []
        
        for cmd_entry in config.get('start_commands', []):
            entity_id = cmd_entry.get('entity')
            command = cmd_entry.get('command')
            
            # Skip if target_entities specified and this entity not in list
            if target_entities and entity_id not in target_entities:
                continue
            
            # Skip ROOT_CA and TLM (usually already running)
            if entity_id in ['ROOT_CA', 'TLM_MAIN']:
                continue
            
            try:
                # Parse command (e.g., "python -m entities.enrollment_authority EA_001 --port 5000")
                cmd_parts = command.split()
                
                # Start process in background (Windows)
                if os.name == 'nt':
                    # Use PowerShell Start-Process for proper background execution
                    ps_cmd = f"Start-Process -FilePath 'python' -ArgumentList '{' '.join(cmd_parts[1:])}' -WindowStyle Hidden -PassThru"
                    subprocess.Popen(
                        ['powershell', '-Command', ps_cmd],
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
                    )
                else:
                    # Linux/Mac
                    subprocess.Popen(
                        cmd_parts,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True
                    )
                
                started.append({
                    "entity": entity_id,
                    "command": command
                })
            except Exception as e:
                failed.append({
                    "entity": entity_id,
                    "reason": str(e)
                })
        
        return jsonify({
            "success": True,
            "message": f"Started {len(started)} entities",
            "started": started,
            "failed": failed
        }), 200
        
    except Exception as e:
        return jsonify({
            "success": False,
            "message": f"Error starting entities: {str(e)}"
        }), 500
