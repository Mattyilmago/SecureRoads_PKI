from flask import Blueprint, current_app, jsonify
from pathlib import Path
from .. import flask_app_factory

from utils.cert_utils import get_certificate_ski, get_certificate_identifier, get_certificate_expiry_time
from utils.pki_paths import PKIPathManager


def create_rootca_blueprint(rootca_instance):
    bp = Blueprint('rootca_bp', __name__)

    @bp.route('/subcas')
    def get_subordinates():
        """Return a list of subordinate CA metadata from the RootCA archive"""
        try:
            # Use the instance-specific base_dir
            base_dir = Path(rootca_instance.base_dir)
            subdir = base_dir / 'subordinates'
            result = []
            if subdir.exists():
                for p in sorted(subdir.glob('*.oer')):
                    try:
                        # best-effort metadata for ASN.1 OER certificates
                        ski = get_certificate_ski(str(p))
                        cert_id = get_certificate_identifier(str(p))
                        expiry = get_certificate_expiry_time(str(p))
                        result.append({
                            'file': p.name,
                            'subject': p.stem,
                            'cert_id': cert_id,
                            'ski': ski,
                            'expiry': expiry,
                        })
                    except Exception:
                        result.append({'file': p.name, 'subject': p.stem})
            return jsonify(result)
        except Exception as e:
            current_app.logger.error(f"rootca.subcas error: {e}")
            return jsonify([]), 500

    @bp.route('/issued-certs')
    def get_issued_certs():
        """Return list of certificates issued by RootCA (archive)"""
        try:
            # Use the instance-specific base_dir
            base_dir = Path(rootca_instance.base_dir)
            issued_dir = base_dir / 'issued'
            result = []
            if issued_dir.exists():
                for p in sorted(issued_dir.glob('*.oer')):
                    try:
                        # ASN.1 OER certificates
                        ski = get_certificate_ski(str(p))
                        cert_id = get_certificate_identifier(str(p))
                        expiry = get_certificate_expiry_time(str(p))
                        result.append({
                            'file': p.name,
                            'subject': p.stem,
                            'cert_id': cert_id,
                            'ski': ski,
                            'not_after': expiry,
                        })
                    except Exception:
                        result.append({'file': p.name, 'subject': p.stem})
            return jsonify(result)
        except Exception as e:
            current_app.logger.error(f"rootca.issued-certs error: {e}")
            return jsonify([]), 500

    return bp
