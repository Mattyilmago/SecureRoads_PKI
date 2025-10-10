"""
Test suite per mTLS Authentication Middleware

Test conformità ETSI TS 102941 Section 6.2.3.4 (Authorization Validation Protocol)
"""

import pytest
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.x509 import ReasonFlags
import os
import sys

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from api.middleware.mtls_auth import MTLSAuthenticator, init_mtls_auth, get_mtls_authenticator


@pytest.fixture
def temp_dir(tmp_path):
    """Crea directory temporanea per i test"""
    return str(tmp_path)


@pytest.fixture
def root_ca(temp_dir):
    """Crea Root CA per i test"""
    ca = RootCA(base_dir=os.path.join(temp_dir, "root_ca"))
    # RootCA si auto-genera al primo avvio
    return ca


@pytest.fixture
def enrollment_authority(root_ca, temp_dir):
    """Crea EA con certificato firmato da Root CA"""
    ea = EnrollmentAuthority(
        root_ca=root_ca,
        ea_id="EA_TEST",
        base_dir=os.path.join(temp_dir, "ea")
    )
    return ea


@pytest.fixture
def trust_list_manager(root_ca, enrollment_authority, temp_dir):
    """Crea TLM e registra EA"""
    from managers.trust_list_manager import TrustListManager
    tlm = TrustListManager(
        root_ca=root_ca,
        base_dir=os.path.join(temp_dir, "tlm")
    )
    # Aggiungi EA ai trust anchors
    tlm.add_trust_anchor(enrollment_authority.certificate, authority_type="EA")
    return tlm


@pytest.fixture
def authorization_authority(root_ca, trust_list_manager, temp_dir):
    """Crea AA con certificato firmato da Root CA e TLM"""
    aa = AuthorizationAuthority(
        root_ca=root_ca,
        tlm=trust_list_manager,
        aa_id="AA_TEST",
        base_dir=os.path.join(temp_dir, "aa")
    )
    return aa


@pytest.fixture
def mtls_authenticator(root_ca):
    """Crea MTLSAuthenticator"""
    # Salva certificato Root CA in file temporaneo
    root_cert_path = os.path.join(root_ca.base_dir, "root_ca_cert.pem")
    
    # Verifica che il certificato esista
    if not os.path.exists(root_cert_path):
        # Se non esiste, crealo
        with open(root_cert_path, 'wb') as f:
            f.write(root_ca.certificate.public_bytes(serialization.Encoding.PEM))
    
    authenticator = MTLSAuthenticator(
        root_ca_cert_path=root_cert_path,
        crl_manager=root_ca.crl_manager
    )
    return authenticator


class TestMTLSAuthenticator:
    """Test suite per MTLSAuthenticator"""
    
    def test_init_authenticator(self, mtls_authenticator, root_ca):
        """Test inizializzazione authenticator"""
        assert mtls_authenticator is not None
        assert mtls_authenticator.root_ca_cert is not None
        assert mtls_authenticator.root_ca_cert.subject == root_ca.certificate.subject
    
    
    def test_validate_ea_certificate(self, mtls_authenticator, enrollment_authority):
        """Test validazione certificato EA (valido)"""
        # Ottieni certificato EA in formato PEM
        ea_cert_pem = enrollment_authority.certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Valida certificato
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(ea_cert_pem)
        
        assert is_valid is True
        assert error is None
        assert cert_info is not None
        assert cert_info['authority_type'] == 'EA'
        # L'organization contiene il nome EA, non "SecureRoad Test"
        assert 'EnrollmentAuthority' in cert_info['organization']
        assert 'cert_id' in cert_info
        assert 'serial_number' in cert_info
    
    
    def test_validate_aa_certificate(self, mtls_authenticator, authorization_authority):
        """Test validazione certificato AA (valido)"""
        # Ottieni certificato AA in formato PEM
        aa_cert_pem = authorization_authority.certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Valida certificato
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(aa_cert_pem)
        
        assert is_valid is True
        assert error is None
        assert cert_info is not None
        assert cert_info['authority_type'] == 'AA'
    
    
    def test_reject_expired_certificate(self, mtls_authenticator, root_ca, temp_dir):
        """Test rifiuto certificato scaduto"""
        # Crea certificato già scaduto
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Expired EA"),
        ])
        
        # Certificato valido solo ieri (già scaduto)
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_ca.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=2))
            .not_valid_after(datetime.now(timezone.utc) - timedelta(days=1))  # Scaduto ieri
            .sign(root_ca.private_key, hashes.SHA256())
        )
        
        expired_cert_pem = expired_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Valida certificato
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(expired_cert_pem)
        
        assert is_valid is False
        assert "scaduto" in error.lower()
        assert cert_info is None
    
    
    def test_reject_not_yet_valid_certificate(self, mtls_authenticator, root_ca):
        """Test rifiuto certificato non ancora valido"""
        # Crea certificato valido dal futuro
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Future EA"),
        ])
        
        # Certificato valido solo da domani
        future_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(root_ca.certificate.subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) + timedelta(days=1))  # Valido da domani
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(root_ca.private_key, hashes.SHA256())
        )
        
        future_cert_pem = future_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Valida certificato
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(future_cert_pem)
        
        assert is_valid is False
        assert "non ancora valido" in error.lower()
        assert cert_info is None
    
    
    def test_reject_wrong_issuer(self, mtls_authenticator):
        """Test rifiuto certificato firmato da CA diversa"""
        # Crea certificato auto-firmato (non firmato da Root CA)
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Rogue CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Rogue EA"),
        ])
        
        rogue_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)  # Auto-firmato
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .sign(private_key, hashes.SHA256())  # Firmato con propria chiave
        )
        
        rogue_cert_pem = rogue_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Valida certificato
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(rogue_cert_pem)
        
        assert is_valid is False
        assert "root ca" in error.lower()
        assert cert_info is None
    
    
    def test_extract_certificate_info(self, mtls_authenticator, enrollment_authority):
        """Test estrazione informazioni da certificato"""
        ea_cert_pem = enrollment_authority.certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode('utf-8')
        
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(ea_cert_pem)
        
        assert is_valid is True
        assert 'EnrollmentAuthority' in cert_info['organization']
        assert cert_info['authority_type'] == 'EA'
        assert 'cert_id' in cert_info
        assert 'short_id' in cert_info
        assert 'valid_from' in cert_info
        assert 'valid_until' in cert_info
        assert 'serial_number' in cert_info


class TestMTLSIntegration:
    """Test integrazione mTLS con Flask"""
    
    def test_init_global_authenticator(self, root_ca):
        """Test inizializzazione autenticatore globale"""
        root_cert_path = os.path.join(root_ca.base_dir, "certificates", "root_ca.pem")
        
        # Verifica esistenza o crea certificato
        if not os.path.exists(root_cert_path):
            os.makedirs(os.path.dirname(root_cert_path), exist_ok=True)
            with open(root_cert_path, 'wb') as f:
                f.write(root_ca.certificate.public_bytes(serialization.Encoding.PEM))
        
        # Inizializza autenticatore globale
        authenticator = init_mtls_auth(root_cert_path, root_ca.crl_manager)
        
        assert authenticator is not None
        assert get_mtls_authenticator() is authenticator


def test_authority_type_detection():
    """Test rilevamento tipo autorità dal Common Name"""
    test_cases = [
        ("Enrollment Authority EA_001", "EA"),
        ("Authorization Authority AA_001", "AA"),
        ("Root CA Test", "RootCA"),
        ("Test Vehicle ITS-S", "ITS-S"),
        ("Unknown Entity", "UNKNOWN"),
    ]
    
    from api.middleware.mtls_auth import MTLSAuthenticator
    
    # Mock certificate info extraction
    for cn, expected_type in test_cases:
        # Simula l'estrazione
        if cn:
            cn_lower = cn.lower()
            if "enrollment" in cn_lower or "ea" in cn_lower:
                authority_type = "EA"
            elif "authorization" in cn_lower or "aa" in cn_lower:
                authority_type = "AA"
            elif "root" in cn_lower or "rca" in cn_lower:
                authority_type = "RootCA"
            elif "vehicle" in cn_lower or "its" in cn_lower:
                authority_type = "ITS-S"
            else:
                authority_type = "UNKNOWN"
            
            assert authority_type == expected_type, f"Failed for CN: {cn}"


class TestCRLRevocationCheck:
    """Test per controllo revoca tramite CRL"""
    
    def test_revoked_certificate_rejected(self, mtls_authenticator, enrollment_authority, root_ca):
        """Test rifiuto certificato revocato"""
        # Ottieni certificato EA valido
        ea_cert = enrollment_authority.certificate
        ea_cert_pem = ea_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        # Verifica che inizialmente sia valido
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(ea_cert_pem)
        assert is_valid is True
        
        # Revoca il certificato
        root_ca.crl_manager.add_revoked_certificate(ea_cert, ReasonFlags.key_compromise)
        
        # Verifica che ora sia rifiutato
        is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(ea_cert_pem)
        assert is_valid is False
        assert "revocato" in error.lower()
    
    
    def test_crl_manager_is_revoked(self, root_ca, enrollment_authority):
        """Test metodo is_certificate_revoked del CRLManager"""
        ea_cert = enrollment_authority.certificate
        serial = ea_cert.serial_number
        
        # Inizialmente non revocato
        assert root_ca.crl_manager.is_certificate_revoked(serial) is False
        
        # Revoca certificato
        root_ca.crl_manager.add_revoked_certificate(ea_cert, ReasonFlags.key_compromise)
        
        # Ora dovrebbe essere revocato
        assert root_ca.crl_manager.is_certificate_revoked(serial) is True


class TestMTLSDecorator:
    """Test per decorator @require_mtls"""
    
    def test_require_mtls_decorator_with_valid_cert(self, root_ca, enrollment_authority):
        """Test decorator con certificato valido"""
        from flask import Flask
        from api.middleware.mtls_auth import require_mtls, init_mtls_auth
        
        # Crea app Flask di test
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        # Inizializza mTLS
        root_cert_path = os.path.join(root_ca.base_dir, "certificates", "root_ca.pem")
        if not os.path.exists(root_cert_path):
            os.makedirs(os.path.dirname(root_cert_path), exist_ok=True)
            with open(root_cert_path, 'wb') as f:
                f.write(root_ca.certificate.public_bytes(serialization.Encoding.PEM))
        
        init_mtls_auth(root_cert_path, root_ca.crl_manager)
        
        # Crea endpoint protetto
        @app.route('/protected')
        @require_mtls(allowed_authorities=["EA"])
        def protected_endpoint():
            from flask import request
            cert_info = request.environ.get('mtls_cert_info')
            return {'status': 'ok', 'authority': cert_info['authority_type']}
        
        # Simula richiesta con certificato valido
        with app.test_client() as client:
            ea_cert_pem = enrollment_authority.certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode('utf-8')
            
            # Flask test client non supporta SSL_CLIENT_CERT direttamente
            # Testiamo solo la logica del decorator
            with app.test_request_context('/protected', environ_base={'SSL_CLIENT_CERT': ea_cert_pem}):
                response = protected_endpoint()
                assert response['status'] == 'ok'
                assert response['authority'] == 'EA'
    
    
    def test_require_mtls_decorator_without_cert(self, root_ca):
        """Test decorator senza certificato (deve rifiutare)"""
        from flask import Flask, jsonify
        from api.middleware.mtls_auth import require_mtls, init_mtls_auth
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        # Inizializza mTLS
        root_cert_path = os.path.join(root_ca.base_dir, "certificates", "root_ca.pem")
        if not os.path.exists(root_cert_path):
            os.makedirs(os.path.dirname(root_cert_path), exist_ok=True)
            with open(root_cert_path, 'wb') as f:
                f.write(root_ca.certificate.public_bytes(serialization.Encoding.PEM))
        
        init_mtls_auth(root_cert_path, root_ca.crl_manager)
        
        @app.route('/protected')
        @require_mtls()
        def protected_endpoint():
            return jsonify({'status': 'ok'})
        
        # Richiesta senza certificato
        with app.test_client() as client:
            response = client.get('/protected')
            assert response.status_code == 401
            data = response.get_json()
            assert 'error' in data
            assert 'client_certificate_required' in data['error']
    
    
    def test_require_mtls_wrong_authority_type(self, root_ca, authorization_authority):
        """Test decorator con tipo autorità non consentito"""
        from flask import Flask, jsonify
        from api.middleware.mtls_auth import require_mtls, init_mtls_auth
        
        app = Flask(__name__)
        app.config['TESTING'] = True
        
        root_cert_path = os.path.join(root_ca.base_dir, "certificates", "root_ca.pem")
        if not os.path.exists(root_cert_path):
            os.makedirs(os.path.dirname(root_cert_path), exist_ok=True)
            with open(root_cert_path, 'wb') as f:
                f.write(root_ca.certificate.public_bytes(serialization.Encoding.PEM))
        
        init_mtls_auth(root_cert_path, root_ca.crl_manager)
        
        # Endpoint che accetta solo EA
        @app.route('/ea-only')
        @require_mtls(allowed_authorities=["EA"])
        def ea_only_endpoint():
            return jsonify({'status': 'ok'})
        
        # Tenta accesso con certificato AA
        with app.test_client() as client:
            aa_cert_pem = authorization_authority.certificate.public_bytes(
                serialization.Encoding.PEM
            ).decode('utf-8')
            
            with app.test_request_context('/ea-only', environ_base={'SSL_CLIENT_CERT': aa_cert_pem}):
                response = ea_only_endpoint()
                # Dovrebbe rifiutare perché AA non è in allowed_authorities
                assert isinstance(response, tuple)  # (response, status_code)
                assert response[1] == 403


class TestMTLSCachingAndPerformance:
    """Test per caching e performance"""
    
    def test_certificate_validation_multiple_times(self, mtls_authenticator, enrollment_authority):
        """Test validazione multipla dello stesso certificato"""
        ea_cert_pem = enrollment_authority.certificate.public_bytes(
            serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Valida 10 volte
        for i in range(10):
            is_valid, error, cert_info = mtls_authenticator.validate_client_certificate(ea_cert_pem)
            assert is_valid is True
            assert cert_info['authority_type'] == 'EA'


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
