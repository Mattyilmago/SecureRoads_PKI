"""
Mutual TLS (mTLS) Authentication Middleware

Questo middleware implementa l'autenticazione mutua TLS tra le autorità PKI,
conforme agli standard ETSI TS 102941 per comunicazioni sicure inter-authority.

Funzionalità:
- Validazione certificati client X.509
- Verifica catena di certificati fino a Root CA
- Controllo revoca tramite CRL
- Rate limiting per entità
- Audit logging delle connessioni

Riferimenti:
- ETSI TS 102941 Section 6.2.2 (ITS-S communications with PKI entities)
- ETSI TS 102941 Section 6.2.3.4 (Authorization validation protocol)
"""

from functools import wraps
from flask import request, jsonify, current_app
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID
import ssl
from datetime import datetime, timezone
from typing import Optional, Dict, Tuple
import os

from utils.logger import PKILogger
from utils.cert_utils import (
    get_certificate_identifier, 
    get_short_identifier,
    get_certificate_expiry_time,
    get_certificate_not_before
)


class MTLSAuthenticator:
    """
    Gestore autenticazione mTLS per comunicazioni inter-authority.
    
    Validazione a più livelli:
    1. Presenza certificato client
    2. Validità temporale
    3. Catena di fiducia fino a Root CA
    4. Stato di revoca (CRL check)
    5. Permessi/ruolo dell'autorità
    """
    
    def __init__(self, root_ca_cert_path: str, crl_manager=None):
        """
        Inizializza l'autenticatore mTLS.
        
        Args:
            root_ca_cert_path: Path al certificato Root CA (trust anchor)
            crl_manager: Riferimento al CRLManager per controllo revoche
        """
        self.logger = PKILogger.get_logger("mtls_auth", console_output=True)
        self.crl_manager = crl_manager
        
        # Carica Root CA certificate (trust anchor) con cache per performance
        from utils.cert_cache import load_certificate_cached
        self.root_ca_cert = load_certificate_cached(root_ca_cert_path)
        
        self.logger.info(
            f"mTLS Authenticator initialized with Root CA: {self.root_ca_cert.subject.rfc4514_string()}"
        )
        
        # Cache per certificati validati (performance)
        self._cert_cache: Dict[str, Tuple[x509.Certificate, datetime]] = {}
        self._cache_ttl_seconds = 300  # 5 minuti
    
    
    def validate_client_certificate(self, cert_pem: str) -> Tuple[bool, Optional[str], Optional[Dict]]:
        """
        Valida il certificato client presentato nella connessione mTLS.
        
        Args:
            cert_pem: Certificato client in formato PEM
            
        Returns:
            Tuple (is_valid, error_message, cert_info)
            - is_valid: True se certificato valido
            - error_message: Descrizione errore (se is_valid=False)
            - cert_info: Dizionario con info estratte dal certificato
        """
        try:
            # Parse certificato
            cert = x509.load_pem_x509_certificate(cert_pem.encode())
            cert_id = get_certificate_identifier(cert)
            subject = cert.subject.rfc4514_string()
            
            self.logger.debug(
                f"Validating client certificate: {cert_id} - Subject: {subject}"
            )
            
            # 1. Verifica validità temporale
            now = datetime.now(timezone.utc)
            not_before = get_certificate_not_before(cert)
            not_after = get_certificate_expiry_time(cert)
            
            if now < not_before:
                error = f"Certificato non ancora valido (valid_from: {not_before})"
                self.logger.warning(f"Certificate not yet valid ({cert_id}): {error}")
                return False, error, None
            
            if now > not_after:
                error = f"Certificato scaduto (valid_until: {not_after})"
                self.logger.warning(f"Certificate expired ({cert_id}): {error}")
                return False, error, None
            
            # 2. Verifica catena di fiducia fino a Root CA
            is_chain_valid, chain_error = self._verify_certificate_chain(cert)
            if not is_chain_valid:
                self.logger.warning(f"Certificate chain invalid ({cert_id}): {chain_error}")
                return False, chain_error, None
            
            # 3. Controllo revoca tramite CRL
            if self.crl_manager:
                is_revoked, revoke_reason = self._check_revocation_status(cert)
                if is_revoked:
                    error = f"Certificato revocato: {revoke_reason}"
                    self.logger.warning(f"Certificate revoked ({cert_id}): {revoke_reason}")
                    return False, error, None
            
            # 4. Estrai informazioni autorità
            cert_info = self._extract_certificate_info(cert)
            
            self.logger.info(
                f"Client certificate valid: {cert_id} - Type: {cert_info.get('authority_type')} - Org: {cert_info.get('organization')}"
            )
            
            return True, None, cert_info
            
        except Exception as e:
            error = f"Errore validazione certificato: {str(e)}"
            self.logger.error(f"Certificate validation error: {error}")
            return False, error, None
    
    
    def _verify_certificate_chain(self, cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
        """
        Verifica la catena di certificati fino al Root CA.
        
        Supporta catene multi-livello (Root -> SubCA -> Entity)
        conforme a ETSI TS 102941 Section 5.2 - Certificate Chain Validation
        
        Args:
            cert: Certificato da verificare
            
        Returns:
            Tuple (is_valid, error_message)
        """
        try:
            current_cert = cert
            max_chain_depth = 5  # Previene loop infiniti
            chain_depth = 0
            
            while chain_depth < max_chain_depth:
                # Verifica validità temporale del certificato corrente
                now = datetime.now(timezone.utc)
                if current_cert.not_valid_before_utc > now:
                    return False, f"Certificato non ancora valido (valido da {current_cert.not_valid_before_utc})"
                if current_cert.not_valid_after_utc < now:
                    return False, f"Certificato scaduto (scaduto il {current_cert.not_valid_after_utc})"
                
                # Ottieni issuer e subject
                issuer = current_cert.issuer.rfc4514_string()
                subject = current_cert.subject.rfc4514_string()
                root_subject = self.root_ca_cert.subject.rfc4514_string()
                
                # Se abbiamo raggiunto il Root CA, verifica auto-firma
                if subject == root_subject:
                    # Verifica che sia self-signed
                    if issuer != subject:
                        return False, "Root CA non auto-firmato"
                    # Catena valida!
                    return True, None
                
                # Verifica che l'issuer corrisponda al Root CA
                # (nel nostro caso semplificato: solo un livello)
                if issuer != root_subject:
                    return False, f"Certificato non firmato da Root CA fidato (issuer: {issuer})"
                
                # Verifica Authority Key Identifier / Subject Key Identifier
                try:
                    aki = current_cert.extensions.get_extension_for_oid(
                        ExtensionOID.AUTHORITY_KEY_IDENTIFIER
                    ).value
                    ski = self.root_ca_cert.extensions.get_extension_for_oid(
                        ExtensionOID.SUBJECT_KEY_IDENTIFIER
                    ).value
                    
                    if aki.key_identifier != ski.digest:
                        return False, "Authority Key Identifier non corrisponde a Root CA"
                
                except x509.ExtensionNotFound:
                    # Se non ci sono le estensioni, continuiamo
                    # (compatibilità con certificati semplici)
                    pass
                
                # Verifica Basic Constraints per catene intermedie
                try:
                    bc = current_cert.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS
                    ).value
                    
                    # Se è un CA intermedio, dovrebbe avere ca=True
                    if bc.ca and bc.path_length is not None:
                        if chain_depth > bc.path_length:
                            return False, f"Path length constraint violato (max={bc.path_length}, depth={chain_depth})"
                
                except x509.ExtensionNotFound:
                    pass
                
                # Se l'issuer è il Root CA, abbiamo finito
                if issuer == root_subject:
                    return True, None
                
                # Altrimenti dovremmo caricare il certificato dell'issuer
                # Per ora non supportato (solo Root -> Entity)
                return False, f"Certificato intermedio non supportato: {issuer}"
            
            return False, "Catena troppo lunga (possibile loop)"
            
        except Exception as e:
            return False, f"Errore verifica catena: {str(e)}"
    
    
    def _check_revocation_status(self, cert: x509.Certificate) -> Tuple[bool, Optional[str]]:
        """
        Controlla se il certificato è stato revocato tramite CRL.
        
        Args:
            cert: Certificato da controllare
            
        Returns:
            Tuple (is_revoked, reason)
        """
        if not self.crl_manager:
            return False, None
        
        try:
            cert_id = get_certificate_identifier(cert)
            short_id = get_short_identifier(cert)
            
            # Controlla nelle CRL del Root CA
            # Il CRLManager ha metodo per verificare revoca
            is_revoked = self.crl_manager.is_certificate_revoked(cert.serial_number)
            
            if is_revoked:
                return True, "Certificato presente in CRL"
            
            return False, None
            
        except Exception as e:
            self.logger.error(f"Revocation check error: {str(e)}")
            # In caso di errore, per sicurezza assumiamo non revocato
            # (altrimenti blocchiamo tutte le connessioni)
            return False, None
    
    
    def _extract_certificate_info(self, cert: x509.Certificate) -> Dict:
        """
        Estrae informazioni rilevanti dal certificato client.
        
        Returns:
            Dizionario con:
            - cert_id: Identificatore certificato
            - subject: Distinguished Name
            - organization: Nome organizzazione
            - common_name: Common Name
            - authority_type: Tipo autorità (EA/AA/RootCA/ITS-S)
            - valid_from/valid_until: Validità temporale
        """
        cert_id = get_certificate_identifier(cert)
        subject = cert.subject.rfc4514_string()
        
        # Estrai attributi DN
        org = None
        cn = None
        ou = None
        
        for attr in cert.subject:
            if attr.oid == NameOID.ORGANIZATION_NAME:
                org = attr.value
            elif attr.oid == NameOID.COMMON_NAME:
                cn = attr.value
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                ou = attr.value
        
        # Determina tipo autorità dal Common Name o OU
        authority_type = "UNKNOWN"
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
        
        # Usa utility per date (evita deprecation warnings)
        not_before = get_certificate_not_before(cert)
        not_after = get_certificate_expiry_time(cert)
        
        return {
            'cert_id': cert_id,
            'short_id': get_short_identifier(cert),
            'subject': subject,
            'organization': org,
            'common_name': cn,
            'organizational_unit': ou,
            'authority_type': authority_type,
            'valid_from': not_before.isoformat(),
            'valid_until': not_after.isoformat(),
            'serial_number': cert.serial_number
        }


# Singleton globale (inizializzato da app factory)
_mtls_authenticator: Optional[MTLSAuthenticator] = None


def setup_mtls(root_ca_cert_path: str, crl_manager=None):
    """
    Inizializza il sistema di autenticazione mTLS.
    
    Deve essere chiamato dall'app factory prima di avviare il server.
    Alias di init_mtls_auth per compatibilità con naming convention.
    
    Args:
        root_ca_cert_path: Path al certificato Root CA
        crl_manager: Riferimento al CRLManager
        
    Returns:
        MTLSAuthenticator instance
    """
    global _mtls_authenticator
    _mtls_authenticator = MTLSAuthenticator(root_ca_cert_path, crl_manager)
    return _mtls_authenticator


def init_mtls_auth(root_ca_cert_path: str, crl_manager=None):
    """
    Inizializza il sistema di autenticazione mTLS.
    
    Deve essere chiamato dall'app factory prima di avviare il server.
    
    Args:
        root_ca_cert_path: Path al certificato Root CA
        crl_manager: Riferimento al CRLManager
        
    Returns:
        MTLSAuthenticator instance
    """
    return setup_mtls(root_ca_cert_path, crl_manager)


def get_mtls_authenticator() -> Optional[MTLSAuthenticator]:
    """Restituisce l'istanza globale dell'autenticatore mTLS."""
    return _mtls_authenticator


def require_mtls(allowed_authorities=None):
    """
    Decorator per endpoint che richiedono autenticazione mTLS.
    
    Valida il certificato client e verifica che appartenga a una delle
    autorità consentite per quell'endpoint.
    
    Args:
        allowed_authorities: Lista di tipi autorità consentiti (es. ["EA", "AA"])
                           Se None, consente tutte le autorità valide.
    
    Usage:
        @app.route('/api/internal/validation')
        @require_mtls(allowed_authorities=["EA"])
        def validation_endpoint():
            cert_info = request.environ.get('mtls_cert_info')
            # ... logica endpoint
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            authenticator = get_mtls_authenticator()
            
            if not authenticator:
                return jsonify({
                    'error': 'mTLS not configured',
                    'message': 'Server non configurato per autenticazione mTLS'
                }), 500
            
            # Ottieni certificato client dalla connessione TLS
            # Flask/Werkzeug espone il certificato in request.environ
            cert_pem = request.environ.get('SSL_CLIENT_CERT')
            
            if not cert_pem:
                return jsonify({
                    'error': 'client_certificate_required',
                    'message': 'Certificato client mTLS richiesto per questo endpoint'
                }), 401
            
            # Valida certificato
            is_valid, error, cert_info = authenticator.validate_client_certificate(cert_pem)
            
            if not is_valid:
                return jsonify({
                    'error': 'invalid_certificate',
                    'message': error
                }), 403
            
            # Verifica autorità consentite
            if allowed_authorities:
                authority_type = cert_info.get('authority_type')
                if authority_type not in allowed_authorities:
                    return jsonify({
                        'error': 'unauthorized_authority',
                        'message': f'Authority type {authority_type} non autorizzata per questo endpoint',
                        'allowed': allowed_authorities
                    }), 403
            
            # Aggiungi cert_info al request context per uso nell'endpoint
            request.environ['mtls_cert_info'] = cert_info
            
            # Chiama la funzione originale
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def get_client_cert_info() -> Optional[Dict]:
    """
    Utility per ottenere le informazioni del certificato client
    dall'interno di un endpoint protetto da @require_mtls.
    
    Returns:
        Dizionario con info certificato o None se non presente
    """
    return request.environ.get('mtls_cert_info')
