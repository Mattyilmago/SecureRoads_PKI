"""
PKI Configuration - Percorsi e costanti centralizzate

Questo file centralizza tutti i percorsi base delle entità PKI.
Modificando qui i percorsi, si applicano automaticamente a tutto il sistema.

Usage:
    from config.pki_config import PKI_PATHS
    
    root_ca = RootCA(base_dir=PKI_PATHS.ROOT_CA)
    ea = EnrollmentAuthority(root_ca, ea_id="EA_001")  # usa automaticamente PKI_PATHS.EA
    tlm = TrustListManager(root_ca, base_dir=PKI_PATHS.TLM_MAIN)
"""

from pathlib import Path
from dataclasses import dataclass


@dataclass(frozen=True)
class PKIPaths:
    """
    Percorsi base centralizzati per tutte le entità PKI.
    
    Attributi:
        BASE: Directory radice per tutti i dati PKI
        ROOT_CA: Directory Root CA
        EA: Directory base per Enrollment Authorities
        AA: Directory base per Authorization Authorities
        TLM: Directory base per Trust List Managers
        TLM_MAIN: Directory TLM principale condiviso
        ITS: Directory base per ITS Stations
        LOGS: Directory log centralizzata
        TLS_DATA: Directory per certificati TLS
    """
    # Directory radice PKI
    BASE: Path = Path("./pki_data")
    
    # Entità PKI principali
    ROOT_CA: Path = Path("./pki_data/root_ca")
    EA: Path = Path("./pki_data/ea")
    AA: Path = Path("./pki_data/aa")
    TLM: Path = Path("./pki_data/tlm")
    TLM_MAIN: Path = Path("./pki_data/tlm/TLM_MAIN")
    ITS: Path = Path("./pki_data/its")
    
    # Directory condivise
    LOGS: Path = Path("./logs")
    TLS_DATA: Path = Path("./tls_data")
    
    def get_ea_path(self, ea_id: str) -> Path:
        """Ottieni path completo per una specifica EA"""
        return self.EA / ea_id
    
    def get_aa_path(self, aa_id: str) -> Path:
        """Ottieni path completo per una specifica AA"""
        return self.AA / aa_id
    
    def get_its_path(self, its_id: str) -> Path:
        """Ottieni path completo per una specifica ITS Station"""
        return self.ITS / its_id
    
    def get_tlm_path(self, tlm_id: str) -> Path:
        """Ottieni path completo per un TLM specifico"""
        return self.TLM / tlm_id


# Istanza singleton globale
PKI_PATHS = PKIPaths()


@dataclass(frozen=True)
class PKIConstants:
    """
    Costanti centralizzate per la PKI.
    
    Attributi di configurazione generale che possono essere modificati
    in un unico punto per applicarsi a tutto il sistema.
    """
    # Validità certificati (giorni)
    ROOT_CA_VALIDITY_DAYS: int = 3650  # 10 anni
    EA_CERT_VALIDITY_DAYS: int = 1095  # 3 anni
    AA_CERT_VALIDITY_DAYS: int = 1095  # 3 anni
    EC_VALIDITY_DAYS: int = 1095  # 3 anni per Enrollment Certificates
    AT_VALIDITY_HOURS: int = 168  # 7 giorni per Authorization Tickets
    
    # CRL
    FULL_CRL_VALIDITY_DAYS: int = 7
    DELTA_CRL_VALIDITY_HOURS: int = 1
    
    # CTL (Certificate Trust List)
    FULL_CTL_VALIDITY_DAYS: int = 7
    DELTA_CTL_VALIDITY_HOURS: int = 1
    
    # Performance
    DEFAULT_CACHE_SIZE: int = 100
    DEFAULT_CACHE_TTL_SECONDS: int = 300  # 5 minuti
    
    # Logging
    LOG_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5
    
    # API
    DEFAULT_API_TIMEOUT: int = 30  # secondi
    DEFAULT_RETRY_COUNT: int = 3


# Istanza singleton globale
PKI_CONSTANTS = PKIConstants()


def get_entity_base_dir(entity_type: str, entity_id: str = None) -> Path:
    """
    Ottieni il path base per un'entità PKI.
    
    Args:
        entity_type: Tipo entità ("root_ca", "ea", "aa", "tlm", "its")
        entity_id: ID entità (opzionale, non serve per root_ca)
    
    Returns:
        Path: Percorso base dell'entità
    
    Examples:
        >>> get_entity_base_dir("root_ca")
        PosixPath('pki_data/root_ca')
        
        >>> get_entity_base_dir("ea", "EA_001")
        PosixPath('pki_data/ea/EA_001')
        
        >>> get_entity_base_dir("tlm", "TLM_MAIN")
        PosixPath('pki_data/tlm/TLM_MAIN')
    """
    entity_type = entity_type.lower()
    
    if entity_type == "root_ca":
        return PKI_PATHS.ROOT_CA
    elif entity_type == "ea":
        if not entity_id:
            return PKI_PATHS.EA
        return PKI_PATHS.get_ea_path(entity_id)
    elif entity_type == "aa":
        if not entity_id:
            return PKI_PATHS.AA
        return PKI_PATHS.get_aa_path(entity_id)
    elif entity_type == "tlm":
        if not entity_id:
            return PKI_PATHS.TLM
        if entity_id.upper() == "TLM_MAIN":
            return PKI_PATHS.TLM_MAIN
        return PKI_PATHS.get_tlm_path(entity_id)
    elif entity_type == "its":
        if not entity_id:
            return PKI_PATHS.ITS
        return PKI_PATHS.get_its_path(entity_id)
    else:
        raise ValueError(f"Tipo entità non riconosciuto: {entity_type}")
