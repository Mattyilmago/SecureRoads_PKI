"""
PKI Filesystem Path Manager

Centralizza tutta la logica di gestione dei path del filesystem PKI per garantire
consistenza tra tutte le entità (RootCA, EA, AA, TLM, ITS Station).

Previene problemi come:
- Directory duplicate (es: pki_data/ea/EA_001/EA_001/)
- Path inconsistenti tra entità diverse
- Difficoltà nel refactoring della struttura directory

Esempio:
    >>> paths = PKIPathManager.get_entity_paths("EA", "EA_001")
    >>> print(paths.base_dir)
    ./data/ea/EA_001
    >>> print(paths.certificates_dir)
    ./data/ea/EA_001/certificates
"""

import os
from pathlib import Path
from typing import Optional, Dict
from dataclasses import dataclass


@dataclass
class EntityPaths:
    """
    Rappresenta tutti i path di un'entità PKI.
    
    Attributi:
        base_dir: Directory base dell'entità
        certificates_dir: Directory certificati
        private_keys_dir: Directory chiavi private
        crl_dir: Directory CRL
        logs_dir: Directory log
        backup_dir: Directory backup
        data_dir: Directory dati aggiuntivi (opzionale)
        
        # Directory specifiche ITS-S (opzionali)
        inbox_dir: Directory inbox (solo ITS-S)
        outbox_dir: Directory outbox (solo ITS-S)
        authorization_tickets_dir: Directory AT (solo ITS-S)
        trust_anchors_dir: Directory trust anchors (solo ITS-S)
        ctl_full_dir: Directory CTL full (solo ITS-S)
        ctl_delta_dir: Directory CTL delta (solo ITS-S)
        own_certificates_dir: Directory certificati propri (solo ITS-S)
    """
    base_dir: Path
    certificates_dir: Path
    private_keys_dir: Path
    crl_dir: Path
    logs_dir: Path
    backup_dir: Path
    data_dir: Optional[Path] = None
    
    # Directory specifiche ITS-S
    inbox_dir: Optional[Path] = None
    outbox_dir: Optional[Path] = None
    authorization_tickets_dir: Optional[Path] = None
    trust_anchors_dir: Optional[Path] = None
    ctl_full_dir: Optional[Path] = None
    ctl_delta_dir: Optional[Path] = None
    own_certificates_dir: Optional[Path] = None
    
    def create_all(self, exist_ok: bool = True) -> None:
        """
        Crea tutte le directory necessarie.
        
        Ottimizzato: Controlla prima l'esistenza per evitare chiamate di sistema inutili.
        """
        # Directory base comuni a tutte le entità
        for path_attr in ['base_dir', 'certificates_dir', 'private_keys_dir', 
                          'crl_dir', 'logs_dir', 'backup_dir']:
            path = getattr(self, path_attr)
            if path and not path.exists():
                path.mkdir(parents=True, exist_ok=exist_ok)
        
        if self.data_dir and not self.data_dir.exists():
            self.data_dir.mkdir(parents=True, exist_ok=exist_ok)
        
        # Directory specifiche ITS-S
        for its_attr in ['inbox_dir', 'outbox_dir', 'authorization_tickets_dir',
                        'trust_anchors_dir', 'ctl_full_dir', 'ctl_delta_dir', 
                        'own_certificates_dir']:
            path = getattr(self, its_attr, None)
            if path and not path.exists():
                path.mkdir(parents=True, exist_ok=exist_ok)
    
    def to_dict(self) -> Dict[str, str]:
        """Converte i path in un dizionario di stringhe."""
        result = {
            'base_dir': str(self.base_dir),
            'certificates_dir': str(self.certificates_dir),
            'private_keys_dir': str(self.private_keys_dir),
            'crl_dir': str(self.crl_dir),
            'logs_dir': str(self.logs_dir),
            'backup_dir': str(self.backup_dir),
            'data_dir': str(self.data_dir) if self.data_dir else None
        }
        
        # Aggiungi directory ITS-S se presenti
        if self.inbox_dir:
            result['inbox_dir'] = str(self.inbox_dir)
        if self.outbox_dir:
            result['outbox_dir'] = str(self.outbox_dir)
        if self.authorization_tickets_dir:
            result['authorization_tickets_dir'] = str(self.authorization_tickets_dir)
        if self.trust_anchors_dir:
            result['trust_anchors_dir'] = str(self.trust_anchors_dir)
        if self.ctl_full_dir:
            result['ctl_full_dir'] = str(self.ctl_full_dir)
        if self.ctl_delta_dir:
            result['ctl_delta_dir'] = str(self.ctl_delta_dir)
        if self.own_certificates_dir:
            result['own_certificates_dir'] = str(self.own_certificates_dir)
        
        return result


class PKIPathManager:
    """
    Gestisce la struttura delle directory del filesystem PKI.
    
    Struttura standard:
        pki_data/
        ├── root_ca/
        │   ├── certificates/
        │   ├── private_keys/
        │   ├── crl/
        │   ├── logs/
        │   ├── backup/
        │   └── subordinates/  # Certificati subordinati
        ├── ea/
        │   ├── EA_001/
        │   │   ├── certificates/
        │   │   ├── private_keys/
        │   │   ├── crl/
        │   │   ├── logs/
        │   │   ├── backup/
        │   │   └── enrollment_certificates/
        │   └── EA_002/
        │       └── ...
        ├── aa/
        │   ├── AA_001/
        │   │   ├── certificates/
        │   │   ├── private_keys/
        │   │   ├── crl/
        │   │   ├── logs/
        │   │   ├── backup/
        │   │   └── authorization_tickets/
        │   └── AA_002/
        │       └── ...
        ├── tlm/
        │   ├── TLM_MAIN/
        │   │   ├── certificates/
        │   │   ├── logs/
        │   │   ├── backup/
        │   │   └── trust_lists/
        │   └── ...
        └── itss/
            ├── VEHICLE_001/
            │   ├── certificates/           # Certificati ricevuti (EC, AT, ecc.)
            │   ├── private_keys/            # Chiavi private del veicolo
            │   ├── crl/                     # CRL scaricate
            │   ├── logs/                    # Log operazioni
            │   ├── backup/                  # Backup certificati
            │   ├── received_messages/       # Messaggi V2V ricevuti
            │   ├── inbox/                   # Inbox messaggi CAM/DENM
            │   ├── outbox/                  # Outbox messaggi inviati
            │   ├── authorization_tickets/   # AT multipli per pseudonimato
            │   ├── trust_anchors/           # Trust anchors (EA/AA fidate)
            │   ├── ctl_full/                # Full CTL
            │   ├── ctl_delta/               # Delta CTL
            │   └── own_certificates/        # Certificati propri (EC principale)
            └── ...
    """
    
    # Directory radice del progetto PKI
    PROJECT_ROOT = Path(__file__).parent.parent
    DATA_ROOT = PROJECT_ROOT / "pki_data" 
    
    # Entity type directories
    ENTITY_TYPE_DIRS = {
        "RootCA": DATA_ROOT / "root_ca",
        "EA": DATA_ROOT / "ea",
        "AA": DATA_ROOT / "aa",
        "TLM": DATA_ROOT / "tlm",
        "ITS": DATA_ROOT / "itss"
    }
    
    # Cache per path già calcolati (ottimizzazione performance)
    # Chiave: (entity_type, entity_id, base_dir)
    _path_cache: Dict[tuple, EntityPaths] = {}
    
    @classmethod
    def get_entity_paths(cls, entity_type: str, entity_id: str, 
                        base_dir: Optional[str] = None) -> EntityPaths:
        """
        Ottiene tutti i path per un'entità specifica.
        
        Args:
            entity_type: Tipo di entità ("EA", "AA", "TLM", "ITS", "RootCA")
            entity_id: ID univoco dell'entità (es: "EA_001", "AA_TEST")
            base_dir: Directory base custom (opzionale, usa default se None)
        
        Returns:
            EntityPaths con tutti i path dell'entità
        
        Raises:
            ValueError: Se entity_type non è valido
        
        Example:
            >>> paths = PKIPathManager.get_entity_paths("EA", "EA_001")
            >>> print(paths.base_dir)
            PosixPath('pki_data/ea/EA_001')
        """
        # Check cache per performance
        cache_key = (entity_type.upper(), entity_id, base_dir)
        if cache_key in cls._path_cache:
            return cls._path_cache[cache_key]
        
        entity_type = entity_type.upper()
        
        if entity_type not in cls.ENTITY_TYPE_DIRS and entity_type != "ROOTCA":
            raise ValueError(
                f"Invalid entity_type: {entity_type}. "
                f"Must be one of: {list(cls.ENTITY_TYPE_DIRS.keys())}"
            )
        
        # Determina base_dir
        if base_dir:
            # Se base_dir è fornito, usalo direttamente
            base_path = Path(base_dir)
            
            # IMPORTANTE: Se base_dir contiene già entity_id, non duplicare!
            # Es: se base_dir = "pki_data/ea/EA_001", NON aggiungere /EA_001
            # Per RootCA: "pki_data/root_ca" contiene già la struttura corretta
            if entity_type == "ROOTCA":
                # RootCA non ha sottodirectory per entity_id
                pass
            elif base_path.name.lower() != entity_id.lower():
                # Aggiungi entity_id solo se non è già presente (case-insensitive)
                base_path = base_path / entity_id
        else:
            # Usa la struttura standard
            if entity_type == "ROOTCA":
                base_path = cls.ENTITY_TYPE_DIRS["RootCA"]
            else:
                entity_type_dir = cls.ENTITY_TYPE_DIRS[entity_type]
                base_path = entity_type_dir / entity_id
        
        # Crea EntityPaths con sottodirectory standard
        paths = EntityPaths(
            base_dir=base_path,
            certificates_dir=base_path / "certificates",
            private_keys_dir=base_path / "private_keys",
            crl_dir=base_path / "crl",
            logs_dir=base_path / "logs",
            backup_dir=base_path / "backup"
        )
        
        # Aggiungi directory specifiche per tipo di entità
        if entity_type == "EA":
            paths.data_dir = base_path / "enrollment_certificates"
        elif entity_type == "AA":
            paths.data_dir = base_path / "authorization_tickets"
        elif entity_type == "TLM":
            paths.data_dir = base_path / "trust_lists"
        elif entity_type == "ITS":
            # ITS-S ha una struttura più complessa con directory multiple
            paths.data_dir = base_path / "received_messages"
            paths.inbox_dir = base_path / "inbox"
            paths.outbox_dir = base_path / "outbox"
            paths.authorization_tickets_dir = base_path / "authorization_tickets"
            paths.trust_anchors_dir = base_path / "trust_anchors"
            paths.ctl_full_dir = base_path / "ctl_full"
            paths.ctl_delta_dir = base_path / "ctl_delta"
            paths.own_certificates_dir = base_path / "own_certificates"
        elif entity_type == "ROOTCA":
            paths.data_dir = base_path / "subordinates"
        
        # Salva in cache
        cls._path_cache[cache_key] = paths
        
        return paths
    
    @classmethod
    def get_entity_base_dir(cls, entity_type: str, entity_id: str) -> Path:
        """
        Ottiene solo la directory base di un'entità.
        
        Args:
            entity_type: Tipo di entità
            entity_id: ID dell'entità
        
        Returns:
            Path della directory base
        """
        return cls.get_entity_paths(entity_type, entity_id).base_dir
    
    @classmethod
    def normalize_base_dir(cls, entity_type: str, entity_id: str, 
                          base_dir: str) -> Path:
        """
        Normalizza un base_dir per evitare duplicazioni di entity_id.
        
        Previene errori come:
            Input: base_dir="pki_data/ea/EA_001", entity_id="EA_001"
            Output: pki_data/ea/EA_001 (NON pki_data/ea/EA_001/EA_001)
        
        Args:
            entity_type: Tipo di entità
            entity_id: ID dell'entità
            base_dir: Directory base da normalizzare
        
        Returns:
            Path normalizzato
        """
        base_path = Path(base_dir)
        
        # Se base_dir termina già con entity_id, non aggiungere
        if base_path.name == entity_id:
            return base_path
        
        # Se base_dir termina con il tipo di entità (es: "ea", "aa")
        # aggiungi entity_id
        entity_type_lower = entity_type.lower()
        if base_path.name == entity_type_lower:
            return base_path / entity_id
        
        # Altrimenti, assumi che base_dir sia la directory del tipo
        # e aggiungi entity_id
        return base_path / entity_id
    
    @classmethod
    def create_entity_structure(cls, entity_type: str, entity_id: str,
                               base_dir: Optional[str] = None) -> EntityPaths:
        """
        Crea l'intera struttura di directory per un'entità.
        
        Args:
            entity_type: Tipo di entità
            entity_id: ID dell'entità
            base_dir: Directory base custom (opzionale)
        
        Returns:
            EntityPaths con i path creati
        """
        paths = cls.get_entity_paths(entity_type, entity_id, base_dir)
        paths.create_all()
        return paths
    
    @classmethod
    def list_entities(cls, entity_type: str) -> list[str]:
        """
        Lista tutti gli ID delle entità di un tipo.
        
        Args:
            entity_type: Tipo di entità
        
        Returns:
            Lista di entity_id
        """
        entity_type = entity_type.upper()
        
        if entity_type == "ROOTCA":
            # RootCA è singolo
            root_dir = cls.ENTITY_TYPE_DIRS["RootCA"]
            return ["ROOT_CA"] if root_dir.exists() else []
        
        entity_type_dir = cls.ENTITY_TYPE_DIRS.get(entity_type)
        if not entity_type_dir or not entity_type_dir.exists():
            return []
        
        # Lista tutte le sottodirectory
        return [
            d.name for d in entity_type_dir.iterdir()
            if d.is_dir() and d.name.startswith(f"{entity_type}_")
        ]
    
    @classmethod
    def entity_exists(cls, entity_type: str, entity_id: str) -> bool:
        """
        Verifica se un'entità esiste nel filesystem.
        
        Args:
            entity_type: Tipo di entità
            entity_id: ID dell'entità
        
        Returns:
            True se la directory base dell'entità esiste
        """
        base_dir = cls.get_entity_base_dir(entity_type, entity_id)
        return base_dir.exists() and base_dir.is_dir()
    
    @classmethod
    def get_certificate_path(cls, entity_type: str, entity_id: str,
                            cert_name: Optional[str] = None) -> Path:
        """
        Ottiene il path del certificato di un'entità.
        
        Args:
            entity_type: Tipo di entità
            entity_id: ID dell'entità
            cert_name: Nome file certificato (default: {entity_type_lower}_certificate.pem)
        
        Returns:
            Path del certificato
        """
        paths = cls.get_entity_paths(entity_type, entity_id)
        
        if cert_name is None:
            entity_type_lower = entity_type.lower()
            if entity_type == "ROOTCA":
                cert_name = "root_ca_certificate.pem"
            else:
                cert_name = f"{entity_type_lower}_certificate.pem"
        
        return paths.certificates_dir / cert_name
    
    @classmethod
    def get_private_key_path(cls, entity_type: str, entity_id: str,
                           key_name: Optional[str] = None) -> Path:
        """
        Ottiene il path della chiave privata di un'entità.
        
        Args:
            entity_type: Tipo di entità
            entity_id: ID dell'entità
            key_name: Nome file chiave (default: {entity_type_lower}_key.pem)
        
        Returns:
            Path della chiave privata
        """
        paths = cls.get_entity_paths(entity_type, entity_id)
        
        if key_name is None:
            entity_type_lower = entity_type.lower()
            if entity_type == "ROOTCA":
                key_name = "root_ca_key.pem"
            else:
                key_name = f"{entity_type_lower}_key.pem"
        
        return paths.private_keys_dir / key_name
