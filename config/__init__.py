"""
PKI Configuration Package

Centralizza configurazioni, percorsi e costanti del sistema PKI.
"""

from .pki_config import (
    PKI_PATHS,
    PKI_CONSTANTS,
    get_entity_base_dir,
)

__all__ = [
    'PKI_PATHS',
    'PKI_CONSTANTS',
    'get_entity_base_dir',
]
