"""
Pytest Configuration and Shared Fixtures

Fornisce fixture condivise per tutti i test:
- RootCA, EA, AA con directory temporanee (default)
- Opzionale: usa directory data/ persistenti (con PKI_USE_DATA_DIRS=1)
- TrustListManager configurato
- Cleanup automatico dopo i test (solo per tmp directories)

Modalità:
1. Temporary directories (default): directory isolate eliminate automaticamente
2. Data directories: usa data/ esistenti, non elimina dati dopo i test

Author: SecureRoad PKI Project
Date: October 2025
"""

import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from entities.authorization_authority import AuthorizationAuthority
from entities.enrollment_authority import EnrollmentAuthority
from entities.its_station import ITSStation
from entities.root_ca import RootCA
from managers.trust_list_manager import TrustListManager


def _use_data_dirs():
    """Check se usare data directories invece di tmp directories"""
    return os.environ.get('PKI_USE_DATA_DIRS', '0') == '1'


@pytest.fixture(scope="session")
def test_base_dir(tmp_path_factory):
    """
    Directory base per i test:
    - Se PKI_USE_DATA_DIRS=1: usa data/ persistente
    - Altrimenti: crea directory temporanea (eliminata automaticamente)
    """
    if _use_data_dirs():
        # Usa directory data/ del progetto
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        base = os.path.join(project_root, "data")
        print(f"\n[CONFTEST] 📂 Modalità DATA DIRECTORIES: {base}")
        return str(base)
    else:
        # Crea directory temporanea (default)
        base = tmp_path_factory.mktemp("pki_test_data")
        print(f"\n[CONFTEST] 🔒 Modalità TEMPORARY DIRECTORIES: {base}")
        return str(base)


@pytest.fixture(scope="session")
def root_ca(test_base_dir):
    """
    RootCA fixture con directory temporanea.
    Scope: session (creata una volta per tutti i test).
    """
    base_dir = os.path.join(test_base_dir, "root_ca")
    return RootCA(base_dir=base_dir)


@pytest.fixture(scope="session")
def ea(root_ca, test_base_dir):
    """
    EnrollmentAuthority fixture con directory temporanea.
    Scope: session (creata una volta per tutti i test).
    """
    base_dir = os.path.join(test_base_dir, "ea")
    return EnrollmentAuthority(root_ca=root_ca, ea_id="EA_TEST", base_dir=base_dir)


@pytest.fixture(scope="session")
def tlm(root_ca, ea, test_base_dir):
    """
    TrustListManager fixture con EA già aggiunta come trust anchor.
    Scope: session (creata una volta per tutti i test).
    """
    base_dir = os.path.join(test_base_dir, "tlm")
    tlm_instance = TrustListManager(root_ca=root_ca, base_dir=base_dir)
    tlm_instance.add_trust_anchor(ea.certificate, authority_type="EA")
    return tlm_instance


@pytest.fixture(scope="session")
def aa(root_ca, tlm, test_base_dir):
    """
    AuthorizationAuthority fixture con TLM configurato.
    Scope: session (creata una volta per tutti i test).
    """
    base_dir = os.path.join(test_base_dir, "aa")
    return AuthorizationAuthority(root_ca=root_ca, tlm=tlm, aa_id="AA_TEST", base_dir=base_dir)


@pytest.fixture(scope="function")
def its_station(test_base_dir):
    """
    ITSStation fixture con directory temporanea.
    Scope: function (nuova istanza per ogni test).
    """
    base_dir = os.path.join(test_base_dir, "itss", f"test_vehicle_{id(object())}")
    return ITSStation(its_id="TEST_VEHICLE", base_dir=base_dir)


@pytest.fixture(scope="function")
def pki_infrastructure(root_ca, ea, tlm, aa):
    """
    Fixture che fornisce l'intera infrastruttura PKI.
    Scope: function (disponibile per ogni test).
    """
    return {
        "root_ca": root_ca,
        "ea": ea,
        "tlm": tlm,
        "aa": aa,
    }


@pytest.fixture(scope="session", autouse=True)
def cleanup_data_folder():
    """
    Cleanup automatico dopo tutti i test.
    
    Comportamento:
    - Se PKI_USE_DATA_DIRS=1: NON elimina nulla (data persistenti)
    - Altrimenti: pytest elimina automaticamente le tmp directories
    
    Autouse=True significa che viene eseguito automaticamente.
    """
    yield  # Esegue tutti i test
    
    # Cleanup SOLO se NON stiamo usando data directories persistenti
    if _use_data_dirs():
        print("\n[CLEANUP] 📂 Modalità DATA DIRECTORIES: dati NON eliminati")
        print("[CLEANUP] ℹ️  Le directory data/ sono state preservate per ispezione")
        return
    
    # In modalità tmp directories, pytest gestisce automaticamente la pulizia
    print("\n[CLEANUP] 🔒 Modalità TEMPORARY DIRECTORIES: cleanup automatico da pytest")
    
    # Cleanup opzionale della cartella data/ principale (se esiste da test precedenti)
    data_dir = Path("./data")
    if data_dir.exists():
        # Rimuovi solo le directory di test note (per sicurezza)
        test_dirs = [
            "data/root_ca",
            "data/ea/EA_TEST",
            "data/ea/EA_API",
            "data/ea/EA_TLM",
            "data/aa/AA_TEST",
            "data/aa/AA_API",
            "data/tlm",
            "data/itss/TEST_VEHICLE",
            "data/itss/test_vehicle_*",
        ]
        
        for test_dir in test_dirs:
            path = Path(test_dir)
            if path.exists():
                try:
                    shutil.rmtree(path, ignore_errors=True)
                    print(f"[CLEANUP] Rimossa directory test residua: {test_dir}")
                except Exception as e:
                    print(f"[CLEANUP] Errore rimozione {test_dir}: {e}")
