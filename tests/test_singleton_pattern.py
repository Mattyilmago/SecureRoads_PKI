"""
Test Singleton Pattern per RootCA e TLM_MAIN

Verifica che le istanze condivise funzionino correttamente e non
causino re-inizializzazioni multiple.

Author: SecureRoad PKI Project
Date: October 2025
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from entities.root_ca import RootCA
from entities.enrollment_authority import EnrollmentAuthority
from entities.authorization_authority import AuthorizationAuthority
from managers.trust_list_manager import TrustListManager


def test_root_ca_singleton():
    """Verifica che il singleton pattern per RootCA funzioni"""
    # Simula il pattern usato in server.py
    _root_ca_instance = None
    
    def get_or_create_root_ca():
        nonlocal _root_ca_instance
        if _root_ca_instance is None:
            _root_ca_instance = RootCA(base_dir="data/root_ca")
        return _root_ca_instance
    
    # Prima chiamata - crea istanza
    root_ca_1 = get_or_create_root_ca()
    assert root_ca_1 is not None
    
    # Seconda chiamata - riusa istanza
    root_ca_2 = get_or_create_root_ca()
    assert root_ca_2 is root_ca_1  # Stessa istanza!
    
    # Terza chiamata - riusa istanza
    root_ca_3 = get_or_create_root_ca()
    assert root_ca_3 is root_ca_1  # Stessa istanza!
    
    print("✅ RootCA singleton pattern works correctly")


def test_tlm_singleton():
    """Verifica che il singleton pattern per TLM_MAIN funzioni"""
    # Simula il pattern usato in server.py
    _root_ca_instance = None
    _tlm_main_instance = None
    
    def get_or_create_root_ca():
        nonlocal _root_ca_instance
        if _root_ca_instance is None:
            _root_ca_instance = RootCA(base_dir="data/root_ca")
        return _root_ca_instance
    
    def get_or_create_tlm_main():
        nonlocal _tlm_main_instance
        if _tlm_main_instance is None:
            root_ca = get_or_create_root_ca()
            _tlm_main_instance = TrustListManager(root_ca, base_dir="./data/tlm/TLM_MAIN/")
        return _tlm_main_instance
    
    # Prima chiamata - crea istanza
    tlm_1 = get_or_create_tlm_main()
    assert tlm_1 is not None
    
    # Seconda chiamata - riusa istanza
    tlm_2 = get_or_create_tlm_main()
    assert tlm_2 is tlm_1  # Stessa istanza!
    
    # Terza chiamata - riusa istanza
    tlm_3 = get_or_create_tlm_main()
    assert tlm_3 is tlm_1  # Stessa istanza!
    
    print("✅ TLM_MAIN singleton pattern works correctly")


def test_aa_requires_tlm():
    """Verifica che AA richieda obbligatoriamente TLM"""
    root_ca = RootCA(base_dir="data/root_ca")
    
    # Tentativo di creare AA senza TLM - deve fallire
    try:
        aa = AuthorizationAuthority(root_ca, tlm=None, aa_id="AA_TEST_FAIL")
        assert False, "AA dovrebbe richiedere TLM obbligatoriamente"
    except ValueError as e:
        assert "TrustListManager" in str(e)
        assert "obbligatorio" in str(e)
        print("✅ AA correctly requires TLM")


def test_multiple_aa_share_tlm():
    """Verifica che multiple AA condividano lo stesso TLM_MAIN"""
    # Simula il pattern usato in server.py
    _root_ca_instance = None
    _tlm_main_instance = None
    
    def get_or_create_root_ca():
        nonlocal _root_ca_instance
        if _root_ca_instance is None:
            _root_ca_instance = RootCA(base_dir="data/root_ca")
        return _root_ca_instance
    
    def get_or_create_tlm_main():
        nonlocal _tlm_main_instance
        if _tlm_main_instance is None:
            root_ca = get_or_create_root_ca()
            _tlm_main_instance = TrustListManager(root_ca, base_dir="./data/tlm/TLM_MAIN/")
        return _tlm_main_instance
    
    # Crea prima AA
    root_ca = get_or_create_root_ca()
    tlm = get_or_create_tlm_main()
    aa1 = AuthorizationAuthority(root_ca, tlm, aa_id="AA_001", base_dir="./data/aa/AA_001")
    
    # Crea seconda AA - usa stesso TLM
    aa2 = AuthorizationAuthority(root_ca, tlm, aa_id="AA_002", base_dir="./data/aa/AA_002")
    
    # Verifica che entrambe le AA usino lo stesso TLM
    assert aa1.tlm is aa2.tlm  # Stessa istanza TLM!
    assert aa1.tlm is tlm
    assert aa2.tlm is tlm
    
    print("✅ Multiple AA correctly share same TLM_MAIN instance")


if __name__ == "__main__":
    test_root_ca_singleton()
    test_tlm_singleton()
    test_aa_requires_tlm()
    test_multiple_aa_share_tlm()
    print("\n✅ Tutti i test singleton superati!")
