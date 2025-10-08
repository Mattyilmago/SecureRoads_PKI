import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from entities.enrollment_authority import EnrollmentAuthority
from entities.root_ca import RootCA
from managers.trust_list_manager import TrustListManager
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

@pytest.fixture(scope='module')
def root_ca():
    return RootCA(base_dir='data/root_ca')

@pytest.fixture(scope='module')
def ea(root_ca):
    return EnrollmentAuthority(root_ca=root_ca, ea_id='EA_TLM', base_dir='data/ea')

class TestTrustListManager:
    def test_initialization(self, root_ca):
        tlm = TrustListManager(root_ca=root_ca, base_dir='data/tlm')
        assert tlm is not None
        assert hasattr(tlm, 'trust_anchors')
    
    def test_add_trust_anchor(self, root_ca, ea):
        tlm = TrustListManager(root_ca=root_ca, base_dir='data/tlm')
        tlm.add_trust_anchor(ea.certificate, authority_type='EA')
        assert len(tlm.trust_anchors) > 0
    
    def test_publish_full_ctl(self, root_ca, ea):
        tlm = TrustListManager(root_ca=root_ca, base_dir='data/tlm')
        tlm.add_trust_anchor(ea.certificate, authority_type='EA')
        ctl_path = tlm.publish_full_ctl(validity_days=30)
        assert ctl_path is not None
    
    def test_tlm_directories(self, root_ca):
        tlm = TrustListManager(root_ca=root_ca, base_dir='data/tlm')
        assert os.path.exists('data/tlm/ctl')

class TestCRLManager:
    def test_crl_statistics(self, ea):
        stats = ea.crl_manager.get_statistics()
        assert 'total_revoked' in stats
    
    def test_publish_full_crl(self, ea):
        crl = ea.crl_manager.publish_full_crl(validity_days=7)
        assert crl is not None
