"""
ETSI ITS PKI Protocol Implementations
Implements the core cryptographic protocols and message types for V2X PKI
according to ETSI TS 102 941 and related standards
"""

__version__ = "1.0.0"

# Import utility functions first
from .etsi_certificate_utils import (
    time32_encode,
    time32_decode,
    compute_hashed_id8,
    extract_validity_period,
    encode_public_key_compressed,
    decode_public_key_compressed,
    verify_asn1_certificate_signature,
    extract_public_key_from_asn1_certificate,
)

# Import message types and enums
from .etsi_message_types import (
    ETSIMessageType,
    ResponseCode,
    PublicKeyAlgorithm,
    SymmetricAlgorithm,
    InnerEcRequest,
    InnerEcResponse,
    InnerAtRequest,
    InnerAtResponse,
    SharedAtRequest,
    compute_request_hash,
)

# Import butterfly key expansion
from .butterfly_key_expansion import (
    derive_at_keys,
    generate_key_tag,
    derive_ecc_key_pair_from_seed,
    compute_shared_secret_ecdh,
    validate_butterfly_keys,
    compute_key_fingerprint,
    derive_ticket_hmac,
)

# Import certificate modules
from .etsi_root_certificate import *
from .etsi_authority_certificate import *
from .etsi_enrollment_certificate import *
from .etsi_authorization_ticket import *
from .etsi_link_certificate import *
from .etsi_trust_list import *
