"""
ECIES (Elliptic Curve Integrated Encryption Scheme) Implementation.

Implements ECIES encryption/decryption according to:
- ETSI TS 102941 V2.1.1 Section 5.2.8 (Encryption algorithms)
- IEEE 1609.2 Section 5.3.4 (ECIES encryption)
- SEC 1 v2.0 (Standards for Efficient Cryptography)

Security Properties:
- Perfect Forward Secrecy: Each message uses new ephemeral keys
- Authenticated Encryption: AES-GCM provides integrity + confidentiality
- Non-malleability: Impossible to modify ciphertext without detection
- IND-CCA2 Security: Secure against chosen-ciphertext attacks

Output Format:
    ephemeral_public_key (65 bytes) || nonce (12 bytes) || ciphertext || auth_tag (16 bytes)
"""

import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def ecies_encrypt(plaintext: bytes, recipient_public_key: EllipticCurvePublicKey) -> bytes:
    """
    Encrypt message using ECIES with AES-128-GCM.

    Encryption Flow:
    1. Generate ephemeral key pair
    2. Perform ECDH key agreement with recipient's public key
    3. Derive AES-128 key using HKDF-SHA256
    4. Encrypt plaintext with AES-128-GCM (authenticated encryption)
    5. Include ephemeral public key in ciphertext

    Args:
        plaintext: Data to encrypt
        recipient_public_key: Recipient's ECDSA public key (SECP256R1)

    Returns:
        Encrypted data: ephemeral_public_key (65 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> recipient_key = ec.generate_private_key(ec.SECP256R1())
        >>> ciphertext = ecies_encrypt(b"secret message", recipient_key.public_key())
        >>> len(ciphertext) >= 65 + 12 + len(b"secret message") + 16
        True
    """
    # 1. Generate ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    # 2. Perform ECDH key agreement
    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)

    # 3. Derive AES-128 key using HKDF-SHA256
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # AES-128 (128 bits = 16 bytes)
        salt=None,
        info=b"ETSI-102941-AES128",
        backend=default_backend(),
    ).derive(shared_secret)

    # 4. Encrypt with AES-128-GCM
    aesgcm = AESGCM(derived_key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # Includes auth tag

    # 5. Serialize ephemeral public key (uncompressed format: 0x04 || x || y)
    ephemeral_public_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    # Output: ephemeral_public_key (65 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
    return ephemeral_public_bytes + nonce + ciphertext


def ecies_decrypt(encrypted_data: bytes, recipient_private_key: EllipticCurvePrivateKey) -> bytes:
    """
    Decrypt message using ECIES with AES-128-GCM.

    Decryption Flow:
    1. Extract ephemeral public key, nonce, and ciphertext
    2. Perform ECDH key agreement with ephemeral public key
    3. Derive AES-128 key using HKDF-SHA256
    4. Decrypt and verify ciphertext with AES-128-GCM

    Args:
        encrypted_data: Encrypted data from ecies_encrypt
        recipient_private_key: Recipient's ECDSA private key (SECP256R1)

    Returns:
        Decrypted plaintext

    Raises:
        ValueError: If decryption fails (wrong key, corrupted data, or authentication failure)

    Example:
        >>> from cryptography.hazmat.primitives.asymmetric import ec
        >>> recipient_key = ec.generate_private_key(ec.SECP256R1())
        >>> ciphertext = ecies_encrypt(b"secret", recipient_key.public_key())
        >>> plaintext = ecies_decrypt(ciphertext, recipient_key)
        >>> plaintext == b"secret"
        True
    """
    # 1. Parse encrypted data
    ephemeral_public_bytes = encrypted_data[:65]  # Uncompressed point (0x04 + 32 + 32)
    nonce = encrypted_data[65:77]  # 12 bytes
    ciphertext = encrypted_data[77:]  # Ciphertext + auth tag (16 bytes)

    # 2. Reconstruct ephemeral public key
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_public_bytes
    )

    # 3. Perform ECDH key agreement
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # 4. Derive AES-128 key using HKDF-SHA256
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # AES-128
        salt=None,
        info=b"ETSI-102941-AES128",
        backend=default_backend(),
    ).derive(shared_secret)

    # 5. Decrypt and verify with AES-128-GCM
    aesgcm = AESGCM(derived_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        raise ValueError(f"ECIES decryption failed: {e}")

