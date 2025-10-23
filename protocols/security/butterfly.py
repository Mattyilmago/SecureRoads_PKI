"""
Butterfly Key Expansion - ETSI TS 102941 V2.1.1 Section 6.3.3

Implements butterfly key expansion for batch Authorization Ticket generation
with unlinkability guarantees using HKDF key derivation.

Standards Reference:
- ETSI TS 102941 V2.1.1 Section 6.3.3 - Butterfly Key Expansion

Author: SecureRoad PKI Project
Date: October 2025
"""

import hashlib
import secrets
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ============================================================================
# CORE BUTTERFLY KEY DERIVATION
# ============================================================================


def derive_at_keys(
    shared_secret: bytes, key_tag: bytes, batch_size: int
) -> List[Tuple[bytes, bytes]]:
    """
    Derives N key pairs for Authorization Tickets using butterfly expansion.

    Uses HKDF with SHA-256 to derive verification and encryption keys
    for each AT, ensuring unlinkability and deterministic derivation.

    Args:
        shared_secret: Shared secret seed (min 32 bytes)
        key_tag: Unique request tag (16 bytes)
        batch_size: Number of key pairs to generate (1-100)

    Returns:
        List of (verification_key, encryption_key) tuples (each 32 bytes)
    """
    # Validazione input
    if len(shared_secret) < 32:
        raise ValueError(
            f"shared_secret deve essere almeno 32 bytes, ricevuto {len(shared_secret)}"
        )

    if len(key_tag) != 16:
        raise ValueError(f"key_tag deve essere 16 bytes, ricevuto {len(key_tag)}")

    if batch_size < 1 or batch_size > 100:
        raise ValueError(f"batch_size deve essere 1-100, ricevuto {batch_size}")

    print(f"[BUTTERFLY] Derivando {batch_size} coppie di chiavi...")
    print(f"[BUTTERFLY]   Shared secret: {len(shared_secret)} bytes")
    print(f"[BUTTERFLY]   Key tag: {key_tag.hex()[:16]}...")

    keys = []

    for i in range(batch_size):
        # === DERIVA VERIFICATION KEY ===
        # Info = keyTag || index || "verification"
        info_verification = key_tag + i.to_bytes(2, "big") + b"verification"

        kdf_verification = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bit key
            salt=None,  # ETSI non specifica salt
            info=info_verification,
        )
        verification_key = kdf_verification.derive(shared_secret)

        # === DERIVA ENCRYPTION KEY ===
        # Info = keyTag || index || "encryption"
        info_encryption = key_tag + i.to_bytes(2, "big") + b"encryption"

        kdf_encryption = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bit key
            salt=None,
            info=info_encryption,
        )
        encryption_key = kdf_encryption.derive(shared_secret)

        keys.append((verification_key, encryption_key))

        # Log solo per primi/ultimi 2 per debug
        if i < 2 or i >= batch_size - 2:
            print(
                f"[BUTTERFLY]   AT #{i}: v_key={verification_key.hex()[:16]}... e_key={encryption_key.hex()[:16]}..."
            )

    print(f"[BUTTERFLY] ✓ Derivate {len(keys)} coppie di chiavi")

    # Verifica unlinkability: tutte le chiavi devono essere diverse
    verification_keys_set = set([k[0] for k in keys])
    if len(verification_keys_set) != batch_size:
        raise RuntimeError("ERRORE: Chiavi duplicate rilevate (unlinkability violata!)")

    return keys


def derive_ecc_key_pair_from_seed(seed: bytes) -> Tuple[ec.EllipticCurvePrivateKey, bytes]:
    """
    Deriva una coppia di chiavi ECC (SECP256R1) da un seed deterministico.

    Questo permette di rigenerare la stessa coppia di chiavi dal seed,
    utile per:
    - ITS-S che vuole rigenerare chiavi senza storage
    - Testing deterministico

    Args:
        seed: Seed da cui derivare la chiave (32 bytes)

    Returns:
        Tuple (private_key, public_key_bytes)
    """
    if len(seed) != 32:
        raise ValueError(f"Seed deve essere 32 bytes, ricevuto {len(seed)}")

    # Genera chiave privata da seed
    # Production note: Use HSM or more robust KDF in production environments
    private_value = int.from_bytes(seed, "big")

    # Crea chiave privata ECC
    private_key = ec.derive_private_key(private_value, ec.SECP256R1())

    # Estrai chiave pubblica
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint
    )

    return private_key, public_key_bytes


def compute_shared_secret_ecdh(
    itss_private_key: ec.EllipticCurvePrivateKey, aa_public_key: ec.EllipticCurvePublicKey
) -> bytes:
    """
    Calcola shared secret usando ECDH (Elliptic Curve Diffie-Hellman).

    ECDH permette a ITS-S e AA di derivare lo stesso segreto condiviso
    senza trasmetterlo sulla rete:

    ITS-S: shared_secret = ECDH(itss_private_key, aa_public_key)
    AA:    shared_secret = ECDH(aa_private_key, itss_public_key)

    → Entrambi ottengono lo stesso shared_secret!

    Args:
        itss_private_key: Chiave privata dell'ITS-S
        aa_public_key: Chiave pubblica dell'AA (da certificato AA)

    Returns:
        Shared secret (32 bytes)
    """
    # ECDH key agreement
    shared_key = itss_private_key.exchange(ec.ECDH(), aa_public_key)

    # Deriva shared secret usando HKDF per avere lunghezza fissa
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"butterfly_shared_secret")

    shared_secret = kdf.derive(shared_key)

    return shared_secret


def generate_key_tag() -> bytes:
    """
    Genera un key tag random per butterfly request.

    Key tag è usato come input nella derivazione delle chiavi,
    garantendo che batch diversi abbiano chiavi diverse anche
    con lo stesso shared_secret.

    Returns:
        Random key tag (16 bytes)
    """
    return secrets.token_bytes(16)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================


def validate_butterfly_keys(keys: List[Tuple[bytes, bytes]]) -> bool:
    """
    Valida che le chiavi derivate siano conformi ai requisiti ETSI.

    Verifica:
    1. Tutte le chiavi sono diverse (unlinkability)
    2. Lunghezza corretta (32 bytes)
    3. Nessuna chiave null

    Args:
        keys: Lista di coppie (verification_key, encryption_key)

    Returns:
        True se tutte le verifiche passano
    """
    if not keys:
        print("[BUTTERFLY] ERRORE: Lista chiavi vuota")
        return False

    # Verifica lunghezza
    for i, (v_key, e_key) in enumerate(keys):
        if len(v_key) != 32:
            print(f"[BUTTERFLY] ERRORE: AT #{i} verification key non 32 bytes")
            return False
        if len(e_key) != 32:
            print(f"[BUTTERFLY] ERRORE: AT #{i} encryption key non 32 bytes")
            return False

    # Verifica unlinkability (tutte diverse)
    all_keys = [k[0] for k in keys] + [k[1] for k in keys]
    unique_keys = set(all_keys)

    if len(unique_keys) != len(all_keys):
        print(f"[BUTTERFLY] ERRORE: Chiavi duplicate rilevate!")
        print(f"[BUTTERFLY]   Totale chiavi: {len(all_keys)}")
        print(f"[BUTTERFLY]   Chiavi uniche: {len(unique_keys)}")
        return False

    print(f"[BUTTERFLY] ✓ Validazione chiavi OK: {len(keys)} coppie, tutte diverse")
    return True


def compute_key_fingerprint(key: bytes) -> str:
    """
    Calcola fingerprint SHA-256 di una chiave per logging.

    Args:
        key: Chiave da cui calcolare fingerprint

    Returns:
        Hex string dei primi 8 bytes dello SHA-256
    """
    hash_obj = hashlib.sha256(key)
    return hash_obj.hexdigest()[:16]


def derive_ticket_hmac(master_hmac: bytes, ticket_index: int) -> bytes:
    """
    Deriva un HMAC key specifico per un ticket dal master HMAC.
    
    Usa HKDF per derivare chiavi univoche per ogni ticket nel batch,
    garantendo unlinkability.
    
    Args:
        master_hmac: Master HMAC key (32 bytes)
        ticket_index: Indice del ticket (0-based)
        
    Returns:
        HMAC key derivato per il ticket (32 bytes)
    """
    if len(master_hmac) != 32:
        raise ValueError(f"master_hmac deve essere 32 bytes, ricevuto {len(master_hmac)}")
    
    # Info = "ticket_hmac" || index
    info = b"ticket_hmac" + ticket_index.to_bytes(4, "big")
    
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    
    return kdf.derive(master_hmac)


# ============================================================================
# CLASS-BASED INTERFACE (WRAPPER)
# ============================================================================


class ButterflyExpansion:
    """
    Butterfly Key Expansion for Authorization Ticket batch generation.
    
    Provides a clean class-based interface to the butterfly key expansion protocol,
    ensuring unlinkability and deterministic key derivation.
    
    Usage:
        butterfly = ButterflyExpansion()
        keys = butterfly.derive_keys(shared_secret, key_tag, batch_size=20)
        for verification_key, encryption_key in keys:
            # Use keys for AT generation
            pass
    """
    
    @staticmethod
    def derive_keys(
        shared_secret: bytes,
        key_tag: bytes,
        batch_size: int
    ) -> List[Tuple[bytes, bytes]]:
        """
        Derive N key pairs for Authorization Tickets using butterfly expansion.
        
        Args:
            shared_secret: Shared secret seed (min 32 bytes)
            key_tag: Unique request tag (16 bytes)
            batch_size: Number of key pairs to generate (1-100)
            
        Returns:
            List of (verification_key, encryption_key) tuples (each 32 bytes)
        """
        return derive_at_keys(shared_secret, key_tag, batch_size)
    
    @staticmethod
    def generate_key_tag() -> bytes:
        """
        Generate random key tag (16 bytes).
        
        Returns:
            bytes: Random 16-byte key tag
        """
        return generate_key_tag()
    
    @staticmethod
    def derive_key_pair_from_seed(seed: bytes):
        """
        Derive ECC key pair from deterministic seed.
        
        Args:
            seed: Seed bytes (32+ bytes)
            
        Returns:
            Tuple of (private_key, public_key_bytes)
        """
        return derive_ecc_key_pair_from_seed(seed)
    
    @staticmethod
    def compute_shared_secret(private_key, public_key) -> bytes:
        """
        Compute ECDH shared secret.
        
        Args:
            private_key: Local private key
            public_key: Remote public key
            
        Returns:
            bytes: Shared secret (32 bytes)
        """
        return compute_shared_secret_ecdh(private_key, public_key)
    
    @staticmethod
    def validate_keys(keys: List[Tuple[bytes, bytes]]) -> bool:
        """
        Validate butterfly keys for unlinkability.
        
        Args:
            keys: List of (verification_key, encryption_key) tuples
            
        Returns:
            bool: True if all keys are unique (unlinkable)
        """
        return validate_butterfly_keys(keys)
    
    @staticmethod
    def compute_fingerprint(key: bytes) -> str:
        """
        Compute key fingerprint for logging/debugging.
        
        Args:
            key: Key bytes
            
        Returns:
            str: Hex fingerprint
        """
        return compute_key_fingerprint(key)
    
    @staticmethod
    def derive_hmac(master_hmac: bytes, ticket_index: int) -> bytes:
        """
        Derive HMAC key for specific ticket.
        
        Args:
            master_hmac: Master HMAC key (32 bytes)
            ticket_index: Index of ticket in batch
            
        Returns:
            bytes: Derived HMAC key (32 bytes)
        """
        return derive_ticket_hmac(master_hmac, ticket_index)
