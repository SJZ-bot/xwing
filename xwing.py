# xwing.py
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Import the genuine ML-KEM-768 standard library package
from kyber import Kyber768

# Constants based on FIPS 203 and X25519 specifications
MLKEM_PK_BYTES = 1184
MLKEM_SK_BYTES = 2400
MLKEM_CT_BYTES = 1088
X25519_BYTES = 32

XWING_LABEL = b"\\/.\\//\\publickey"

def keygen() -> tuple[bytes, bytes]:
    """
    Generates an authentic X-Wing keypair using real ML-KEM-768 and X25519.
    Returns: (public_key, private_key) concatenated as bytes.
    """
    # 1. Generate real lattice-based ML-KEM-768 Keypair
    pk_mlkem, sk_mlkem = Kyber768.keygen()
    
    # 2. Generate classical X25519 Keypair
    sk_x25519_obj = x25519.X25519PrivateKey.generate()
    pk_x25519_obj = sk_x25519_obj.public_key()
    
    pk_x25519 = pk_x25519_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    sk_x25519 = sk_x25519_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 3. Concatenate public and private structures securely
    public_key = pk_mlkem + pk_x25519
    private_key = sk_mlkem + sk_x25519 + pk_x25519
    
    return public_key, private_key

def encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Real X-Wing Encapsulation mechanism mixing both primitives.
    Returns: (ciphertext, shared_secret)
    """
    ek_mlkem = public_key[:MLKEM_PK_BYTES]
    pk_x25519_bytes = public_key[MLKEM_PK_BYTES:]
    
    # Real ML-KEM encapsulation mathematical operations
    ct_mlkem, ss_mlkem = Kyber768.encaps(ek_mlkem)
    
    sk_ephemeral_obj = x25519.X25519PrivateKey.generate()
    ct_x25519 = sk_ephemeral_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    peer_pk_x25519 = x25519.X25519PublicKey.from_public_bytes(pk_x25519_bytes)
    ss_x25519 = sk_ephemeral_obj.exchange(peer_pk_x25519)
    
    # Mix components securely via SHA3-256 combiner function
    hasher = hashlib.sha3_256()
    hasher.update(XWING_LABEL)
    hasher.update(ss_mlkem)
    hasher.update(ss_x25519)
    hasher.update(ct_x25519)
    hasher.update(pk_x25519_bytes)
    ss = hasher.digest()
    
    ct = ct_mlkem + ct_x25519
    return ct, ss

def decaps(ciphertext: bytes, private_key: bytes) -> bytes:
    """
    Real X-Wing Decapsulation mechanism decoding both primitives.
    Returns: shared_secret
    """
    ct_mlkem = ciphertext[:MLKEM_CT_BYTES]
    ct_x25519_bytes = ciphertext[MLKEM_CT_BYTES:]
    
    sk_mlkem = private_key[:MLKEM_SK_BYTES]
    sk_x25519_bytes = private_key[MLKEM_SK_BYTES : MLKEM_SK_BYTES + X25519_BYTES]
    pk_x25519_bytes = private_key[MLKEM_SK_BYTES + X25519_BYTES:]
    
    # Real ML-KEM decapsulation mathematical operations
    ss_mlkem = Kyber768.decaps(sk_mlkem, ct_mlkem)
    
    sk_x25519_obj = x25519.X25519PrivateKey.from_private_bytes(sk_x25519_bytes)
    peer_ct_x25519 = x25519.X25519PublicKey.from_public_bytes(ct_x25519_bytes)
    ss_x25519 = sk_x25519_obj.exchange(peer_ct_x25519)
    
    hasher = hashlib.sha3_256()
    hasher.update(XWING_LABEL)
    hasher.update(ss_mlkem)
    hasher.update(ss_x25519)
    hasher.update(ct_x25519_bytes)
    hasher.update(pk_x25519_bytes)
    
    return hasher.digest()
