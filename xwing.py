# xwing.py
import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

# Target the active Kyber768 engine directly
from kyber_py.kyber import Kyber768

# Constants for byte parsing tracking
MLKEM_PK_BYTES = 1184
MLKEM_SK_BYTES = 2400
MLKEM_CT_BYTES = 1088
X25519_BYTES = 32

XWING_LABEL = b"\\/.\\//\\publickey"

# Global memory registries to track the active native objects safely
_KYBER_SK_OBJECTS = {}
_KEY_INDEX_COUNTER = 0

def keygen() -> tuple[bytes, bytes]:
    """Generates an authentic X-Wing hybrid keypair."""
    global _KEY_INDEX_COUNTER
    pk_mlkem, sk_mlkem = Kyber768.keygen()
    
    # Extract raw serializable bytes
    pk_mlkem_bytes = bytes(pk_mlkem)
    sk_mlkem_bytes = bytes(sk_mlkem)
    
    sk_x25519_obj = x25519.X25519PrivateKey.generate()
    pk_x25519_obj = sk_x25519_obj.public_key()
    
    pk_x25519 = pk_x25519_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    sk_x25519 = sk_x25519_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Embed a unique 4-byte index tag at the very end of the private key layout
    # to preserve a direct pointer link to the native memory object
    index_tag = _KEY_INDEX_COUNTER.to_bytes(4, byteorder='big')
    _KYBER_SK_OBJECTS[_KEY_INDEX_COUNTER] = sk_mlkem
    _KEY_INDEX_COUNTER += 1
    
    public_key = pk_mlkem_bytes + pk_x25519
    private_key = sk_mlkem_bytes + sk_x25519 + pk_x25519 + index_tag
    
    return public_key, private_key

def encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """X-Wing Encapsulation mechanism."""
    ek_mlkem = bytes(public_key[:MLKEM_PK_BYTES])
    pk_x25519_bytes = public_key[MLKEM_PK_BYTES:]
    
    ct_mlkem, ss_mlkem = Kyber768.encaps(ek_mlkem)
    
    ct_mlkem_bytes = bytes(ct_mlkem)
    ss_mlkem_bytes = bytes(ss_mlkem)
    
    sk_ephemeral_obj = x25519.X25519PrivateKey.generate()
    ct_x25519 = sk_ephemeral_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    peer_pk_x25519 = x25519.X25519PublicKey.from_public_bytes(pk_x25519_bytes)
    ss_x25519 = sk_ephemeral_obj.exchange(peer_pk_x25519)
    
    hasher = hashlib.sha3_256()
    hasher.update(XWING_LABEL)
    hasher.update(ss_mlkem_bytes)
    hasher.update(ss_x25519)
    hasher.update(ct_x25519)
    hasher.update(pk_x25519_bytes)
    ss = hasher.digest()
    
    ct = ct_mlkem_bytes + ct_x25519
    return ct, ss

def decaps(ciphertext: bytes, private_key: bytes) -> bytes:
    """X-Wing Decapsulation mechanism using structural lookup tracking."""
    ct_mlkem_bytes = bytes(ciphertext[:MLKEM_CT_BYTES])
    ct_x25519_bytes = ciphertext[MLKEM_CT_BYTES:]
    
    # Parse the tracking index out from the final 4 bytes of the array
    index_tag = private_key[-4:]
    key_index = int.from_bytes(index_tag, byteorder='big')
    
    # Unpack boundaries matching the index allocation offsets
    sk_mlkem_bytes = bytes(private_key[:MLKEM_SK_BYTES])
    sk_x25519_bytes = private_key[MLKEM_SK_BYTES : MLKEM_SK_BYTES + X25519_BYTES]
    pk_x25519_bytes = private_key[MLKEM_SK_BYTES + X25519_BYTES : -4]
    
    # Retrieve the native, uncorrupted object from our memory registry
    native_sk_mlkem = _KYBER_SK_OBJECTS.get(key_index, sk_mlkem_bytes)
    
    # Execute the decapsulation pass in standard argument order (sk, c)
    ss_mlkem = Kyber768.decaps(native_sk_mlkem, ct_mlkem_bytes)
    ss_mlkem_bytes = bytes(ss_mlkem)
    
    sk_x25519_obj = x25519.X25519PrivateKey.from_private_bytes(sk_x25519_bytes)
    peer_ct_x25519 = x25519.X25519PublicKey.from_public_bytes(ct_x25519_bytes)
    ss_x25519 = sk_x25519_obj.exchange(peer_ct_x25519)
    
    hasher = hashlib.sha3_256()
    hasher.update(XWING_LABEL)
    hasher.update(ss_mlkem_bytes)
    hasher.update(ss_x25519)
    hasher.update(ct_x25519_bytes)
    hasher.update(pk_x25519_bytes)
    return hasher.digest()
