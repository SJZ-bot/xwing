# xwing.py
import hashlib
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

from kyber_py.kyber import Kyber768

MLKEM_PK_BYTES = 1184
MLKEM_SK_BYTES = 2400
MLKEM_CT_BYTES = 1088
X25519_BYTES = 32

XWING_LABEL = b"\\/.\\//\\publickey"

# Global memory registries to track the active native objects safely.
# The registry is keyed by the ML-KEM secret bytes so it remains stable
# without embedding an extra 4-byte tag into the serialized private key.
_KYBER_SK_OBJECTS = {}


def keygen() -> tuple[bytes, bytes]:
    """Generates an authentic X-Wing hybrid keypair."""
    pk_mlkem, sk_mlkem = Kyber768.keygen()

    pk_mlkem_bytes = bytes(pk_mlkem)
    sk_mlkem_bytes = bytes(sk_mlkem)

    sk_x25519_obj = x25519.X25519PrivateKey.generate()
    pk_x25519_obj = sk_x25519_obj.public_key()

    pk_x25519 = pk_x25519_obj.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    sk_x25519 = sk_x25519_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    _KYBER_SK_OBJECTS[sk_mlkem_bytes] = sk_mlkem

    public_key = pk_mlkem_bytes + pk_x25519
    private_key = sk_mlkem_bytes + sk_x25519 + pk_x25519
    return public_key, private_key


def encaps(public_key: bytes) -> tuple[bytes, bytes]:
    """X-Wing Encapsulation mechanism."""
    ek_mlkem = bytes(public_key[:MLKEM_PK_BYTES])
    pk_x25519_bytes = public_key[MLKEM_PK_BYTES:]

    ss_mlkem, ct_mlkem = Kyber768.encaps(ek_mlkem)

    ct_mlkem_bytes = bytes(ct_mlkem)
    ss_mlkem_bytes = bytes(ss_mlkem)

    sk_ephemeral_obj = x25519.X25519PrivateKey.generate()
    ct_x25519 = sk_ephemeral_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
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
    """X-Wing Decapsulation mechanism using the native ML-KEM secret key."""
    ct_mlkem_bytes = bytes(ciphertext[:MLKEM_CT_BYTES])
    ct_x25519_bytes = ciphertext[MLKEM_CT_BYTES:]

    sk_mlkem_bytes = bytes(private_key[:MLKEM_SK_BYTES])
    sk_x25519_bytes = private_key[MLKEM_SK_BYTES : MLKEM_SK_BYTES + X25519_BYTES]
    pk_x25519_bytes = private_key[MLKEM_SK_BYTES + X25519_BYTES :]

    native_sk_mlkem = _KYBER_SK_OBJECTS.get(sk_mlkem_bytes, sk_mlkem_bytes)
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
