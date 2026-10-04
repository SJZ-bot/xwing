import unittest
import os
import xwing

class TestXWing(unittest.TestCase):
    def test_roundtrip_success(self):
        """Tests a successful full key exchange round-trip."""
        pk, sk = xwing.keygen()
        ct, ss_encaps = xwing.encaps(pk)
        ss_decaps = xwing.decaps(ct, sk)
        self.assertEqual(ss_encaps, ss_decaps, "Shared secrets must match perfectly.")

    def test_key_lengths(self):
        """Verifies structure and size of generated keys."""
        pk, sk = xwing.keygen()
        expected_pk_len = xwing.MLKEM_PK_BYTES + xwing.X25519_BYTES
        expected_sk_len = xwing.MLKEM_SK_BYTES + xwing.X25519_BYTES + xwing.X25519_BYTES
        self.assertEqual(len(pk), expected_pk_len)
        self.assertEqual(len(sk), expected_sk_len)

    def test_decaps_failure_with_wrong_key(self):
        """Verifies decapsulation failure/mismatch with incorrect keys (Edge Case)."""
        pk1, sk1 = xwing.keygen()
        pk2, sk2 = xwing.keygen()
        ct, ss_encaps = xwing.encaps(pk1)
        
        # Decapsulate using the wrong private key
        ss_wrong = xwing.decaps(ct, sk2)
        self.assertNotEqual(ss_encaps, ss_wrong, "Decapsulation with wrong key must fail to reproduce the secret.")

    def test_decaps_failure_with_corrupted_ciphertext(self):
        """Verifies decapsulation behavior with modified ciphertexts."""
        pk, sk = xwing.keygen()
        ct, ss_encaps = xwing.encaps(pk)
        
        # Corrupt the last byte of ciphertext
        corrupted_ct = bytearray(ct)
        corrupted_ct[-1] ^= 0xFF
        
        ss_corrupted = xwing.decaps(bytes(corrupted_ct), sk)
        self.assertNotEqual(ss_encaps, ss_corrupted)

if __name__ == "__main__":
    unittest.main()
