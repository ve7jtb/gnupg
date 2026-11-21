"""PIN-free regression tests for the hardware adapter's protocol boundary."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('component', Path(__file__).parents[1]/'component.py')
component = importlib.util.module_from_spec(spec)
spec.loader.exec_module(component)


class ComponentTests(unittest.TestCase):
    def test_ed25519_preserves_digest(self):
        # Ed25519 signs the OpenPGP digest as a raw message, without prehashing.
        digest = bytes(range(48))
        self.assertEqual(component.payload('Ed25519', b'', digest), digest)

    def test_ed25519_accepts_sha256_digest(self):
        # GnuPG can select SHA-256 for classical v4/v5 Ed25519 signatures.
        # The component signs these 32 bytes directly, without rehashing.
        digest = bytes(range(32))
        self.assertEqual(component.payload('Ed25519', b'', digest), digest)

    def test_mldsa_rejects_sha256_digest(self):
        # Fixing classical compatibility must not weaken the hybrid profile.
        public = bytes.fromhex('308207b2300b0609608648016503040312038207a100') + bytes(1952)
        with self.assertRaises(ValueError):
            component.payload('ML-DSA-65', public, bytes(32))

    def test_mlkem_preserves_ciphertext(self):
        # The RFC/LibrePGP combiner remains in GnuPG, outside this primitive.
        ciphertext = b'\x41' * 1088
        self.assertEqual(component.payload('ML-KEM-768', b'', ciphertext), ciphertext)

    def test_x25519_constructs_spki(self):
        # Only the ephemeral public key is wrapped; no secret is serialized.
        peer = bytes(range(32))
        self.assertEqual(component.payload('X25519', b'', peer),
                         bytes.fromhex('302a300506032b656e032100') + peer)

    def test_wrong_lengths_fail(self):
        # Reject malformed requests before asking the hardware for any PIN.
        for algorithm, size in [('Ed25519', 31), ('ML-KEM-768', 1087), ('X25519', 33)]:
            with self.subTest(algorithm=algorithm), self.assertRaises(ValueError):
                component.payload(algorithm, b'', bytes(size))

    def test_mldsa_rejects_wrong_public_encoding(self):
        # A wrong SPKI cannot be used to calculate external mu for another key.
        with self.assertRaises(ValueError):
            component.payload('ML-DSA-65', b'\0' * 1974, b'\0' * 48)

    def test_unknown_algorithm_fails(self):
        # No generic algorithm passthrough or provisioning operations exist.
        with self.assertRaises(ValueError):
            component.payload('RESET', b'', b'')


if __name__ == '__main__':
    unittest.main()
