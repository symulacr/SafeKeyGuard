"""
SafeKeyGuard - Encryption Module Tests

"""

import unittest
from safekeyguard import SafeKeyGuard

class TestEncryption(unittest.TestCase):
    def setUp(self):
        """
        Set up the test environment.
        """
        self.skg = SafeKeyGuard()

    def test_generate_key(self):
        """
        Test the generation of a new encryption key.
        """
        key1 = self.skg.generate_key()
        key2 = self.skg.generate_key()

        self.assertNotEqual(key1, key2)
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)

  def test_encrypt_decrypt_data(self):
        """
        Test encryption and decryption of data.
        """
        data = b"Hello, World!"
        encrypted_data = self.skg.encrypt_data(data)
        decrypted_data = self.skg.decrypt_data(encrypted_data)

        self.assertNotEqual(encrypted_data, data)
        self.assertEqual(decrypted_data, data)

if __name__ == "__main__":
    unittest.main()
