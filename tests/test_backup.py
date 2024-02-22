"""
SafeKeyGuard - Backup Module Test

"""

import unittest

class TestBackup(unittest.TestCase):
    def test_backup_data(self):
    # Initialize SafeKeyGuard instance
    skg = SafeKeyGuard()

    data_to_backup = b"example_data"

    backup_data = skg.backup_data(data_to_backup)

    self.assertIsNotNone(backup_data)

    backup_file_path = "backup_data.json"
    self.assertTrue(os.path.exists(backup_file_path))

    restored_data = skg.restore_data(backup_data)
    self.assertEqual(restored_data, data_to_backup)
        pass

    def test_restore_data(self):
        """
        Test restoring data from a backup.
        """
       import os
import unittest
from safekeyguard import SafeKeyGuard

class TestBackup(unittest.TestCase):
    def test_restore_data(self):
       
        backup_file_path = "backup_data.txt"
        backup_data = b"encrypted_backup_data_here"

        with open(backup_file_path, "wb") as backup_file:
            backup_file.write(backup_data)

        skg = SafeKeyGuard()
        skg.load_key()

        with open(backup_file_path, "rb") as backup_file:
            restored_data = skg.decrypt_data(backup_file.read())

        original_data = b"original_data"
        self.assertEqual(restored_data, original_data)

        os.remove(backup_file_path)

        pass

if __name__ == "__main__":
    unittest.main()
