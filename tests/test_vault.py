import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import PassKeeper as Pk  # noqa: E402
import legacy_v1  # noqa: E402

# Cheap scrypt settings so the tests run fast. Real vaults use Pk.DEFAULT_KDF.
FAST_KDF = {"name": "scrypt", "n": 2 ** 10, "r": 8, "p": 1}
MASTER = "correct horse battery"


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.vault_path = self.dir / "vault.pk"

    def tearDown(self):
        self._tmp.cleanup()

    def new_vault(self):
        return Pk.Vault.create(self.vault_path, MASTER, FAST_KDF)


class VaultTests(TempDirTest):
    def test_round_trip(self):
        vault = self.new_vault()
        vault.add_entry("Email", "me@example.com", "s3cret-ção-🔑", notes="2FA on")
        vault.add_entry("Bank", "me", "hunter2")

        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual(
            [(e.name, e.username, e.password, e.notes) for e in reopened.entries],
            [("Email", "me@example.com", "s3cret-ção-🔑", "2FA on"), ("Bank", "me", "hunter2", "")])

    def test_wrong_password(self):
        self.new_vault().add_entry("Email", "me", "pw")
        with self.assertRaises(Pk.WrongPasswordError):
            Pk.Vault.open(self.vault_path, "not the password")

    def test_file_contains_no_plaintext(self):
        self.new_vault().add_entry("MyBankName", "myusername", "MyVerySecretPassword")
        raw = self.vault_path.read_text()
        for secret in ("MyBankName", "myusername", "MyVerySecretPassword", MASTER):
            self.assertNotIn(secret, raw)

    def test_tampering_is_detected(self):
        self.new_vault().add_entry("Email", "me", "pw")
        doc = json.loads(self.vault_path.read_text())
        ct = bytearray(Pk._b64d(doc["ciphertext"]))
        ct[0] ^= 1
        doc["ciphertext"] = Pk._b64e(bytes(ct))
        self.vault_path.write_text(json.dumps(doc))
        with self.assertRaises(Pk.WrongPasswordError):
            Pk.Vault.open(self.vault_path, MASTER)

    def test_header_tampering_is_detected(self):
        self.new_vault()
        doc = json.loads(self.vault_path.read_text())
        doc["cipher"] = "something-else"
        self.vault_path.write_text(json.dumps(doc))
        with self.assertRaises(Pk.WrongPasswordError):
            Pk.Vault.open(self.vault_path, MASTER)

    def test_not_a_vault(self):
        self.vault_path.write_text("hello")
        with self.assertRaises(Pk.CorruptVaultError):
            Pk.Vault.open(self.vault_path, MASTER)

    def test_create_refuses_to_overwrite_and_short_password(self):
        self.new_vault()
        with self.assertRaises(Pk.VaultError):
            self.new_vault()
        with self.assertRaises(Pk.VaultError):
            Pk.Vault.create(self.dir / "other.pk", "short", FAST_KDF)

    def test_duplicate_names_and_many_entries(self):
        vault = self.new_vault()
        for i in range(120):
            vault.add_entry("Same name", f"user{i}", f"pw{i}")
        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual(len(reopened.entries), 120)
        self.assertEqual(len({e.id for e in reopened.entries}), 120)

    def test_update_and_remove(self):
        vault = self.new_vault()
        a = vault.add_entry("A", "a", "1")
        b = vault.add_entry("B", "b", "2")
        vault.update_entry(a.id, password="new")
        vault.remove_entry(b.id)
        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual([(e.name, e.password) for e in reopened.entries], [("A", "new")])
        with self.assertRaises(ValueError):
            vault.update_entry(a.id, id="x")

    def test_change_master_password(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        vault.change_master_password("a brand new password")
        with self.assertRaises(Pk.WrongPasswordError):
            Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual(Pk.Vault.open(self.vault_path, "a brand new password").entries[0].password, "1")

    def test_no_temp_files_left_behind(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["vault.pk"])


class BackupTests(TempDirTest):
    def test_backup_and_restore(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        backup = vault.create_backup()
        vault.add_entry("B", "b", "2")

        self.assertEqual(vault.restore_backup(backup, MASTER), 1)
        self.assertEqual([e.name for e in Pk.Vault.open(self.vault_path, MASTER).entries], ["A"])
        # restoring made a safety backup of the 2-entry state first
        self.assertEqual(len(Pk.list_backups(self.dir / "backups")), 2)

    def test_restore_with_wrong_password_changes_nothing(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        backup = vault.create_backup()
        with self.assertRaises(Pk.WrongPasswordError):
            vault.restore_backup(backup, "wrong password")
        self.assertEqual(len(vault.entries), 1)

    def test_old_backups_are_pruned(self):
        vault = self.new_vault()
        for _ in range(5):
            vault.create_backup(keep=3)
        self.assertEqual(len(Pk.list_backups(self.dir / "backups")), 3)

    def test_backup_is_encrypted(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "TopSecretValue")
        self.assertNotIn("TopSecretValue", vault.create_backup().read_text())


class MigrationTests(TempDirTest):
    """Build real 1.x files with the original 1.1 code, then migrate them."""

    def make_legacy(self, master, accounts, delete_index=None):
        old_cwd = os.getcwd()
        os.chdir(self.dir)
        try:
            (self.dir / "safe").mkdir()
            legacy_v1.store_main_password("someone", master)
            for name, usr, pwd in accounts:
                legacy_v1.addentry(name, usr, pwd)
            if delete_index is not None:
                legacy_v1.remove_account(str(delete_index))
            if accounts:  # 1.x crashed here with no accounts (the "close error")
                legacy_v1.create_backup()
            # sanity check: this is what the 1.x app itself would display
            return [tuple(e) for e in legacy_v1.show_entry_password(range(1, 50))]
        finally:
            os.chdir(old_cwd)

    def migrate(self, master):
        return Pk.migrate_legacy(self.dir, master, self.vault_path, FAST_KDF)

    def test_migrates_accounts_and_removes_old_files(self):
        accounts = [("Email", "me@example.com", "Tiger-12-Ocean"),
                    ("Bank", "123", "pässwörd ✓"),
                    ("Game", "", "x")]
        shown_by_v1 = self.make_legacy(MASTER, accounts)
        self.assertEqual(shown_by_v1, accounts)
        self.assertTrue(Pk.legacy_files_present(self.dir))

        vault = self.migrate(MASTER)
        self.assertEqual([(e.name, e.username, e.password) for e in vault.entries], accounts)
        self.assertEqual(
            [(e.name, e.username, e.password) for e in Pk.Vault.open(self.vault_path, MASTER).entries],
            accounts)
        self.assertFalse(Pk.legacy_files_present(self.dir))
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["vault.pk"])

    def test_migration_after_a_deletion(self):
        accounts = [("A", "a", "1aaaaaa"), ("B", "b", "2bbbbbb"), ("C", "c", "3cccccc")]
        self.make_legacy(MASTER, accounts, delete_index=2)
        vault = self.migrate(MASTER)
        self.assertEqual([(e.name, e.password) for e in vault.entries],
                         [("A", "1aaaaaa"), ("C", "3cccccc")])

    def test_short_legacy_master_password_still_migrates(self):
        self.make_legacy("abc", [("A", "a", "1")])
        vault = self.migrate("abc")
        self.assertEqual(vault.entries[0].password, "1")
        Pk.Vault.open(self.vault_path, "abc")

    def test_wrong_password_keeps_old_files(self):
        self.make_legacy(MASTER, [("A", "a", "1")])
        with self.assertRaises(Pk.WrongPasswordError):
            self.migrate("nope")
        self.assertTrue(Pk.legacy_files_present(self.dir))
        self.assertFalse(self.vault_path.exists())

    def test_master_password_without_accounts(self):
        self.make_legacy(MASTER, [])
        self.assertEqual(self.migrate(MASTER).entries, [])


class GeneratorTests(unittest.TestCase):
    def test_generates_from_dictionary(self):
        import PasswordGenerator as G
        words = set(G.load_dictionary())
        for _ in range(50):
            parts = G.pw(no_special_characters=False)
            self.assertGreaterEqual(len(parts), 10)
        plain = G.pw(number_of_elements=4, no_special_characters=True)
        self.assertTrue(plain.isalnum())
        self.assertTrue(any(w.title() in plain for w in words if len(w) >= 3))

    def test_uses_secrets_not_random(self):
        source = (ROOT / "PasswordGenerator.py").read_text()
        self.assertNotIn("from random", source)
        self.assertNotIn("import random", source)


if __name__ == "__main__":
    unittest.main()
