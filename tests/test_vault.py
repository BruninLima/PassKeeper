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
        vault.remove_entry(b.id)   # moves it to the trash
        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual([(e.name, e.password) for e in reopened.active_entries()], [("A", "new")])
        self.assertEqual([e.name for e in reopened.trash_entries()], ["B"])
        with self.assertRaises(ValueError):
            vault.update_entry(a.id, id="x")

    def test_change_master_password(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        vault.change_master_password(MASTER, "a brand new password")
        with self.assertRaises(Pk.WrongPasswordError):
            Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual(Pk.Vault.open(self.vault_path, "a brand new password").entries[0].password, "1")

    def test_no_temp_files_left_behind(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["vault.pk"])

    def test_old_2_0_vault_still_opens(self):
        """A vault written by 2.0 (entries without the new fields) opens fine."""
        vault = self.new_vault()
        payload = json.dumps({"entries": [{"name": "Old", "username": "u", "password": "p",
                                           "notes": "", "id": "abc", "created": "2026-01-01T00:00:00+00:00",
                                           "modified": "2026-01-01T00:00:00+00:00"}]}).encode()
        header = {"format": Pk.FORMAT_NAME, "version": 2, "kdf": vault._kdf, "cipher": "AES-256-GCM"}
        self.vault_path.write_bytes(Pk.Vault._encrypt_payload(header, payload, vault._key))
        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual(reopened.entries[0].name, "Old")
        self.assertEqual(reopened.entries[0].url, "")
        self.assertEqual(reopened.settings.autolock_minutes, 5)


class BackupTests(TempDirTest):
    def test_backup_and_restore(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        backup = vault.create_backup()
        vault.add_entry("B", "b", "2")

        self.assertEqual(vault.restore_backup(backup, MASTER), 1)
        self.assertEqual([e.name for e in Pk.Vault.open(self.vault_path, MASTER).entries], ["A"])
        # restoring made a safety backup of the 2-entry state first
        backups = Pk.list_backups(self.dir / "backups")
        self.assertEqual(len(backups), 2)
        self.assertEqual(len(list((self.dir / "backups").glob("vault-safety-*.pk"))), 1)

    def test_restore_with_wrong_password_changes_nothing(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        backup = vault.create_backup()
        with self.assertRaises(Pk.WrongPasswordError):
            vault.restore_backup(backup, "wrong password")
        self.assertEqual(len(vault.entries), 1)

    def test_backups_are_pruned_per_kind(self):
        vault = self.new_vault()
        vault.create_backup("manual")
        for _ in range(Pk.BACKUP_KEEP["auto"] + 3):
            vault.create_backup("auto")
        for _ in range(Pk.BACKUP_KEEP["safety"] + 2):
            vault.create_backup("safety")
        folder = self.dir / "backups"
        self.assertEqual(len(list(folder.glob("vault-auto-*.pk"))), Pk.BACKUP_KEEP["auto"])
        self.assertEqual(len(list(folder.glob("vault-safety-*.pk"))), Pk.BACKUP_KEEP["safety"])
        self.assertEqual(len(list(folder.glob("vault-manual-*.pk"))), 1)  # never pruned

    def test_backup_is_encrypted(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "TopSecretValue")
        self.assertNotIn("TopSecretValue", vault.create_backup().read_text())


class TrashHistoryTests(TempDirTest):
    def test_trash_restore_and_delete_forever(self):
        vault = self.new_vault()
        a = vault.add_entry("A", "a", "1")
        b = vault.add_entry("B", "b", "2")
        vault.remove_entry(a.id)
        vault.remove_entry(b.id)
        self.assertEqual(vault.active_entries(), [])
        vault.restore_entry(a.id)
        vault.delete_forever(b.id)
        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual([e.name for e in reopened.active_entries()], ["A"])
        self.assertEqual(reopened.trash_entries(), [])

    def test_trash_is_emptied_after_the_configured_days(self):
        from datetime import datetime, timedelta, timezone
        vault = self.new_vault()
        old = vault.add_entry("Old", "o", "1")
        new = vault.add_entry("New", "n", "2")
        vault.remove_entry(new.id)
        vault.get(old.id).deleted = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
        vault.save()
        reopened = Pk.Vault.open(self.vault_path, MASTER)   # purges on open
        self.assertEqual([e.name for e in reopened.trash_entries()], ["New"])
        self.assertEqual(len(reopened.entries), 1)

    def test_empty_trash(self):
        vault = self.new_vault()
        for name in "ABC":
            vault.remove_entry(vault.add_entry(name).id)
        self.assertEqual(vault.empty_trash(), 3)
        self.assertEqual(vault.entries, [])

    def test_password_history(self):
        vault = self.new_vault()
        e = vault.add_entry("A", "a", "first")
        vault.update_entry(e.id, password="second")
        vault.update_entry(e.id, notes="only notes changed")
        vault.update_entry(e.id, password="third")
        self.assertEqual([h["password"] for h in vault.get(e.id).history], ["second", "first"])
        for i in range(Pk.PASSWORD_HISTORY_LIMIT + 5):
            vault.update_entry(e.id, password=f"p{i}")
        self.assertEqual(len(vault.get(e.id).history), Pk.PASSWORD_HISTORY_LIMIT)

    def test_fields_search_and_categories(self):
        vault = self.new_vault()
        vault.add_entry("Gmail", "me@gmail.com", "x", url="mail.google.com", category="Email")
        vault.add_entry("Bank", "123", "y", category="Finance", notes="branch 0001")
        vault.add_entry("Misc", "m", "z")
        self.assertEqual(vault.categories(), ["Email", "Finance"])
        self.assertEqual([e.name for e in vault.search("google")], ["Gmail"])
        self.assertEqual([e.name for e in vault.search("branch")], ["Bank"])
        self.assertEqual([e.name for e in vault.search(category="Finance")], ["Bank"])
        self.assertEqual([e.name for e in vault.search(category="")], ["Misc"])

    def test_invalid_totp_is_rejected(self):
        vault = self.new_vault()
        with self.assertRaises(ValueError):
            vault.add_entry("A", totp="not base32 !!")
        e = vault.add_entry("A", totp="JBSW Y3DP EHPK 3PXP")
        self.assertEqual(e.totp, "JBSW Y3DP EHPK 3PXP")

    def test_settings_are_saved_encrypted(self):
        vault = self.new_vault()
        vault.update_settings(autolock_minutes=15, clipboard_seconds=0, trash_days=0)
        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual((reopened.settings.autolock_minutes, reopened.settings.clipboard_seconds,
                          reopened.settings.trash_days), (15, 0, 1))   # trash_days min is 1


class MasterPasswordTests(TempDirTest):
    def test_change_requires_current_password(self):
        vault = self.new_vault()
        with self.assertRaises(Pk.WrongPasswordError):
            vault.change_master_password("wrong current", "a brand new password")
        Pk.Vault.open(self.vault_path, MASTER)   # unchanged

    def test_verify_password(self):
        vault = self.new_vault()
        self.assertTrue(vault.verify_password(MASTER))
        self.assertFalse(vault.verify_password("nope"))

    def test_backups_are_reencrypted_with_the_new_password(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        b1 = vault.create_backup("manual")
        b2 = vault.create_backup("auto")
        leftovers = vault.change_master_password(MASTER, "a brand new password")
        self.assertEqual(leftovers, [])
        for backup in (b1, b2):
            with self.assertRaises(Pk.WrongPasswordError):
                vault.restore_backup(backup, MASTER)
            self.assertEqual(vault.restore_backup(backup, "a brand new password"), 1)

    def test_backups_from_an_older_password_are_reported(self):
        vault = self.new_vault()
        old = vault.create_backup("manual")
        vault.change_master_password(MASTER, "second password!")
        # this backup was re-encrypted; make one with a different password by hand
        stranger = Pk.Vault.create(self.dir / "other.pk", "a third password", FAST_KDF)
        foreign = stranger.create_backup("manual", backup_dir=self.dir / "backups")
        leftovers = vault.change_master_password("second password!", "fourth password!")
        self.assertEqual(leftovers, [foreign])
        self.assertEqual(vault.restore_backup(old, "fourth password!"), 0)


class RestoreMergeTests(TempDirTest):
    def test_merge_adds_missing_and_newer_entries_only(self):
        vault = self.new_vault()
        keep = vault.add_entry("Keep", "k", "1")
        changed = vault.add_entry("Changed", "c", "old")
        backup = vault.create_backup()
        lost = vault.add_entry("Added after backup", "x", "x")
        vault.update_entry(changed.id, password="newer here")
        # simulate a backup from another device with a newer edit and a new entry
        other = Pk.Vault.open(self.vault_path, MASTER)
        other.path = self.dir / "other.pk"
        other.entries = [e for e in other.entries if e.id != lost.id]
        other.add_entry("Only in backup", "o", "o")
        other.update_entry(keep.id, password="edited in backup")
        other.save()

        count = vault.restore_backup(other.path, MASTER, mode="merge")
        self.assertEqual(count, 2)
        by_name = {e.name: e for e in vault.active_entries()}
        self.assertEqual(sorted(by_name), ["Added after backup", "Changed", "Keep", "Only in backup"])
        self.assertEqual(by_name["Keep"].password, "edited in backup")
        self.assertEqual(by_name["Changed"].password, "newer here")
        self.assertTrue(backup.exists())


class LockAndWipeTests(TempDirTest):
    def test_second_lock_is_refused_until_released(self):
        first = Pk.VaultLock(self.vault_path).acquire()
        with self.assertRaises(Pk.VaultLockedError):
            Pk.VaultLock(self.vault_path).acquire()
        first.release()
        with Pk.VaultLock(self.vault_path):
            pass

    def test_lock_works_across_processes(self):
        import subprocess
        with Pk.VaultLock(self.vault_path):
            code = ("import sys; sys.path.insert(0, %r); import PassKeeper as Pk\n"
                    "try:\n    Pk.VaultLock(%r).acquire()\nexcept Pk.VaultLockedError:\n"
                    "    sys.exit(3)\n" % (str(ROOT), str(self.vault_path)))
            result = subprocess.run([sys.executable, "-c", code])
        self.assertEqual(result.returncode, 3)

    def test_secure_delete(self):
        target = self.dir / "secret.txt"
        target.write_text("top secret " * 1000)
        Pk.secure_delete(target)
        self.assertFalse(target.exists())
        Pk.secure_delete(target)   # missing file is fine

    def test_wipe_all_data(self):
        vault = self.new_vault()
        vault.create_backup()
        vault.create_backup("auto")
        (self.dir / "unrelated.txt").write_text("keep me")
        self.assertEqual(Pk.wipe_all_data(self.vault_path), 3)
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["unrelated.txt"])

    def test_closed_vault_cannot_save(self):
        vault = self.new_vault()
        vault.close()
        with self.assertRaises(Pk.VaultError):
            vault.save()


class CsvTests(TempDirTest):
    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_chrome_csv(self):
        path = self.write("chrome.csv", "name,url,username,password,note\n"
                          "github.com,https://github.com/login,bruno,pw1,\n"
                          ",https://www.example.com/,ex,pw2,hello\n")
        vault = self.new_vault()
        self.assertEqual(vault.import_csv(path), (2, 0))
        names = [(e.name, e.url, e.username, e.password, e.notes) for e in vault.active_entries()]
        self.assertIn(("example.com", "https://www.example.com/", "ex", "pw2", "hello"), names)
        self.assertEqual(vault.import_csv(path), (0, 2))   # no duplicates

    def test_firefox_csv(self):
        path = self.write("ff.csv", '"url","username","password","httpRealm","formActionOrigin",'
                          '"guid","timeCreated"\n"https://mail.example.org","me","pw","","","{x}","1"\n')
        vault = self.new_vault()
        vault.import_csv(path)
        self.assertEqual(vault.entries[0].name, "mail.example.org")

    def test_bitwarden_csv(self):
        path = self.write("bw.csv", "folder,favorite,type,name,notes,fields,reprompt,login_uri,"
                          "login_username,login_password,login_totp\n"
                          "Email,,login,Gmail,n,,0,https://mail.google.com,me,pw,JBSWY3DPEHPK3PXP\n"
                          ",,login,Bad totp,,,0,,u,p,not-valid!\n")
        vault = self.new_vault()
        self.assertEqual(vault.import_csv(path), (2, 0))
        gmail = vault.search("gmail")[0]
        self.assertEqual((gmail.category, gmail.totp), ("Email", "JBSWY3DPEHPK3PXP"))
        self.assertEqual(vault.search("Bad totp")[0].totp, "")

    def test_keepassxc_csv(self):
        path = self.write("kp.csv", '"Group","Title","Username","Password","URL","Notes","TOTP"\n'
                          '"Root/Work","VPN","bruno","pw","vpn.example.com","",""\n')
        vault = self.new_vault()
        vault.import_csv(path)
        self.assertEqual((vault.entries[0].name, vault.entries[0].category), ("VPN", "Work"))

    def test_export_then_import_round_trip(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "p,with \"quotes\"", url="a.com", category="C", notes="multi\nline")
        out = self.dir / "export.csv"
        self.assertEqual(vault.export_csv(out), 1)
        other = Pk.Vault.create(self.dir / "other.pk", MASTER, FAST_KDF)
        other.import_csv(out)
        self.assertTrue(other.entries[0].same_content(vault.entries[0]))

    def test_csv_without_password_column(self):
        path = self.write("bad.csv", "a,b\n1,2\n")
        with self.assertRaises(Pk.VaultError):
            self.new_vault().import_csv(path)


class TotpTests(unittest.TestCase):
    # RFC 6238 test vectors (SHA1, 8 digits)
    SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    def test_rfc_vectors(self):
        import totp
        uri = f"otpauth://totp/Test?secret={self.SECRET}&digits=8"
        for at, expected in ((59, "94287082"), (1111111109, "07081804"),
                             (1234567890, "89005924"), (2000000000, "69279037")):
            self.assertEqual(totp.code(uri, at), expected)

    def test_plain_secret_and_seconds_left(self):
        import totp
        self.assertEqual(totp.code(self.SECRET, 59), "287082")
        self.assertEqual(totp.seconds_left(self.SECRET, 59), 1)
        with self.assertRaises(ValueError):
            totp.parse("otpauth://hotp/x?secret=" + self.SECRET)


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

    def test_random_password_has_every_kind(self):
        import PasswordGenerator as G
        for _ in range(50):
            p = G.random_password(12, avoid_ambiguous=True)
            self.assertEqual(len(p), 12)
            self.assertTrue(any(c.islower() for c in p) and any(c.isupper() for c in p))
            self.assertTrue(any(c.isdigit() for c in p) and any(c in G.SYMBOLS for c in p))
            self.assertFalse(set(p) & G.AMBIGUOUS)
        self.assertTrue(G.random_password(30, upper=False, digits=False, symbols=False).islower())
        with self.assertRaises(ValueError):
            G.random_password(10, False, False, False, False)

    def test_passphrase(self):
        import PasswordGenerator as G
        p = G.passphrase(5, "-", capitalize=False, include_number=False)
        self.assertEqual(len(p.split("-")), 5)
        self.assertTrue(p.replace("-", "").islower())

    def test_strength(self):
        import PasswordGenerator as G
        self.assertEqual(G.estimate_strength("password")[1], "Very weak")
        self.assertIn(G.estimate_strength("Password123!")[1], ("Very weak", "Weak"))
        self.assertIn(G.estimate_strength(G.random_password(20))[1], ("Strong", "Very strong"))
        self.assertIn(G.estimate_strength(G.passphrase(5))[1], ("Strong", "Very strong"))

    def test_uses_secrets_not_random(self):
        source = (ROOT / "PasswordGenerator.py").read_text()
        self.assertNotIn("from random", source)
        self.assertNotIn("import random", source)


if __name__ == "__main__":
    unittest.main()
