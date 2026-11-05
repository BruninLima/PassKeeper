"""GUI tests: drive the real windows with scripted events.

Needs tkinter, FreeSimpleGUI (or PySimpleGUI) and a display. On Linux without
a screen, run them with:  xvfb-run python -m unittest discover -s tests
They are skipped automatically when any of these is missing.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

try:
    import tkinter
    try:
        import FreeSimpleGUI as sg
    except ImportError:
        import PySimpleGUI as sg
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        raise ImportError("no display")
    tkinter.Tk().destroy()
    import PassKeeper_GUI as G
    GUI_OK = True
except Exception as exc:  # pragma: no cover - depends on the machine
    GUI_OK, SKIP_REASON = False, f"GUI not available: {exc}"
else:
    SKIP_REASON = ""

import PassKeeper as Pk  # noqa: E402

FAST_KDF = {"name": "scrypt", "n": 2 ** 10, "r": 8, "p": 1}
MASTER = "correct horse battery"
MAIN_TITLE = "PassKeeper - vault.pk"


@unittest.skipUnless(GUI_OK, SKIP_REASON)
class GuiTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.vault_path = self.dir / "vault.pk"
        self.script = {}          # window title -> list of steps
        self.popups = []
        self.clip = {"value": ""}
        orig_read = sg.Window.read
        test = self

        def fake_read(window, timeout=None, **kwargs):
            if timeout == 0:
                return orig_read(window, timeout=0)
            orig_read(window, timeout=10)
            steps = test.script.get(window.Title)
            if not steps:
                raise AssertionError(f"No scripted events left for window {window.Title!r}")
            step = steps.pop(0)
            if callable(step):
                step = step(window)
            event, updates = step
            for key, value in updates.items():
                window[key].update(value)
            values = orig_read(window, timeout=10)[1]
            return event, values

        def record(kind, answer=None):
            def popup(*args, **kwargs):
                test.popups.append((kind, args[0] if args else ""))
                return answer
            return popup

        patches = [
            mock.patch.object(sg.Window, "read", fake_read),
            mock.patch.object(sg, "popup", record("info")),
            mock.patch.object(sg, "popup_error", record("error")),
            mock.patch.object(sg, "popup_yes_no", record("confirm", "Yes")),
            mock.patch.object(sg, "clipboard_set", lambda t: self.clip.update(value=t)),
            mock.patch.object(sg, "clipboard_get", lambda: self.clip["value"]),
            mock.patch.object(Pk, "DEFAULT_KDF", FAST_KDF),
            mock.patch.dict(os.environ, {"PASSKEEPER_HOME": str(self.dir)}),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self._tmp.cleanup)

    def new_vault(self):
        return Pk.Vault.create(self.vault_path, MASTER, FAST_KDF)

    @staticmethod
    def select(row):
        def step(window):
            window["-TABLE-"].update(select_rows=[row])
            window.read(timeout=0)
            return "-TABLE-", {}
        return step

    # ------------------------------------------------------------------ #

    def test_first_run_setup_then_exit(self):
        self.script["PassKeeper"] = [
            ("Create vault", {"-PWD-": "short", "-PWD2-": "short"}),           # too short
            ("Create vault", {"-PWD-": "password12", "-PWD2-": "different1"}),
            ("Create vault", {"-PWD-": "password12", "-PWD2-": "password12"}),  # weak -> confirm
        ]
        self.script[MAIN_TITLE] = [("-EXIT-", {})]
        G.main()
        self.assertTrue(self.vault_path.exists())
        self.assertIn("confirm", [kind for kind, _ in self.popups])
        Pk.Vault.open(self.vault_path, "password12")

    def test_unlock_add_copy_delete_and_clipboard_clears(self):
        vault = self.new_vault()
        vault.update_settings(clipboard_seconds=1)
        self.script["PassKeeper"] = [("Unlock", {"-PWD-": "wrong"}),
                                     ("Unlock", {"-PWD-": MASTER})]
        self.script["New account"] = [
            ("Save", {"-NAME-": ""}),                                        # name required
            ("Save", {"-NAME-": "Gmail", "-USR-": "me@x.com", "-PWD-": "S3cret-pass",
                      "-TOTP-": "not valid!"}),                              # bad 2FA secret
            ("Save", {"-TOTP-": "JBSWY3DPEHPK3PXP", "-CAT-": "Email"}),
        ]
        clock = [1000.0]

        def tick(seconds):
            def step(window):
                clock[0] += seconds
                return sg.TIMEOUT_EVENT, {}
            return step

        self.script[MAIN_TITLE] = [
            ("-C-PWD-", {}),               # nothing selected: ignored
            ("-ADD-", {}),
            ("-C-PWD-", {}),
            tick(0.2),
            tick(2),                       # clipboard clear deadline passes
            ("-C-USR-", {}),
            ("-DELETE-", {}),
            ("-EXIT-", {}),
        ]
        observed = []
        orig_tick = G.Clipboard.tick

        def spy_tick(clipboard):
            result = orig_tick(clipboard)
            observed.append(self.clip["value"])
            return result

        with mock.patch.object(G.time, "monotonic", lambda: clock[0]), \
                mock.patch.object(G.Clipboard, "tick", spy_tick):
            G.main()
        self.assertEqual(observed, ["S3cret-pass", ""])      # cleared after the deadline
        self.assertEqual(self.clip["value"], "", "clipboard is cleared on exit")
        reopened = Pk.Vault.open(self.vault_path, MASTER)
        self.assertEqual([e.name for e in reopened.trash_entries()], ["Gmail"])
        self.assertEqual(reopened.trash_entries()[0].totp, "JBSWY3DPEHPK3PXP")
        self.assertEqual(len(list((self.dir / "backups").glob("vault-auto-*.pk"))), 1)

    def test_auto_lock_after_idle_minutes(self):
        vault = self.new_vault()
        vault.add_entry("A", "a", "1")
        vault.update_settings(autolock_minutes=1)
        clock = [5000.0]

        def idle(window):
            clock[0] += 61
            return sg.TIMEOUT_EVENT, {}

        self.script["PassKeeper"] = [("Unlock", {"-PWD-": MASTER}),
                                     ("Exit", {})]                  # 2nd unlock screen = locked
        self.script[MAIN_TITLE] = [self.select(0), ("-C-PWD-", {}), idle]
        with mock.patch.object(G.time, "monotonic", lambda: clock[0]):
            G.main()
        self.assertEqual(self.script["PassKeeper"], [], "the unlock window was shown again")
        self.assertEqual(self.clip["value"], "", "locking clears the clipboard")

    def test_second_window_is_refused(self):
        self.new_vault()
        with Pk.VaultLock(self.vault_path):
            G.main()
        self.assertEqual(self.popups[0][0], "error")
        self.assertIn("already open", self.popups[0][1])

    def test_edit_keeps_history_and_trash_restore(self):
        vault = self.new_vault()
        vault.add_entry("Bank", "me", "old-password")
        self.script["PassKeeper"] = [("Unlock", {"-PWD-": MASTER})]
        self.script["Edit account"] = [("Save", {"-PWD-": "new-password"})]
        self.script["Trash"] = [self._trash_select_restore, ("Close", {})]
        self.script[MAIN_TITLE] = [self.select(0), ("-EDIT-", {}), ("-DELETE-", {}),
                                   ("-TRASH-", {}), ("-EXIT-", {})]
        G.main()
        entry = Pk.Vault.open(self.vault_path, MASTER).active_entries()[0]
        self.assertEqual(entry.password, "new-password")
        self.assertEqual([h["password"] for h in entry.history], ["old-password"])

    @staticmethod
    def _trash_select_restore(window):
        window["-T-"].update(select_rows=[0])
        window.read(timeout=0)
        return "-RESTORE-", {}

    def test_change_master_password_dialog(self):
        vault = self.new_vault()
        vault.create_backup("manual")
        self.script["PassKeeper"] = [("Unlock", {"-PWD-": MASTER})]
        self.script["Change master password"] = [
            ("Change", {"-CUR-": "wrong", "-PWD-": "Brand-New-Pass-42", "-PWD2-": "Brand-New-Pass-42"}),
            ("Change", {"-CUR-": MASTER}),
        ]
        self.script[MAIN_TITLE] = [("-CHANGEMP-", {}), ("-EXIT-", {})]
        G.main()
        with self.assertRaises(Pk.WrongPasswordError):
            Pk.Vault.open(self.vault_path, MASTER)
        reopened = Pk.Vault.open(self.vault_path, "Brand-New-Pass-42")
        backup = Pk.list_backups(self.dir / "backups")[0]
        self.assertEqual(reopened.restore_backup(backup, "Brand-New-Pass-42"), 0)

    def test_wipe_everything(self):
        vault = self.new_vault()
        vault.create_backup("manual")
        self.script["PassKeeper"] = [("Unlock", {"-PWD-": MASTER})]
        self.script["Wipe everything"] = [
            ("Wipe everything", {"-PWD-": MASTER, "-CONFIRM-": "delete"}),   # must be capitals
            ("Wipe everything", {"-PWD-": "wrong", "-CONFIRM-": "DELETE"}),
            ("Wipe everything", {"-PWD-": MASTER}),
        ]
        self.script[MAIN_TITLE] = [("-WIPE-", {})]
        G.main()
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_generator_dialog(self):
        self.script["Password generator"] = [
            ("-RANDOM-", {"-RANDOM-": True}),
            ("-LEN-", {"-LEN-": 32}),
            ("-USE-", {}),
        ]
        password = G.generator_dialog()
        self.assertEqual(len(password), 32)

    def test_menu_import_export_csv(self):
        vault = self.new_vault()
        csv_in = self.dir / "in.csv"
        csv_in.write_text("name,url,username,password\nSite,site.com,me,pw\n")
        csv_out = self.dir / "out.csv"
        files = iter([str(csv_in), str(csv_out)])
        self.script["PassKeeper"] = [("Unlock", {"-PWD-": MASTER})]
        self.script[MAIN_TITLE] = [("Import from CSV...::-IMPORT-", {}),
                                   ("Export to CSV...::-EXPORT-", {}), ("-EXIT-", {})]
        with mock.patch.object(sg, "popup_get_file", lambda *a, **k: next(files)), \
                mock.patch.object(sg, "popup_get_text", lambda *a, **k: MASTER):
            G.main()
        self.assertIn("Site,site.com,me,pw", csv_out.read_text())
        del vault


if __name__ == "__main__":
    unittest.main()
