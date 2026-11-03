"""PassKeeper GUI.

Run with:  python PassKeeper_GUI.py
"""

import sys
import time
import webbrowser
from datetime import datetime
from pathlib import Path

try:  # FreeSimpleGUI is the free, LGPL fork of PySimpleGUI with the same API.
    import FreeSimpleGUI as sg
except ImportError:  # pragma: no cover - fall back to PySimpleGUI if installed
    import PySimpleGUI as sg

import PassKeeper as Pk
import PasswordGenerator as Gen
import totp

APP_TITLE = "PassKeeper"
APP_VERSION = "2.1"
HIDDEN = "•" * 10          # never reveals the real length
MASK = "•"
TICK_MS = 500

FONT = ("Segoe UI", 10) if sys.platform.startswith("win") else ("Helvetica", 11)
MONO = ("Consolas", 11) if sys.platform.startswith("win") else ("Courier", 12)
TITLE_FONT = (FONT[0], FONT[1] + 6, "bold")
HEADER_FONT = (FONT[0], FONT[1] + 2, "bold")
SMALL_FONT = (FONT[0], FONT[1] - 1)

STRENGTH_COLORS = {"Very weak": "#d9534f", "Weak": "#f0ad4e", "Fair": "#e6d74e",
                   "Strong": "#5cb85c", "Very strong": "#3c9d5d"}

sg.theme("DarkAmber")
sg.set_options(font=FONT, element_padding=(6, 4))


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #

def resource_path(*parts) -> Path:
    """Path to a file shipped with the app (also inside a PyInstaller bundle)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base.joinpath(*parts)


def window_icon():
    icon = resource_path("Figures", "padlock.ico")
    # Tk only understands .ico files on Windows.
    return str(icon) if sys.platform.startswith("win") and icon.exists() else None


def make_window(title, layout, **kwargs):
    kwargs.setdefault("finalize", True)
    return sg.Window(title, layout, icon=window_icon(), **kwargs)


def error(message):
    sg.popup_error(message, title=APP_TITLE, icon=window_icon(), keep_on_top=True)


def info(message):
    sg.popup(message, title=APP_TITLE, icon=window_icon(), keep_on_top=True)


def confirm(message):
    return sg.popup_yes_no(message, title=APP_TITLE, icon=window_icon(),
                           keep_on_top=True) == "Yes"


def local_time(iso_text):
    try:
        return datetime.fromisoformat(iso_text).astimezone().strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return ""


def title_image():
    image = resource_path("Figures", "main_title.png")
    return [[sg.Image(str(image))]] if image.exists() else \
        [[sg.Text(APP_TITLE, font=TITLE_FONT)]]


def strength_row(key):
    return [sg.ProgressBar(100, orientation="h", size=(22, 10), key=f"{key}-BAR-"),
            sg.Text("", key=f"{key}-LABEL-", size=(22, 1), font=SMALL_FONT)]


def update_strength(window, key, password):
    bits, label = Gen.estimate_strength(password)
    color = STRENGTH_COLORS[label]
    bar = window[f"{key}-BAR-"]
    try:
        bar.update(current_count=min(bits, 100), bar_color=(color, sg.theme_input_background_color()))
    except TypeError:  # older PySimpleGUI without bar_color
        bar.update(min(bits, 100))
    window[f"{key}-LABEL-"].update(f"{label} (~{bits} bits)" if password else "", text_color=color)
    return label


def toggle_masked(window, key, show):
    window[key].update(password_char="" if show else MASK)


class Clipboard:
    """Copies text and clears it again after a while (if it is still ours)."""

    def __init__(self):
        self.value = None
        self.deadline = None

    def copy(self, text, seconds):
        sg.clipboard_set(text)
        self.value = text
        self.deadline = time.monotonic() + seconds if seconds else None

    def tick(self):
        if self.deadline and time.monotonic() >= self.deadline:
            self.clear_now()
            return True
        return False

    def clear_now(self):
        if self.value is None:
            return
        try:
            if sg.clipboard_get() == self.value:
                sg.clipboard_set("")
        except Exception:  # clipboard unavailable / owned by another app
            pass
        self.value = self.deadline = None


# --------------------------------------------------------------------------- #
# Unlock / first-time setup / 1.x migration
# --------------------------------------------------------------------------- #

def unlock_window(vault_path):
    """Ask for the master password until the vault opens. Returns the Vault,
    or None if the user gives up."""
    layout = title_image() + [
        [sg.Text("Vault is locked", font=HEADER_FONT)],
        [sg.Text("Master password")],
        [sg.Input(key="-PWD-", password_char=MASK, focus=True, size=(36, 1)),
         sg.Checkbox("Show", key="-SHOWPWD-", enable_events=True)],
        [sg.Text("", key="-MSG-", text_color="#ff6b6b", size=(45, 1))],
        [sg.Button("Unlock", bind_return_key=True, size=(10, 1)), sg.Button("Exit")],
        [sg.Text(str(vault_path), font=SMALL_FONT, text_color="gray")],
    ]
    window = make_window(APP_TITLE, layout, element_justification="center")
    failures = 0
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Exit"):
                return None
            if event == "-SHOWPWD-":
                toggle_masked(window, "-PWD-", values["-SHOWPWD-"])
                continue
            window["-MSG-"].update("Unlocking...", text_color="gray")
            window["Unlock"].update(disabled=True)
            window.refresh()
            try:
                return Pk.Vault.open(vault_path, values["-PWD-"])
            except Pk.WrongPasswordError:
                failures += 1
                if failures >= 3:  # slow down guessing at the keyboard
                    time.sleep(min(2 ** (failures - 3), 30))
                window["-MSG-"].update("Wrong master password. Try again.", text_color="#ff6b6b")
                window["-PWD-"].update("")
            except Pk.VaultError as exc:
                error(str(exc))
                return None
            finally:
                if window.TKroot:
                    window["Unlock"].update(disabled=False)
    finally:
        window.close()


def new_password_rows(intro):
    return [
        [sg.Text(intro)],
        [sg.Text("Master password", size=(16, 1)),
         sg.Input(key="-PWD-", password_char=MASK, focus=True, enable_events=True, size=(32, 1)),
         sg.Checkbox("Show", key="-SHOWPWD-", enable_events=True)],
        [sg.Text("", size=(16, 1))] + strength_row("-STR"),
        [sg.Text("Repeat it", size=(16, 1)),
         sg.Input(key="-PWD2-", password_char=MASK, size=(32, 1))],
    ]


def accept_new_password(window, values):
    """Shared checks for a new master password. Returns True if it may be used."""
    if values["-PWD-"] != values["-PWD2-"]:
        window["-MSG-"].update("The passwords do not match.")
        return False
    try:
        Pk.check_master_password_rules(values["-PWD-"])
    except Pk.VaultError as exc:
        window["-MSG-"].update(str(exc))
        return False
    label = Gen.estimate_strength(values["-PWD-"])[1]
    if label in ("Very weak", "Weak"):
        return confirm(f"This master password is {label.lower()} and could be guessed.\n"
                       "Tip: use 4 or more random words.\n\nUse it anyway?")
    return True


def setup_window(vault_path):
    """First run: choose a master password and create an empty vault."""
    layout = title_image() + [[sg.Text("Welcome! Let's create your vault.", font=HEADER_FONT)]] + \
        new_password_rows(
            f"Choose a master password (at least {Pk.MIN_MASTER_PASSWORD_LENGTH} characters).\n"
            "It protects everything, and it cannot be recovered if you forget it.") + [
        [sg.Text("", key="-MSG-", text_color="#ff6b6b", size=(60, 1))],
        [sg.Button("Create vault", bind_return_key=True), sg.Button("Exit")],
    ]
    window = make_window(APP_TITLE, layout)
    update_strength(window, "-STR", "")
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Exit"):
                return None
            if event == "-SHOWPWD-":
                toggle_masked(window, "-PWD-", values["-SHOWPWD-"])
                toggle_masked(window, "-PWD2-", values["-SHOWPWD-"])
            elif event == "-PWD-":
                update_strength(window, "-STR", values["-PWD-"])
            elif event == "Create vault" and accept_new_password(window, values):
                try:
                    return Pk.Vault.create(vault_path, values["-PWD-"])
                except Pk.VaultError as exc:
                    window["-MSG-"].update(str(exc))
    finally:
        window.close()


def migrate_window(directory, vault_path):
    """Upgrade PassKeeper 1.x files to the encrypted vault."""
    layout = title_image() + [
        [sg.Text("Upgrade from PassKeeper 1.x", font=HEADER_FONT)],
        [sg.Text("Found data from PassKeeper 1.x, which was not stored securely.\n"
                 "Type your old master password to move it into an encrypted vault.\n"
                 "The old files will be overwritten and deleted after the upgrade.")],
        [sg.Input(key="-PWD-", password_char=MASK, focus=True, size=(36, 1))],
        [sg.Text("", key="-MSG-", text_color="#ff6b6b", size=(60, 1))],
        [sg.Button("Upgrade", bind_return_key=True), sg.Button("Exit")],
    ]
    window = make_window(APP_TITLE, layout)
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Exit"):
                return None
            try:
                vault = Pk.migrate_legacy(directory, values["-PWD-"], vault_path)
            except Pk.WrongPasswordError:
                window["-MSG-"].update("Wrong master password. Try again.")
                continue
            except Exception as exc:  # keep the old files, tell the user why
                error(f"The upgrade failed and your old files were kept:\n{exc}")
                return None
            info(f"Upgrade complete: {len(vault.entries)} account(s) moved to the encrypted vault.")
            return vault
    finally:
        window.close()


# --------------------------------------------------------------------------- #
# Dialogs
# --------------------------------------------------------------------------- #

def generator_dialog(clipboard=None, seconds=20, allow_use=True):
    """Password generator. Returns the chosen password, or None."""
    sep_choices = ["Random", "-", "_", ".", "Space", "None"]
    phrase_opts = [
        [sg.Text("Words"), sg.Spin(list(range(3, 11)), initial_value=4, key="-WORDS-",
                                    enable_events=True, size=(3, 1)),
         sg.Text("Separator"), sg.Combo(sep_choices, "Random", key="-SEP-", readonly=True,
                                        enable_events=True, size=(8, 1))],
        [sg.Checkbox("Capitalize", True, key="-CAP-", enable_events=True),
         sg.Checkbox("Add a number", True, key="-NUM-", enable_events=True)],
    ]
    random_opts = [
        [sg.Text("Length"), sg.Slider((8, 64), 20, orientation="h", key="-LEN-",
                                      enable_events=True, size=(28, 15))],
        [sg.Checkbox("a-z", True, key="-LOW-", enable_events=True),
         sg.Checkbox("A-Z", True, key="-UP-", enable_events=True),
         sg.Checkbox("0-9", True, key="-DIG-", enable_events=True),
         sg.Checkbox("!@#", True, key="-SYM-", enable_events=True),
         sg.Checkbox("Avoid look-alikes (l, 1, O, 0)", False, key="-AMB-", enable_events=True)],
    ]
    buttons = [sg.Button("New password", key="-REGEN-"), sg.Button("Copy", key="-COPY-")]
    if allow_use:
        buttons.append(sg.Button("Use this password", key="-USE-", bind_return_key=True))
    buttons.append(sg.Button("Close", key="-CLOSE-"))
    layout = [
        [sg.Radio("Passphrase (easy to type)", "KIND", True, key="-PHRASE-", enable_events=True),
         sg.Radio("Random characters", "KIND", False, key="-RANDOM-", enable_events=True)],
        [sg.pin(sg.Frame("Passphrase", phrase_opts, key="-PF-")),
         sg.pin(sg.Frame("Random characters", random_opts, key="-RF-", visible=False))],
        [sg.Input("", key="-OUT-", font=MONO, size=(48, 1), readonly=True,
                  disabled_readonly_background_color=sg.theme_input_background_color(),
                  disabled_readonly_text_color=sg.theme_input_text_color())],
        strength_row("-GSTR"),
        buttons,
        [sg.Text("", key="-MSG-", size=(50, 1))],
    ]
    window = make_window("Password generator", layout, modal=True)

    def regenerate(values):
        try:
            if values["-PHRASE-"]:
                sep = values["-SEP-"]
                sep = None if sep == "Random" else {"Space": " ", "None": ""}.get(sep, sep)
                password = Gen.passphrase(int(values["-WORDS-"]), sep, values["-CAP-"],
                                          values["-NUM-"])
            else:
                password = Gen.random_password(int(values["-LEN-"]), values["-LOW-"],
                                               values["-UP-"], values["-DIG-"], values["-SYM-"],
                                               values["-AMB-"])
        except ValueError as exc:
            window["-MSG-"].update(str(exc))
            return
        window["-MSG-"].update("")
        window["-OUT-"].update(password)
        update_strength(window, "-GSTR", password)

    regenerate(window.read(timeout=0)[1])
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "-CLOSE-"):
                return None
            if event in ("-PHRASE-", "-RANDOM-"):
                window["-PF-"].update(visible=values["-PHRASE-"])
                window["-RF-"].update(visible=values["-RANDOM-"])
            if event == "-COPY-":
                if clipboard:
                    clipboard.copy(values["-OUT-"], seconds)
                else:
                    sg.clipboard_set(values["-OUT-"])
                window["-MSG-"].update("Copied." + (f" The clipboard clears in {seconds}s."
                                                    if clipboard and seconds else ""))
                continue
            if event == "-USE-":
                return values["-OUT-"]
            regenerate(values)
    finally:
        window.close()


def entry_dialog(vault, entry=None, clipboard=None):
    """Add or edit an account. Returns a dict of fields, or None if cancelled."""
    e = entry
    label = lambda text: sg.Text(text, size=(12, 1))  # noqa: E731
    layout = [
        [sg.Text("Edit account" if e else "New account", font=HEADER_FONT)],
        [label("Name *"), sg.Input(e.name if e else "", key="-NAME-", focus=True, size=(40, 1))],
        [label("Username"), sg.Input(e.username if e else "", key="-USR-", size=(40, 1))],
        [label("Password"), sg.Input(e.password if e else "", key="-PWD-", password_char=MASK,
                                     enable_events=True, size=(40, 1), font=MONO)],
        [label(""), sg.Checkbox("Show", key="-SHOWPWD-", enable_events=True),
         sg.Button("Generate...", key="-GEN-")],
        [label("")] + strength_row("-ESTR"),
        [label("Website"), sg.Input(e.url if e else "", key="-URL-", size=(40, 1))],
        [label("Category"), sg.Combo(vault.categories(), e.category if e else "",
                                     key="-CAT-", size=(38, 1))],
        [label("2FA secret"), sg.Input(e.totp if e else "", key="-TOTP-", password_char=MASK,
                                       size=(40, 1))],
        [label(""), sg.Text("Optional: the setup key or otpauth:// link a site gives you\n"
                            "when you turn on two-factor authentication.",
                            font=SMALL_FONT, text_color="gray")],
        [label("Notes"), sg.Multiline(e.notes if e else "", key="-NOTES-", size=(40, 4))],
        [sg.Text("", key="-MSG-", text_color="#ff6b6b", size=(55, 1))],
        [sg.Push(), sg.Button("Save", size=(8, 1)), sg.Button("Cancel")],
    ]
    window = make_window("Edit account" if e else "New account", layout, modal=True)
    update_strength(window, "-ESTR", e.password if e else "")
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Cancel"):
                return None
            if event == "-SHOWPWD-":
                toggle_masked(window, "-PWD-", values["-SHOWPWD-"])
                toggle_masked(window, "-TOTP-", values["-SHOWPWD-"])
            elif event == "-PWD-":
                update_strength(window, "-ESTR", values["-PWD-"])
            elif event == "-GEN-":
                password = generator_dialog(clipboard, vault.settings.clipboard_seconds)
                if password:
                    window["-PWD-"].update(password)
                    update_strength(window, "-ESTR", password)
            elif event == "Save":
                if not values["-NAME-"].strip():
                    window["-MSG-"].update("The account name cannot be empty.")
                    continue
                if values["-TOTP-"].strip():
                    try:
                        totp.parse(values["-TOTP-"])
                    except ValueError as exc:
                        window["-MSG-"].update(str(exc))
                        continue
                return {"name": values["-NAME-"].strip(), "username": values["-USR-"],
                        "password": values["-PWD-"], "url": values["-URL-"].strip(),
                        "category": (values["-CAT-"] or "").strip(),
                        "totp": values["-TOTP-"].strip(),
                        "notes": values["-NOTES-"].rstrip("\n")}
    finally:
        window.close()


def history_dialog(entry, clipboard, seconds):
    if not entry.history:
        info(f'"{entry.name}" has no previous passwords.')
        return
    rows = [[local_time(h.get("changed")), HIDDEN] for h in entry.history]
    layout = [
        [sg.Text(f'Previous passwords for "{entry.name}"', font=HEADER_FONT)],
        [sg.Table(rows, headings=["Replaced on", "Password"], col_widths=[18, 30],
                  auto_size_columns=False, justification="left", num_rows=min(10, len(rows)),
                  key="-T-", select_mode=sg.TABLE_SELECT_MODE_BROWSE, font=MONO)],
        [sg.Checkbox("Show passwords", key="-SHOW-", enable_events=True),
         sg.Button("Copy selected", key="-COPY-"), sg.Push(), sg.Button("Close")],
    ]
    window = make_window("Password history", layout, modal=True)
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Close"):
            break
        if event == "-SHOW-":
            window["-T-"].update(values=[[local_time(h.get("changed")),
                                          h["password"] if values["-SHOW-"] else HIDDEN]
                                         for h in entry.history])
        elif event == "-COPY-" and values["-T-"]:
            clipboard.copy(entry.history[values["-T-"][0]]["password"], seconds)
    window.close()


def trash_dialog(vault):
    """Returns True if anything changed."""
    def rows():
        return [[e.name, e.username, local_time(e.deleted)] for e in vault.trash_entries()]

    layout = [
        [sg.Text("Trash", font=HEADER_FONT)],
        [sg.Text(f"Deleted accounts are kept for {vault.settings.trash_days} days, "
                 "then removed for good.", font=SMALL_FONT)],
        [sg.Table(rows(), headings=["Name", "Username", "Deleted on"], col_widths=[22, 22, 16],
                  auto_size_columns=False, justification="left", num_rows=12, key="-T-",
                  select_mode=sg.TABLE_SELECT_MODE_BROWSE)],
        [sg.Button("Restore", key="-RESTORE-"), sg.Button("Delete forever", key="-FOREVER-"),
         sg.Button("Empty trash", key="-EMPTY-"), sg.Push(), sg.Button("Close")],
    ]
    window = make_window("Trash", layout, modal=True)
    changed = False
    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, "Close"):
            break
        trashed = vault.trash_entries()
        picked = trashed[values["-T-"][0]] if values["-T-"] and values["-T-"][0] < len(trashed) \
            else None
        if event == "-RESTORE-" and picked:
            vault.restore_entry(picked.id)
            changed = True
        elif event == "-FOREVER-" and picked and \
                confirm(f'Delete "{picked.name}" forever? This cannot be undone.'):
            vault.delete_forever(picked.id)
            changed = True
        elif event == "-EMPTY-" and trashed and \
                confirm(f"Delete all {len(trashed)} account(s) in the trash forever?"):
            vault.empty_trash()
            changed = True
        window["-T-"].update(values=rows())
    window.close()
    return changed


def settings_dialog(vault):
    s = vault.settings
    layout = [
        [sg.Text("Settings", font=HEADER_FONT)],
        [sg.Text("Lock after this many idle minutes (0 = never)", size=(42, 1)),
         sg.Spin(list(range(0, 121)), s.autolock_minutes, key="-LOCK-", size=(4, 1))],
        [sg.Text("Clear copied passwords after seconds (0 = never)", size=(42, 1)),
         sg.Spin(list(range(0, 301)), s.clipboard_seconds, key="-CLIP-", size=(4, 1))],
        [sg.Text("Keep deleted accounts in the trash for days", size=(42, 1)),
         sg.Spin(list(range(1, 366)), s.trash_days, key="-TRASH-", size=(4, 1))],
        [sg.Push(), sg.Button("Save"), sg.Button("Cancel")],
    ]
    window = make_window("Settings", layout, modal=True)
    event, values = window.read()
    window.close()
    if event == "Save":
        try:
            vault.update_settings(autolock_minutes=int(values["-LOCK-"]),
                                  clipboard_seconds=int(values["-CLIP-"]),
                                  trash_days=int(values["-TRASH-"]))
        except ValueError:
            error("Please enter whole numbers.")
            return False
        return True
    return False


def change_master_dialog(vault):
    """Returns True if the master password was changed."""
    layout = [[sg.Text("Change master password", font=HEADER_FONT)],
              [sg.Text("Current password", size=(16, 1)),
               sg.Input(key="-CUR-", password_char=MASK, size=(32, 1), focus=True)]] + \
        new_password_rows("Your backups will be re-encrypted with the new password.") + [
        [sg.Text("", key="-MSG-", text_color="#ff6b6b", size=(60, 1))],
        [sg.Push(), sg.Button("Change"), sg.Button("Cancel")]]
    window = make_window("Change master password", layout, modal=True)
    update_strength(window, "-STR", "")
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Cancel"):
                return False
            if event == "-SHOWPWD-":
                toggle_masked(window, "-PWD-", values["-SHOWPWD-"])
                toggle_masked(window, "-PWD2-", values["-SHOWPWD-"])
            elif event == "-PWD-":
                update_strength(window, "-STR", values["-PWD-"])
            elif event == "Change" and accept_new_password(window, values):
                window["-MSG-"].update("Working...", text_color="gray")
                window.refresh()
                try:
                    leftovers = vault.change_master_password(values["-CUR-"], values["-PWD-"])
                except Pk.WrongPasswordError:
                    window["-MSG-"].update("The current password is wrong.", text_color="#ff6b6b")
                    continue
                except Pk.VaultError as exc:
                    window["-MSG-"].update(str(exc), text_color="#ff6b6b")
                    continue
                window.close()
                if leftovers and confirm(
                        f"{len(leftovers)} older backup(s) were made with an earlier master "
                        "password and still open with it.\n\nDelete them now?"):
                    for path in leftovers:
                        Pk.secure_delete(path)
                info("Master password changed.")
                return True
    finally:
        window.close()


def restore_dialog(vault):
    """Returns the number of restored accounts, or None if cancelled."""
    layout = [
        [sg.Text("Restore a backup", font=HEADER_FONT)],
        [sg.Text("Backup file", size=(18, 1)), sg.Input(key="-FILE-", size=(40, 1)),
         sg.FileBrowse(initial_folder=str(vault.backup_dir),
                       file_types=(("PassKeeper backups", "*.pk"), ("All files", "*.*")))],
        [sg.Text("Its master password", size=(18, 1)),
         sg.Input(key="-PWD-", password_char=MASK, size=(40, 1))],
        [sg.Radio("Merge: add missing accounts and newer changes (recommended)", "MODE", True,
                  key="-MERGE-")],
        [sg.Radio("Replace: make the vault exactly like the backup", "MODE", False,
                  key="-REPLACE-")],
        [sg.Text("A backup of the current accounts is made first.", font=SMALL_FONT)],
        [sg.Text("", key="-MSG-", text_color="#ff6b6b", size=(60, 1))],
        [sg.Push(), sg.Button("Restore"), sg.Button("Cancel")],
    ]
    window = make_window("Restore backup", layout, modal=True)
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Cancel"):
                return None
            if not values["-FILE-"]:
                window["-MSG-"].update("Choose a backup file.")
                continue
            mode = "merge" if values["-MERGE-"] else "replace"
            if mode == "replace" and not confirm(
                    "Replace ALL current accounts with the ones in this backup?"):
                continue
            try:
                return vault.restore_backup(Path(values["-FILE-"]), values["-PWD-"], mode)
            except Pk.WrongPasswordError:
                window["-MSG-"].update("That password does not open this backup.")
            except (Pk.VaultError, OSError) as exc:
                window["-MSG-"].update(str(exc))
    finally:
        window.close()


def ask_master_password(vault, reason):
    password = sg.popup_get_text(f"{reason}\n\nType your master password:", title=APP_TITLE,
                                 password_char=MASK, icon=window_icon(), keep_on_top=True)
    if password is None:
        return False
    if not vault.verify_password(password):
        error("Wrong master password.")
        return False
    return True


def wipe_dialog(vault):
    """Panic button. Returns True if everything was wiped."""
    layout = [
        [sg.Text("Wipe everything", font=HEADER_FONT, text_color="#ff6b6b")],
        [sg.Text("This permanently destroys the vault and ALL backups in\n"
                 f"{vault.backup_dir}.\nCopies you saved elsewhere are not touched.")],
        [sg.Text("Master password", size=(22, 1)),
         sg.Input(key="-PWD-", password_char=MASK, size=(30, 1))],
        [sg.Text("Type DELETE to confirm", size=(22, 1)), sg.Input(key="-CONFIRM-", size=(30, 1))],
        [sg.Text("", key="-MSG-", text_color="#ff6b6b", size=(55, 1))],
        [sg.Push(), sg.Button("Wipe everything", button_color=("white", "#b52b27")),
         sg.Button("Cancel")],
    ]
    window = make_window("Wipe everything", layout, modal=True)
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, "Cancel"):
                return False
            if values["-CONFIRM-"].strip() != "DELETE":
                window["-MSG-"].update("Type DELETE (in capitals) to confirm.")
            elif not vault.verify_password(values["-PWD-"]):
                window["-MSG-"].update("Wrong master password.")
            else:
                Pk.wipe_all_data(vault.path)
                vault.close()
                return True
    finally:
        window.close()


# --------------------------------------------------------------------------- #
# Main window
# --------------------------------------------------------------------------- #

MENU = [
    ["&File", ["&New account   Ctrl+N::-ADD-", "---",
               "&Import from CSV...::-IMPORT-", "&Export to CSV...::-EXPORT-", "---",
               "&Backup now::-BACKUP-", "Save backup &copy to...::-EXPORTBKP-",
               "&Restore backup...::-RESTORE-", "---",
               "&Lock   Ctrl+L::-LOCK-", "E&xit::-EXIT-"]],
    ["&Vault", ["&Trash...::-TRASH-", "&Settings...::-SETTINGS-",
                "&Change master password...::-CHANGEMP-", "---",
                "&Wipe everything...::-WIPE-"]],
    ["&Tools", ["Password &generator...::-GEN-"]],
    ["&Help", ["&About PassKeeper::-ABOUT-"]],
]
ALL_CATEGORIES = "All categories"
NO_CATEGORY = "(No category)"
DETAIL_BUTTONS = ("-C-USR-", "-C-PWD-", "-SHOW-", "-C-URL-", "-OPEN-", "-C-OTP-",
                  "-EDIT-", "-HISTORY-", "-DELETE-")


def detail_row(label, value_key, buttons):
    """Label, value, then right-aligned buttons ("Copy" always last, so they line up)."""
    return [sg.Text(label, size=(10, 1), text_color="gray"),
            sg.Text("", key=value_key, size=(26, 1), font=MONO if value_key in
                    ("-D-PWD-", "-D-OTP-") else FONT), sg.Push()] + buttons


def main_window(vault, clipboard):
    """Returns "lock", "exit" or "wiped"."""
    top = [sg.Text(APP_TITLE, font=TITLE_FONT), sg.Push(), sg.Text("Search"),
           sg.Input(key="-SEARCH-", enable_events=True, size=(26, 1),
                    tooltip="Search name, username, website, notes  (Ctrl+F)"),
           sg.Combo([ALL_CATEGORIES], ALL_CATEGORIES, key="-CATF-", readonly=True,
                    enable_events=True, size=(16, 1)),
           sg.Button("+ New", key="-ADD-"), sg.Button("Lock", key="-LOCK-")]
    table = sg.Table([], headings=["Name", "Username", "Category"], col_widths=[18, 20, 11],
                     auto_size_columns=False, justification="left", num_rows=18,
                     key="-TABLE-", enable_events=True, expand_x=True, expand_y=True,
                     select_mode=sg.TABLE_SELECT_MODE_BROWSE, alternating_row_color=None)
    details = [
        [sg.Text("Select an account", key="-D-NAME-", font=HEADER_FONT, size=(36, 1))],
        detail_row("Username", "-D-USR-", [sg.Button("Copy", key="-C-USR-")]),
        detail_row("Password", "-D-PWD-", [sg.Button("Show", key="-SHOW-", size=(5, 1)),
                                           sg.Button("Copy", key="-C-PWD-")]),
        detail_row("Website", "-D-URL-", [sg.Button("Open", key="-OPEN-", size=(5, 1)),
                                          sg.Button("Copy", key="-C-URL-")]),
        detail_row("2FA code", "-D-OTP-", [sg.Button("Copy", key="-C-OTP-")]),
        detail_row("Category", "-D-CAT-", []),
        [sg.Text("Notes", text_color="gray")],
        [sg.Multiline("", key="-D-NOTES-", size=(46, 5), disabled=True, expand_x=True)],
        [sg.Text("", key="-D-META-", font=SMALL_FONT, text_color="gray", size=(46, 1))],
        [sg.Button("Edit", key="-EDIT-"), sg.Button("Password history", key="-HISTORY-"),
         sg.Push(), sg.Button("Delete", key="-DELETE-")],
    ]
    layout = [
        [sg.Menu(MENU, key="-MENU-")],
        top,
        [sg.Column([[table]], expand_x=True, expand_y=True),
         sg.VSeparator(),
         sg.Column(details, vertical_alignment="top")],
        [sg.Text("", key="-STATUS-", size=(70, 1), font=SMALL_FONT, expand_x=True),
         sg.Text("", key="-COUNT-", font=SMALL_FONT)],
    ]
    window = make_window(f"{APP_TITLE} - {vault.path.name}", layout, resizable=True)
    for key, event in (("<Control-n>", "-ADD-"), ("<Control-l>", "-LOCK-"),
                       ("<Control-f>", "-FOCUS-SEARCH-")):
        window.bind(key, event)
    # Any mouse movement or key press counts as activity for the auto-lock.
    window.bind("<Motion>", "-ACTIVITY-")
    window.bind("<KeyPress>", "-ACTIVITY-")
    window["-TABLE-"].bind("<Double-Button-1>", "+DOUBLE")

    state = {"ids": [], "selected": None, "show": False, "changed": False,
             "last_activity": time.monotonic()}

    def status(message):
        window["-STATUS-"].update(message)

    def selected():
        return vault.get(state["selected"]) if state["selected"] else None

    def refresh_categories():
        cats = vault.categories()
        values = [ALL_CATEGORIES] + cats + ([NO_CATEGORY] if any(
            not e.category for e in vault.active_entries()) and cats else [])
        current = window["-CATF-"].get()
        window["-CATF-"].update(values=values,
                                value=current if current in values else ALL_CATEGORIES)

    def refresh_table(select_id=None):
        refresh_categories()
        cat = window["-CATF-"].get()
        cat = None if cat == ALL_CATEGORIES else ("" if cat == NO_CATEGORY else cat)
        entries = vault.search(window["-SEARCH-"].get(), cat)
        state["ids"] = [e.id for e in entries]
        if select_id is not None:
            state["selected"] = select_id
        if state["selected"] not in state["ids"]:
            state["selected"] = None
        rows = [[e.name, e.username, e.category] for e in entries]
        if state["selected"]:
            window["-TABLE-"].update(values=rows,
                                     select_rows=[state["ids"].index(state["selected"])])
        else:
            window["-TABLE-"].update(values=rows)
        total = len(vault.active_entries())
        window["-COUNT-"].update(f"{len(entries)} of {total} account(s)" if len(entries) != total
                                 else f"{total} account(s)")
        refresh_details()

    def refresh_details():
        e = selected()
        for key in DETAIL_BUTTONS:
            window[key].update(disabled=e is None)
        if e is None:
            for key in ("-D-USR-", "-D-PWD-", "-D-URL-", "-D-OTP-", "-D-CAT-", "-D-META-"):
                window[key].update("")
            window["-D-NAME-"].update("Select an account" if state["ids"] else
                                      "No accounts yet - click + New")
            window["-D-NOTES-"].update("")
            return
        window["-D-NAME-"].update(e.name)
        window["-D-USR-"].update(e.username or "-")
        window["-D-PWD-"].update(e.password if state["show"] else (HIDDEN if e.password else "-"))
        window["-SHOW-"].update("Hide" if state["show"] else "Show")
        window["-D-URL-"].update(e.url or "-")
        window["-C-URL-"].update(disabled=not e.url)
        window["-OPEN-"].update(disabled=not e.url)
        window["-C-OTP-"].update(disabled=not e.totp)
        window["-HISTORY-"].update(disabled=not e.history)
        window["-D-CAT-"].update(e.category or "-")
        window["-D-NOTES-"].update(e.notes)
        window["-D-META-"].update(f"Created {local_time(e.created)}   ·   "
                                  f"Modified {local_time(e.modified)}")
        refresh_otp()

    def refresh_otp():
        e = selected()
        if not e or not e.totp:
            window["-D-OTP-"].update("-" if e else "")
            return
        try:
            c = totp.code(e.totp)
            window["-D-OTP-"].update(f"{c[:len(c)//2]} {c[len(c)//2:]}   ({totp.seconds_left(e.totp)}s)")
        except ValueError:
            window["-D-OTP-"].update("invalid secret")

    def copy(text, what):
        seconds = vault.settings.clipboard_seconds
        clipboard.copy(text, seconds)
        status(f"{what} copied." + (f" The clipboard will be cleared in {seconds} seconds."
                                     if seconds else ""))

    def mark_changed():
        state["changed"] = True

    def finish(result):
        clipboard.clear_now()
        window.close()
        if state["changed"] and result != "wiped":
            try:
                vault.create_backup("auto")
            except OSError as exc:
                error(f"Automatic backup failed:\n{exc}")
        if result == "lock":
            vault.close()
        return result

    refresh_table()
    status(f"Vault: {vault.path}")

    while True:
        event, values = window.read(timeout=TICK_MS)
        if event == sg.WIN_CLOSED:
            return finish("exit")
        if isinstance(event, str) and "::" in event:
            event = event.split("::")[-1]

        if event == sg.TIMEOUT_EVENT:
            if clipboard.tick():
                status("Clipboard cleared.")
            refresh_otp()
            minutes = vault.settings.autolock_minutes
            if minutes and time.monotonic() - state["last_activity"] > minutes * 60:
                return finish("lock")
            continue
        state["last_activity"] = time.monotonic()
        if event == "-ACTIVITY-":
            continue

        try:
            if event == "-EXIT-":
                return finish("exit")
            elif event == "-LOCK-":
                return finish("lock")

            elif event == "-FOCUS-SEARCH-":
                window["-SEARCH-"].set_focus()
            elif event in ("-SEARCH-", "-CATF-"):
                refresh_table()

            elif event == "-TABLE-":
                rows = values["-TABLE-"]
                new = state["ids"][rows[0]] if rows and rows[0] < len(state["ids"]) else None
                if new != state["selected"]:
                    state["selected"], state["show"] = new, False
                    refresh_details()

            elif event == "-SHOW-" and selected():
                state["show"] = not state["show"]
                refresh_details()

            elif event == "-C-USR-" and selected():
                copy(selected().username, "Username")
            elif event == "-C-PWD-" and selected():
                copy(selected().password, "Password")
            elif event == "-C-URL-" and selected():
                copy(selected().url, "Website")
            elif event == "-C-OTP-" and selected() and selected().totp:
                copy(totp.code(selected().totp), "2FA code")
            elif event == "-OPEN-" and selected() and selected().url:
                url = selected().url
                webbrowser.open(url if "://" in url else "https://" + url)

            elif event == "-ADD-":
                data = entry_dialog(vault, clipboard=clipboard)
                if data:
                    entry = vault.add_entry(**data)
                    mark_changed()
                    refresh_table(select_id=entry.id)
                    status(f'Saved "{entry.name}".')

            elif event in ("-EDIT-", "-TABLE-+DOUBLE") and selected():
                entry = selected()
                data = entry_dialog(vault, entry, clipboard)
                if data:
                    vault.update_entry(entry.id, **data)
                    mark_changed()
                    refresh_table(select_id=entry.id)
                    status(f'Updated "{entry.name}".')

            elif event == "-HISTORY-" and selected():
                history_dialog(selected(), clipboard, vault.settings.clipboard_seconds)

            elif event == "-DELETE-" and selected():
                entry = selected()
                vault.remove_entry(entry.id)
                mark_changed()
                refresh_table()
                status(f'Moved "{entry.name}" to the Trash (Vault > Trash to restore it).')

            elif event == "-TRASH-":
                if trash_dialog(vault):
                    mark_changed()
                    refresh_table()

            elif event == "-GEN-":
                generator_dialog(clipboard, vault.settings.clipboard_seconds, allow_use=False)

            elif event == "-BACKUP-":
                status(f"Backup saved to {vault.create_backup('manual')}")

            elif event == "-EXPORTBKP-":
                path = sg.popup_get_file(
                    "Save an encrypted backup copy (e.g. to a USB stick or cloud folder):",
                    title=APP_TITLE, save_as=True, default_extension=".pk",
                    default_path=f"passkeeper-backup-{datetime.now():%Y%m%d}.pk",
                    file_types=(("PassKeeper backups", "*.pk"),), icon=window_icon())
                if path:
                    status(f"Backup copy saved to {vault.export_backup(Path(path))}")

            elif event == "-RESTORE-":
                count = restore_dialog(vault)
                if count is not None:
                    mark_changed()
                    refresh_table()
                    status(f"Restored {count} account(s).")

            elif event == "-IMPORT-":
                path = sg.popup_get_file(
                    "Import accounts from a CSV file exported by your browser or another\n"
                    "password manager (Chrome, Edge, Firefox, Bitwarden, KeePassXC...):",
                    title=APP_TITLE, file_types=(("CSV files", "*.csv"), ("All files", "*.*")),
                    icon=window_icon())
                if path:
                    added, skipped = vault.import_csv(Path(path))
                    mark_changed()
                    refresh_table()
                    info(f"Imported {added} account(s)." +
                         (f" Skipped {skipped} that were already in the vault." if skipped else "")
                         + "\n\nRemember to delete the CSV file: it is not encrypted.")

            elif event == "-EXPORT-":
                if ask_master_password(
                        vault, "Exporting writes ALL your passwords to a plain, unencrypted file."):
                    path = sg.popup_get_file("Save the CSV file as:", title=APP_TITLE,
                                             save_as=True, default_extension=".csv",
                                             file_types=(("CSV files", "*.csv"),),
                                             icon=window_icon())
                    if path:
                        count = vault.export_csv(Path(path))
                        info(f"Exported {count} account(s) to\n{path}\n\n"
                             "Delete this file as soon as you are done with it.")

            elif event == "-SETTINGS-":
                if settings_dialog(vault):
                    status("Settings saved.")

            elif event == "-CHANGEMP-":
                if change_master_dialog(vault):
                    status("Master password changed.")

            elif event == "-WIPE-":
                if wipe_dialog(vault):
                    info("Everything was wiped.")
                    return finish("wiped")

            elif event == "-ABOUT-":
                info(f"{APP_TITLE} {APP_VERSION}\n\nA small local password manager.\n"
                     "Encryption: scrypt + AES-256-GCM.\n\n"
                     f"Vault: {vault.path}\nBackups: {vault.backup_dir}")

        except Pk.VaultError as exc:
            error(str(exc))
        except OSError as exc:
            error(f"Could not read or write a file:\n{exc}")
        except ValueError as exc:
            error(str(exc))


def open_vault(vault_path):
    if vault_path.exists():
        return unlock_window(vault_path)
    if Pk.legacy_files_present(vault_path.parent):
        return migrate_window(vault_path.parent, vault_path)
    return setup_window(vault_path)


def main():
    vault_path = Pk.default_vault_path()
    lock = Pk.VaultLock(vault_path)
    try:
        lock.acquire()
    except Pk.VaultLockedError as exc:
        error(str(exc))
        return
    except OSError as exc:
        error(f"Could not open the vault folder:\n{exc}")
        return

    clipboard = Clipboard()
    try:
        vault = open_vault(vault_path)
        while vault is not None:
            result = main_window(vault, clipboard)
            vault = unlock_window(vault_path) if result == "lock" else None
    except OSError as exc:
        error(f"Could not open the vault:\n{exc}")
    finally:
        clipboard.clear_now()
        lock.release()
        if not vault_path.exists():
            try:
                lock.path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    main()
