# PassKeeper 2.1

Little app to generate and locally store passwords/accounts.

The GUI uses [FreeSimpleGUI](https://github.com/spyoungtech/FreeSimpleGUI), the free fork of
PySimpleGUI (PySimpleGUI 5 needs a paid licence key). Passphrases are based on
[password-generator-py](https://github.com/gabfl/password-generator-py).

## How to use

```bash
pip install -r requirements.txt
```

```bash
python PassKeeper_GUI.py
```

- **First use:** choose a master password (at least 8 characters; a strength meter shows how
  good it is). There is no way to recover it, so don't forget it.
- **After that:** type the master password to unlock the vault.

In the main window you can:

- add, edit and delete accounts, each with a name, username, password, website, category,
  notes and an optional **2FA secret**. PassKeeper then shows the current 6-digit code.
- search and filter by category (Ctrl+F searches, Ctrl+N adds an account, double-click edits);
- copy the username, password, website or 2FA code. **Copied values are cleared from the
  clipboard after 20 seconds**;
- see an account's **password history** (the last 10 passwords);
- generate passwords (**Tools > Password generator**): passphrases or random characters;
- restore deleted accounts from the **Trash** (kept for 30 days);
- **import** from a CSV exported by Chrome, Edge, Firefox, Bitwarden, KeePassXC and others,
  or **export** to CSV (it asks for your master password, since the CSV file is not encrypted).

The vault **locks itself after 5 idle minutes** (or click **Lock**, or press Ctrl+L).
The timings can be changed in **Vault > Settings**.

Only one PassKeeper window can have the vault open at a time, so two windows can't overwrite
each other's changes.

### Backups

- **File > Backup now** saves a backup that is never deleted automatically.
- An automatic backup is saved when you close or lock the app after making changes. The last 10
  are kept.
- Before a restore, a safety backup of the current state is saved. The last 5 are kept.
- **File > Save backup copy to...** saves an encrypted copy anywhere, e.g. a USB stick or a
  cloud folder. Do this now and then: backups in the `backups/` folder are lost together with
  the vault if the drive is lost.
- **File > Restore backup...** either **merges** (adds missing accounts and newer changes,
  removes nothing) or **replaces** everything.

Changing the master password (**Vault > Change master password**) also re-encrypts the backups
in `backups/`, so the old password no longer opens them. Copies saved elsewhere still open with
the password they were made with.

### Panic button

**Vault > Wipe everything** overwrites and deletes the vault and all backups in `backups/`.
It asks for the master password and for you to type `DELETE`.

### Upgrading from 1.x

If PassKeeper finds 1.x files (`accounts.json`, `salt.txt`, `safe/main_password.txt`) next to
the app, it asks for your old master password and moves everything into the new encrypted
vault. The old files are overwritten and deleted after the new vault has been checked. They
have to go: 1.x did not really encrypt passwords, so anyone with those files could read them.

## How your data is protected

Everything is stored in one file, `vault.pk`:

- A key is derived from your master password with **scrypt** (n=2^17, r=8, p=1), which
  makes guessing the master password slow and expensive.
- All accounts and settings are encrypted together with **AES-256-GCM**. A wrong password, or
  any change to the file, makes decryption fail. No password hash is stored.
- Files are saved atomically, so a crash or power loss during a save can't corrupt the vault.
- Backups are encrypted the same way.

By default the vault lives next to the app, so the whole folder can be carried on a USB
stick. To keep it somewhere else, set the `PASSKEEPER_HOME` environment variable to a folder.

### What PassKeeper can't protect against

- **A compromised computer.** Malware or a keylogger can capture the master password or read
  passwords while the vault is unlocked. While the app runs, passwords are in memory as
  ordinary Python strings, which can't be reliably erased.
- **A weak master password.** Use 4 or more random words.
- **Recovering deleted files.** Old files are overwritten before deletion, but SSDs, file
  system journals and cloud-sync folders can still keep earlier copies.
- **Code review.** It uses standard, well-reviewed cryptography (`cryptography` and
  `hashlib.scrypt`), but nobody independent has reviewed PassKeeper itself. For your most
  important accounts, an audited manager such as Bitwarden or KeePassXC is the safer choice.

PassKeeper has no sync between devices, no phone app and no browser autofill.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

The GUI tests need a display. On Linux without one, run them with `xvfb-run`:

```bash
xvfb-run -a python -m unittest discover -s tests -v
```

## Building the .exe

With PyInstaller (run in the project folder on Windows):

```bash
pyinstaller --onefile -w --icon=Figures\padlock.ico --add-data "data;data" --add-data "Figures;Figures" PassKeeper_GUI.py
```

Admin rights (`--uac-admin`) are not needed. The vault is created next to the .exe.

## Latest changes

- **2.1**
  - New main window: account table, details panel with copy buttons, search, category filter,
    menus and keyboard shortcuts.
  - Security: clipboard auto-clear, auto-lock when idle, masked password fields, a strength
    meter, slower retries after wrong passwords, changing the master password requires the
    current one and re-encrypts backups, old files are overwritten before deletion.
  - Only one window can open the vault at a time.
  - Website, category and 2FA (TOTP) fields; password history; Trash.
  - Password generator: passphrases or random characters, with options.
  - CSV import (Chrome, Edge, Firefox, Bitwarden, KeePassXC...) and export.
  - Backups by kind (manual/auto/safety), save a backup copy anywhere, merge or replace on
    restore. Settings are stored in the encrypted vault.
  - Panic button (Wipe everything) is back, with confirmation.
  - GUI tests.
- **2.0**: real encryption (scrypt + AES-256-GCM), migration from 1.x, many crash fixes, tests.
- **1.1**: backups, delete accounts, cleaned up the salt file.

## Possible features to add

- Portuguese word list for the passphrase generator
- Sync between devices / browser autofill (would need a much bigger app)
