# PassKeeper 2.0

Little app to generate and locally store passwords/accounts.

The GUI uses [FreeSimpleGUI](https://github.com/spyoungtech/FreeSimpleGUI), the free fork of
PySimpleGUI (PySimpleGUI 5 needs a paid licence key). Generated passwords are based on
[password-generator-py](https://github.com/gabfl/password-generator-py).

## How to use

```bash
pip install -r requirements.txt
python PassKeeper_GUI.py
```

- **First use:** choose a master password (at least 8 characters). There is no way to
  recover it, so don't forget it.
- **After that:** type the master password to unlock the vault. Then you can:
  - add, edit, delete and search accounts (the **Generate** button creates a password);
  - show/hide a password and copy the username or password to the clipboard;
  - make a backup, restore a backup or change the master password.

A timestamped backup is saved automatically when you close the app after making changes.
The 10 most recent backups are kept in the `backups/` folder.

### Upgrading from 1.x

If PassKeeper finds 1.x files (`accounts.json`, `salt.txt`, `safe/main_password.txt`), it
asks for your old master password and moves everything into the new encrypted vault. The
old files are deleted only after the new vault has been checked. They have to be deleted:
1.x did not really encrypt passwords, so anyone with those files could read them.

## How your data is protected

Everything is stored in one file, `vault.pk`:

- A key is derived from your master password with **scrypt** (n=2^17, r=8, p=1), which
  makes guessing the master password slow and expensive.
- All accounts are encrypted together with **AES-256-GCM**. A wrong password, or any
  change to the file, makes decryption fail. No password hash is stored.
- Files are saved atomically, so a crash or power loss during a save can't corrupt the vault.
- Backups are copies of the encrypted vault, so they are just as safe.

By default the vault lives next to the app, so the whole folder can be carried on a USB
stick. To keep it somewhere else, set the `PASSKEEPER_HOME` environment variable to a folder.

## Running the tests

```bash
python -m unittest discover -s tests -v
```

## Building the .exe

With PyInstaller (run in the project folder on Windows):

```bash
pyinstaller --onefile -w --icon=Figures\padlock.ico --add-data "data;data" --add-data "Figures;Figures" PassKeeper_GUI.py
```

Admin rights (`--uac-admin`) are no longer needed. The vault is created next to the .exe.

## Latest changes

- **2.0**
  - Real encryption: scrypt + AES-256-GCM in a single vault file, plus automatic migration from 1.x.
  - Fixed: crash on first run, error when closing the app, the app closing on a wrong
    password, "Copy Username" doing nothing, crashes when no account is selected,
    the 49-account limit, accounts with the same name overwriting each other, and
    Windows-only file paths.
  - Edit accounts, notes, search, change master password.
  - Timestamped backups (the last 10 are kept); restoring asks for confirmation and
    backs up the current state first.
  - The password generator now uses the `secrets` module.
  - Tests and CI.
- **1.1**: backups, delete accounts, cleaned up the salt file.

## Possible features to add

- Clear the clipboard automatically after a few seconds
- Lock the vault automatically when idle
- Restore the panic button (with a confirmation prompt)
- Folders/categories to organise the passwords
- Portuguese dictionary for the generator?
