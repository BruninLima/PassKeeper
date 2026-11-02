"""PassKeeper GUI.

Run with:  python PassKeeper_GUI.py
"""

import sys
from pathlib import Path

try:  # FreeSimpleGUI is the free, LGPL fork of PySimpleGUI with the same API.
    import FreeSimpleGUI as sg
except ImportError:  # pragma: no cover - fall back to PySimpleGUI if installed
    import PySimpleGUI as sg

import PassKeeper as Pk
from PasswordGenerator import pw

APP_TITLE = "Password Keeper"
HIDDEN = "********"

sg.theme('DarkAmber')


def resource_path(*parts) -> Path:
    """Path to a file shipped with the app (also inside a PyInstaller bundle)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base.joinpath(*parts)


def window_icon():
    icon = resource_path("Figures", "padlock.ico")
    # Tk only understands .ico files on Windows.
    return str(icon) if sys.platform.startswith("win") and icon.exists() else None


def make_window(title, layout, **kwargs):
    return sg.Window(title, layout, icon=window_icon(), finalize=True, **kwargs)


def error(message):
    sg.popup_error(message, title=APP_TITLE, icon=window_icon())


# --------------------------------------------------------------------------- #
# Unlock / first-time setup / 1.x migration
# --------------------------------------------------------------------------- #

def title_image():
    image = resource_path("Figures", "main_title.png")
    return [[sg.Image(str(image))]] if image.exists() else []


def unlock_window(vault_path):
    """Ask for the master password until the vault opens. Returns the Vault,
    or None if the user gives up."""
    layout = title_image() + [
        [sg.Text('Please type your master password')],
        [sg.Input(key='-PWD-', password_char='*', focus=True)],
        [sg.Text('', key='-MSG-', text_color='red', size=(45, 1))],
        [sg.Button('Unlock', bind_return_key=True), sg.Button('Exit')],
    ]
    window = make_window(APP_TITLE, layout)
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, 'Exit'):
                return None
            window['-MSG-'].update('Unlocking...')
            window.refresh()
            try:
                return Pk.Vault.open(vault_path, values['-PWD-'])
            except Pk.WrongPasswordError:
                window['-MSG-'].update('Wrong master password. Try again.')
                window['-PWD-'].update('')
            except Pk.VaultError as exc:
                error(str(exc))
                return None
    finally:
        window.close()


def setup_window(vault_path):
    """First run: choose a master password and create an empty vault."""
    layout = title_image() + [
        [sg.Text('Welcome! Choose a master password.')],
        [sg.Text(f'It must have at least {Pk.MIN_MASTER_PASSWORD_LENGTH} characters. '
                 'If you forget it, your passwords cannot be recovered.')],
        [sg.Text('Master password', size=(16, 1)),
         sg.Input(key='-PWD-', password_char='*', focus=True)],
        [sg.Text('Repeat it', size=(16, 1)), sg.Input(key='-PWD2-', password_char='*')],
        [sg.Text('', key='-MSG-', text_color='red', size=(60, 1))],
        [sg.Button('Create vault', bind_return_key=True), sg.Button('Exit')],
    ]
    window = make_window(APP_TITLE, layout)
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, 'Exit'):
                return None
            if values['-PWD-'] != values['-PWD2-']:
                window['-MSG-'].update('The passwords do not match.')
                continue
            try:
                return Pk.Vault.create(vault_path, values['-PWD-'])
            except Pk.VaultError as exc:
                window['-MSG-'].update(str(exc))
    finally:
        window.close()


def migrate_window(directory, vault_path):
    """Upgrade PassKeeper 1.x files to the encrypted vault."""
    layout = title_image() + [
        [sg.Text('Found data from PassKeeper 1.x, which was not stored securely.')],
        [sg.Text('Type your old master password to move it into an encrypted vault.\n'
                 'The old files will be deleted after the upgrade.')],
        [sg.Input(key='-PWD-', password_char='*', focus=True)],
        [sg.Text('', key='-MSG-', text_color='red', size=(60, 1))],
        [sg.Button('Upgrade', bind_return_key=True), sg.Button('Exit')],
    ]
    window = make_window(APP_TITLE, layout)
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, 'Exit'):
                return None
            try:
                vault = Pk.migrate_legacy(directory, values['-PWD-'], vault_path)
            except Pk.WrongPasswordError:
                window['-MSG-'].update('Wrong master password. Try again.')
                continue
            except Exception as exc:  # keep the old files, tell the user why
                error(f'The upgrade failed and your old files were kept:\n{exc}')
                return None
            sg.popup(f'Upgrade complete: {len(vault.entries)} account(s) moved to the '
                     'encrypted vault.', title=APP_TITLE, icon=window_icon())
            return vault
    finally:
        window.close()


# --------------------------------------------------------------------------- #
# Add / edit dialog
# --------------------------------------------------------------------------- #

def entry_dialog(title, entry=None):
    """Ask for name/username/password. Returns a dict, or None if cancelled."""
    layout = [
        [sg.Text('Account name', size=(12, 1)),
         sg.Input(entry.name if entry else '', key='-NAME-', focus=True)],
        [sg.Text('Username', size=(12, 1)), sg.Input(entry.username if entry else '', key='-USR-')],
        [sg.Text('Password', size=(12, 1)), sg.Input(entry.password if entry else '', key='-PWD-'),
         sg.Button('Generate')],
        [sg.Text('Notes', size=(12, 1)),
         sg.Multiline(entry.notes if entry else '', key='-NOTES-', size=(43, 3))],
        [sg.Text('', key='-MSG-', text_color='red', size=(50, 1))],
        [sg.Button('Save'), sg.Button('Cancel')],
    ]
    window = make_window(title, layout, modal=True)
    try:
        while True:
            event, values = window.read()
            if event in (sg.WIN_CLOSED, 'Cancel'):
                return None
            if event == 'Generate':
                window['-PWD-'].update(pw())
            elif event == 'Save':
                if not values['-NAME-'].strip():
                    window['-MSG-'].update('The account name cannot be empty.')
                    continue
                return {'name': values['-NAME-'].strip(), 'username': values['-USR-'],
                        'password': values['-PWD-'], 'notes': values['-NOTES-'].rstrip('\n')}
    finally:
        window.close()


# --------------------------------------------------------------------------- #
# Main window
# --------------------------------------------------------------------------- #

def describe(entry, show_password):
    text = (f"Name: {entry.name}\n"
            f"Username: {entry.username}\n"
            f"Password: {entry.password if show_password else HIDDEN}")
    if entry.notes:
        text += f"\n\nNotes:\n{entry.notes}"
    return text


def main_window(vault):
    left = [
        [sg.Text('Search'), sg.Input(key='-SEARCH-', enable_events=True, size=(38, 1))],
        [sg.Listbox(values=[], size=(45, 22), key='-LIST-', enable_events=True)],
        [sg.Button('Add', key='-ADD-'), sg.Button('Edit', key='-EDIT-'),
         sg.Button('Delete', key='-DELETE-')],
    ]
    right = [
        [sg.Text('Choose an account from the list on the left')],
        [sg.Text('', size=(50, 18), key='-DETAILS-')],
        [sg.Button('Show Password', key='-SHOW-'), sg.Button('Hide Password', key='-HIDE-')],
        [sg.Button('Copy Username', key='-COPYUSR-'),
         sg.Button('Copy Password', key='-COPYPWD-')],
    ]
    layout = [
        [sg.Column(left), sg.VSeperator(), sg.Column(right, vertical_alignment='top')],
        [sg.Button('Backup now', key='-BACKUP-'), sg.Button('Restore backup', key='-RESTORE-'),
         sg.Button('Change master password', key='-CHANGEMP-'), sg.Push(),
         sg.Button('Exit', key='-EXIT-')],
        [sg.StatusBar('', key='-STATUS-', size=(80, 1))],
    ]
    window = make_window(APP_TITLE, layout)

    shown_ids = []        # entry ids in the same order as the listbox rows
    selected_id = None
    show_password = False
    changed = False       # make an automatic backup on exit only if something changed

    def status(message):
        window['-STATUS-'].update(message)

    def refresh_list(keep_selection=True):
        nonlocal shown_ids, selected_id
        query = window['-SEARCH-'].get().strip().casefold()
        entries = [e for e in vault.sorted_entries()
                   if not query or query in e.name.casefold() or query in e.username.casefold()]
        shown_ids = [e.id for e in entries]
        window['-LIST-'].update([f"{e.name}  ({e.username})" if e.username else e.name
                                 for e in entries])
        if keep_selection and selected_id in shown_ids:
            window['-LIST-'].update(set_to_index=[shown_ids.index(selected_id)])
        else:
            selected_id = None
        refresh_details()

    def refresh_details():
        if selected_id is None:
            window['-DETAILS-'].update('')
        else:
            window['-DETAILS-'].update(describe(vault.get(selected_id), show_password))

    def require_selection():
        if selected_id is None:
            status('Select an account first.')
            return None
        return vault.get(selected_id)

    refresh_list()
    status(f'{len(vault.entries)} account(s) - vault: {vault.path}')

    while True:
        event, values = window.read()
        if event in (sg.WIN_CLOSED, '-EXIT-'):
            break

        try:
            if event == '-SEARCH-':
                refresh_list()

            elif event == '-LIST-':
                rows = window['-LIST-'].get_indexes()
                selected_id = shown_ids[rows[0]] if rows else None
                show_password = False
                refresh_details()

            elif event == '-SHOW-':
                if require_selection():
                    show_password = True
                    refresh_details()

            elif event == '-HIDE-':
                show_password = False
                refresh_details()

            elif event == '-COPYUSR-':
                entry = require_selection()
                if entry:
                    sg.clipboard_set(entry.username)
                    status(f'Username for "{entry.name}" copied to the clipboard.')

            elif event == '-COPYPWD-':
                entry = require_selection()
                if entry:
                    sg.clipboard_set(entry.password)
                    status(f'Password for "{entry.name}" copied to the clipboard.')

            elif event == '-ADD-':
                data = entry_dialog('Add account')
                if data:
                    selected_id = vault.add_entry(**data).id
                    changed = True
                    refresh_list()
                    status(f'Saved "{data["name"]}".')

            elif event == '-EDIT-':
                entry = require_selection()
                data = entry and entry_dialog('Edit account', entry)
                if data:
                    vault.update_entry(entry.id, **data)
                    changed = True
                    refresh_list()
                    status(f'Updated "{data["name"]}".')

            elif event == '-DELETE-':
                entry = require_selection()
                if entry and sg.popup_yes_no(f'Delete "{entry.name}"? This cannot be undone.',
                                             title=APP_TITLE, icon=window_icon()) == 'Yes':
                    vault.remove_entry(entry.id)
                    changed = True
                    refresh_list(keep_selection=False)
                    status(f'Deleted "{entry.name}".')

            elif event == '-BACKUP-':
                target = vault.create_backup()
                status(f'Backup saved to {target}')

            elif event == '-RESTORE-':
                path = sg.popup_get_file(
                    'Choose a backup to restore', title=APP_TITLE, icon=window_icon(),
                    initial_folder=str(vault.path.parent / Pk.BACKUP_DIRNAME),
                    file_types=(('Vault backups', '*.pk'), ('All files', '*.*')))
                if path:
                    password = sg.popup_get_text(
                        'Master password used when this backup was made:',
                        title=APP_TITLE, password_char='*', icon=window_icon())
                    if password is not None and sg.popup_yes_no(
                            'Replace all current accounts with the ones in this backup?\n'
                            '(A backup of the current accounts is made first.)',
                            title=APP_TITLE, icon=window_icon()) == 'Yes':
                        count = vault.restore_backup(Path(path), password)
                        changed = True
                        refresh_list(keep_selection=False)
                        status(f'Restored {count} account(s) from {path}')

            elif event == '-CHANGEMP-':
                new = sg.popup_get_text('New master password:', title=APP_TITLE,
                                        password_char='*', icon=window_icon())
                if new is not None:
                    again = sg.popup_get_text('Repeat the new master password:', title=APP_TITLE,
                                              password_char='*', icon=window_icon())
                    if again != new:
                        error('The passwords do not match. Nothing was changed.')
                    else:
                        vault.change_master_password(new)
                        status('Master password changed.')

        except Pk.WrongPasswordError:
            error('That password does not open this backup.')
        except Pk.VaultError as exc:
            error(str(exc))
        except OSError as exc:
            error(f'Could not read or write a file:\n{exc}')

    window.close()
    if changed:
        try:
            vault.create_backup()
        except OSError as exc:
            error(f'Automatic backup failed:\n{exc}')


def main():
    vault_path = Pk.default_vault_path()
    try:
        if vault_path.exists():
            vault = unlock_window(vault_path)
        elif Pk.legacy_files_present(vault_path.parent):
            vault = migrate_window(vault_path.parent, vault_path)
        else:
            vault = setup_window(vault_path)
    except OSError as exc:
        error(f'Could not open the vault:\n{exc}')
        return
    if vault is not None:
        main_window(vault)


if __name__ == '__main__':
    main()
