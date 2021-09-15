### Main file for the Password Keeper GUI ###

# Imports
from tkinter import Tk
import PySimpleGUI as sg
import PassKeeper as Pk
from PasswordGenerator import pw

# Global Variables
accs_path = 'accounts.json'
mpwd_path = 'safe/main_password.txt'
MAIN_PATH = r''

# Main Functions

sg.theme('DarkAmber')    # Keep things interesting for your users

main_screen_layout = [
    [sg.Image(MAIN_PATH + '\Figures\main_title.png')],
    [sg.Text("Hello from Brunin")],
    [sg.Button("Start", key='hello_friend'), sg.Button("No")]]

check_mp_layout = [[sg.Text('Hello. Please Type Your Master Password')],
                   [sg.Input(key='-MasterPassword-', password_char='*')],
                   [sg.Button('Start', key='Check_mp'), sg.Exit()]]

insert_mp_layout = [[sg.Text('Hello. Please Type Your Master Username and Master Password.')],
                    # I still dont have a use for this username :<
                    [sg.Input(key='-SetMasterUsername-')],
                    [sg.Input(key='-SetMasterPassword-', password_char='*')],
                    [sg.Button('Start', key='SetupMasterUser'), sg.Exit()]]

main_menu_layout = [[sg.Text('Hello. What do you want for today?')],
                    [sg.Button('Add new account and password',
                               key='-StoreAcc-')],
                    [sg.Button('View Stored Passwords', key='-Storage-')],
                    [sg.Button('Backup files', key='-Create_Bkp-'), sg.Button('Load Backup', key='-Load_Bkp-')]]  # ,
# [sg.Button('Panic', key='-Panic-')]]

add_new_acc_layout = [[sg.Text('Hello. Please Type a Name, Username and Password')],
                      [sg.Text("Account Name: "), sg.Input(key='-NewName-')],
                      [sg.Text("Username: "), sg.Input(key='-NewUsr-')],
                      [sg.Text("Password: "), sg.Input(key='-NewPwd-'),
                       sg.Button('Generate', key='GenPwd')],
                      [sg.Button('Save', key='NewSave'), sg.Exit()]]

name_list_column = [[sg.Text("Account Names")],
                    [sg.Listbox(values=[], size=(50, 25),
                                key='-LIST-', enable_events=True)],
                    [sg.Button("Show Password", key='-SHOWPASSWORD-'), sg.Button("Hide Password", key='-HIDEPASSWORD-'), sg.Button("Delete Account", key='-delete_account-'), sg.Button("Back", key='-BACK-')]]
password_viewer_column = [
    [sg.Text("Choose an account from the list on the left")],
    [sg.Text(size=(50, 25), key='-PASSWORDOUT-')],
    [sg.Button("Copy Username", key='-COPYUSR-'), sg.Button("Copy Password", key='-COPYTOCBOARD-')]]

storage_layout = [
                 [sg.Column(name_list_column),
                  sg.VSeperator(),
                  sg.Column(password_viewer_column)]]


layout = [
    [sg.pin(sg.Column(main_screen_layout, key='-MainTitle-', visible=True))],
    [sg.pin(sg.Column(check_mp_layout, key='-CheckMP-', visible=False))],
    [sg.pin(sg.Column(insert_mp_layout, key='-SetupMP-', visible=False))],
    [sg.pin(sg.Column(main_menu_layout, key='-MainMenu-', visible=False))],
    [sg.pin(sg.Column(add_new_acc_layout, key='-NewAccMenu-', visible=False))],
    [sg.pin(sg.Column(storage_layout, key='-StorageMenu-', visible=False))]
]


window = sg.Window(
    "Password Keeper",
    layout,
    # margins=(width, height)
    icon=MAIN_PATH + '\Figures\padlock.ico'
)


def check_new_acc():
    try:
        with open(mpwd_path, 'r') as f:
            f.read()
            return False
    except:
        return True


while True:
    event, values = window.read()
    new_acc = check_new_acc()
    window['-MainTitle-'].update(visible=False)

    if new_acc == True:
        window['-SetupMP-'].update(visible=True)

    if event == 'SetupMasterUser':
        Pk.store_main_password(
            values['-SetMasterUsername-'], values['-SetMasterPassword-'])
        window['-SetupMP-'].update(visible=False)
    if new_acc == False or event == 'SetupMasterUser':
        window['-CheckMP-'].update(visible=True)
    if event == 'Check_mp':
        password_input = values['-MasterPassword-']
        if Pk.check_master_password(password_input) == True:
            # Enable the App
            window['-CheckMP-'].update(visible=False)
            window['-MainMenu-'].update(visible=True)
            window['-MasterPassword-'].update('')
        else:
            break
        if event == sg.WIN_CLOSED or event == 'Exit':
            break

    if event == '-StoreAcc-':
        window['-CheckMP-'].update(visible=False)
        window['-MainMenu-'].update(visible=False)
        window['-NewAccMenu-'].update(visible=True)

    if event == '-Storage-':

        p_names, p_urss, p_pwds, accounts, acc_idxs = Pk.load_storage()
        window['-CheckMP-'].update(visible=False)
        window['-MainMenu-'].update(visible=False)
        window['-StorageMenu-'].update(visible=True)
        window["-LIST-"].update(p_names)

    if event == "-LIST-":  # a file was chosen from the list
        acc_name = values['-LIST-'][0]
        window['-CheckMP-'].update(visible=False)
        window['-PASSWORDOUT-'].update(accounts[acc_name])

    if event == "-SHOWPASSWORD-":
        window['-CheckMP-'].update(visible=False)
        window['-PASSWORDOUT-'].update(accounts[acc_name]
                                       [:-4] + p_pwds[acc_name])

    if event == "-HIDEPASSWORD-":
        window['-CheckMP-'].update(visible=False)
        window['-PASSWORDOUT-'].update(accounts[acc_name])

    if event == '-delete_account-':
        Pk.remove_account(acc_idxs[acc_name])
        p_names, p_urss, p_pwds, accounts, acc_idxs = Pk.load_storage()
        window['-CheckMP-'].update(visible=False)
        window["-LIST-"].update([])
        window["-LIST-"].update(p_names)

    if event == "-COPYUSR":
        window['CheckMP-'].update(visible=False)
        r = Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(p_urss[acc_name])
        r.update()
        r.destroy()

    if event == "-COPYTOCBOARD-":
        window['-CheckMP-'].update(visible=False)
        r = Tk()
        r.withdraw()
        r.clipboard_clear()
        r.clipboard_append(p_pwds[acc_name])
        r.update()
        r.destroy()
    if event == "-BACK-":
        window["-StorageMenu-"].update(visible=False)

    if event == 'NewSave':
        new_name, new_usr, new_pwd = values['-NewName-'], values['-NewUsr-'], values['-NewPwd-']
        Pk.addentry(new_name, new_usr, new_pwd)
        window['-NewAccMenu-'].update(visible=False)
        window['-CheckMP-'].update(visible=True)
        window['-NewName-'].update('')
        window['-NewUsr-'].update('')
        window['-NewPwd-'].update('')
    if event == '-Panic-':
        Pk.wipe_all_data()
        break
    if event == "GenPwd":
        window['-NewPwd-'].update(pw())
        window['-CheckMP-'].update(visible=False)

    if event == "-Create_Bkp-":
        Pk.create_backup()
        window['-CheckMP-'].update(visible=False)

    if event == "-Load_Bkp-":
        Pk.loads_backup()
        window['-MainMenu-'].update(visible=False)

    if event == 'No' or event == sg.WIN_CLOSED or event == "Exit":
        Pk.create_backup()
        window.close()
window.close()
