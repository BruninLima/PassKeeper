import json
from os import remove as os_remove
from math import atan, tan
from hashlib import sha512
from secrets import SystemRandom, token_bytes

# Global Paths

accs_path = 'accounts.json'
salt_path = 'salt.txt'
mpwd_path = 'safe/main_password.txt'
bkps_path = 'bkp.txt'

# Main Functions


def encrypt(password):
    """ Function to encrypt password.
        Takes a string type password -> breaks to a list -> Magic -> Safe Password """
    encrypt_pass = [str(atan(ord(p))) + 'x' for p in list(password)]
    return ''.join(encrypt_pass)


def decrypt(encrypt_pass):
    """ Function to decrypt said password.
        Takes a string type encrypted password -> breaks to a list -> Magic -> Password """

    temp_pass = encrypt_pass.split('x')
    password = [chr(round(tan(float(p)))) for p in temp_pass[:-1]]
    return ''.join(password)


def store_main_password(username, password):
    p = int(SystemRandom().random()**10)
    salt = str(token_bytes(16+len(username)**p))
    ps = password + salt
    with open(salt_path, 'w') as file:
        file.write(salt)
    with open(mpwd_path, 'w') as file:
        file.write(str(sha512(ps.encode()).digest()))


def check_master_password(password):
    with open(salt_path, 'r') as file:
        salt = file.readline()
        salt = salt.split('\n')[0]
    with open(mpwd_path, 'r') as file:
        stored_password = file.read()
    ps = password + salt
    return str(sha512(ps.encode()).digest()) == stored_password


def addentry(name, usr, pwd):
    " Function that adds data to the json file"
    seed = int(SystemRandom().random()**10)
    pwd_salt = str(token_bytes(16+len(name)**seed))
    enc_pwd = encrypt(pwd+pwd_salt)
    entry = {'name': name, "usr": usr, 'pwd': enc_pwd}
    try:
        with open(accs_path, 'r') as f:
            temp = json.load(f)

        entry_idx = len(temp) + 1
        temp[entry_idx] = entry

        with open(accs_path, 'w') as f:
            json.dump(temp, f)
    except:
        entry_idx = 1
        with open(accs_path, 'w') as datafile:
            json.dump({str(entry_idx): entry}, datafile)

    with open(salt_path, 'a') as f:
        f.write('\n')
        f.write(pwd_salt)


def show_entry_password(entries):

    a_list = []
    for entry_idx in entries:
        try:
            with open(salt_path, 'r') as f:
                temp = f.read()
            salt = temp.split('\n')[entry_idx]
            with open(accs_path, 'r') as f:
                temp = json.load(f)
            acc = temp[str(entry_idx)]
        except:
            break

        a_list.append([acc['name'], acc['usr'], decrypt(
            acc["pwd"]).split(salt[:-2])[0]])
    return a_list


def remove_account(acc_idx):
    # remove the acc salt

    with open(salt_path, 'r') as f:
        lines = f.readlines()

    int_idx = int(acc_idx)
    lines = lines[:int_idx] + lines[int_idx+1:]

    with open(salt_path, 'w') as f:
        for line in lines:
            f.write(line)

    # remove the acc from the json and update the acc.json file

    with open(accs_path, 'r') as f:
        temp = json.load(f)
    temp.pop(acc_idx)
    vals = [temp[t] for t in temp]
    data = {i+1: val for i, val in enumerate(vals)}
    with open(accs_path, 'w') as f:
        json.dump(data, f)


def create_backup():

    # Stores: Salt, Accs, Mainpasswrd
    with open(salt_path, 'r') as f:
        temp_salt = f.read()
    with open(accs_path, 'r') as f:
        temp_accs = f.read()
    with open(mpwd_path, 'r') as f:
        temp_mpwd = f.read()

    with open(bkps_path, 'w') as f:
        f.write(encrypt(temp_salt))
        f.write('.b1.')
        f.write(encrypt(temp_accs))
        f.write('.b1.')
        f.write(encrypt(temp_mpwd))


def loads_backup():

    # Loads: Salt, Accs, Mainpasswrd

    with open(bkps_path, 'r') as f:
        temp_bkp = f.read().split('.b1.')

    salt, accs, mpwd = map(decrypt, temp_bkp)

    with open(salt_path, 'w') as f:
        f.write(salt)
    with open(accs_path, 'w') as f:
        f.write(accs)
    with open(mpwd_path, 'w') as f:
        f.write(mpwd)


def check_files_integrity():
    # creates a backup hash and compares with current backup.
    pass


def wipe_all_data():
    "function that wipes all data used by this program :)"

    os_remove(accs_path)
    os_remove(salt_path)
    os_remove(mpwd_path)


def load_storage():

    p_names = []
    p_urss = {}
    p_pwds = {}
    accounts = {'': ''}
    acc_idxs = {}
    sep = show_entry_password(range(1, 50))
    for idx, pwrd_entry in enumerate(sep):
        p_name, p_usr, p_pwd = pwrd_entry
        main_str = "Name: " + p_name + \
            '\n' + "Username: " + p_usr + '\n' + "Password: ****"
        p_urss[p_name] = p_usr
        p_pwds[p_name] = p_pwd
        accounts[p_name] = main_str
        acc_idxs[p_name] = str(idx+1)
        p_names.append(p_name)

    return p_names, p_urss, p_pwds, accounts, acc_idxs
