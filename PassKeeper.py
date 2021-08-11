import json
from os import remove as os_remove
from math import atan, tan
from hashlib import sha512
from secrets import SystemRandom, token_bytes

# Global Paths

accs_path = 'accounts.json'
salt_path = 'salt.txt'
mpwd_path = 'safe/main_password.txt'

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
        f.write(str(entry_idx) + ', ' + pwd_salt)


def show_entry_password(entries):
    # print('Please Type Your Main Password')
    # mp_temp = input()

    # if check_master_password(mp_temp):
    a_list = []
    for entry_idx in entries:
        try:
            with open(salt_path, 'r') as f:
                temp = f.read()
            seed_idx = temp.split(
                str(entry_idx) + ', ')[-1].split(str(entry_idx+1) + ', ')[0]
            with open(accs_path, 'r') as f:
                temp = json.load(f)
            acc = temp[str(entry_idx)]
        except:
            break

        a_list.append([acc['name'], acc['usr'], decrypt(
            acc["pwd"]).split(seed_idx[:-2])[0]])
    return a_list
    # else:
    #     print('Wrong Master Password')


def wipe_all_data():
    "function that wipes all data used by this program :)"

    os_remove(accs_path)
    os_remove(salt_path)
    os_remove(mpwd_path)
