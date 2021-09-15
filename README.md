# PassKeeper 1.1

Little app to generate and locally store passwords/accounts.

Using pysimplegui to create the GUI.
The generation is based on the library passwordgenerator.

## Instructions to use:

-TODO
At the first use, it creates and stores a main password (the main username is useless xd)
Once you type the main password there are two main functions:

- Store new accounts.
- View Stored Accounts.

## Latest Changes:

- Patch 1.1
  - Finally implemented a backup files/load backup;
  - Option to delete a stored account;
  - Cleaned up the salt file.

## Possible features to add:

- Restore the panic button
- Draw a padlock.ico
- Maybe Portuguese Dictionary ?
- Folders/Categories to organize the passwords
- Move the passwords up/down?
- when should we type the main password?
- Close the app without an error...

## Instructions to create the .exe:

Using pyinstaller can be built to an .exe file, preferable with the comand:

pyinstaller --icon=Figures\padlock.ico --onefile -w --uac-admin PassKeeper_GUI.py

To get the icon and the admin privilege needed to create/modify files where it stores hashes/salts.

## Important thoughts:

As this is a local based storage, it is best used with a random pendrive to be the salt_path, thus becoming a 2FA method to store the passwords.
Unfortunently this means that you need to be at the local to access.

Got the padlock icon from random google image search lmao.
