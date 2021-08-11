# PassKeeper 1.0
Little app to generate and (locally) store passwords/accounts.

Using pysimplegui to create the GUI.
The generation is based on the library passwordgenerator.

## Instructions to use:
-TODO
At the first use, it creates and stores a main password (the main username is useless xd)
Once you type the main password there are two main functions: 
- Store new accounts.
- View Stored Accounts.

## Instructions to create the .exe:

Using pyinstaller can be built to an .exe file, preferable with the comand:

pyinstaller --icon=Figures\padlock.ico --onefile -w --uac-admin PassKeeper_GUI.py

To get the icon and the admin privilege needed to create/modify files where it stores hashes/salts.

## Possible features to add:
- Backup? 
- Restore the panic button
- Draw a padlock.ico

## Important thoughts:

As this is a local based storage, it is best used with a random pendrive to be the salt_path, thus becoming a 2FA method to store the passwords.
Unfortunently this means that you need to be at the local to access.
Probably needs some sort of server to store some data so that you can use from different pc's. (setup server/ssh...)


Got the padlock icon from random google image search lmao.
