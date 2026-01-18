# encryptsafelocal
EncryptSafe Local is a lightweight, offline password manager built with Python and Tkinter. It stores all credentials locally, protects them using AES encryption, and adds an extra security layer with Google Authenticator (TOTP).

Key Features

1.Encrypted password storage (AES)

2.Local SQLite database (no cloud sync)

3.Google Authenticator–based 2FA

4.Simple full-screen GUI

5.Add, view, and delete credentials securely

Requirements

-Python 3.8+

How It Works

-Passwords are encrypted before saving to the local database. Accessing them requires both the correct encryption key and a valid TOTP code from Google Authenticator.
