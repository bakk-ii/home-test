# Password Manager.
Design a program that will program that will manage passwords that meets the requirements of a
password for the system.
## class PasswordManager
The PasswordManager class should have just 2 member variable, which will store the user name and the
encrypted password (a string).

- The **PasswordManager** class should have the following two protected functions
  - **encrypt(string)**: takes a password (string) and returns the encrypted form of the password
  - **verifyPassword(string)**: takes a string (a password) and returns true if, once encrypted, it matches the
encrypted string stored in the the member variable. Else returns false.
- The **PasswordManager** class should have the following two public functions
  - **validatePassword(string)**: this takes a string (a password) and returns true if it meets the following
criteria
```commandline
- The password must not contain any whitespace
- The password must be at least 6 characters long.
- The password must contain at least one uppercase and at least one lowercase letter.
- The password must have at least one digit and symbol.
If the password does not meet these requirements, the program should display a message telling the
user why the password is invalid, specifically. It should also continue to loop until the user enters a valid
password.
```
  - **setNewPassword**: takes a string (a proposed password). If it meets the criteria in validatePassword, it
encrypts the password and stores it in the member variable and returns true. Otherwise returns false.
## Storage
Use a file **password.txt** to store username and encrypted password. If not exist, create it at first run.
## Input - Output
The main function should create and use one instance of the PasswordManager class.
Your program will use the following menu to prompt the user to test the implementation:
```commandline
A. New User
B. Validate Password
C. Login
D. Change Password
```
## REQUIREMENTS
- Python 3

## How to run
```commandline
python3 password_manager.py
```
