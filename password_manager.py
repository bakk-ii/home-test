import re
import json
from hashlib import sha256

SECURE_CODE = 'wiw15htd3ffyqj7n'
FILE_NAME = 'password.txt'


class PasswordManager:
    username = ''
    password = ''

    def __encrypt(self, pwd=''):
        pwd = '{}-{}'.format(SECURE_CODE, pwd)
        pwd_encrypted = sha256(pwd.encode('utf8')).hexdigest()
        return pwd_encrypted

    def __verify(self, pwd=''):
        pwd = self.__encrypt(pwd)
        if pwd == self.password:
            return True
        return False

    def validate(self, pwd=''):
        pattern = '^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W).\S{5,}'
        is_valid = re.findall(pattern, pwd)
        if not is_valid:
            if re.findall('\s', pwd):
                print("- The password must not contain any whitespace.")
            if len(pwd) < 6:
                print("- The password must be at least 6 characters long.")
            if not re.findall('^(?=.*[a-z])(?=.*[A-Z]).{0,}', pwd):
                print("- The password must contain at least one uppercase "
                      "and at least one lowercase letter.")
            if not re.findall('^(?=.*\d)(?=.*\W).{0,}', pwd):
                print("- The password must have at least one digit and symbol.")
            return False
        return True

    def set_new_password(self, pwd=''):
        is_valid = self.validate(pwd)
        if is_valid:
            self.password = self.__encrypt(pwd)
            return True
        return False

    def login(self, username='', pwd=''):
        pwd = self.__encrypt(pwd)
        users_db = {}

        with open(FILE_NAME, 'a+') as f:
            f.seek(0)
            users_db = f.read()

        if not users_db:
            print('Please create new user first!')
            return False

        users_db = json.loads(users_db)

        for user in users_db['users']:
            if user['username'] == username and user['password'] == pwd:
                self.username = username
                self.password = pwd
                return True
        return False


if __name__ == '__main__':
    is_continue = True
    while is_continue:
        print("""Password Manager:
                A. New User
                B. Validate Password
                C. Login
                D. Change Password
                E. Quit""")
        option = input("Please choose: ")

        pwdm_obj = PasswordManager()
        users_db = {}

        with open(FILE_NAME, 'a+') as f:
            f.seek(0)
            users_db = f.read()

        if option == "A":
            """ A. New User """
            username = input("Enter username: ")
            flag = True
            while flag:
                pwd = input("Enter password: ")
                if pwdm_obj.set_new_password(pwd):
                    print('Create User successfully.')
                    pwdm_obj.username = username
                    flag = False

                    with open(FILE_NAME, 'w') as f:
                        if not users_db:
                            users_db = {
                                'users': [{
                                    'username': pwdm_obj.username,
                                    'password': pwdm_obj.password
                                }]
                            }
                        else:
                            users_db = json.loads(users_db)
                            users_db['users'].append({
                                'username': pwdm_obj.username,
                                'password': pwdm_obj.password
                            })
                        f.write(json.dumps(users_db))
        elif option == "B":
            """ B. Validate Password """
            flag = True
            while flag:
                pwd = input("Enter password: ")
                if pwdm_obj.validate(pwd):
                    print('Password is valid')
                    flag = False
        elif option == "C":
            """ C. Login """
            username = input("Enter username: ")
            pwd = input("Enter password: ")
            if pwdm_obj.login(username, pwd):
                print('Login successfully.')
            else:
                print('Login failed.')
        elif option == "D":
            """ D. Change Password """
            username = input("Enter username: ")
            pwd = input("Enter password: ")
            if pwdm_obj.login(username, pwd):
                flag = True
                while flag:
                    new_pwd = input("Enter new password: ")
                    if pwdm_obj.validate(new_pwd):
                        with open(FILE_NAME, 'w') as f:
                            users_db = json.loads(users_db)
                            for user in users_db['users']:
                                user['password'] = pwdm_obj.password
                            f.write(json.dumps(users_db))
                        print('Change Password successfully.')
                        flag = False
            else:
                print('Login failed.')
        elif option == "E":
            exit()
        else:
            print("Please choose A, B, C, D or E!")

        print('Press C for continue program, or any key except C for exit'
              ' program')
        next_action = input(': ')
        if next_action != 'C':
            is_continue = False
