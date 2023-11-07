from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64, platform, os

import base64, platform, os

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file():
    password = input("Enter the encryption password: ")
    salt = os.urandom(16) 
    key = generate_key(password, salt)  
    cipher_suite = Fernet(key)
    file_path = input("File Path:")

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    encrypted_data = cipher_suite.encrypt(plaintext)

    with open(file_path, 'wb') as file:
        file.write(salt + encrypted_data)

def decrypt_file():
    encrypted_file_path = input("Enter the path to the encrypted file: ")

    with open(encrypted_file_path, 'rb') as file:
        encrypted_data = file.read()

    password = input("Enter the password: ")
    salt = encrypted_data[:16]  
    key = generate_key(password, salt)  
    fernet_cipher = Fernet(key)

    decrypted_data = fernet_cipher.decrypt(encrypted_data[16:])  

    with open(encrypted_file_path, 'wb') as file:
        file.write(decrypted_data)


def clearscreen():
    if platform.sytem == "Linux":
        os.system("clear")
    elif platform.system == "Windows":
        os.system("cls")

def menu():
    print("""

  sSSs    sSSs   .S_sSSs     .S S.    .S_sSSs    sdSS_SSSSSSbs  
 d%%SP   d%%SP  .SS~YS%%b   .SS SS.  .SS~YS%%b   YSSS~S%SSSSSP  
d%S'    d%S'    S%S   `S%b  S%S S%S  S%S   `S%b       S%S       
S%S     S%S     S%S    S%S  S%S S%S  S%S    S%S       S%S       
S&S     S&S     S%S    d*S  S%S S%S  S%S    d*S       S&S       
S&S_Ss  S&S     S&S   .S*S   SS SS   S&S   .S*S       S&S       
S&S~SP  S&S     S&S_sdSSS     S S    S&S_sdSSS        S&S       
S&S     S&S     S&S~YSY%b     SSS    S&S~YSSY         S&S       
S*b     S*b     S*S   `S%b    S*S    S*S              S*S       
S*S     S*S.    S*S    S%S    S*S    S*S              S*S       
S*S      SSSbs  S*S    S&S    S*S    S*S              S*S       
S*S       YSSP  S*S    SSS    S*S    S*S              S*S       
SP              SP            SP     SP               SP        
Y               Y             Y      Y                Y         
                                                                
          
            [1] Encrypt File
            [2] Decrypt File    
""")
    choice = input("                 fcrypt>:")

    if choice == "1":
        encrypt_file()
    elif choice == "2":
        decrypt_file()

if __name__ == "__main__":
    menu()