import base64
#import os not needed
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#OOP that encrypts and decrypts files using a username and pass
# each instance is unique to that user/pass combination
class file_encrypt_decrypt:
    #initialize object w user and pass
    def __init__(self, username: str, password: str):
        #username is used as a salt, a unique value that ensures 2 users
        #with the same pass still have diff keys
        #pass is used to derive the encryption key

        #convert to bytes, necessary for key derivation
        self.username = username.encode()
        self.password = password.encode()

        #key derivation function kdf to securely derive a key
        kdf = PBKDF2HMAC(
            #secure hashing algorithm
            algorithm=hashes.SHA256(),
            #generate a 32-byte key
            length = 32,
            salt = self.username,
            #num of hash iterations
            iterations = 480000,
        )

        #derive the final key and encode it safely for fernet
        key = base64.urlsafe_b64encode(kdf.derive(self.password))

        #create the fernet object using this key
        self.fernet = Fernet(key)

    #encrypts the contents of a file and saves it as a new file
    def encrypt(self, input_file: str, output_file: str):
        try:
            #open & read the file in bytes:
            with open(input_file, "rb") as file:
                token = file.read()

            #encrypts the data
            data = self.fernet.encrypt(token)

            #save encrypted data to output file
            with open(output_file, "wb") as file:
                file.write(data)

            print(f'File "{input_file}" has been encrypted to "{output_file}".')
        except Exception as e:
            print(f"Encryption failed: {e}")

    #decrypts an encrypted file and saves the original contents to a new file
    def decrypt(self, input_file: str, output_file: str):
        try:
            #open and read encrypted file
            with open(input_file, "rb") as file:
                token = file.read()

            #decrypt the data
            data = self.fernet.decrypt(token)

            #write decrypted bytes to output file
            with open(output_file, "wb") as file:
                file.write(data)

            print(f'File "{input_file}" has been decrypted to "{output_file}".')

        except Exception as e:
            print(f"Decryption failed: {e}")

username = input("Please enter your username: ")
password = input("Please enter your password: ")

#create unique object for user
user = file_encrypt_decrypt(username, password)

#ask user which operation theyd like
print("\nPlease select what you'd like me to:")
print("1. Encrypt file")
print("2. Decrypt file")

user_choice = input("Please enter your choice: ")
if user_choice == "1":
    input_file = input("Please enter the file you want to encrypt: ")
    output_file = input("Please enter the name of the output encrypted file: ")
    user.encrypt(input_file, output_file)

elif user_choice == "2":
    input_file = input("Please enter the file you want to decrypt: ")
    output_file = input("Please enter the name of the output decrypted file: ")
    user.decrypt(input_file, output_file)

else:
    print("Invalid choice.")
