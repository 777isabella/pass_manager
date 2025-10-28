from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
print("Running from:", os.getcwd())


#symmetric encryption
#same key is used to encrypt and decrypt
#key is randomly generated (ergo not based on a pass)
class SymmetricEncryption:
    def __init__(self):
        #init attribute to hold generated key
        self.key = None

    #
    def generate_key(self, filename):
        # Generate a random symmetric key using Fernet
        key = Fernet.generate_key()

        # Save the key to a new file
        with open(filename, "wb") as file:
            file.write(key)

        print(f"Symmetric key generated and saved as {filename}")

    #file encryption
    def encrypt_file(selfself, file_encrypt, key_file):
        #read in file to encrypt
        with open(file_encrypt, "rb") as file:
            data = file.read()
        #read key from the key ifle
        with open(key_file, "rb") as file:
            key = file.read()

        #create fernet obj
        fernet = Fernet(key)

        #encrypt the data
        encrypted = fernet.encrypt(data)

        #save encrypted data to a new file
        output_name = file_encrypt + ".encrypted"
        with open(output_name, "wb") as file:
            file.write(encrypted)

        print(f"Encrypted file {output_name}")

    #file decryption
    def decrypt_file(self, encrypted_file, key_file):
        with open(encrypted_file, "rb") as file:
            data = file.read()

        #read symm key
        with open(key_file, "rb") as file:
            key = file.read()

        #create a fernet object to decrypt file
        fernet = Fernet(key)
        #decrypt data
        decrypted = fernet.decrypt(data)
        #remove ".encrypted" from file name
        # new_file_name = encrypted_file.replace(".encrypted", "")
        # Decide output file name
        if encrypted_file.endswith(".encrypted"):
            new_file_name = encrypted_file.replace(".encrypted", ".decrypted")
        else:
            new_file_name = encrypted_file + ".decrypted"

        #write decrypted content back to a new file
        with open(new_file_name, "wb") as file:
            file.write(decrypted)

        print(f"File decrypted as {new_file_name}")

    #__call__ method
    def __call__(self):
        ##callable interactive mini menu
        print("\nSymmetric Encryption Menu:")
        print("1. Generate Key")
        print("2. Encrypt File")
        print("3. Decrypt File")
        print("4. Exit")

        choice = input("\nPlease enter your choice: ")
        match choice:
            case "1":
                name = input("Enter key name: ")
                self.generate_key(name)
            case "2":
                file = input("Enter file name to encrypt: ")
                key = input("Enter key file: ")
                self.encrypt_file(file, key)
            case "3":
                file = input("Enter file name to decrypt: ")
                key = input("Enter key file: ")
                self.decrypt_file(file, key)
            case _:
                print("Returning to main menu")

#Assymetric encryption
#use two keys: public & private
#public key encrypts data
#private key decrypts dsta

class AsymmetricEncryption:
    def __init__(self):
        #init public and private keys
        self.private_key = None
        self.public_key = None

    #RSA key pair generation
    def generate_keys(self, filename):
        #craete private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        #gte public key from the private key
        self.public_key = self.private_key.public_key()

        #save private key to file
        with open(f"{filename}_private.pem", "wb") as file:
            file.write(
                self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        #save public key to file
        with open(f"{filename}_public.pem", "wb") as file:
            file.write(
                self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        print(f"RSA key pair saved as {filename}_private.pem and {filename}_public.pem")

    #encrypt symmetric key
    def encrypt_key(self, public_key_file, symmetric_key_file):
        #load public key from PEM file
        with open(public_key_file, "rb") as file:
            public_key = serialization.load_pem_public_key(file.read(), backend=default_backend())

        #load symmetric key
        with open(symmetric_key_file, "rb") as file:
            symm_key = file.read()

        #encrypt symm key using RSA and OAEP padding
        encrypted_key = public_key.encrypt(
            symm_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #save encrypted symm key
        with open(symmetric_key_file + ".encrypted", "wb") as file:
            file.write(encrypted_key)
        print(f"Encrypted symmetric key saved as {symmetric_key_file}.encrypted")

    def decrypt_key(self, private_key_file, encrypted_key_file):
        #load private key
        with open(private_key_file, "rb") as file:
            private_key = serialization.load_pem_private_key(file.read(), password=None, backend=default_backend())

        #load encrypted symmetric key
        with open(encrypted_key_file, "rb") as file:
            encrypted_data=file.read()

        #decrypt it using the private key and same padding scheme
        decrypted_key = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        #save decrypted key back to a file
        #and remove .encrypted
        output_name = encrypted_key_file.replace(".encrypted", "")
        with open(output_name, "wb") as file:
            file.write(decrypted_key)
        print(f"Decrypted symmetric key saved as {output_name}")

    #callable menu
    def __call__(self):
        print("\nAssymetric Encryption Menu:")
        print("1. Generate RSA Key Pair")
        print("2. Encrypt Symmetric File")
        print("3. Decrypt Symmetric File")
        print("4. Exit")

        choice = input("\nPlease enter your choice: ")
        match choice:
            case "1":
                name = input("Enter key pair name: ")
                self.generate_keys(name)
            case "2":
                public_key = input("Enter private key filename: ")
                symm_key = input("Enter symmetric key filename: ")
                self.encrypt_key(public_key, symm_key)
            case "3":
                private_key = input("Enter private key filename: ")
                encrypted_key = input("Enter encrypted key filename: ")
                self.decrypt_key(private_key, encrypted_key)
            case _:
                print("Returning to main menu.")

def main():
    #init of instance of each encryption system
    symm = SymmetricEncryption()
    asymm = AsymmetricEncryption()

    #loop will continue until user quits
    while True:
        print("\nMain Menu:")
        print("1. Symmetric Encryption")
        print("2. Asymmetric Encryption")
        print("3. Exit")

        choice = input("\nPlease enter your choice: ")

        match choice:
            case "1":
                symm()
            case "2":
                asymm()
            case "3":
                print("Exiting.")
                break
            case _:
                print("Invalid choice. Try again.")


if __name__ == "__main__":
    main()
