import os, shutil, stat, hashlib, zipfile
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import pwinput

# Notes:
# Run with: python .\crypt_manager.py
# ---
# - requires: pip install pyCryptodome gitpython pwinput
# - make sure git is all setup first in a test repo elsewhere.
# - executable build with "pip install pyinstaller" > pyinstaller crypt_manager.py

vault_path = "Vault"
zipped_vault_path = "vault.zip"
encrypted_zip_path = "vault.enc"

def on_rm_error( func, path, exc_info):
    # path contains the path of the file that couldn't be removed
    # let's just assume that it's read-only and unlink it.
    os.chmod( path, stat.S_IWRITE )
    os.unlink( path )

def delete_folder(folder_path):
    if not os.path.exists(folder_path):
        print(f"The folder {folder_path} does not exist.")
        return False
    if not os.path.isdir(folder_path):
        print(f"{folder_path} is not a directory.")
        return False

    try:
        shutil.rmtree(folder_path, onerror = on_rm_error)
        return True
    except Exception as e:
        print(f"An error occurred while deleting the folder: {e}")
        return False

def delete_file(file_path):
    if not os.path.exists(file_path):
        print(f"The file {file_path} does not exist.")
        return False
    if not os.path.isfile(file_path):
        print(f"{file_path} is not a file.")
        return False

    try:
        os.remove(file_path)
        return True
    except Exception as e:
        print(f"An error occurred while deleting the file: {e}")
        return False

def copy_file(original_path, new_path):
    try:
        shutil.copy2(original_path, new_path)
        return True
    except Exception as e:
        print(f"Error copying file from {original_path} to {new_path}: {e}")
        return False

def encrypt_file_contents(file_path, key):
    try:
        iv = get_random_bytes(AES.block_size)
        with open(file_path, 'rb') as file:
            file_contents = file.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))
        with open(file_path, 'wb') as file:
            file.write(iv + encrypted_contents)
        return True
    except Exception as e:
        print(f"Error encrypting file contents: {e}")
        return False

def encrypt_zip(zip_name, new_zip_name, key):
    try:
        if not copy_file(zip_name, new_zip_name):
            return False
        return encrypt_file_contents(new_zip_name, key)
    except Exception as e:
        print(f"Error encrypting zip file: {e}")
        return False

def decrypt_file_contents(file_path, key):
    # Declare all variables at the top of the function
    iv = None
    encrypted_contents = None
    cipher = None
    decrypted_contents = None

    try:
        # Check if the file exists
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The file {file_path} does not exist.")

        with open(file_path, 'rb') as file:
            iv = file.read(AES.block_size)
            encrypted_contents = file.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_contents = unpad(cipher.decrypt(encrypted_contents), AES.block_size)

        with open(file_path, 'wb') as file:
            file.write(decrypted_contents)

        return True
    except FileNotFoundError as fnf_error:
        print(f"Error: {fnf_error}")
        # Handle the error appropriately, e.g., retry, log, or exit
        return False

    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

def decrypt_zip(enc_zip_name, dec_zip_name, key):
    if not copy_file(enc_zip_name, dec_zip_name):
        return False

    if not decrypt_file_contents(dec_zip_name, key):
        return False

    return True

def zip_folder(folder_path, zip_name):
    try:
        with zipfile.ZipFile(zip_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    zipf.write(os.path.join(root, file),
                        os.path.relpath(os.path.join(root, file), folder_path))
        return True
    except Exception as e:
        print(f"Error zipping folder: {e}")
        return False

def unzip_file(zip_path, extract_path):
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)
        return True
    except Exception as e:
        print(f"Error unzipping file: {e}")
        return False

def get_password():
    # Declare variables at the top of the function
    password1 = None
    password2 = None

    while True:
        # Ask for the password the first time
        password1 = pwinput.pwinput(prompt='PW: ', mask='*')
        if not password1:
            raise ValueError("Password cannot be empty.")

        # Ask for the password the second time
        password2 = pwinput.pwinput(prompt='Confirm PW: ', mask='*')
        if not password2:
            raise ValueError("Confirmation password cannot be empty.")

        # Compare the two passwords
        if password1 == password2:
            # Passwords match, proceed with the rest of your code
            return password1
        else:
            # Passwords do not match, inform the user and ask again
            print("Passwords do not match. Please try again.")

def main():
    # Determine aes_key from user input
    try:
        # Get password from user
        password = get_password()

        # Generate salt
        salt = hashlib.sha256(password.encode()).digest()[:16]

        # Generate AES key
        aes_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
    except ValueError as ve:
        print(f"Error: {ve}")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return

    if os.path.isfile(encrypted_zip_path): # create Vault folder
        # decrypt it
        if not decrypt_zip(encrypted_zip_path, zipped_vault_path, aes_key):
            return

        if not unzip_file(zipped_vault_path, vault_path):
            return

        if not delete_file(encrypted_zip_path):
            return

        if not delete_file(zipped_vault_path):
            return

        # notify
        print("Decrypted vault.")
    elif os.path.isdir(vault_path):  # create vault.enc
        # encrypt it
        if not zip_folder(vault_path, zipped_vault_path):
            return

        if not encrypt_zip(zipped_vault_path, encrypted_zip_path, aes_key):
            return

        if not delete_folder(vault_path):
            return

        if not delete_file(zipped_vault_path):
            return

        # notify
        print("Encrypted files.")

if __name__ == "__main__":
    main()
