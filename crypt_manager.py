from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import shutil
import zipfile
import hashlib
import pwinput

# Notes:
# Run with: python .\crypt_manager.py
# ---
# - requires: pip install pyCryptodome gitpython pwinput
# - make sure git is all setup first in a test repo elsewhere.

desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop') 
key_path = f"{desktop_path}/Desktop Files/VP/obsidian_key.txt"
vault_path = "Vault"
zipped_vault_path = "vault.zip"
encrypted_zip_path = "vault.enc"

def delete_folder(folder_path):
    if not os.path.exists(folder_path):
        print(f"The folder {folder_path} does not exist.")
        return False
    if not os.path.isdir(folder_path):
        print(f"{folder_path} is not a directory.")
        return False
    try:
        shutil.rmtree(folder_path)
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

def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
    return key

def copy_file(original_path, new_path):
    try:
        shutil.copy2(original_path, new_path)
        return True
    except Exception as e:
        print(f"Error copying file from {original_path} to {new_path}: {e}")
        return False

def copy_folder(src, dst):
    try:
        shutil.copytree(src, dst)
        return True
    except Exception as e:
        print(f"Error copying file from {src} to {dst}: {e}")
        return False

def encrypt_filename(filename, key):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_filename = cipher.encrypt(pad(filename.encode(), AES.block_size))
        return encrypted_filename.hex()
    except Exception as e:
        print(f"Error encrypting filename: {e}")
        return None

def encrypt_file_contents(file_path, key):
    try:
        iv = get_random_bytes(AES.block_size)
        with open(file_path, 'rb') as file:
            file_contents = file.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))
        with open(file_path, 'wb') as file:
            file.write(iv + encrypted_contents)
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

def decrypt_filename(encrypted_filename, key):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_filename = unpad(cipher.decrypt(bytes.fromhex(encrypted_filename)), AES.block_size).decode()
        return decrypted_filename
    except Exception as e:
        print(f"Error decrypting filename: {e}")
        return None

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

    except FileNotFoundError as fnf_error:
        print(f"Error: {fnf_error}")
        # Handle the error appropriately, e.g., retry, log, or exit

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def decrypt_zip(enc_zip_name, dec_zip_name, key):
    if not copy_file(enc_zip_name, dec_zip_name):
        return False

    if not decrypt_file_contents(dec_zip_name, key):
        return False

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


#### GIT SPECIFIC SECTION ####
from git import Repo

# requires: pip install gitpython

PATH_OF_GIT_REPO = r'.git'  # make sure .git folder is properly configured
COMMIT_MESSAGE = 'Vault Backup'

def git_pull():
    try:
        repo = Repo(PATH_OF_GIT_REPO)
        origin = repo.remote(name='origin')
        origin.pull()
        return True
    except Exception as e:
        print(f'Error occured while pushing the code: {e}')
        return False

def git_push():
    try:
        repo = Repo(PATH_OF_GIT_REPO)
        repo.git.add("-A")
        repo.index.commit(COMMIT_MESSAGE)
        origin = repo.remote(name='origin')
        origin.push()
        return True
    except Exception as e:
        print(f'Error occured while pushing: {e}')
        return False

def git_add():
    try:
        repo = Repo(PATH_OF_GIT_REPO)
        repo.git.add("-A")
        return True
    except Exception as e:
        print(f'Error occured while adding: {e}')
        return False

#### GIT SPECIFIC SECTION END ####

def main():
    # Determine aes_key from user input
    try:
        # Input validation
        password = pwinput.pwinput(prompt='PW: ', mask='*')
        if not password:
            raise ValueError("Password cannot be empty.")

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
        # pull latest
        git_pull() 

        # decrypt it
        if (decrypt_zip(encrypted_zip_path, zipped_vault_path, aes_key) == False):
            return

        if (unzip_file(zipped_vault_path, vault_path) == False):
            return

        delete_file(encrypted_zip_path)
        delete_file(zipped_vault_path)

        # notify
        print("Fetched files -> pulled and decrypted vault.")
    elif os.path.isdir(vault_path):  # create vault.enc
        # encrypt it
        if (zip_folder(vault_path, zipped_vault_path) == False):
            return

        if (encrypt_zip(zipped_vault_path, encrypted_zip_path, aes_key) == False):
            return

        delete_folder(vault_path)
        delete_file(zipped_vault_path)

        # push it
        git_push()

        # notify
        print("Saved files -> encrypted and pushed files.")

if __name__ == "__main__":
    main()
