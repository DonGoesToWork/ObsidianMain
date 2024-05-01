from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import shutil
import zipfile

# Notes:
# - requires: pip install pyCryptodome
# - requires: pip install gitpython

desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop') 
key_path = f"{desktop_path}/Desktop Files/VP/obsidian_key.txt"
backup_vault_path = f"{desktop_path}/Desktop Files/VP/Vault"
vault_path = "Vault"
zipped_vault_path = "vault.zip"
encrypted_zip_path = "vault.enc"

def delete_folder(folder_path):
    if not os.path.exists(folder_path):
        print(f"The folder {folder_path} does not exist.")
        return
    if not os.path.isdir(folder_path):
        print(f"{folder_path} is not a directory.")
        return
    try:
        shutil.rmtree(folder_path)
    except Exception as e:
        print(f"An error occurred while deleting the folder: {e}")

def delete_file(file_path):
    if not os.path.exists(file_path):
        print(f"The file {file_path} does not exist.")
        return
    if not os.path.isfile(file_path):
        print(f"{file_path} is not a file.")
        return
    try:
        os.remove(file_path)
    except Exception as e:
        print(f"An error occurred while deleting the file: {e}")

def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
    return key

def copy_file(original_path, new_path):
    try:
        shutil.copy2(original_path, new_path)
    except Exception as e:
        print(f"Error copying file from {original_path} to {new_path}: {e}")

import shutil

def copy_folder(src, dst):
    try:
        shutil.copytree(src, dst)
    except Exception as e:
        print(f"Error copying file from {src} to {dst}: {e}")

def encrypt_filename(filename, key):
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_filename = cipher.encrypt(pad(filename.encode(), AES.block_size))
    return encrypted_filename.hex()

def encrypt_file_contents(file_path, key):
    iv = get_random_bytes(AES.block_size)
    with open(file_path, 'rb') as file:
        file_contents = file.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_contents = cipher.encrypt(pad(file_contents, AES.block_size))
    with open(file_path, 'wb') as file:
        file.write(iv + encrypted_contents)

def encrypt_zip(zip_name, new_zip_name, key):
    copy_file(zip_name, new_zip_name)
    encrypt_file_contents(new_zip_name, key)

def decrypt_filename(encrypted_filename, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_filename = unpad(cipher.decrypt(bytes.fromhex(encrypted_filename)), AES.block_size).decode()
    return decrypted_filename

def decrypt_file_contents(file_path, key):
    with open(file_path, 'rb') as file:
        iv = file.read(AES.block_size)
        encrypted_contents = file.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_contents = unpad(cipher.decrypt(encrypted_contents), AES.block_size)
    with open(file_path, 'wb') as file:
        file.write(decrypted_contents)

def decrypt_zip(enc_zip_name, dec_zip_name, key):
    copy_file(enc_zip_name, dec_zip_name)
    decrypt_file_contents(dec_zip_name, key)

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
    except Exception as e:
        print(f'Error occured while pushing the code: {e}')

def git_push():
    try:
        repo = Repo(PATH_OF_GIT_REPO)
        repo.git.add("-A")
        repo.index.commit(COMMIT_MESSAGE)
        origin = repo.remote(name='origin')
        origin.push()
    except Exception as e:
        print(f'Error occured while pushing: {e}')

def git_add():
    try:
        repo = Repo(PATH_OF_GIT_REPO)
        repo.git.add("-A")
    except Exception as e:
        print(f'Error occured while adding: {e}')

#### GIT SPECIFIC SECTION END ####

def main():
    key = load_key(key_path)

    if os.path.isfile(encrypted_zip_path): # create MyVault
        # pull latest
        git_pull() 

        # decrypt it
        decrypt_zip(encrypted_zip_path, zipped_vault_path, key)
        unzip_file(zipped_vault_path, vault_path)
        delete_file(encrypted_zip_path)
        delete_file(zipped_vault_path)

        # notify
        print("Pulled and decrypted files.")
    elif os.path.isdir(vault_path):  # create vault.enc
        # encrypt it
        zip_folder(vault_path, zipped_vault_path)
        encrypt_zip(zipped_vault_path, encrypted_zip_path, key)
        delete_folder(vault_path)
        delete_file(zipped_vault_path)

        # push it
        git_push()

        # notify
        print("Encrypted and pushed files.")

if __name__ == "__main__":
    main()
