from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import shutil
import zipfile

# requires: pip install pyCryptodome

desktop_path = os.path.join(os.path.join(os.environ['USERPROFILE']), 'Desktop') 
key_path = f"{desktop_path}/Desktop Files/obsidian_key.txt"
zip_path = "vault.zip"
unzip_temp_path = "unzip_temp/"
decrypted_directory_path = "ObsidianVaults"
encrypted_directory_path = "Encrypted"

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
        print(f"Error copying file from {original_path} to {new_path}.")

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

def encrypt_directory(original_path, new_path, key):
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    for item in os.listdir(original_path):
        original_item_path = os.path.join(original_path, item)
        new_item_path = os.path.join(new_path, encrypt_filename(item, key))
        if os.path.isfile(original_item_path):
            copy_file(original_item_path, new_item_path)
            encrypt_file_contents(new_item_path, key)
        elif os.path.isdir(original_item_path):
            encrypt_directory(original_item_path, new_item_path, key)

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

def decrypt_directory(original_path, new_path, key):
    if not os.path.exists(new_path):
        os.makedirs(new_path)
    for item in os.listdir(original_path):
        original_item_path = os.path.join(original_path, item)
        decrypted_item_path = os.path.join(new_path, decrypt_filename(item, key))
        if os.path.isfile(original_item_path):
            copy_file(original_item_path, decrypted_item_path)
            decrypt_file_contents(decrypted_item_path, key)
        elif os.path.isdir(original_item_path):
            decrypt_directory(original_item_path, decrypted_item_path, key)

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

def main():
    key = load_key(key_path)

    # create decrypted
    if os.path.isfile(zip_path):
        unzip_file(zip_path, unzip_temp_path)
        decrypt_directory(unzip_temp_path, decrypted_directory_path, key)
        delete_folder(unzip_temp_path)
        delete_file(zip_path)
    # create vault.zip
    elif os.path.isdir(decrypted_directory_path):
        encrypt_directory(decrypted_directory_path, encrypted_directory_path, key)
        zip_folder(encrypted_directory_path, zip_path)
        delete_folder(decrypted_directory_path)
        delete_folder(encrypted_directory_path)

if __name__ == "__main__":
    main()
