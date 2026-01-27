import os
import random
import string
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

def generate_key(password, salt=b'salt_'): 
    # In a real app, salt should be unique per user/file and stored. 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Using a fixed key for simplicity in this prototype
# Ideally, load from env var or generate securely
if not os.path.exists('secret.key'):
    GLOBAL_key = Fernet.generate_key()
    with open('secret.key', 'wb') as key_file:
        key_file.write(GLOBAL_key)
else:
    with open('secret.key', 'rb') as key_file:
        GLOBAL_key = key_file.read()

cipher_suite = Fernet(GLOBAL_key)

def encrypt_file_content(file_data):
    return cipher_suite.encrypt(file_data)

def decrypt_file_content(encrypted_data):
    return cipher_suite.decrypt(encrypted_data)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))
