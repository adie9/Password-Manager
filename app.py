from flask import Flask
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os, sqlite3

#app = Flask(__name__)

#@app.route("/")
#def it_inventory():
#    return "<h1>Password Manager</h1>"

def encrypt_password(password, key):
    password = password.encode()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password)
    nonce = cipher.nonce
    return nonce + tag + ciphertext

def decrypt_password(encrypted_password, key):
    nonce = encrypted_password[:16]
    tag = encrypted_password[16:32]
    ciphertext = encrypted_password[32:]

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_password = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_password.decode()

def save_password(service, username, password):
    pass


# Test Case
pass_word = "testpass011"
aes_key = get_random_bytes(16)
encrypted_password = encrypt_password(pass_word, aes_key)
decrypted_password = decrypt_password(encrypted_password, aes_key)
print(encrypted_password)
print(decrypted_password)

