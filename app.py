from flask import Flask
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os, sqlite3

#app = Flask(__name__)

#@app.route("/")
#def it_inventory():
#    return "<h1>Password Manager</h1>"

def encrypt_password(password):
    password = password.encode()
    aes_key = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(password)
    with open("encrypted.bin", wb) as file:
        file.write(tag)
        file.write(cipher.nonce)
        file.write(ciphertext)
    return cipher
    
def decrypt_password(password, key):
    
    pass

# Test Case
pass_word = "testpass011"
print(encrypt_password(pass_word))