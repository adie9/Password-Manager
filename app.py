from flask import Flask
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os, sqlite3

#app = Flask(__name__)

#@app.route("/")
#def it_inventory():
#    return "<h1>Password Manager</h1>"

# Encrypting password using AES mode EAX
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
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (service text, username text, encrypted_password text)''')
    pass


# Test Case
pass_word = "testpass011"
aes_key = get_random_bytes(16)

while True:
    user_choice = input("Select option: \n\n [1] Save Password \n [2] Delete Password \n [3] Get Password \n [4] List Services \n [5] Exit\n\n")

    match user_choice:
        case "1":
            print("Saving password...")
        case "2":
            print("Deleting password...")
        case "3":
            print("Getting password...")
        case "4":
            print("Listing services...")
        case "5":
            break
        case default:
            print("Not a valid option...")
