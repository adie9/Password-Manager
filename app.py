from flask import Flask
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os, sqlite3

#app = Flask(__name__)

#@app.route("/")
#def it_inventory():
#    return "<h1>Password Manager</h1>"

def encrypt_password(password):
    key = get_random_bytes(16)
    pass