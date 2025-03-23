from flask import Flask
from Cryptodome.Cipher import AES
import os, sqlite3

app = Flask(__name__)

@app.route("/")
def it_inventory():
    return "<h1>Password Manager</h1>"