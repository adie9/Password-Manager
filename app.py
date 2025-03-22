from flask import Flask
import os, sqlite3

app = Flask(__name__)

@app.route("/")
def it_inventory():
    return "<h1>IT Inventory</h1>"