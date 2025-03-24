from flask import Flask
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os, sqlite3, getpass

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
    pass


# Test Case
if __name__ == "__main__":
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (service text PRIMARY_KEY, username text PRIMARY KEY, encrypted_password BLOB)''')
    conn.commit()
    conn.close()
    
    aes_key = get_random_bytes(16)

    while True:
        user_choice = input("Select option: \n\n [1] Save Password \n [2] Delete Password \n [3] Get Password \n [4] List Services \n [5] Exit\n\n")

        match user_choice:
            case "1":
                service = input("Enter service name: ")
                user_name = input("Enter username: ")
                pass_word = getpass.getpass("Enter a password: ")

                pass_word = encrypt_password(pass_word, aes_key)
                print("Saving password...")

                conn = sqlite3.connect("password_storage.db")
                cursor = conn.cursor()
                cursor.execute("INSERT OR REPLACE INTO passwords (service, username, encrypted_password) values (?, ?, ?)", (service, user_name, pass_word))
                conn.commit()
                conn.close()

                print("Password saved...")
            case "2":
                service = input("Enter service name: ")
                user_name = input("Enter username: ")
                print("Deleting password...")

                conn = sqlite3.connect("password_storage.db")
                cursor = conn.cursor()
                cursor.execute("DELETE FROM passwords WHERE (service, username) = (?, ?)", (service, user_name))
                conn.commit()
                conn.close()

                print("Password deleted...")
            case "3":
                service = input("Input service name: ")
                user_name = input("Input username: ")
                print("Getting password...")
                conn = sqlite3.connect("password_storage.db")
                cursor = conn.cursor()

                try:
                    cursor.execute(f"SELECT encrypted_password from passwords WHERE service = {service}")
                except:
                    print("Service doesn't exist in database...")

                results = cursor.fetchall()
                conn.close()

                print(results)
            case "4":
                print("Listing services...")
                conn = sqlite3.connect("password_storage.db")
                cursor = conn.cursor()
                cursor.execute('''SELECT service FROM passwords''')
                results = cursor.fetchall()
                conn.close()

                if len(results) == 0:
                    print("There are currently no services in the database...")
                else: print(results)
            case "5":
                break
            case "6": # Temporary case for checking if table operations are working
                print("Displaying table...")
                conn = sqlite3.connect("password_storage.db")
                cursor = conn.cursor()
                cursor.execute("SELECT * from passwords")
                results = cursor.fetchall()
                conn.close()

                print(results)
            case default:
                print("Not a valid option...")
