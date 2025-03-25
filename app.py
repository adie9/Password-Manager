from flask import Flask
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os, sqlite3, getpass

#app = Flask(__name__)

#@app.route("/")
#def it_inventory():
#    return "<h1>Password Manager</h1>"

# Encrypting password using AES mode GCM
def encrypt_password(password, key):
    nonce = get_random_bytes(12)
    password = password.encode()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(password)
    return nonce + tag + ciphertext

def decrypt_password(encrypted_password, key):
    encrypted_password = encrypted_password[0] # Setting variable to binary inside tuple
    nonce = encrypted_password[:12]
    tag = encrypted_password[12:28]
    ciphertext = encrypted_password[28:]
    

    # At beginning, nonce =  b'\xf2:\xca\x06&\xe4\x80U\x0c\xd0\xfe\xc8' , ciphertext =  b'x^\x83\xfe\xa3\xd6\x0f1C\xe1' , and tag =  b'i\r]\x94M\xac\xf7\x9d\xfd\x8eQ\xf4\xb4h\xc5\x1e'
    # At end, nonce =        b'\xf2:\xca\x06&\xe4\x80U\x0c\xd0\xfe\xc8' , ciphertext =  b'x^\x83\xfe\xa3\xd6\x0f1C\xe1i\r]' , and tag =  b'\x94M\xac\xf7\x9d\xfd\x8eQ\xf4\xb4h\xc5\x1e'
    
    print("At end, nonce = ", nonce, ", ciphertext = ", ciphertext, ", and tag = ", tag)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    return password.decode()

def save_password(service, username, password):
    pass_word = encrypt_password(password, aes_key)
    print("Saving password...")

    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE (service, username) = (?, ?)", (service, username))
    results = cursor.fetchall()

    if results:
        update = input("It seems that username is already bound to the specified service. Would you like to update its password? (Enter 'yes' or 'no'): ")
        match update.lower():
            case "yes":
                cursor.execute("UPDATE passwords SET encrypted_password = (?) WHERE (service, username) = (?, ?)", (pass_word, service, username))
                print("Password saved...")
            case "no":
                print("Returning to options...")
    else:
        cursor.execute("INSERT OR REPLACE INTO passwords (service, username, encrypted_password) values (?, ?, ?)", (service, username, pass_word))
        print("Password saved...")
    conn.commit()
    conn.close()


def delete_password(service, username):
    print("Deleting password...")

    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE (service, username) = (?, ?)", (service, username))
    conn.commit()
    conn.close()

    print("Password deleted...")

def get_password(service, username):
    print("Getting password...")
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT encrypted_password FROM passwords WHERE (service, username) = (?, ?)", (service_name, user_name))
    except:
        print("Service/Username doesn't exist in database...")

    results = cursor.fetchone()
    print(results)
    conn.close()
    
    decrypted_password = decrypt_password(results, aes_key)
    print("The password is: ", decrypted_password)

def list_services():
    print("Listing services...\n")
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM passwords")
    results = cursor.fetchall()
    conn.close()

    if len(results) == 0:
        print("There are currently no services in the database...")
    else:
        for service in results:
            print(service)


# Test Case
if __name__ == "__main__":
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (service text UNIQUE, username text UNIQUE, encrypted_password BLOB)''')
    conn.commit()
    conn.close()
    
    aes_key = b'o+\xc3\xff\x00j\x0e\x07\xc8\xeb\xed\xd7\xb0\x04\x91\xbb' # hard-coded key only for demonstration
    print(aes_key)

    while True:
        user_choice = input("\nSelect option: \n\n [1] Save Password \n [2] Delete Password \n [3] Get Password \n [4] List Services \n [5] Exit\n\n")

        match user_choice:
            case "1":
                service_name = input("Enter service name: ")
                user_name = input("Enter username: ")
                pass_word = getpass.getpass("Enter a password: ")

                save_password(service_name, user_name, pass_word)
                
            case "2":
                service_name = input("Enter service name: ")
                user_name = input("Enter username: ")
                
                delete_password(service_name, user_name)

            case "3":
                service_name = input("Input service name: ")
                user_name = input("Input username: ")
                
                get_password(service_name, user_name)

            case "4":
                list_services()

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
