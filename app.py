from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sqlite3, getpass

# Encrypting password using AES mode GCM
def encrypt_password(password, key):
    nonce = get_random_bytes(12)
    password = password.encode()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(password)
    return nonce + tag + ciphertext # Concatenating nonce, tag, and ciphertext for retrieval later

# Decrypting password using AES mode GCM
def decrypt_password(encrypted_password, key):
    encrypted_password = encrypted_password[0] # Accessing binary value inside tuple

    # Accessing nonce, tag, and ciphertext by splicing their respective lengths from encrypted_password
    nonce = encrypted_password[:12]
    tag = encrypted_password[12:28]
    ciphertext = encrypted_password[28:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    return password.decode()

# Function that saves password based on service, username, and password input
def save_password(service, username, password):
    pass_word = encrypt_password(password, aes_key) # Passing user password to function for encryption
    print("Saving password...")

    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE (service, username) = (?, ?)", (service, username)) 
    results = cursor.fetchall()

    # Checking if the (service, username) pair already exists in the database
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

# Function that deletes password based on service and username input
def delete_password(service, username):
    print("Deleting password...")
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE (service, username) = (?, ?)", (service, username))
    results = cursor.fetchall()

    # Checking if the password exists
    if not results:
        print("Password to delete does not exist. Returning to options...")
    else:
        cursor.execute("DELETE FROM passwords WHERE (service, username) = (?, ?)", (service, username))
        print("Password deleted...")
    conn.commit()
    conn.close()

# Function that returns password based on service and username input
def get_password(service, username):
    try: # Try/except clause that throws exception if the (service, username) pair doesn't exist in the database
        print("Getting password...")
        conn = sqlite3.connect("password_storage.db")
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_password FROM passwords WHERE (service, username) = (?, ?)", (service_name, user_name))
        results = cursor.fetchone()
        print(results)
        conn.close()
        decrypted_password = decrypt_password(results, aes_key)
        print("The password is:", decrypted_password)
    except:
        print("(service, username) pair doesn't exist in database...")

def list_services():
    print("Listing services...\n")
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("SELECT service FROM passwords")
    results = cursor.fetchall()
    conn.close()

    if not results:
        print("There are currently no services in the database...")
    else:
        for service in results:
            print(service)

    

# Main
if __name__ == "__main__":
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (service text UNIQUE, username text UNIQUE, encrypted_password BLOB)''')
    conn.commit()
    conn.close()
    
    aes_key = b'o+\xc3\xff\x00j\x0e\x07\xc8\xeb\xed\xd7\xb0\x04\x91\xbb' # hard-coded key only for demonstration

    while True:
        user_choice = input("\nSelect option: \n\n [1] Save Password \n [2] Delete Password \n [3] Get Password \n [4] List Services \n [5] Exit\n\n")

        match user_choice:
            case "1":
                service_name = input("Enter service name: ").lower()
                user_name = input("Enter username: ")
                pass_word = getpass.getpass("Enter a password: ")

                save_password(service_name, user_name, pass_word)
                
            case "2":
                service_name = input("Enter service name: ").lower()
                user_name = input("Enter username: ")
                
                delete_password(service_name, user_name)

            case "3":
                service_name = input("Input service name: ").lower()
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
