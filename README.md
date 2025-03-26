# Python Password Manager

## Description

This project entails creating a password manager in Python using AES encryption. For this project, I used the PyCrypto library for AES encryption and decryption, and SQLite for storing the service names, usernames, and encrypted passwords in a database.

## Features

### Encryption/Decryption

For AES encryption/decryption, I used the PyCrypto library. 

```python
while True:
    aes_key = getpass.getpass("Please enter your aes key (Must be 16 bytes long): ").encode()
    if len(aes_key) != 16:
        print("Invalid key size. Try again.")
    else: break
```

The key used for encryption and decryption is input by the user at the beginning of the main program. This code snippet receives the key and obsfuscates the input using ```getpass```. If the length of a key is not 16 bytes, the program prompts the user to enter a key again until it is.

```python
# Encrypting password using AES mode GCM
def encrypt_password(password, key):
    nonce = get_random_bytes(12)
    password = password.encode()

    # Creating cipher using key and nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(password)
    return nonce + tag + ciphertext
```

The encrypt_password function takes in the password and key (16 bytes) that the user input. It generates a random nonce with a length of 12 bytes and encodes the password. The function creates a cipher using the key and nonce, which creates a ciphertext and tag. The function returns the concatenated value of the nonce, tag, and ciphertext. This concatenation is important when it comes to decrypting the password.

```python
# Decrypting password using AES mode GCM
def decrypt_password(encrypted_password, key):
    encrypted_password = encrypted_password[0] # Accessing binary value inside tuple

    # Accessing nonce, tag, and ciphertext by splicing their respective lengths from encrypted_password
    nonce = encrypted_password[:12]
    tag = encrypted_password[12:28]
    ciphertext = encrypted_password[28:]

    # Creating cipher using key and nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    password = cipher.decrypt_and_verify(ciphertext, tag)
    return password.decode()
```

The decrypt_password function takes in the encrypted password and key (16 bytes). After accessing the value that contains the concatenation in encrypted_password, the nonce, tag, and ciphertext are retrieved by splicing the concatenation based on their respective sizes. The cipher is once again created using the values of the key and tag, and the encrypted password is returned (If the correct key is used).

### SQLite Database

The SQLite database was used to save/update, get, and delete passwords.

```python
# Creating "passwords" table
conn = sqlite3.connect("password_storage.db")
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS passwords (service text UNIQUE, username text UNIQUE, encrypted_password BLOB)''')
conn.commit()
conn.close()
```

At the beginning of the main program, `conn = sqlite3.connect("password_storage.db")` connects to the database by name, and creates a .db file if it doesn't yet exist.`cursor = conn.cursor()` creates a cursor object to execute functions. Then the program creates a table (if it doesn't yet exist) called "passwords" with column names of "service", "username", and "encrypted_password". `conn.commit()` saves the changes to the database and `conn.close()` closes the connection.

The program will be connecting, executing, committing, and closing the connection to the database whenever changes need to be made to it based on user instruction.

### Main Program Options 

The main program has 5 options:

[1] Save Password
[2] Delete Password
[3] Get Password
[4] List Services
[5] Exit

The user inputs the number corresponding to the operation they want to perform. This is done via matching the user input to case statements.
At the beginning of the code blocks corresponding to "Save Password", "Delete Password", and "Get Password", three functions may be called: `service_is_valid()`, `username_is_valid()`, and `password_is_valid()`. 

```python
# Functions that checks to see if there are spaces in any of the inputs
def service_is_valid():
    while True:
        service = input("Enter service name: ").lower()
        if " " in service:
            print("No spaces are allowed. Try again.")
        elif not service:
            print("Input cannot be empty. Try again.")
        else: return service

def username_is_valid():
    while True:
        username = input("Enter username: ")
        if " " in username:
            print("No spaces are allowed. Try again.")
        elif not username:
            print("Input cannot be empty. Try again.")
        else: return username

def password_is_valid():
    while True:
        password = getpass.getpass("Enter a password: ")
        if " " in password:
            print("No spaces are allowed. Try again.")
        elif not password:
            print("Input cannot be empty. Try again.")
        else: return password
```

These functions check to see if the inputs by the user are valid (No spaces; Not empty). 

#### Save Password

If the user inputs '1', the code under case "1" is run. 

```python
match user_choice:
    case "1":
        service_name = service_is_valid()
        user_name = username_is_valid()
        pass_word = password_is_valid()

        save_password(service_name, user_name, pass_word)
```

The `save_password()` function takes in three parameters: `service`, `username`, and `password`. 

```python
def save_password(service, username, password):
    pass_word = encrypt_password(password, aes_key) # Passing user password to function for encryption
    print("Saving password...")

    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE (service, username) = (?, ?)", (service, username)) 
    results = cursor.fetchall()
```

First, the password input by the user is passed to the `encrypt_password()` function where it will be encrypted and return the nonce + tag + ciphertext concatenation. The program will connect to the database and return a list where the service, username in the database equals the service, username input by the user. That list is stored in `results` using `cursor.fetchall()`. 

```python
    # Checking if the (service, username) pair already exists in the database
    if results:
        update = input("It seems that username is already bound to the specified service. Would you like to update its password? (Enter 'yes' or 'no'): ")
        match update.lower():
            case "yes":
                cursor.execute("UPDATE passwords SET encrypted_password = (?) WHERE (service, username) = (?, ?)", (pass_word, service, username))
                print("Password saved...")
            case "no":
                print("Returning to options...")
            case default:
                print("Input of 'yes' or 'no' not detected. Returning to options...")
    else:
        cursor.execute("INSERT OR REPLACE INTO passwords (service, username, encrypted_password) values (?, ?, ?)", (service, username, pass_word))
        print("Password saved...")
    conn.commit()
    conn.close()
```

If the list is not empty (Meaning that the specified (service, username) pair is already stored in the database), the program presents the user with a choice. The user can either update the specified service and username with a new password, or return to options. If the list is empty, then the program saves the password to the database.

#### Delete Password

If the user inputs '2', the code block under case "2" is run.

```python
case "2":
    service_name = service_is_valid()
    user_name = username_is_valid()
    
    delete_password(service_name, user_name)
```

The `delete_password()` function takes in two parameters: `service` and `username`.

```python
# Function that deletes password based on service and username input
def delete_password(service, username):
    print("Deleting password...")
    conn = sqlite3.connect("password_storage.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM passwords WHERE (service, username) = (?, ?)", (service, username))
    results = cursor.fetchall()
```

It performs the same operations as `save_password()` at the start, connecting to the database and returning the query result.

```python
# Checking if the password exists
    if not results:
        print("Password to delete does not exist. Returning to options...")
    else:
        cursor.execute("DELETE FROM passwords WHERE (service, username) = (?, ?)", (service, username))
        print("Password deleted...")
    conn.commit()
    conn.close()
```

If there are no passwords matching the (service, username) pair, then the function will inform the user and return to options. Otherwise, it will delete the entry from the database.

#### Get Password

If the user inputs '3', the code block under case "3" will run.

```python
case "3":
    service_name = service_is_valid()
    user_name = username_is_valid()
    
    get_password(service_name, user_name)
```

It performs the same operations as `delete_password()` at the start.

```python
# Function that returns password based on service and username input
def get_password(service, username):
    try: # Try/except clause that throws exception if the (service, username) pair doesn't exist in the database OR key doesn't match
        print("Getting password...")
        conn = sqlite3.connect("password_storage.db")
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_password FROM passwords WHERE (service, username) = (?, ?)", (service_name, user_name))
        results = cursor.fetchone()
        print(results)
        conn.close()

        # Calling decrypt_password() function
        decrypted_password = decrypt_password(results, aes_key)
        print("The password is:", decrypted_password)
    except ValueError:
        print("Incorrect key was used.")
    except TypeError:
        print("(Service, Username) pair was not found in the database.")
```

The function passes results into the `decrypt_password()` function along with the key. I added a try-except block to catch the exceptions that would arise when the (service, username) pair didn't exist in the database OR if the key the user input was wrong. If no errors occurred, the function would return the decrypted password to the user.

#### List Services

If the user inputs '4', the code block under case "4' will run.

```python
case "4":
    list_services()
```

The only code is a call to the `list_services()` function, which looks like this:

```python
# Function that lists the services in the database
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

```

This function will connect to the database and execute a simple query, returning the services in the table. If there are no services in the table, the program will inform the user.

#### Exit

If the user inputs '5', the code block under case "5" will run.

```python
case "5":
    print("Exiting program...")
    break
```
In this case, the program breaks the while loop and exits the program.