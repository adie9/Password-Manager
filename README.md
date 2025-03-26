# Python Password Manager

## Description

This project entails creating a password manager in Python using AES encryption. For this project, I used the PyCrypto library for AES encryption and decryption, and SQLite for storing the service names, usernames, and encrypted passwords in a database.

## Features

### Encryption/Decryption

For AES encryption/decryption, I used the PyCrypto library. The function for encryption is shown below:

```python
# Encrypting password using AES mode GCM
def encrypt_password(password, key):
    nonce = get_random_bytes(12)
    password = password.encode()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(password)
    return nonce + tag + ciphertext
```

The function takes in the password and key (16 bytes) that the user input. It generates a random nonce with a length of 12 bytes and encodes the password. The function creates a cipher using the key and nonce, which creates a ciphertext and tag. The function returns the concatenated value of the nonce, tag, and ciphertext. This concatenation is important when it comes to decrypting the password.

```python
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
```

The function takes in the encrypted password and key (16 bytes). After accessing the value that contains the concatenation in encrypted_password,
the nonce, tag, and ciphertext are retrieved by splicing the concatenation based on their respective sizes. The cipher is once again created using the values of the key and tag, and the encrypted password is returned (If the correct key is used).

### SQLite Database



### Main Program Options 

