from tkinter import *
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from math import gcd
import numpy as np

# ROT13 Encryption and Decryption
def rot13_encrypt(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))

def rot13_decrypt(text):
    return rot13_encrypt(text)

# AES Encryption and Decryption
def aes_encrypt(text, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data.hex()

def aes_decrypt(text, key):
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(bytes.fromhex(text)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return unpadded_data.decode()

# Rail Fence Cipher Encryption and Decryption
def rail_fence_encrypt(text, key):
    rail = ['' for _ in range(key)]
    level, delta = 0, 1
    for char in text:
        rail[level] += char
        if level == 0:
            delta = 1
        elif level == key - 1:
            delta = -1
        level += delta
    return ''.join(rail)

def rail_fence_decrypt(text, key):
    decrypted = ['' for _ in range(len(text))]
    index, delta = 0, 1
    for i in range(len(text)):
        decrypted[index] += '*'
        if index == 0:
            delta = 1
        elif index == key - 1:
            delta = -1
        index += delta
    pos = 0
    for i in range(key):
        for j in range(len(text)):
            if decrypted[j][i] == '*' and pos < len(text):
                decrypted[j][i] = text[pos]
                pos += 1
    result = ''
    index, delta = 0, 1
    for i in range(len(text)):
        result += decrypted[index][i]
        if index == 0:
            delta = 1
        elif index == key - 1:
            delta = -1
        index += delta
    return result

# Playfair Cipher Encryption and Decryption
def playfair_encrypt(text, key):
    matrix = []
    key = key.upper().replace(" ", "")
    key += "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in key:
        if char not in matrix:
            matrix.append(char)
    text = text.upper().replace(" ", "").replace("J", "I")
    text = text.replace("J", "I")
    pairs = [(text[i], text[i + 1]) for i in range(0, len(text), 2)]
    encrypted_text = ''
    for pair in pairs:
        row1, col1 = divmod(matrix.index(pair[0]), 5)
        row2, col2 = divmod(matrix.index(pair[1]), 5)
        if row1 == row2:
            encrypted_text += matrix[row1 * 5 + (col1 + 1) % 5] + matrix[row2 * 5 + (col2 + 1) % 5]
        elif col1 == col2:
            encrypted_text += matrix[((row1 + 1) % 5) * 5 + col1] + matrix[((row2 + 1) % 5) * 5 + col2]
        else:
            encrypted_text += matrix[row1 * 5 + col2] + matrix[row2 * 5 + col1]
    return encrypted_text

def playfair_decrypt(text, key):
    matrix = []
    key = key.upper().replace(" ", "")
    key += "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in key:
        if char not in matrix:
            matrix.append(char)
    text = text.upper().replace(" ", "").replace("J", "I")
    pairs = [(text[i], text[i + 1]) for i in range(0, len(text), 2)]
    decrypted_text = ''
    for pair in pairs:
        row1, col1 = divmod(matrix.index(pair[0]), 5)
        row2, col2 = divmod(matrix.index(pair[1]), 5)
        if row1 == row2:
            decrypted_text += matrix[row1 * 5 + (col1 - 1) % 5] + matrix[row2 * 5 + (col2 - 1) % 5]
        elif col1 == col2:
            decrypted_text += matrix[((row1 - 1) % 5) * 5 + col1] + matrix[((row2 - 1) % 5) * 5 + col2]
        else:
            decrypted_text += matrix[row1 * 5 + col2] + matrix[row2 * 5 + col1]
    return decrypted_text

# Affine Cipher Encryption and Decryption
def affine_encrypt(text, key):
    a, b = key
    return ''.join([chr(((a * (ord(char) - ord('A')) + b) % 26) + ord('A')) if char.isalpha() else char for char in text.upper()])

def affine_decrypt(text, key):
    a, b = key
    a_inv = -1
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break
    if a_inv == -1:
        return "Invalid key"
    return ''.join([chr(((a_inv * (ord(char) - ord('A') - b)) % 26) + ord('A')) if char.isalpha() else char for char in text.upper()])

# Hill Cipher Encryption and Decryption
def hill_encrypt(text, key):
    key = np.array(key).reshape(2, 2)
    text = text.upper().replace(" ", "").replace("J", "I")
    if len(text) % 2 != 0:
        text += 'X'
    pairs = [(ord(text[i]) - ord('A'), ord(text[i + 1]) - ord('A')) for i in range(0, len(text), 2)]
    encrypted_text = ''
    for pair in pairs:
        encrypted_pair = np.dot(key, np.array(pair)) % 26
        encrypted_text += chr(encrypted_pair[0] + ord('A')) + chr(encrypted_pair[1] + ord('A'))
    return encrypted_text

def hill_decrypt(text, key):
    key = np.array(key).reshape(2, 2)
    determinant = int(np.linalg.det(key))
    if gcd(determinant, 26) != 1:
        return "Invalid key"
    inverse_determinant = [i for i in range(26) if (i * determinant) % 26 == 1][0]
    inverse_key = (inverse_determinant * np.linalg.det(key) * np.linalg.inv(key)).astype(int) % 26
    text = text.upper().replace(" ", "").replace("J", "I")
    pairs = [(ord(text[i]) - ord('A'), ord(text[i + 1]) - ord('A')) for i in range(0, len(text), 2)]
    decrypted_text = ''
    for pair in pairs:
        decrypted_pair = np.dot(inverse_key, np.array(pair)) % 26
        decrypted_text += chr(decrypted_pair[0] + ord('A')) + chr(decrypted_pair[1] + ord('A'))
    return decrypted_text

# Vigenère Cipher Encryption and Decryption
def vigenere_encrypt(text, key):
    key = key.upper()
    key_len = len(key)
    encrypted_text = ''
    for i, char in enumerate(text.upper()):
        if char.isalpha():
            shift = ord(key[i % key_len]) - ord('A')
            encrypted_text += chr(((ord(char) - ord('A') + shift) % 26) + ord('A'))
        else:
            encrypted_text += char
    return encrypted_text

def vigenere_decrypt(text, key):
    key = key.upper()
    key_len = len(key)
    decrypted_text = ''
    for i, char in enumerate(text.upper()):
        if char.isalpha():
            shift = ord(key[i % key_len]) - ord('A')
            decrypted_text += chr(((ord(char) - ord('A') - shift + 26) % 26) + ord('A'))
        else:
            decrypted_text += char
    return decrypted_text

# Monoalphabetic Substitution Cipher Encryption and Decryption
def monoalphabetic_substitution_encrypt(text, key):
    key = key.upper()
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encrypted_alphabet = ''.join(sorted(set(key), key=key.find))
    translation_table = str.maketrans(alphabet, encrypted_alphabet)
    return text.upper().translate(translation_table)

def monoalphabetic_substitution_decrypt(text, key):
    key = key.upper()
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encrypted_alphabet = ''.join(sorted(set(key), key=key.find))
    translation_table = str.maketrans(encrypted_alphabet, alphabet)
    return text.upper().translate(translation_table)

# Atbash Cipher Encryption and Decryption
def atbash_encrypt(text):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    reversed_alphabet = 'ZYXWVUTSRQPONMLKJIHGFEDCBA'
    translation_table = str.maketrans(alphabet, reversed_alphabet)
    return text.upper().translate(translation_table)

def atbash_decrypt(text):
    return atbash_encrypt(text)

# Caesar Cipher Encryption and Decryption
def caesar_encrypt(text, key):
    key = key % 26
    return ''.join([chr(((ord(char) - ord('A') + key) % 26) + ord('A')) if char.isalpha() else char for char in text.upper()])

def caesar_decrypt(text, key):
    key = key % 26
    return ''.join([chr(((ord(char) - ord('A') - key + 26) % 26) + ord('A')) if char.isalpha() else char for char in text.upper()])

# GUI
root = Tk()
root.title("Text Encryption and Decryption")

text_label = Label(root, text="Enter Text:")
text_label.grid(row=0, column=0)
text_entry = Entry(root)
text_entry.grid(row=0, column=1)

key_label = Label(root, text="Enter Key:")
key_label.grid(row=1, column=0)
key_entry = Entry(root)
key_entry.grid(row=1, column=1)

cipher_var = StringVar(root)
cipher_var.set("ROT13")  # default value

cipher_label = Label(root, text="Select Cipher:")
cipher_label.grid(row=2, column=0)
cipher_option = OptionMenu(root, cipher_var, "ROT13", "AES", "Rail Fence", "Playfair", "Affine", "Hill", "Vigenère", "Monoalphabetic", "Atbash", "Caesar")
cipher_option.grid(row=2, column=1)

result_label = Label(root, text="Result:")
result_label.grid(row=3, column=0)
result_text = Text(root, height=10, width=30)
result_text.grid(row=3, column=1)

def encrypt_decrypt():
    text = text_entry.get()
    key = key_entry.get()
    cipher = cipher_var.get()

    if cipher == "ROT13":
        result = rot13_encrypt(text) if encrypt_decrypt_var.get() == "Encrypt" else rot13_decrypt(text)
    elif cipher == "AES":
        result = aes_encrypt(text, key) if encrypt_decrypt_var.get() == "Encrypt" else aes_decrypt(text, key)
    elif cipher == "Rail Fence":
        result = rail_fence_encrypt(text, int(key)) if encrypt_decrypt_var.get() == "Encrypt" else rail_fence_decrypt(text, int(key))
    elif cipher == "Playfair":
        result = playfair_encrypt(text, key) if encrypt_decrypt_var.get() == "Encrypt" else playfair_decrypt(text, key)
    elif cipher == "Affine":
        result = affine_encrypt(text, eval(key)) if encrypt_decrypt_var.get() == "Encrypt" else affine_decrypt(text, eval(key))
    elif cipher == "Hill":
        result = hill_encrypt(text, eval(key)) if encrypt_decrypt_var.get() == "Encrypt" else hill_decrypt(text, eval(key))
    elif cipher == "Vigenère":
        result = vigenere_encrypt(text, key) if encrypt_decrypt_var.get() == "Encrypt" else vigenere_decrypt(text, key)
    elif cipher == "Monoalphabetic":
        result = monoalphabetic_substitution_encrypt(text, key) if encrypt_decrypt_var.get() == "Encrypt" else monoalphabetic_substitution_decrypt(text, key)
    elif cipher == "Atbash":
        result = atbash_encrypt(text) if encrypt_decrypt_var.get() == "Encrypt" else atbash_decrypt(text)
    elif cipher == "Caesar":
        result = caesar_encrypt(text, int(key)) if encrypt_decrypt_var.get() == "Encrypt" else caesar_decrypt(text, int(key))

    result_text.delete("1.0", END)
    result_text.insert(END, result)

encrypt_decrypt_var = StringVar(root)
encrypt_decrypt_var.set("Encrypt")  # default value

encrypt_button = Button(root, text="Encrypt", command=encrypt_decrypt)
encrypt_button.grid(row=4, column=0)

decrypt_button = Button(root, text="Decrypt", command=encrypt_decrypt)
decrypt_button.grid(row=4, column=1)

root.mainloop()
