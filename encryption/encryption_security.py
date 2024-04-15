from tkinter import *
import tkinter
import random
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Initialize Tkinter window
root = Tk()
root.geometry("450x760")
root.title("Text Encryptor")

# String variable for input
textvar = tkinter.StringVar()
inp = tkinter.Entry(root, textvariable=textvar)


# ROT13 Encryption function
def rot13_encrypt(text):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted_text += chr(((ord(char) - ord("a") + 13) % 26) + ord("a"))
            elif char.isupper():
                encrypted_text += chr(((ord(char) - ord("A") + 13) % 26) + ord("A"))
        else:
            encrypted_text += char
    return encrypted_text


# ROT13 Decryption function
def rot13_decrypt(text):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                decrypted_text += chr(((ord(char) - ord("a") - 13) % 26) + ord("a"))
            elif char.isupper():
                decrypted_text += chr(((ord(char) - ord("A") - 13) % 26) + ord("A"))
        else:
            decrypted_text += char
    return decrypted_text


# AES Encryption function
def aes_encrypt(text, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted_data.hex()


# AES Decryption function
def aes_decrypt(text, key):
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(bytes.fromhex(text)) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    return unpadded_data.decode()


# Rail Fence Cipher Encryption function
def rail_fence_encrypt(text, rails):
    encrypted_text = ""
    for i in range(rails):
        for j in range(i, len(text), rails):
            encrypted_text += text[j]
    return encrypted_text


# Rail Fence Cipher Decryption function
def rail_fence_decrypt(text, rails):
    decrypted_text = [""] * len(text)
    pos = 0
    for i in range(rails):
        j = i
        while j < len(text):
            decrypted_text[j] = text[pos]
            pos += 1
            j += rails
    return "".join(decrypted_text)


# Playfair Cipher Encryption function
def playfair_encrypt(text, key):
    # Generate the Playfair matrix
    def generate_matrix(key):
        matrix = []
        key = key.replace(" ", "").upper()
        key += "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        for char in key:
            if char not in matrix:
                matrix.append(char)
        return matrix

    # Prepare the text for encryption
    def prepare_text(text):
        text = text.replace(" ", "").upper()
        prepared_text = ""
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                prepared_text += text[i] + "X"
            elif text[i] == text[i + 1]:
                prepared_text += text[i] + "X"
                i += 1
            else:
                prepared_text += text[i] + text[i + 1]
                i += 2
            i += 1
        return prepared_text

    # Find the position of a character in the matrix
    def find_position(matrix, char):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return i, j

    # Encrypt a pair of characters
    def encrypt_pair(matrix, pair):
        x1, y1 = find_position(matrix, pair[0])
        x2, y2 = find_position(matrix, pair[1])
        if x1 == x2:
            return matrix[x1][(y1 + 1) % 5] + matrix[x2][(y2 + 1) % 5]
        elif y1 == y2:
            return matrix[(x1 + 1) % 5][y1] + matrix[(x2 + 1) % 5][y2]
        else:
            return matrix[x1][y2] + matrix[x2][y1]

    # Generate the Playfair matrix
    matrix = generate_matrix(key)
    # Prepare the text
    text = prepare_text(text)
    # Encrypt pairs of characters
    encrypted_text = ""
    for i in range(0, len(text), 2):
        encrypted_text += encrypt_pair(matrix, text[i : i + 2])
    return encrypted_text


# Playfair Cipher Decryption function
def playfair_decrypt(text, key):
    # Generate the Playfair matrix
    def generate_matrix(key):
        matrix = []
        key = key.replace(" ", "").upper()
        key += "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        for char in key:
            if char not in matrix:
                matrix.append(char)
        return matrix

    # Find the position of a character in the matrix
    def find_position(matrix, char):
        for i in range(5):
            for j in range(5):
                if matrix[i][j] == char:
                    return i, j

    # Decrypt a pair of characters
    def decrypt_pair(matrix, pair):
        x1, y1 = find_position(matrix, pair[0])
        x2, y2 = find_position(matrix, pair[1])
        if x1 == x2:
            return matrix[x1][(y1 - 1) % 5] + matrix[x2][(y2 - 1) % 5]
        elif y1 == y2:
            return matrix[(x1 - 1) % 5][y1] + matrix[(x2 - 1) % 5][y2]
        else:
            return matrix[x1][y2] + matrix[x2][y1]

    # Generate the Playfair matrix
    matrix = generate_matrix(key)
    # Decrypt pairs of characters
    decrypted_text = ""
    for i in range(0, len(text), 2):
        decrypted_text += decrypt_pair(matrix, text[i : i + 2])
    return decrypted_text


# Affine Cipher Encryption function
def affine_encrypt(text, a, b):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted_text += chr(
                    ((a * (ord(char) - ord("a")) + b) % 26) + ord("a")
                )
            elif char.isupper():
                encrypted_text += chr(
                    ((a * (ord(char) - ord("A")) + b) % 26) + ord("A")
                )
        else:
            encrypted_text += char
    return encrypted_text


# Affine Cipher Decryption function
def affine_decrypt(text, a, b):
    decrypted_text = ""
    a_inv = -1
    for i in range(26):
        if (a * i) % 26 == 1:
            a_inv = i
            break
    if a_inv == -1:
        return "Invalid key"

    for char in text:
        if char.isalpha():
            if char.islower():
                decrypted_text += chr(
                    ((a_inv * ((ord(char) - ord("a")) - b)) % 26) + ord("a")
                )
            elif char.isupper():
                decrypted_text += chr(
                    ((a_inv * ((ord(char) - ord("A")) - b)) % 26) + ord("A")
                )
        else:
            decrypted_text += char
    return decrypted_text


# Hill Cipher Encryption function
def hill_encrypt(text, key_matrix):
    def matrix_multiply(matrix1, matrix2):
        result = []
        for i in range(len(matrix1)):
            row = []
            for j in range(len(matrix2[0])):
                sum = 0
                for k in range(len(matrix2)):
                    sum += matrix1[i][k] * matrix2[k][j]
                row.append(sum % 26)
            result.append(row)
        return result

    def text_to_numbers(text):
        return [ord(char) - ord("A") for char in text.upper() if char.isalpha()]

    def numbers_to_text(numbers):
        return "".join([chr(num + ord("A")) for num in numbers])

    text_numbers = text_to_numbers(text)
    padded_text = text_numbers + [0] * (len(text_numbers) % len(key_matrix))
    encrypted_numbers = []
    for i in range(0, len(padded_text), len(key_matrix)):
        block = padded_text[i : i + len(key_matrix)]
        block_matrix = [
            block[i : i + len(key_matrix)]
            for i in range(0, len(block), len(key_matrix))
        ]
        encrypted_block_matrix = matrix_multiply(key_matrix, block_matrix)
        encrypted_block = [num for row in encrypted_block_matrix for num in row]
        encrypted_numbers.extend(encrypted_block)

    return numbers_to_text(encrypted_numbers)


# Hill Cipher Decryption function
def hill_decrypt(text, key_matrix):
    def matrix_inverse(matrix):
        determinant = matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        inverse_determinant = -1
        for i in range(26):
            if (determinant * i) % 26 == 1:
                inverse_determinant = i
                break
        if inverse_determinant == -1:
            return "Invalid key"

        inverse_matrix = [[matrix[1][1], -matrix[0][1]], [-matrix[1][0], matrix[0][0]]]
        for i in range(2):
            for j in range(2):
                inverse_matrix[i][j] *= inverse_determinant
                inverse_matrix[i][j] %= 26
        return inverse_matrix

    def matrix_multiply(matrix1, matrix2):
        result = []
        for i in range(len(matrix1)):
            row = []
            for j in range(len(matrix2[0])):
                sum = 0
                for k in range(len(matrix2)):
                    sum += matrix1[i][k] * matrix2[k][j]
                row.append(sum % 26)
            result.append(row)
        return result

    def text_to_numbers(text):
        return [ord(char) - ord("A") for char in text.upper() if char.isalpha()]

    def numbers_to_text(numbers):
        return "".join([chr(num + ord("A")) for num in numbers])

    text_numbers = text_to_numbers(text)
    padded_text = text_numbers + [0] * (len(text_numbers) % len(key_matrix))
    decrypted_numbers = []
    inverse_key_matrix = matrix_inverse(key_matrix)
    for i in range(0, len(padded_text), len(key_matrix)):
        block = padded_text[i : i + len(key_matrix)]
        block_matrix = [
            block[i : i + len(key_matrix)]
            for i in range(0, len(block), len(key_matrix))
        ]
        decrypted_block_matrix = matrix_multiply(inverse_key_matrix, block_matrix)
        decrypted_block = [num for row in decrypted_block_matrix for num in row]
        decrypted_numbers.extend(decrypted_block)

    return numbers_to_text(decrypted_numbers)


# Vigenère Cipher Encryption function
def vigenere_encrypt(text, key):
    encrypted_text = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index].upper()) - ord("A")
            if char.islower():
                encrypted_text += chr(((ord(char) - ord("a") + shift) % 26) + ord("a"))
            elif char.isupper():
                encrypted_text += chr(((ord(char) - ord("A") + shift) % 26) + ord("A"))
            key_index = (key_index + 1) % len(key)
        else:
            encrypted_text += char
    return encrypted_text


# Vigenère Cipher Decryption function
def vigenere_decrypt(text, key):
    decrypted_text = ""
    key_index = 0
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index].upper()) - ord("A")
            if char.islower():
                decrypted_text += chr(
                    ((ord(char) - ord("a") - shift + 26) % 26) + ord("a")
                )
            elif char.isupper():
                decrypted_text += chr(
                    ((ord(char) - ord("A") - shift + 26) % 26) + ord("A")
                )
            key_index = (key_index + 1) % len(key)
        else:
            decrypted_text += char
    return decrypted_text


# Monoalphabetic Substitution Encryption function
def monoalphabetic_encrypt(text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted_text += key[alphabet.index(char)]
            elif char.isupper():
                encrypted_text += key[alphabet.index(char.lower())].upper()
        else:
            encrypted_text += char
    return encrypted_text


# Monoalphabetic Substitution Decryption function
def monoalphabetic_decrypt(text, key):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                decrypted_text += alphabet[key.index(char)]
            elif char.isupper():
                decrypted_text += alphabet[key.index(char.lower())].upper()
        else:
            decrypted_text += char
    return decrypted_text


# Atbash Cipher Encryption and Decryption function
def atbash_encrypt_decrypt(text):
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    atbash_alphabet = alphabet[::-1]
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted_text += atbash_alphabet[alphabet.index(char)]
            elif char.isupper():
                encrypted_text += atbash_alphabet[alphabet.index(char.lower())].upper()
        else:
            encrypted_text += char
    return encrypted_text


# Caesar Cipher Encryption function
def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted_text += chr(((ord(char) - ord("a") + shift) % 26) + ord("a"))
            elif char.isupper():
                encrypted_text += chr(((ord(char) - ord("A") + shift) % 26) + ord("A"))
        else:
            encrypted_text += char
    return encrypted_text


# Caesar Cipher Decryption function
def caesar_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                decrypted_text += chr(
                    ((ord(char) - ord("a") - shift + 26) % 26) + ord("a")
                )
            elif char.isupper():
                decrypted_text += chr(
                    ((ord(char) - ord("A") - shift + 26) % 26) + ord("A")
                )
        else:
            decrypted_text += char
    return decrypted_text


# Function to update the text area with encrypted or decrypted text
def update_text_area(operation):
    text = textvar.get()
    shift = 3  # Default shift value for Caesar Cipher

    if operation == "encrypt_rot13":
        text = rot13_encrypt(text)
    elif operation == "decrypt_rot13":
        text = rot13_decrypt(text)
    elif operation == "encrypt_aes":
        key = "1234567890123456"
        text = aes_encrypt(text, key)
    elif operation == "decrypt_aes":
        key = "1234567890123456"
        text = aes_decrypt(text, key)
    elif operation == "encrypt_rail_fence":
        rails = 3
        text = rail_fence_encrypt(text, rails)
    elif operation == "decrypt_rail_fence":
        rails = 3
        text = rail_fence_decrypt(text, rails)
    elif operation == "encrypt_playfair":
        key = "KEYWORD"
        text = playfair_encrypt(text, key)
    elif operation == "decrypt_playfair":
        key = "KEYWORD"
        text = playfair_decrypt(text, key)
    elif operation == "encrypt_affine":
        a, b = 3, 5
        text = affine_encrypt(text, a, b)
    elif operation == "decrypt_affine":
        a, b = 3, 5
        text = affine_decrypt(text, a, b)
    elif operation == "encrypt_hill":
        key_matrix = [[6, 24], [1, 3]]
        text = hill_encrypt(text, key_matrix)
    elif operation == "decrypt_hill":
        key_matrix = [[6, 24], [1, 3]]
        text = hill_decrypt(text, key_matrix)
    elif operation == "encrypt_vigenere":
        key = "KEY"
        text = vigenere_encrypt(text, key)
    elif operation == "decrypt_vigenere":
        key = "KEY"
        text = vigenere_decrypt(text, key)
    elif operation == "encrypt_monoalphabetic":
        key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        text = monoalphabetic_encrypt(text, key)
    elif operation == "decrypt_monoalphabetic":
        key = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        text = monoalphabetic_decrypt(text, key)
    elif operation == "encrypt_atbash":
        text = atbash_encrypt_decrypt(text)
    elif operation == "decrypt_atbash":
        text = atbash_encrypt_decrypt(text)
    elif operation == "encrypt_caesar":
        text = caesar_encrypt(text, shift)
    elif operation == "decrypt_caesar":
        text = caesar_decrypt(text, shift)
    text_area.delete("1.0", END)
    text_area.insert(END, text)


# Create widgets: Text area, Buttons, and Entry
text_area = Text(root, height=10, width=50)

# Encryption Table
btn_encrypt_rot13 = Button(
    root, text="ROT13_Encryption", command=lambda: update_text_area("encrypt_rot13")
)
btn_encrypt_aes = Button(
    root, text="AES_Encryption", command=lambda: update_text_area("encrypt_aes")
)
btn_encrypt_rail_fence = Button(
    root,
    text="Rail Fence_Encryption",
    command=lambda: update_text_area("encrypt_rail_fence"),
)
btn_encrypt_playfair = Button(
    root,
    text="Playfair_Encryption",
    command=lambda: update_text_area("encrypt_playfair"),
)
btn_encrypt_affine = Button(
    root, text="Affine_Encryption", command=lambda: update_text_area("encrypt_affine")
)
btn_encrypt_hill = Button(
    root, text="Hill_Encryption", command=lambda: update_text_area("encrypt_hill")
)
btn_encrypt_vigenere = Button(
    root,
    text="Vigenère_Encryption",
    command=lambda: update_text_area("encrypt_vigenere"),
)
btn_encrypt_monoalphabetic = Button(
    root,
    text="Monoalphabetic_Encryption",
    command=lambda: update_text_area("encrypt_monoalphabetic"),
)
btn_encrypt_atbash = Button(
    root, text="Atbash_Encryption", command=lambda: update_text_area("encrypt_atbash")
)
btn_encrypt_caesar = Button(
    root, text="Caesar_Encryption", command=lambda: update_text_area("encrypt_caesar")
)

# Decryption Table
btn_decrypt_rot13 = Button(
    root, text="ROT13_Decrypt", command=lambda: update_text_area("decrypt_rot13")
)
btn_decrypt_aes = Button(
    root, text="AES_Decrypt", command=lambda: update_text_area("decrypt_aes")
)
btn_decrypt_rail_fence = Button(
    root,
    text="Rail Fence_Decrypt",
    command=lambda: update_text_area("decrypt_rail_fence"),
)
btn_decrypt_playfair = Button(
    root, text="Playfair_Decrypt", command=lambda: update_text_area("decrypt_playfair")
)
btn_decrypt_affine = Button(
    root, text="Affine_Decrypt", command=lambda: update_text_area("decrypt_affine")
)
btn_decrypt_hill = Button(
    root, text="Hill_Decrypt", command=lambda: update_text_area("decrypt_hill")
)
btn_decrypt_vigenere = Button(
    root, text="Vigenère_Decrypt", command=lambda: update_text_area("decrypt_vigenere")
)
btn_decrypt_monoalphabetic = Button(
    root,
    text="Monoalphabetic_Decrypt",
    command=lambda: update_text_area("decrypt_monoalphabetic"),
)
btn_decrypt_atbash = Button(
    root, text="Atbash_Decrypt", command=lambda: update_text_area("decrypt_atbash")
)
btn_decrypt_caesar = Button(
    root, text="Caesar_Decrypt", command=lambda: update_text_area("decrypt_caesar")
)

# Grid layout for widgets
inp.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
text_area.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

# Encryption Table
btn_encrypt_rot13.grid(row=2, column=0, padx=10, pady=10)
btn_encrypt_aes.grid(row=3, column=0, padx=10, pady=10)
btn_encrypt_rail_fence.grid(row=4, column=0, padx=10, pady=10)
btn_encrypt_playfair.grid(row=5, column=0, padx=10, pady=10)
btn_encrypt_affine.grid(row=6, column=0, padx=10, pady=10)
btn_encrypt_hill.grid(row=7, column=0, padx=10, pady=10)
btn_encrypt_vigenere.grid(row=8, column=0, padx=10, pady=10)
btn_encrypt_monoalphabetic.grid(row=9, column=0, padx=10, pady=10)
btn_encrypt_atbash.grid(row=10, column=0, padx=10, pady=10)
btn_encrypt_caesar.grid(row=11, column=0, padx=10, pady=10)

# Decryption Table
btn_decrypt_rot13.grid(row=2, column=1, padx=10, pady=10)
btn_decrypt_aes.grid(row=3, column=1, padx=10, pady=10)
btn_decrypt_rail_fence.grid(row=4, column=1, padx=10, pady=10)
btn_decrypt_playfair.grid(row=5, column=1, padx=10, pady=10)
btn_decrypt_affine.grid(row=6, column=1, padx=10, pady=10)
btn_decrypt_hill.grid(row=7, column=1, padx=10, pady=10)
btn_decrypt_vigenere.grid(row=8, column=1, padx=10, pady=10)
btn_decrypt_monoalphabetic.grid(row=9, column=1, padx=10, pady=10)
btn_decrypt_atbash.grid(row=10, column=1, padx=10, pady=10)
btn_decrypt_caesar.grid(row=11, column=1, padx=10, pady=10)


root.mainloop()
