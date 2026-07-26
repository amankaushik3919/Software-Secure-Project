import codecs
import base64
import string
import numpy as np

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


class Encrypt:
    @staticmethod
    def rot13_encrypt(user_input: str) -> str:
        return codecs.encode(user_input, "rot13")

    @staticmethod
    def aes_encrypt(plaintext: str) -> str:
        # Standard 16-byte (128-bit) AES key
        key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        plaintext_bytes = str(plaintext).encode("utf-8")

        # Cipher initialization (Backend omitted to support modern cryptography versions)
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()

        padder = PKCS7(128).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(ciphertext).decode("utf-8")

    @staticmethod
    def encryptRailFence(text: str, key: int = 2) -> str:
        if key <= 1 or key >= len(text):
            return text

        rail = [["\n" for _ in range(len(text))] for _ in range(key)]
        dir_down = False
        row, col = 0, 0

        for char in text:
            if row == 0 or row == key - 1:
                dir_down = not dir_down

            rail[row][col] = char
            col += 1
            row += 1 if dir_down else -1

        result = []
        for i in range(key):
            for j in range(len(text)):
                if rail[i][j] != "\n":
                    result.append(rail[i][j])
        return "".join(result)

    @staticmethod
    def playfair_encrypt(user_input: str, key_text: str = "bestkey") -> str:
        alphabet_list = [c for c in string.ascii_lowercase if c != "j"]

        def generate_key_matrix(word):
            key_letters = []
            for char in word:
                if char not in key_letters and char in alphabet_list:
                    key_letters.append(char)
            for char in alphabet_list:
                if char not in key_letters:
                    key_letters.append(char)

            return [key_letters[i:i+5] for i in range(0, 25, 5)]

        def search_element(matrix, element):
            for r in range(5):
                for c in range(5):
                    if matrix[r][c] == element:
                        return r, c
            return 0, 0

        # Process input text
        cleaned = "".join([c.lower()
                          for c in user_input if c.isalpha()]).replace("j", "i")
        if not cleaned:
            return ""

        # Handle duplicate characters & odd lengths
        formatted_text = []
        i = 0
        while i < len(cleaned):
            char1 = cleaned[i]
            if i + 1 < len(cleaned) and char1 == cleaned[i + 1]:
                formatted_text.append(char1 + "x")
                i += 1
            elif i + 1 < len(cleaned):
                formatted_text.append(char1 + cleaned[i + 1])
                i += 2
            else:
                formatted_text.append(char1 + "x")
                i += 1

        pairs = formatted_text
        key_processed = key_text.lower().replace("j", "i")
        matrix = generate_key_matrix(key_processed)

        cipher_list = []
        for pair in pairs:
            r1, c1 = search_element(matrix, pair[0])
            r2, c2 = search_element(matrix, pair[1])

            if r1 == r2:
                cipher_list.append(
                    matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5])
            elif c1 == c2:
                cipher_list.append(
                    matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2])
            else:
                cipher_list.append(matrix[r1][c2] + matrix[r2][c1])

        return "".join(cipher_list)

    @staticmethod
    def affine_encrypt(text: str, a: int = 5, b: int = 8) -> str:
        result = []
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                result.append(chr(((a * (ord(char) - base) + b) % 26) + base))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def caesar_encrypt(text: str, shift: int = 3) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base + shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def atbash_encrypt(text: str) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                limit = ord("Z") if ch.isupper() else ord("z")
                result.append(chr(limit - (ord(ch) - base)))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def monoalphabetic_encrypt(text: str, mapping=None) -> str:
        if mapping is None:
            mapping = "QWERTYUIOPASDFGHJKLZXCVBNM"
        upper_map = {k: v for k, v in zip(string.ascii_uppercase, mapping)}
        lower_map = {k.lower(): v.lower() for k, v in upper_map.items()}

        result = []
        for ch in text:
            if ch.isupper() and ch in upper_map:
                result.append(upper_map[ch])
            elif ch.islower() and ch in lower_map:
                result.append(lower_map[ch])
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def vigenere_encrypt(text: str, key: str = "KEY") -> str:
        result = []
        key_clean = "".join([k for k in key if k.isalpha()]).lower()
        if not key_clean:
            return text

        ki = 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                k = ord(key_clean[ki % len(key_clean)]) - ord("a")
                result.append(chr((ord(ch) - base + k) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def hill_encrypt(text: str, key_matrix=None) -> str:
        if key_matrix is None:
            key_matrix = [[3, 3], [2, 5]]

        key_matrix = np.array(key_matrix, dtype=int)
        n = key_matrix.shape[0]

        filtered = "".join([c for c in text.lower() if c.isalpha()])
        remainder = len(filtered) % n
        if remainder != 0:
            filtered += "x" * (n - remainder)

        result = []
        for i in range(0, len(filtered), n):
            block = np.array([[ord(c) - 97] for c in filtered[i: i + n]])
            prod = np.dot(key_matrix, block) % 26
            for val in prod.flatten():
                result.append(chr(int(val) + 97))

        return "".join(result)
