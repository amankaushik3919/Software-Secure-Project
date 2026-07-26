import codecs
import base64
import string
import numpy as np

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


class Decrypt:
    @staticmethod
    def rot13_decrypt(user_input: str) -> str:
        return codecs.encode(user_input, "rot13")

    @staticmethod
    def aes_decrypt(ciphertext: str) -> str:
        # Standard 16-byte (128-bit) key matching AES-128
        key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"

        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()

        try:
            decoded_ciphertext = base64.b64decode(ciphertext)
            padded_data = decryptor.update(
                decoded_ciphertext) + decryptor.finalize()
            unpadder = PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()
            return plaintext.decode("utf-8")
        except Exception:
            return ""

    @staticmethod
    def decryptRailFence(cipher: str, key: int = 2) -> str:
        if key <= 1 or key >= len(cipher):
            return cipher

        rail = [["\n" for _ in range(len(cipher))] for _ in range(key)]
        dir_down = None
        row, col = 0, 0

        for i in range(len(cipher)):
            if row == 0:
                dir_down = True
            if row == key - 1:
                dir_down = False

            rail[row][col] = "*"
            col += 1
            row += 1 if dir_down else -1

        index = 0
        for i in range(key):
            for j in range(len(cipher)):
                if rail[i][j] == "*" and index < len(cipher):
                    rail[i][j] = cipher[index]
                    index += 1

        result = []
        row, col = 0, 0
        for i in range(len(cipher)):
            if row == 0:
                dir_down = True
            if row == key - 1:
                dir_down = False

            if rail[row][col] != "*":
                result.append(rail[row][col])
                col += 1

            row += 1 if dir_down else -1

        return "".join(result)

    @staticmethod
    def decryptPlayfairCipher(ciphertext: str, key: str = "bestkey") -> str:
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

        cleaned_cipher = "".join(
            [c.lower() for c in ciphertext if c.isalpha()]).replace("j", "i")
        key_processed = key.lower().replace("j", "i")
        matrix = generate_key_matrix(key_processed)

        plain_list = []
        for i in range(0, len(cleaned_cipher), 2):
            if i + 1 >= len(cleaned_cipher):
                break
            pair1, pair2 = cleaned_cipher[i], cleaned_cipher[i + 1]
            r1, c1 = search_element(matrix, pair1)
            r2, c2 = search_element(matrix, pair2)

            if r1 == r2:
                plain_list.append(matrix[r1][(c1 - 1) %
                                  5] + matrix[r2][(c2 - 1) % 5])
            elif c1 == c2:
                plain_list.append(matrix[(r1 - 1) % 5]
                                  [c1] + matrix[(r2 - 1) % 5][c2])
            else:
                plain_list.append(matrix[r1][c2] + matrix[r2][c1])

        return "".join(plain_list)

    @staticmethod
    def affine_decrypt(text: str, a: int = 5, b: int = 8) -> str:
        m = 26
        try:
            a_inv = pow(a, -1, m)
        except ValueError:
            return text  # No modular inverse exists if gcd(a, 26) != 1

        result = []
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                result.append(
                    chr(((a_inv * (ord(char) - base - b)) % m) + base))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def caesar_decrypt(text: str, shift: int = 3) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                result.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def vigenere_decrypt(text: str, key: str = "KEY") -> str:
        result = []
        key_clean = "".join([k for k in key if k.isalpha()]).lower()
        if not key_clean:
            return text

        ki = 0
        for ch in text:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                k = ord(key_clean[ki % len(key_clean)]) - ord("a")
                result.append(chr((ord(ch) - base - k) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def hill_decrypt(ciphertext: str, key_matrix=None) -> str:
        if key_matrix is None:
            key_matrix = [[3, 3], [2, 5]]

        key_matrix = np.array(key_matrix, dtype=int)

        # Calculate determinant for 2x2 integer matrix precisely
        det = int(key_matrix[0, 0] * key_matrix[1, 1] -
                  key_matrix[0, 1] * key_matrix[1, 0]) % 26

        try:
            inv_det = pow(det, -1, 26)
        except ValueError:
            raise ValueError("Key matrix is not invertible modulo 26")

        # Construct adjugate matrix
        adj = np.array([
            [key_matrix[1, 1], -key_matrix[0, 1]],
            [-key_matrix[1, 0], key_matrix[0, 0]]
        ], dtype=int)

        inv_mat = (inv_det * adj) % 26

        filtered = "".join([c for c in ciphertext.lower() if c.isalpha()])
        if len(filtered) % 2 != 0:
            filtered += "x"

        result = []
        for i in range(0, len(filtered), 2):
            pair = np.array(
                [[ord(filtered[i]) - 97], [ord(filtered[i + 1]) - 97]], dtype=int)
            prod = np.dot(inv_mat, pair) % 26
            result.append(chr(int(prod[0, 0]) + 97))
            result.append(chr(int(prod[1, 0]) + 97))

        return "".join(result)
