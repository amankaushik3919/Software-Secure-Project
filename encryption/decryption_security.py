import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import codecs
import base64


class Decrypt:
    @staticmethod
    def rot13_decrypt(self, user_input):
        self.encrypt = codecs.encode(user_input, "rot13")

    @staticmethod
    def aes_decrypt(
        ciphertext,
    ):
        key = (
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        )
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decodedciphertext = base64.b64decode(ciphertext)
        padded_data = decryptor.update(decodedciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext

    @staticmethod
    def decryptRailFence(cipher, key=2):
        # create the matrix to cipher
        # plain text key = rows ,
        # length(text) = columns
        # filling the rail matrix to
        # distinguish filled spaces
        # from blank ones
        rail = [["\n" for i in range(len(cipher))] for j in range(key)]

        # to find the direction
        dir_down = None
        row, col = 0, 0

        # mark the places with '*'
        for i in range(len(cipher)):
            if row == 0:
                dir_down = True
            if row == key - 1:
                dir_down = False

            # place the marker
            rail[row][col] = "*"
            col += 1

            # find the next row
            # using direction flag
            if dir_down:
                row += 1
            else:
                row -= 1

        # now we can construct the
        # fill the rail matrix
        index = 0
        for i in range(key):
            for j in range(len(cipher)):
                if (rail[i][j] == "*") and (index < len(cipher)):
                    rail[i][j] = cipher[index]
                    index += 1

        # now read the matrix in
        # zig-zag manner to construct
        # the resultant text
        result = []
        row, col = 0, 0
        for i in range(len(cipher)):
            # check the direction of flow
            if row == 0:
                dir_down = True
            if row == key - 1:
                dir_down = False

            # place the marker
            if rail[row][col] != "*":
                result.append(rail[row][col])
                col += 1

            # find the next row using
            # direction flag
            if dir_down:
                row += 1
            else:
                row -= 1
        return "".join(result)

    @staticmethod
    def decryptPlayfairCipher(string, key="bestkey"):
        """Decrypts a Playfair ciphertext using a custom defined text matrix."""

        def toLowerCase(plain):
            plain = list(plain)
            for i in range(len(plain)):
                if 64 < ord(plain[i]) < 91:
                    plain[i] = chr(ord(plain[i]) + 32)
            return "".join(plain)

        def removeSpaces(plain):
            return "".join([c for c in plain if c != " "])

        def generateKeyTable(key, keyT):
            n = len(key)
            keyT[:] = [["" for _ in range(5)] for _ in range(5)]
            hashArr = [0] * 26

            for i in range(n):
                if key[i] != "j":
                    hashArr[ord(key[i]) - 97] = 2

            hashArr[ord("j") - 97] = 1
            i = j = 0

            for k in range(n):
                if hashArr[ord(key[k]) - 97] == 2:
                    hashArr[ord(key[k]) - 97] -= 1
                    keyT[i][j] = key[k]
                    j += 1
                    if j == 5:
                        i += 1
                        j = 0

            for k in range(26):
                if hashArr[k] == 0:
                    keyT[i][j] = chr(k + 97)
                    j += 1
                    if j == 5:
                        i += 1
                        j = 0

        def search(keyT, a, b, arr):
            if a == "j":
                a = "i"
            if b == "j":  # Fixed tracking bug
                b = "i"

            for r in range(5):
                for c in range(5):
                    if keyT[r][c] == a:
                        arr[0] = r
                        arr[1] = c
                    if keyT[r][c] == b:  # Fixed tracking bug
                        arr[2] = r
                        arr[3] = c

        def decrypt_core(text, keyT):
            n = len(text)
            text_list = list(text)
            arr = [0] * 4
            for i in range(0, n, 2):
                search(keyT, text_list[i], text_list[i + 1], arr)
                if arr[0] == arr[2]:
                    text_list[i] = keyT[arr[0]][(arr[1] - 1 + 5) % 5]
                    text_list[i + 1] = keyT[arr[0]][(arr[3] - 1 + 5) % 5]
                elif arr[1] == arr[3]:
                    text_list[i] = keyT[(arr[0] - 1 + 5) % 5][arr[1]]
                    text_list[i + 1] = keyT[(arr[2] - 1 + 5) % 5][arr[1]]
                else:
                    text_list[i] = keyT[arr[0]][arr[3]]
                    text_list[i + 1] = keyT[arr[2]][arr[1]]
            return "".join(text_list)

        # Main wrapper logic execution
        keyT = []
        key = removeSpaces(key)
        key = toLowerCase(key)
        string = toLowerCase(string)
        string = removeSpaces(string)
        generateKeyTable(key, keyT)
        decrypted_result = decrypt_core(string, keyT)

        # return decrypt_core(string, keyT)
        # Remove trailing 'z' padding if it was artificially added to an odd-length plaintext
        if decrypted_result.endswith("z"):
            decrypted_result = decrypted_result[:-1]

        return decrypted_result

    @staticmethod
    # Decryption function
    def affine_decrypt(text, a=5, b=8):
        decrypted_text = ""
        m = 26
        a_inv = pow(a, -1, m)
        for char in text:
            if char.isalpha():
                if char.isupper():
                    decrypted_text += chr(
                        ((a_inv * (ord(char) - ord("A") - b)) % 26) + ord("A")
                    )
                else:
                    decrypted_text += chr(
                        ((a_inv * (ord(char) - ord("a") - b)) % 26) + ord("a")
                    )
            else:
                decrypted_text += char
        return decrypted_text
