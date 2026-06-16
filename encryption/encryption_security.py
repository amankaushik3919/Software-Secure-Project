from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import codecs
import base64


class Encrypt:
    @staticmethod
    def rot13_encrypt(user_input):
        encrypt = codecs.encode(user_input, "rot13")
        return encrypt

    @staticmethod
    def aes_encrypt(
        plaintext,
    ):
        key = (
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        )
        plaintext = str(plaintext).encode("utf-8")
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        encodedciphertext = base64.b64encode(ciphertext)
        return encodedciphertext

    @staticmethod
    def encryptRailFence(text, key=2):

        # create the matrix to cipher
        # plain text key = rows ,
        # length(text) = columns
        # filling the rail matrix
        # to distinguish filled
        # spaces from blank ones
        rail = [["\n" for i in range(len(text))] for j in range(key)]

        # to find the direction
        dir_down = False
        row, col = 0, 0

        for i in range(len(text)):
            # check the direction of flow
            # reverse the direction if we've just
            # filled the top or bottom rail
            if (row == 0) or (row == key - 1):
                dir_down = not dir_down

            # fill the corresponding alphabet
            rail[row][col] = text[i]
            col += 1

            # find the next row using
            # direction flag
            if dir_down:
                row += 1
            else:
                row -= 1
        # now we can construct the cipher
        # using the rail matrix
        result = []
        for i in range(key):
            for j in range(len(text)):
                if rail[i][j] != "\n":
                    result.append(rail[i][j])
        return "".join(result)

    @staticmethod
    def playfair_encrypt(user_input, key_text="bestkey"):
        """Lowercase Playfair Cipher implementation using your exact mathematical matrix mechanics."""
        alphabet_list = [
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
            "g",
            "h",
            "i",
            "k",
            "l",
            "m",
            "n",
            "o",
            "p",
            "q",
            "r",
            "s",
            "t",
            "u",
            "v",
            "w",
            "x",
            "y",
            "z",
        ]

        # Your original utility functions
        def to_lowercase(text):
            return text.lower()

        def remove_spaces(text):
            new_text = ""
            for char in text:
                if char != " ":
                    new_text += char
            return new_text

        def group_characters(text):
            groups = []
            group_start = 0
            for i in range(2, len(text), 2):
                groups.append(text[group_start:i])
                group_start = i
            groups.append(text[group_start:])
            return groups

        def fill_letter(text):
            k = len(text)
            if k % 2 == 0:
                for i in range(0, k, 2):
                    if text[i] == text[i + 1]:
                        new_word = text[0 : i + 1] + str("x") + text[i + 1 :]
                        new_word = fill_letter(new_word)
                        break
                    else:
                        new_word = text
            else:
                for i in range(0, k - 1, 2):
                    if text[i] == text[i + 1]:
                        new_word = text[0 : i + 1] + str("x") + text[i + 1 :]
                        new_word = fill_letter(new_word)
                        break
                    else:
                        new_word = text
            return new_word

        def generate_key_matrix(word, alphabets):
            key_letters = []
            for char in word:
                if char not in key_letters:
                    key_letters.append(char)
            complementary_elements = []
            for char in key_letters:
                if char not in complementary_elements:
                    complementary_elements.append(char)
            for char in alphabets:
                if char not in complementary_elements:
                    complementary_elements.append(char)
            matrix_grid = []
            while complementary_elements != []:
                matrix_grid.append(complementary_elements[:5])
                complementary_elements = complementary_elements[5:]
            return matrix_grid

        def search_element(matrix_grid, element):
            for r in range(5):
                for c in range(5):
                    if matrix_grid[r][c] == element:
                        return r, c

        def encrypt_row_rule(matrix_grid, e1_row, e1_column, e2_row, e2_column):
            if e1_column == 4:
                char1 = matrix_grid[e1_row][0]
            else:
                char1 = matrix_grid[e1_row][e1_column + 1]
            if e2_column == 4:
                char2 = matrix_grid[e2_row][0]
            else:
                char2 = matrix_grid[e2_row][e2_column + 1]
            return char1, char2

        def encrypt_column_rule(matrix_grid, e1_row, e1_column, e2_row, e2_column):
            if e1_row == 4:
                char1 = matrix_grid[0][e1_column]
            else:
                char1 = matrix_grid[e1_row + 1][e1_column]
            if e2_row == 4:
                char2 = matrix_grid[0][e2_column]
            else:
                char2 = matrix_grid[e2_row + 1][e2_column]
            return char1, char2

        def encrypt_rectangle_rule(matrix_grid, e1_row, e1_column, e2_row, e2_column):
            char1 = matrix_grid[e1_row][e2_column]
            char2 = matrix_grid[e2_row][e1_column]
            return char1, char2

        def encrypt_playfair_cipher(matrix_grid, plaintext_list):
            cipher_text_list = []
            for i in range(0, len(plaintext_list)):
                # Filter out illegal spaces or missing key elements if text contains non-alphabet values
                if len(plaintext_list[i]) < 2:
                    continue
                ele1_x, ele1_y = search_element(matrix_grid, plaintext_list[i][0])
                ele2_x, ele2_y = search_element(matrix_grid, plaintext_list[i][1])
                if ele1_x == ele2_x:
                    char1, char2 = encrypt_row_rule(
                        matrix_grid, ele1_x, ele1_y, ele2_x, ele2_y
                    )
                elif ele1_y == ele2_y:
                    char1, char2 = encrypt_column_rule(
                        matrix_grid, ele1_x, ele1_y, ele2_x, ele2_y
                    )
                else:
                    char1, char2 = encrypt_rectangle_rule(
                        matrix_grid, ele1_x, ele1_y, ele2_x, ele2_y
                    )
                cipher_text_list.append(char1 + char2)
            return cipher_text_list

        # Execution steps using your exact processing sequence
        # Clean special chars/numbers to map perfectly to your 5x5 alphabet tracking array
        cleaned_input = "".join([c for c in user_input if c.isalpha() or c == " "])
        text_plain = remove_spaces(to_lowercase(cleaned_input)).replace("j", "i")

        if not text_plain:
            return ""

        plaintext_list = group_characters(fill_letter(text_plain))
        if len(plaintext_list[-1]) != 2:
            plaintext_list[-1] = plaintext_list[-1] + "z"

        key_processed = to_lowercase(key_text).replace("j", "i")
        matrix = generate_key_matrix(key_processed, alphabet_list)
        cipher_list = encrypt_playfair_cipher(matrix, plaintext_list)

        return "".join(cipher_list)

    @staticmethod
    # Encryption function
    def affine_encrypt(text, a=5, b=8):
        encrypted_text = ""
        for char in text:
            if char.isalpha():
                if char.isupper():
                    encrypted_text += chr(
                        ((a * (ord(char) - ord("A")) + b) % 26) + ord("A")
                    )
                else:
                    encrypted_text += chr(
                        ((a * (ord(char) - ord("a")) + b) % 26) + ord("a")
                    )
            else:
                encrypted_text += char
        return encrypted_text
    
    
