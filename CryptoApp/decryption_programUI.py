import sys
import codecs
import base64
import string
import numpy as np

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QComboBox, QPushButton, QLineEdit, QFormLayout, QGroupBox,
    QMessageBox
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt


# =====================================================================
# DECRYPTION BACKEND ENGINE
# =====================================================================
class Decrypt:
    @staticmethod
    def rot13_decrypt(user_input: str) -> str:
        return codecs.decode(user_input, "rot13")

    @staticmethod
    def aes_decrypt(encoded_ciphertext: str) -> str:
        # Standard 16-byte (128-bit) key matching AES-128
        key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        try:
            ciphertext = base64.b64decode(encoded_ciphertext)
            cipher = Cipher(algorithms.AES(key), modes.ECB())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()
            return plaintext.decode("utf-8")
        except Exception as e:
            return f"AES Decryption Error: {str(e)}"

    @staticmethod
    def caesar_decrypt(text: str, shift: int = 3) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base - shift) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def atbash_decrypt(text: str) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                limit = ord('Z') if ch.isupper() else ord('z')
                result.append(chr(limit - (ord(ch) - base)))
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
                base = ord('A') if ch.isupper() else ord('a')
                k = ord(key_clean[ki % len(key_clean)]) - ord('a')
                result.append(chr((ord(ch) - base - k) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    @staticmethod
    def playfair_decrypt(user_input: str, key_text: str = "bestkey") -> str:
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

        key_processed = key_text.lower().replace("j", "i")
        matrix = generate_key_matrix(key_processed)

        cleaned = "".join([c.lower()
                          for c in user_input if c.isalpha()]).replace("j", "i")
        if len(cleaned) % 2 != 0:
            return "Error: Playfair ciphertext must contain an even number of letters."

        pairs = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]
        plaintext_list = []

        for pair in pairs:
            r1, c1 = search_element(matrix, pair[0])
            r2, c2 = search_element(matrix, pair[1])

            if r1 == r2:  # Same row -> Shift Left
                p1 = matrix[r1][(c1 - 1) % 5]
                p2 = matrix[r2][(c2 - 1) % 5]
            elif c1 == c2:  # Same column -> Shift Up
                p1 = matrix[(r1 - 1) % 5][c1]
                p2 = matrix[(r2 - 1) % 5][c2]
            else:  # Rectangle rule -> Swap columns
                p1 = matrix[r1][c2]
                p2 = matrix[r2][c1]

            plaintext_list.append(p1 + p2)

        return "".join(plaintext_list)

    @staticmethod
    def hill_decrypt(text: str, key_matrix=None) -> str:
        if key_matrix is None:
            key_matrix = np.array([[3, 3], [2, 5]])
        else:
            key_matrix = np.array(key_matrix, dtype=int)

        if key_matrix.shape != (2, 2):
            return "Error: Only 2x2 Hill Cipher matrix supported in UI."

        # Exact integer determinant modulo 26 calculation
        det = int(key_matrix[0, 0] * key_matrix[1, 1] -
                  key_matrix[0, 1] * key_matrix[1, 0]) % 26

        try:
            inv_det = pow(det, -1, 26)
        except ValueError:
            return "Error: Key matrix is not invertible modulo 26!"

        adj = np.array([[key_matrix[1, 1], -key_matrix[0, 1]],
                        [-key_matrix[1, 0], key_matrix[0, 0]]], dtype=int)
        inv_matrix = (inv_det * adj) % 26

        filtered = "".join([c for c in text.lower() if c.isalpha()])
        if len(filtered) % 2 != 0:
            filtered += "x"

        result = []
        for i in range(0, len(filtered), 2):
            block = np.array(
                [[ord(filtered[i]) - 97], [ord(filtered[i+1]) - 97]], dtype=int)
            prod = np.dot(inv_matrix, block) % 26
            result.append(chr(int(prod[0, 0]) + 97))
            result.append(chr(int(prod[1, 0]) + 97))

        return "".join(result)


# =====================================================================
# PYQT6 DECRYPTION INTERFACE
# =====================================================================
class DecryptionUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle(
            "Cybersecurity Cryptography Suite - Decryption Tool")
        self.resize(750, 680)
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QGroupBox {
                border: 1px solid #45475a;
                border-radius: 8px;
                margin-top: 10px;
                padding: 10px;
                font-weight: bold;
                color: #89b4fa;
            }
            QTextEdit, QLineEdit, QComboBox {
                background-color: #313244;
                border: 1px solid #45475a;
                border-radius: 6px;
                padding: 8px;
                color: #cdd6f4;
            }
            QPushButton {
                background-color: #89b4fa;
                color: #11111b;
                font-size: 15px;
                font-weight: bold;
                border-radius: 6px;
                padding: 12px;
            }
            QPushButton:hover {
                background-color: #b4befe;
            }
            QLabel {
                font-weight: 500;
            }
        """)

        main_layout = QVBoxLayout()

        # Header Title
        header = QLabel("🔓 Decryption Workstation")
        header.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(header)

        # Cipher Choice Box
        cipher_box = QGroupBox("1. Select Decryption Algorithm")
        cipher_layout = QHBoxLayout()
        self.cipher_dropdown = QComboBox()
        self.cipher_dropdown.addItems([
            "Caesar", "ROT13", "Vigenère", "Atbash",
            "Playfair", "Hill (2x2 Matrix)", "AES (ECB)"
        ])
        self.cipher_dropdown.currentIndexChanged.connect(
            self.update_param_visibility)
        cipher_layout.addWidget(self.cipher_dropdown)
        cipher_box.setLayout(cipher_layout)
        main_layout.addWidget(cipher_box)

        # Dynamic Parameters Input Box
        self.param_box = QGroupBox("2. Cipher Key / Parameters")
        self.param_layout = QFormLayout()

        self.shift_input = QLineEdit("3")
        self.key_input = QLineEdit("KEY")
        self.matrix_input = QLineEdit("3 3 2 5")
        self.matrix_input.setPlaceholderText(
            "e.g. 3 3 2 5 (Row 1: 3,3 | Row 2: 2,5)")

        self.param_layout.addRow("Shift Value:", self.shift_input)
        self.param_layout.addRow("Secret Key / Keyword:", self.key_input)
        self.param_layout.addRow(
            "2x2 Matrix (4 space-separated ints):", self.matrix_input)

        self.param_box.setLayout(self.param_layout)
        main_layout.addWidget(self.param_box)

        # Encrypted Text Input Box
        main_layout.addWidget(QLabel("3. Encrypted Ciphertext Input:"))
        self.ciphertext_input = QTextEdit()
        self.ciphertext_input.setPlaceholderText(
            "Paste your ciphertext here...")
        main_layout.addWidget(self.ciphertext_input)

        # Action Trigger Button
        self.decrypt_btn = QPushButton("Execute Decryption")
        self.decrypt_btn.clicked.connect(self.handle_decryption)
        main_layout.addWidget(self.decrypt_btn)

        # Decrypted Output Box
        main_layout.addWidget(QLabel("Decrypted Plaintext Output:"))
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        main_layout.addWidget(self.result_output)

        self.setLayout(main_layout)
        self.update_param_visibility()

    def _set_row_visible(self, widget, visible: bool):
        """Helper to set visibility for a field and its attached form label."""
        label = self.param_layout.labelForField(widget)
        if label:
            label.setVisible(visible)
        widget.setVisible(visible)

    def update_param_visibility(self):
        """Show/Hide inputs dynamically depending on selected algorithm."""
        cipher = self.cipher_dropdown.currentText()

        # Hide all inputs first
        self._set_row_visible(self.shift_input, False)
        self._set_row_visible(self.key_input, False)
        self._set_row_visible(self.matrix_input, False)
        self.param_box.setVisible(True)

        if cipher == "Caesar":
            self._set_row_visible(self.shift_input, True)
        elif cipher in ["Vigenère", "Playfair"]:
            self._set_row_visible(self.key_input, True)
        elif cipher == "Hill (2x2 Matrix)":
            self._set_row_visible(self.matrix_input, True)
        else:
            self.param_box.setVisible(False)

    def handle_decryption(self):
        cipher = self.cipher_dropdown.currentText()
        text = self.ciphertext_input.toPlainText().strip()

        if not text:
            QMessageBox.warning(self, "Missing Input",
                                "Please enter ciphertext to decrypt.")
            return

        try:
            if cipher == "Caesar":
                try:
                    shift = int(self.shift_input.text() or 3)
                except ValueError:
                    QMessageBox.critical(
                        self, "Invalid Shift", "Shift value must be an integer.")
                    return
                res = Decrypt.caesar_decrypt(text, shift)
            elif cipher == "ROT13":
                res = Decrypt.rot13_decrypt(text)
            elif cipher == "Vigenère":
                key = self.key_input.text() or "KEY"
                res = Decrypt.vigenere_decrypt(text, key)
            elif cipher == "Atbash":
                res = Decrypt.atbash_decrypt(text)
            elif cipher == "Playfair":
                key = self.key_input.text() or "bestkey"
                res = Decrypt.playfair_decrypt(text, key)
            elif cipher == "Hill (2x2 Matrix)":
                try:
                    matrix_nums = list(
                        map(int, self.matrix_input.text().split()))
                    if len(matrix_nums) != 4:
                        res = "Error: Please enter exactly 4 integers separated by spaces."
                    else:
                        matrix = np.array(matrix_nums).reshape((2, 2))
                        res = Decrypt.hill_decrypt(text, matrix)
                except ValueError:
                    res = "Error: Matrix inputs must be valid integers."
            elif cipher == "AES (ECB)":
                res = Decrypt.aes_decrypt(text)
            else:
                res = "Unsupported Algorithm Selection"

            self.result_output.setText(res)
        except Exception as e:
            self.result_output.setText(f"Decryption Failure: {str(e)}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DecryptionUI()
    window.show()
    sys.exit(app.exec())
