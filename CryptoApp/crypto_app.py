import sys
import codecs
import base64
import string
import numpy as np

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QComboBox, QPushButton, QLineEdit, QFormLayout, QGroupBox,
    QTabWidget, QMessageBox
)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt


# =====================================================================
# CRYPTOGRAPHIC ENGINE (ENCRYPT & DECRYPT)
# =====================================================================
class CryptoEngine:
    # --- ROT13 ---
    @staticmethod
    def rot13_transform(text: str) -> str:
        return codecs.encode(text, "rot13")

    # --- AES (ECB) ---
    @staticmethod
    def aes_encrypt(plaintext: str) -> str:
        # Fixed 256-bit key for demonstration purposes
        key = (
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        )
        plaintext_bytes = plaintext.encode("utf-8")
        cipher = Cipher(algorithms.AES(key), modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(128).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode("utf-8")

    @staticmethod
    def aes_decrypt(encoded_ciphertext: str) -> str:
        key = (
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
        )
        try:
            ciphertext = base64.b64decode(encoded_ciphertext)
            cipher = Cipher(algorithms.AES(key), modes.ECB(),
                            backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_data) + unpadder.finalize()
            return plaintext.decode("utf-8")
        except Exception as e:
            return f"AES Error: {str(e)}"

    # --- CAESAR CIPHER ---
    @staticmethod
    def caesar_transform(text: str, shift: int, decrypt: bool = False) -> str:
        shift_val = -shift if decrypt else shift
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                result.append(chr((ord(ch) - base + shift_val) % 26 + base))
            else:
                result.append(ch)
        return "".join(result)

    # --- ATBASH CIPHER ---
    @staticmethod
    def atbash_transform(text: str) -> str:
        result = []
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                limit = ord('Z') if ch.isupper() else ord('z')
                result.append(chr(limit - (ord(ch) - base)))
            else:
                result.append(ch)
        return "".join(result)

    # --- VIGENÈRE CIPHER ---
    @staticmethod
    def vigenere_transform(text: str, key: str, decrypt: bool = False) -> str:
        key_clean = "".join([k for k in key if k.isalpha()]).lower()
        if not key_clean:
            return text

        result = []
        ki = 0
        for ch in text:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                k = ord(key_clean[ki % len(key_clean)]) - ord('a')
                shift_val = -k if decrypt else k
                result.append(chr((ord(ch) - base + shift_val) % 26 + base))
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    # --- PLAYFAIR CIPHER ---
    @staticmethod
    def playfair_transform(text: str, key_text: str, decrypt: bool = False) -> str:
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
                          for c in text if c.isalpha()]).replace("j", "i")
        if not cleaned:
            return ""

        if not decrypt:
            new_text = ""
            i = 0
            while i < len(cleaned):
                char1 = cleaned[i]
                if i + 1 < len(cleaned) and char1 == cleaned[i + 1]:
                    new_text += char1 + "x"
                    i += 1
                elif i + 1 < len(cleaned):
                    new_text += char1 + cleaned[i + 1]
                    i += 2
                else:
                    new_text += char1
                    i += 1
            if len(new_text) % 2 != 0:
                new_text += "x"
            cleaned = new_text

        pairs = [cleaned[i:i+2] for i in range(0, len(cleaned), 2)]
        out_list = []
        step = -1 if decrypt else 1

        for pair in pairs:
            if len(pair) < 2:
                continue
            r1, c1 = search_element(matrix, pair[0])
            r2, c2 = search_element(matrix, pair[1])

            if r1 == r2:
                p1 = matrix[r1][(c1 + step) % 5]
                p2 = matrix[r2][(c2 + step) % 5]
            elif c1 == c2:
                p1 = matrix[(r1 + step) % 5][c1]
                p2 = matrix[(r2 + step) % 5][c2]
            else:
                p1 = matrix[r1][c2]
                p2 = matrix[r2][c1]

            out_list.append(p1 + p2)

        return "".join(out_list)

    # --- HILL CIPHER (2x2) ---
    @staticmethod
    def hill_transform(text: str, key_matrix, decrypt: bool = False) -> str:
        key_matrix = np.array(key_matrix, dtype=int)

        if decrypt:
            # Determinant calculation mod 26 using pure integer arithmetic
            det = int(key_matrix[0, 0] * key_matrix[1, 1] -
                      key_matrix[0, 1] * key_matrix[1, 0]) % 26
            inv_det = -1
            for i in range(1, 26):
                if (det * i) % 26 == 1:
                    inv_det = i
                    break
            if inv_det == -1:
                return "Error: Key matrix is not invertible mod 26 (gcd(det, 26) != 1)."

            # Adjugate matrix
            adj = np.array([[key_matrix[1, 1], -key_matrix[0, 1]],
                            [-key_matrix[1, 0], key_matrix[0, 0]]])
            matrix_op = (inv_det * adj) % 26
        else:
            matrix_op = key_matrix % 26

        filtered = "".join([c for c in text.lower() if c.isalpha()])
        if not filtered:
            return ""

        if len(filtered) % 2 != 0:
            filtered += "x"

        result = []
        for i in range(0, len(filtered), 2):
            block = np.array(
                [[ord(filtered[i]) - 97], [ord(filtered[i+1]) - 97]])
            prod = np.dot(matrix_op, block) % 26
            result.append(chr(int(prod[0, 0]) + 97))
            result.append(chr(int(prod[1, 0]) + 97))

        return "".join(result)


# =====================================================================
# UNIFIED CRYPTO WORKSTATION GUI
# =====================================================================
class CryptoTabWidget(QWidget):
    """Reusable panel for both Encryption and Decryption tabs."""

    def __init__(self, mode="encrypt"):
        super().__init__()
        self.mode = mode  # "encrypt" or "decrypt"
        self.initUI()

    def initUI(self):
        main_layout = QVBoxLayout()

        # Cipher Selection
        cipher_box = QGroupBox(f"1. Select Algorithm ({self.mode.upper()})")
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
        self.param_box = QGroupBox("2. Cipher Parameters")
        self.param_layout = QFormLayout()

        self.shift_input = QLineEdit("3")
        self.key_input = QLineEdit("KEY")
        self.matrix_input = QLineEdit("3 3 2 5")
        self.matrix_input.setPlaceholderText("e.g. 3 3 2 5")

        self.param_layout.addRow("Shift Value:", self.shift_input)
        self.param_layout.addRow("Secret Key / Word:", self.key_input)
        self.param_layout.addRow(
            "2x2 Matrix (4 space-separated ints):", self.matrix_input)

        self.param_box.setLayout(self.param_layout)
        main_layout.addWidget(self.param_box)

        # Input Text
        input_label = "Input Plaintext:" if self.mode == "encrypt" else "Input Ciphertext:"
        main_layout.addWidget(QLabel(f"3. {input_label}"))
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText(
            f"Enter text to {self.mode} here...")
        main_layout.addWidget(self.text_input)

        # Action Button
        btn_text = "🔒 Encrypt Message" if self.mode == "encrypt" else "🔓 Decrypt Message"
        self.action_btn = QPushButton(btn_text)
        if self.mode == "decrypt":
            self.action_btn.setStyleSheet(
                "background-color: #f38ba8; color: #11111b;")
        self.action_btn.clicked.connect(self.process_action)
        main_layout.addWidget(self.action_btn)

        # Output Text
        output_label = "Encrypted Output:" if self.mode == "encrypt" else "Decrypted Output:"
        main_layout.addWidget(QLabel(output_label))
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
        cipher = self.cipher_dropdown.currentText()

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

    def process_action(self):
        cipher = self.cipher_dropdown.currentText()
        text = self.text_input.toPlainText().strip()
        is_decrypt = (self.mode == "decrypt")

        if not text:
            QMessageBox.warning(self, "Missing Input",
                                f"Please enter text to {self.mode}.")
            return

        try:
            if cipher == "Caesar":
                shift = int(self.shift_input.text() or 3)
                res = CryptoEngine.caesar_transform(
                    text, shift, decrypt=is_decrypt)
            elif cipher == "ROT13":
                res = CryptoEngine.rot13_transform(text)
            elif cipher == "Vigenère":
                key = self.key_input.text() or "KEY"
                res = CryptoEngine.vigenere_transform(
                    text, key, decrypt=is_decrypt)
            elif cipher == "Atbash":
                res = CryptoEngine.atbash_transform(text)
            elif cipher == "Playfair":
                key = self.key_input.text() or "bestkey"
                res = CryptoEngine.playfair_transform(
                    text, key, decrypt=is_decrypt)
            elif cipher == "Hill (2x2 Matrix)":
                matrix_nums = list(map(int, self.matrix_input.text().split()))
                if len(matrix_nums) != 4:
                    res = "Error: Please enter 4 space-separated integers."
                else:
                    matrix = np.array(matrix_nums).reshape((2, 2))
                    res = CryptoEngine.hill_transform(
                        text, matrix, decrypt=is_decrypt)
            elif cipher == "AES (ECB)":
                res = CryptoEngine.aes_decrypt(
                    text) if is_decrypt else CryptoEngine.aes_encrypt(text)
            else:
                res = "Unsupported Selection"

            self.result_output.setText(res)
        except Exception as e:
            self.result_output.setText(f"Processing Error: {str(e)}")


class UnifiedCryptoApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("Unified Cryptography Suite")
        self.resize(780, 720)
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e2e;
                color: #cdd6f4;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QTabWidget::pane {
                border: 1px solid #45475a;
                border-radius: 8px;
                background-color: #1e1e2e;
            }
            QTabBar::tab {
                background: #313244;
                color: #cdd6f4;
                padding: 12px 24px;
                font-weight: bold;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background: #89b4fa;
                color: #11111b;
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
                opacity: 0.9;
            }
        """)

        layout = QVBoxLayout()

        header = QLabel("🛡️ Cryptographic Operations Center")
        header.setFont(QFont("Segoe UI", 18, QFont.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(CryptoTabWidget(mode="encrypt"), "🔒 Encryption Mode")
        self.tabs.addTab(CryptoTabWidget(mode="decrypt"), "🔓 Decryption Mode")

        layout.addWidget(self.tabs)
        self.setLayout(layout)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = UnifiedCryptoApp()
    window.show()
    sys.exit(app.exec_())
