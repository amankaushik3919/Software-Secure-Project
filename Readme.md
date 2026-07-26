# 🛡️ CryptoApp: Cryptography Suite

A Python-based desktop workstation for exploring, testing, and visualizing classic and modern cryptographic algorithms. Featuring both PyQt5 and Tkinter graphical interfaces, **CryptoApp** provides an interactive environment to encrypt, decrypt, and learn about symmetric, substitution, polyalphabetic, and transposition ciphers.

---

## 🗝️ Supported Algorithms

| Category | Algorithm | Description |
| :--- | :--- | :--- |
| **Modern Symmetric** | **AES (ECB)** | Advanced Encryption Standard using block cipher architecture. |
| **Substitution** | **Caesar Cipher** | Classic shift cipher operating on fixed character offsets. |
| | **ROT13** | Fixed-shift variant of the Caesar cipher ($N = 13$). |
| | **Atbash Cipher** | Monoalphabetic cipher mapping $A \leftrightarrow Z$, $B \leftrightarrow Y$. |
| | **Monoalphabetic** | Keyed substitution cipher mapping letters to a randomized alphabet. |
| | **Affine Cipher** | Mathematical cipher using modular arithmetic ($E(x) = (ax + b) \pmod{26}$). |
| | **Playfair Cipher** | Digraph substitution operating on letter pairs using a $5 \times 5$ matrix. |
| **Polyalphabetic** | **Vigenère Cipher** | Cipher utilizing a repeating keyword for character shifts. |
| **Polygraphic** | **Hill Cipher** | Linear algebra cipher performing matrix multiplication mod 26. |
| **Transposition** | **Rail Fence Cipher** | Geometric cipher arranging text in a zig-zag pattern across rails. |

---

## 📁 Project Structure

```text
software_project_updated/
├── CryptoApp/
│   ├── crypto_app.py           # Unified PyQt5 Workstation GUI
│   ├── encryption_programUI.py # Tkinter UI for Encryption
│   ├── encryption_security.py  # Backend logic for Encryption algorithms
│   ├── decryption_programUI.py # Tkinter UI for Decryption
│   └── decryption_security.py  # Backend logic for Decryption algorithms
├── requirements.txt            # Project dependencies
└── README.md                   # Project documentation