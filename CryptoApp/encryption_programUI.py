import tkinter as tk
from tkinter import ttk
from tkinter import messagebox as msb
from CryptoApp.encryption_security import Encrypt


class UI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Encryption Software Suite")
        self.root.geometry("560x650")
        self.root.minsize(500, 400)

        # Instantiate backend logic
        self.encrypt = Encrypt()

        # Title Header
        tk.Label(
            self.root,
            text="Cryptographic Operations Center",
            font=("Arial", 16, "bold")
        ).pack(pady=(15, 5))

        # Setup Scrollable Canvas View
        self.canvas = tk.Canvas(self.root, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(
            self.root, orient="vertical", command=self.canvas.yview)

        self.container = tk.Frame(self.canvas)
        self.container.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.container, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both",
                         expand=True, padx=(20, 0), pady=10)
        self.scrollbar.pack(side="right", fill="y", padx=(0, 10), pady=10)

        # Bind mouse scroll wheel to canvas
        self.root.bind_all("<MouseWheel>", self._on_mousewheel)

        self.setup_ui()

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def setup_ui(self):
        rows = [
            ("ROT13", self.perform_rot13),
            ("AES", self.perform_aes),
            ("Rail Fence Cipher", self.perform_railFenceCipher),
            ("Playfair", self.perform_playfair),
            ("Affine Cipher", self.perform_affineCipher),
            ("Vigenère", self.perform_vigenere),
            ("Caesar", self.perform_caesar),
            ("Hill Cipher", self.perform_hill),
            ("Monoalphabetic", self.perform_monoalphabetic),
            ("Atbash", self.perform_atbash),
        ]

        for index, (label, command) in enumerate(rows):
            self.create_encryption_row(index, label, command)

    def create_encryption_row(self, row_index, label_text, command):
        """Creates an aligned row with label, entry field, action button, and centered copyable output."""
        row_frame = tk.Frame(self.container)
        row_frame.grid(row=row_index * 2, column=0, pady=4, sticky="ew")

        tk.Label(row_frame, text=label_text, width=16, anchor="w", font=("Arial", 10, "bold")).grid(row=0, column=0)
        entry = tk.Entry(row_frame, width=32)
        entry.grid(row=0, column=1, padx=8)

        btn = tk.Button(
            row_frame,
            text="Encrypt",
            width=10,
            command=lambda: self.execute_handler(entry, output_field, command),
        )
        btn.grid(row=0, column=2, padx=4)

        # Output label centered right below the controls
        output_field = tk.Label(
            self.container,
            text="",
            font=("Arial", 9, "bold"),
            fg="#2e7d32",
            bd=0,
            bg=self.root.cget("bg"),
            anchor="center",
            justify="center",
            cursor="hand2",
        )

        output_field.grid(
            row=(row_index * 2) + 1,
            column=0,
            columnspan=3,
            pady=(2, 8),
            sticky="ew",
        )

        output_field.bind(
            "<Button-1>", lambda event: self.handle_inline_copy(output_field)
        )

    def execute_handler(self, entry_widget, output_label, command_func):
        val = entry_widget.get().strip()
        if not val:
            msb.showwarning("Missing Input",
                            "Please enter text before encrypting.")
            return
        command_func(val, output_label)

    def handle_inline_copy(self, widget):
        text_to_copy = widget.cget("text")
        if text_to_copy.startswith("Result: "):
            try:
                clean_text = text_to_copy.replace("Result: ", "")
                self.root.clipboard_clear()
                self.root.clipboard_append(clean_text)

                # Visual feedback on click
                original_color = widget.cget("fg")
                widget.config(fg="#1565c0")
                self.root.after(300, lambda: widget.config(fg=original_color))

                msb.showinfo("Copied", "Result copied to clipboard!")
            except Exception:
                msb.showerror("Error", "Could not copy text.")

    # --- Encryption Handlers ---
    def perform_rot13(self, text, output_label):
        output_label.config(text=f"Result: {self.encrypt.rot13_encrypt(text)}")

    def perform_aes(self, text, output_label):
        output_label.config(text=f"Result: {self.encrypt.aes_encrypt(text)}")

    def perform_railFenceCipher(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.encryptRailFence(text)}")

    def perform_playfair(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.playfair_encrypt(text)}")

    def perform_affineCipher(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.affine_encrypt(text)}")

    def perform_vigenere(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.vigenere_encrypt(text, 'LEMON')}")

    def perform_caesar(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.caesar_encrypt(text, shift=3)}")

    def perform_hill(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.hill_encrypt(text, key_matrix=[[3, 3], [2, 5]])}")

    def perform_monoalphabetic(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.monoalphabetic_encrypt(text)}")

    def perform_atbash(self, text, output_label):
        output_label.config(
            text=f"Result: {self.encrypt.atbash_encrypt(text)}")

    def main(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = UI()
    app.main()
