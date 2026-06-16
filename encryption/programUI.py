import tkinter as tk
from decryption_security import Decrypt
from encryption_security import Encrypt
from tkinter import messagebox as msb


# First Encryption Handled
class UI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Encryption/Decryption Software")
        self.encrypt = Encrypt
        self.decrypt = Decrypt

        # UI Setup
        tk.Label(self.root, text="Encryption", font=("Arial", 20, "bold")).pack(pady=20)
        self.container = tk.Frame(self.root)
        self.container.pack(padx=20, pady=20)

        self.setup_ui()

    def setup_ui(self):
        # Create rows dynamically
        self.create_encryption_row(0, "ROT13", self.perform_rot13)
        self.create_encryption_row(1, "AES", self.perform_aes)
        self.create_encryption_row(2, "Rail Fence Cipher", self.perform_railFenceCipher)
        self.create_encryption_row(2, "Playfair", self.perform_playfair)

    def create_encryption_row(self, row_index, label_text, command):
        """Creates a row with input, button, and result label below them."""
        # Using a sub-frame for each row ensures the result is always below the inputs
        row_frame = tk.Frame(self.container)
        row_frame.grid(row=row_index * 2, column=0, pady=10, sticky="w")

        tk.Label(row_frame, text=label_text, width=15, anchor="w").grid(row=0, column=0)
        entry = tk.Entry(row_frame, width=30)
        entry.grid(row=0, column=1, padx=5)

        btn = tk.Button(row_frame, text="Encrypt", command=lambda: command(entry))
        btn.grid(row=0, column=2, padx=5)

        # Flat, borderless Entry widget dressed up to look like a label
        output_field = tk.Label(
            self.container,
            text="",
            font=("Arial", 10, "bold"),
            fg="green",
            bd=0,
            bg=self.root.cget("bg"),
            width=50,
        )
        output_field.grid(
            row=(row_index * 2) + 1,
            column=0,
            columnspan=3,
            pady=(0, 10),
            sticky="w",
        )

        # FIXED: Removed the call to self.copy_to_clipboard.
        # This clean inline lambda copies the exact text string to your OS clipboard on left-click.
        output_field.bind(
            "<Button-1>",
            lambda event: self.handle_inline_copy(output_field),
        )

        entry.output_field = output_field

    def handle_inline_copy(self, widget):
        """Helper method to execute clean safety loops on click events."""
        text_to_copy = widget.cget("text")

        # Only trigger copy actions if there is an active result printed
        if text_to_copy.startswith("Result: "):
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(text_to_copy.replace("Result: ", ""))
                # Fires the popup successfully only AFTER data is appended to clipboard
                msb.showinfo("Success", "Copied to clipboard!")
            except Exception:
                msb.showerror("Error", "Could not copy text.")

    def perform_rot13(self, entry_widget):
        text = entry_widget.get()
        result = self.encrypt.rot13_encrypt(text)
        entry_widget.output_field.config(text=f"Result: {result}")

    def perform_aes(self, entry_widget):
        text = entry_widget.get()
        result = self.encrypt.aes_encrypt(text)
        entry_widget.output_field.config(text=f"Result: {result}")

    def perform_railFenceCipher(self, entry_widget):
        text = entry_widget.get()
        result = self.encrypt.encryptRailFence(text)
        entry_widget.output_field.config(text=f"Result: {result}")

    def perform_playfair(self, entry_widget):
        text = entry_widget.get()
        result = self.encrypt.playfair_encrypt(text)
        entry_widget.output_field.config(text=f"Result: {result}")

    def main(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = UI()
    app.main()
