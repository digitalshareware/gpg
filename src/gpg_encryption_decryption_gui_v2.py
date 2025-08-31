import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import gnupg
import pyperclip
import os

# Initialize GPG
gpg = gnupg.GPG()

class GPGApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GPG Symmetric Encryption/Decryption")
        self.root.geometry("800x600")

        # Notebook tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        # Encrypt and Decrypt Tabs
        self.encrypt_tab = ttk.Frame(self.notebook)
        self.decrypt_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_tab, text="Encrypt")
        self.notebook.add(self.decrypt_tab, text="Decrypt")

        self.build_encrypt_tab()
        self.build_decrypt_tab()

    def build_encrypt_tab(self):
        # Passphrase
        tk.Label(self.encrypt_tab, text="Passphrase:").pack(anchor="w", padx=10, pady=5)
        self.encrypt_passphrase_var = tk.StringVar()
        self.encrypt_passphrase_entry = tk.Entry(
            self.encrypt_tab, textvariable=self.encrypt_passphrase_var, show="*", width=40
        )
        self.encrypt_passphrase_entry.pack(padx=10, pady=5)

        # Show/hide password toggle
        self.show_pass_encrypt = tk.BooleanVar()
        tk.Checkbutton(
            self.encrypt_tab,
            text="Show Passphrase",
            variable=self.show_pass_encrypt,
            command=lambda: self.toggle_password(self.encrypt_passphrase_entry, self.show_pass_encrypt),
        ).pack(anchor="w", padx=10)

        # Plain text
        tk.Label(self.encrypt_tab, text="Plain Text to Encrypt:").pack(anchor="w", padx=10, pady=5)
        self.encrypt_input = tk.Text(self.encrypt_tab, height=10)
        self.encrypt_input.pack(fill="x", padx=10, pady=5)

        # Encrypt Button
        tk.Button(self.encrypt_tab, text="Encrypt Text", command=self.encrypt_text).pack(pady=5)

        # Encrypted output
        tk.Label(self.encrypt_tab, text="Encrypted Text:").pack(anchor="w", padx=10, pady=5)
        self.encrypt_output = tk.Text(self.encrypt_tab, height=10)
        self.encrypt_output.pack(fill="x", padx=10, pady=5)

        tk.Button(self.encrypt_tab, text="Copy Encrypted Text", command=lambda: self.copy_to_clipboard(self.encrypt_output)).pack(pady=5)

        # File encryption
        tk.Button(self.encrypt_tab, text="Encrypt File", command=self.encrypt_file).pack(pady=10)

        # Notes
        tk.Label(self.encrypt_tab, text="Note: Encryption uses symmetric GPG with your passphrase.\nSave the passphrase securely!", fg="blue").pack(pady=10)

    def build_decrypt_tab(self):
        # Passphrase
        tk.Label(self.decrypt_tab, text="Passphrase:").pack(anchor="w", padx=10, pady=5)
        self.decrypt_passphrase_var = tk.StringVar()
        self.decrypt_passphrase_entry = tk.Entry(
            self.decrypt_tab, textvariable=self.decrypt_passphrase_var, show="*", width=40
        )
        self.decrypt_passphrase_entry.pack(padx=10, pady=5)

        # Show/hide password toggle
        self.show_pass_decrypt = tk.BooleanVar()
        tk.Checkbutton(
            self.decrypt_tab,
            text="Show Passphrase",
            variable=self.show_pass_decrypt,
            command=lambda: self.toggle_password(self.decrypt_passphrase_entry, self.show_pass_decrypt),
        ).pack(anchor="w", padx=10)

        # Encrypted text
        tk.Label(self.decrypt_tab, text="Encrypted Text to Decrypt:").pack(anchor="w", padx=10, pady=5)
        self.decrypt_input = tk.Text(self.decrypt_tab, height=10)
        self.decrypt_input.pack(fill="x", padx=10, pady=5)

        # Decrypt Button
        tk.Button(self.decrypt_tab, text="Decrypt Text", command=self.decrypt_text).pack(pady=5)

        # Decrypted output
        tk.Label(self.decrypt_tab, text="Decrypted Text:").pack(anchor="w", padx=10, pady=5)
        self.decrypt_output = tk.Text(self.decrypt_tab, height=10)
        self.decrypt_output.pack(fill="x", padx=10, pady=5)

        tk.Button(self.decrypt_tab, text="Copy Decrypted Text", command=lambda: self.copy_to_clipboard(self.decrypt_output)).pack(pady=5)

        # File decryption
        tk.Button(self.decrypt_tab, text="Decrypt File", command=self.decrypt_file).pack(pady=10)

        # Notes
        tk.Label(self.decrypt_tab, text="Note: Decryption requires the same passphrase used for encryption.", fg="blue").pack(pady=10)

    def toggle_password(self, entry, var):
        if var.get():
            entry.config(show="")
        else:
            entry.config(show="*")

    def encrypt_text(self):
        passphrase = self.encrypt_passphrase_var.get()
        text = self.encrypt_input.get("1.0", tk.END).strip()
        if not passphrase or not text:
            messagebox.showerror("Error", "Passphrase and text are required")
            return
        encrypted_data = gpg.encrypt(text, None, symmetric='AES256', passphrase=passphrase)
        if encrypted_data.ok:
            self.encrypt_output.delete("1.0", tk.END)
            self.encrypt_output.insert(tk.END, str(encrypted_data))
        else:
            messagebox.showerror("Error", "Encryption failed")

    def decrypt_text(self):
        passphrase = self.decrypt_passphrase_var.get()
        encrypted_text = self.decrypt_input.get("1.0", tk.END).strip()
        if not passphrase or not encrypted_text:
            messagebox.showerror("Error", "Passphrase and encrypted text are required")
            return
        decrypted_data = gpg.decrypt(encrypted_text, passphrase=passphrase)
        if decrypted_data.ok:
            self.decrypt_output.delete("1.0", tk.END)
            self.decrypt_output.insert(tk.END, str(decrypted_data))
        else:
            messagebox.showerror("Error", "Decryption failed")

    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".gpg", filetypes=[("GPG files", "*.gpg")])
        if not save_path:
            return
        passphrase = self.encrypt_passphrase_var.get()
        with open(file_path, "rb") as f:
            status = gpg.encrypt_file(f, None, symmetric="AES256", passphrase=passphrase, output=save_path)
        if status.ok:
            messagebox.showinfo("Success", f"File encrypted and saved to {save_path}")
        else:
            messagebox.showerror("Error", "File encryption failed")

    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Select Encrypted File", filetypes=[("GPG files", "*.gpg")])
        if not file_path:
            return
        save_path = filedialog.asksaveasfilename(title="Save Decrypted File As")
        if not save_path:
            return
        passphrase = self.decrypt_passphrase_var.get()
        with open(file_path, "rb") as f:
            status = gpg.decrypt_file(f, passphrase=passphrase, output=save_path)
        if status.ok:
            messagebox.showinfo("Success", f"File decrypted and saved to {save_path}")
        else:
            messagebox.showerror("Error", "File decryption failed")

    def copy_to_clipboard(self, text_widget):
        data = text_widget.get("1.0", tk.END).strip()
        if data:
            pyperclip.copy(data)
            messagebox.showinfo("Copied", "Text copied to clipboard")

if __name__ == "__main__":
    root = tk.Tk()
    app = GPGApp(root)
    root.mainloop()
