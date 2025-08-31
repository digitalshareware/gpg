import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import gnupg
import os
import secrets
import string

# Initialize GPG
gpg = gnupg.GPG()

# Password strength checker
def check_strength(passphrase):
    length = len(passphrase)
    has_upper = any(c.isupper() for c in passphrase)
    has_lower = any(c.islower() for c in passphrase)
    has_digit = any(c.isdigit() for c in passphrase)
    has_symbol = any(c in string.punctuation for c in passphrase)

    score = sum([has_upper, has_lower, has_digit, has_symbol]) + (length >= 12)
    if score <= 2:
        return "Weak", "red"
    elif score == 3:
        return "Medium", "orange"
    else:
        return "Strong", "green"

# Suggest secure passphrase
def suggest_passphrase():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(16))

# Update strength label dynamically
def update_strength(event, label, entry):
    pwd = entry.get()
    status, color = check_strength(pwd)
    label.config(text=f"Strength: {status}", fg=color)

# Encryption function
def encrypt_text(passphrase, plaintext, output_widget):
    if not passphrase or not plaintext:
        messagebox.showwarning("Input Error", "Both passphrase and text are required!")
        return
    encrypted_data = gpg.encrypt(plaintext, recipients=None, symmetric="AES256", passphrase=passphrase)
    if encrypted_data.ok:
        output_widget.delete("1.0", tk.END)
        output_widget.insert(tk.END, str(encrypted_data))
    else:
        messagebox.showerror("Encryption Error", encrypted_data.status)

# Decryption function
def decrypt_text(passphrase, ciphertext, output_widget):
    if not passphrase or not ciphertext:
        messagebox.showwarning("Input Error", "Both passphrase and ciphertext are required!")
        return
    decrypted_data = gpg.decrypt(ciphertext, passphrase=passphrase)
    if decrypted_data.ok:
        output_widget.delete("1.0", tk.END)
        output_widget.insert(tk.END, str(decrypted_data))
    else:
        messagebox.showerror("Decryption Error", decrypted_data.status)

# File Encryption
def encrypt_file(passphrase):
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    output_file = file_path + ".gpg"
    with open(file_path, "rb") as f:
        status = gpg.encrypt_file(f, recipients=None, symmetric="AES256",
                                  passphrase=passphrase, output=output_file)
    if status.ok:
        messagebox.showinfo("Success", f"File encrypted → {output_file}")
    else:
        messagebox.showerror("Error", status.status)

# File Decryption
def decrypt_file(passphrase):
    file_path = filedialog.askopenfilename(filetypes=[("GPG files", "*.gpg")])
    if not file_path:
        return
    output_file = os.path.splitext(file_path)[0] + ".dec"
    with open(file_path, "rb") as f:
        status = gpg.decrypt_file(f, passphrase=passphrase, output=output_file)
    if status.ok:
        messagebox.showinfo("Success", f"File decrypted → {output_file}")
    else:
        messagebox.showerror("Error", status.status)

# Copy to clipboard
def copy_to_clipboard(root, widget):
    root.clipboard_clear()
    root.clipboard_append(widget.get("1.0", tk.END).strip())
    root.update()
    messagebox.showinfo("Copied", "Text copied to clipboard!")

# ------------------- GUI -------------------
root = tk.Tk()
root.title("🔐 GPG Encryption/Decryption Tool")
root.geometry("700x550")

tab_control = ttk.Notebook(root)

# ---------------- Encrypt Tab ----------------
encrypt_tab = ttk.Frame(tab_control)
tab_control.add(encrypt_tab, text="Encrypt")

ttk.Label(encrypt_tab, text="Enter Passphrase:").pack(pady=5)
enc_pass_entry = ttk.Entry(encrypt_tab, show="*", width=40)
enc_pass_entry.pack(pady=5)

strength_label_enc = tk.Label(encrypt_tab, text="Strength: ", fg="black")
strength_label_enc.pack()
enc_pass_entry.bind("<KeyRelease>", lambda e: update_strength(e, strength_label_enc, enc_pass_entry))

ttk.Button(encrypt_tab, text="Suggest Strong Passphrase",
           command=lambda: enc_pass_entry.insert(0, suggest_passphrase())).pack(pady=5)

ttk.Label(encrypt_tab, text="Enter Plain Text:").pack(pady=5)
enc_text_input = tk.Text(encrypt_tab, height=6, width=70)
enc_text_input.pack()

ttk.Button(encrypt_tab, text="Encrypt",
           command=lambda: encrypt_text(enc_pass_entry.get(), enc_text_input.get("1.0", tk.END), enc_text_output)).pack(pady=10)

ttk.Label(encrypt_tab, text="Encrypted Text:").pack(pady=5)
enc_text_output = tk.Text(encrypt_tab, height=6, width=70)
enc_text_output.pack()

ttk.Button(encrypt_tab, text="Copy Encrypted Text", command=lambda: copy_to_clipboard(root, enc_text_output)).pack(pady=5)
ttk.Button(encrypt_tab, text="Encrypt File", command=lambda: encrypt_file(enc_pass_entry.get())).pack(pady=10)

tk.Label(encrypt_tab, text="Note: Use a strong passphrase. Encrypted files end with .gpg", fg="blue").pack(pady=5)

# ---------------- Decrypt Tab ----------------
decrypt_tab = ttk.Frame(tab_control)
tab_control.add(decrypt_tab, text="Decrypt")

ttk.Label(decrypt_tab, text="Enter Passphrase:").pack(pady=5)
dec_pass_entry = ttk.Entry(decrypt_tab, show="*", width=40)
dec_pass_entry.pack(pady=5)

strength_label_dec = tk.Label(decrypt_tab, text="Strength: ", fg="black")
strength_label_dec.pack()
dec_pass_entry.bind("<KeyRelease>", lambda e: update_strength(e, strength_label_dec, dec_pass_entry))

ttk.Label(decrypt_tab, text="Enter Encrypted Text:").pack(pady=5)
dec_text_input = tk.Text(decrypt_tab, height=6, width=70)
dec_text_input.pack()

ttk.Button(decrypt_tab, text="Decrypt",
           command=lambda: decrypt_text(dec_pass_entry.get(), dec_text_input.get("1.0", tk.END), dec_text_output)).pack(pady=10)

ttk.Label(decrypt_tab, text="Decrypted Text:").pack(pady=5)
dec_text_output = tk.Text(decrypt_tab, height=6, width=70)
dec_text_output.pack()

ttk.Button(decrypt_tab, text="Copy Decrypted Text", command=lambda: copy_to_clipboard(root, dec_text_output)).pack(pady=5)
ttk.Button(decrypt_tab, text="Decrypt File", command=lambda: decrypt_file(dec_pass_entry.get())).pack(pady=10)

tk.Label(decrypt_tab, text="Note: Ensure you enter the same passphrase used during encryption.", fg="blue").pack(pady=5)

tab_control.pack(expand=1, fill="both")

root.mainloop()
