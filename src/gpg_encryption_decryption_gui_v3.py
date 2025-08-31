#!/usr/bin/env python3
"""
gpg_symm_gui.py
GPG symmetric (passphrase) encrypt/decrypt GUI with file support (no themes).
Requirements: python-gnupg and system gpg.
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import gnupg

# initialize GPG (uses default gnupghome, e.g. ~/.gnupg)
gpg = gnupg.GPG()

# def select_all(event):
#         widget = event.widget
#         try:
#             if isinstance(widget, tk.Entry):
#                 widget.select_range(0, tk.END)
#                 widget.icursor(tk.END)
#             elif isinstance(widget, tk.Text):
#                 widget.tag_add("sel", "1.0", "end-1c")
#             return "break"
#         except Exception as e:
#             print("Select all error:", e)

# --- Ctrl+A (Select All) support for Entry / TEntry / Text ---
def select_all(event):
    widget = event.widget
    try:
        # ensure widget has focus so selection is visible
        widget.focus_set()
        cls = widget.winfo_class()

        # Entry-like widgets (ttk.Entry is class "TEntry")
        if cls in ("Entry", "TEntry"):
            # select whole text in entry
            # use '0' and 'end' (string indices) for maximum compatibility
            try:
                widget.selection_range(0, 'end')
            except Exception:
                # fallback
                widget.selection_range(0, tk.END)
            try:
                widget.icursor(tk.END)
            except Exception:
                pass
            return "break"

        # Text widgets
        if cls == "Text":
            # select everything in the Text widget
            widget.tag_add("sel", "1.0", "end-1c")
            return "break"

    except Exception as e:
        # harmless debug print if something odd happens
        print("select_all error:", e)
        return None

class GPGApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GPG Symmetric Encrypt / Decrypt")
        self.root.geometry("820x620")

        # Bind for both Entry types and Text
        self.root.bind_class("Entry", "<Control-a>", select_all)
        self.root.bind_class("Entry", "<Control-A>", select_all)
        self.root.bind_class("TEntry", "<Control-a>", select_all)
        self.root.bind_class("TEntry", "<Control-A>", select_all)
        self.root.bind_class("Text", "<Control-a>", select_all)
        self.root.bind_class("Text", "<Control-A>", select_all)

        # Optional: macOS users can also bind Command-A
        self.root.bind_class("Entry", "<Command-a>", select_all)
        self.root.bind_class("TEntry", "<Command-a>", select_all)
        self.root.bind_class("Text", "<Command-a>", select_all)


        # Notebook tabs
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=8, pady=8)

        # Encrypt tab
        self.tab_enc = ttk.Frame(self.nb)
        self.nb.add(self.tab_enc, text="Encrypt")

        # Decrypt tab
        self.tab_dec = ttk.Frame(self.nb)
        self.nb.add(self.tab_dec, text="Decrypt")

        self._build_encrypt_tab()
        self._build_decrypt_tab()

    # ---------------- Encrypt Tab ----------------
    def _build_encrypt_tab(self):
        f = self.tab_enc

        # Passphrase row
        lbl = ttk.Label(f, text="Passphrase:")
        lbl.pack(anchor="w", padx=12, pady=(12,4))
        row = ttk.Frame(f)
        row.pack(fill="x", padx=12)
        self.enc_pass_var = tk.StringVar()
        self.enc_pass_entry = ttk.Entry(row, textvariable=self.enc_pass_var, show="*", width=50)
        self.enc_pass_entry.pack(side="left", padx=(0,6))
        self.enc_show_var = tk.BooleanVar(value=False)
        self.enc_show_cb = ttk.Checkbutton(row, text="Show", variable=self.enc_show_var, command=self._toggle_enc_show)
        self.enc_show_cb.pack(side="left")

        # Plaintext input
        ttk.Label(f, text="Plain text to encrypt:").pack(anchor="w", padx=12, pady=(10,0))
        self.enc_input = tk.Text(f, height=9, wrap="word")
        self.enc_input.pack(fill="both", expand=False, padx=12, pady=(4,8))

        # Buttons row
        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", padx=12, pady=(0,8))
        ttk.Button(btn_row, text="Encrypt Text", command=self.encrypt_text).pack(side="left")
        ttk.Button(btn_row, text="Copy Text", command=lambda: self._copy_widget_text(self.enc_input)).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Encrypt File...", command=self.encrypt_file).pack(side="left")
        ttk.Button(btn_row, text="Suggest Passphrase", command=self._suggest_passphrase).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Clear Input", command=lambda: self.enc_input.delete("1.0", tk.END)).pack(side="right")

        # Encrypted output
        ttk.Label(f, text="Encrypted (ASCII-armored):").pack(anchor="w", padx=12, pady=(6,0))
        self.enc_output = tk.Text(f, height=9, wrap="word")
        self.enc_output.pack(fill="both", expand=False, padx=12, pady=(4,8))

        out_row = ttk.Frame(f)
        out_row.pack(fill="x", padx=12, pady=(0,8))
        ttk.Button(out_row, text="Copy Encrypted", command=lambda: self._copy_widget_text(self.enc_output)).pack(side="left")
        ttk.Button(out_row, text="Save Encrypted To...", command=lambda: self._save_widget_to_file(self.enc_output, def_ext=".asc")).pack(side="left", padx=8)
        ttk.Button(out_row, text="Clear Output", command=lambda: self.enc_output.delete("1.0", tk.END)).pack(side="right")

        ttk.Label(f, text="Notes: Uses symmetric AES256. Keep passphrase safe; losing it means lost data.", wraplength=760).pack(anchor="w", padx=12, pady=(6,12))

    def _toggle_enc_show(self):
        if self.enc_show_var.get():
            self.enc_pass_entry.config(show="")
        else:
            self.enc_pass_entry.config(show="*")

    def _suggest_passphrase(self):
        # simple suggestion - you can replace with stronger generator if desired
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_"
        suggestion = ''.join(secrets.choice(alphabet) for _ in range(32))
        self.enc_pass_var.set(suggestion)

    def encrypt_text(self):
        passphrase = self.enc_pass_var.get()
        plaintext = self.enc_input.get("1.0", tk.END)
        if not passphrase:
            messagebox.showwarning("Missing passphrase", "Please enter a passphrase.")
            return
        if not plaintext.strip():
            messagebox.showwarning("Missing plaintext", "Please enter text to encrypt.")
            return

        try:
            result = gpg.encrypt(plaintext, recipients=None, symmetric='AES256', passphrase=passphrase, armor=True)
            if getattr(result, "ok", False):
                self.enc_output.delete("1.0", tk.END)
                self.enc_output.insert("1.0", str(result))
                messagebox.showinfo("Encrypted", "Text encrypted successfully.")
            else:
                # result.status often contains human message
                messagebox.showerror("Encryption failed", result.status or "Unknown error")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption exception: {e}")

    def encrypt_file(self):
        # pick input file
        in_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not in_path:
            return

        # default output filename
        default = os.path.basename(in_path) + ".gpg"
        out_path = filedialog.asksaveasfilename(title="Save encrypted file as", defaultextension=".gpg", initialfile=default)
        if not out_path:
            return

        passphrase = self.enc_pass_var.get()
        if not passphrase:
            messagebox.showwarning("Missing passphrase", "Please enter passphrase used for encryption.")
            return

        try:
            with open(in_path, "rb") as f:
                result = gpg.encrypt_file(f, recipients=None, symmetric='AES256', passphrase=passphrase, output=out_path)
            if getattr(result, "ok", False):
                messagebox.showinfo("Success", f"File encrypted and saved to:\n{out_path}")
            else:
                messagebox.showerror("Encryption failed", result.status or "Unknown error")
        except Exception as e:
            messagebox.showerror("Error", f"File encryption exception: {e}")

    # ---------------- Decrypt Tab ----------------
    def _build_decrypt_tab(self):
        f = self.tab_dec

        # Passphrase row
        ttk.Label(f, text="Passphrase:").pack(anchor="w", padx=12, pady=(12,4))
        row = ttk.Frame(f)
        row.pack(fill="x", padx=12)
        self.dec_pass_var = tk.StringVar()
        self.dec_pass_entry = ttk.Entry(row, textvariable=self.dec_pass_var, show="*", width=50)
        self.dec_pass_entry.pack(side="left", padx=(0,6))
        self.dec_show_var = tk.BooleanVar(value=False)
        self.dec_show_cb = ttk.Checkbutton(row, text="Show", variable=self.dec_show_var, command=self._toggle_dec_show)
        self.dec_show_cb.pack(side="left")

        # Encrypted text input
        ttk.Label(f, text="Encrypted text (paste ASCII-armored here):").pack(anchor="w", padx=12, pady=(10,0))
        self.dec_input = tk.Text(f, height=9, wrap="word")
        self.dec_input.pack(fill="both", expand=False, padx=12, pady=(4,8))

        # Buttons row
        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", padx=12, pady=(0,8))
        ttk.Button(btn_row, text="Decrypt Text", command=self.decrypt_text).pack(side="left")
        ttk.Button(btn_row, text="Copy Text", command=lambda: self._copy_widget_text(self.dec_input)).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Load Encrypted File...", command=self._load_encrypted_file_into_decrypt_input).pack(side="left")
        ttk.Button(btn_row, text="Clear Input", command=lambda: self.dec_input.delete("1.0", tk.END)).pack(side="right")

        # Decrypted output
        ttk.Label(f, text="Decrypted output:").pack(anchor="w", padx=12, pady=(6,0))
        self.dec_output = tk.Text(f, height=9, wrap="word")
        self.dec_output.pack(fill="both", expand=False, padx=12, pady=(4,8))

        out_row = ttk.Frame(f)
        out_row.pack(fill="x", padx=12, pady=(0,8))
        ttk.Button(out_row, text="Copy Decrypted", command=lambda: self._copy_widget_text(self.dec_output)).pack(side="left")
        ttk.Button(out_row, text="Save Decrypted To...", command=lambda: self._save_widget_to_file(self.dec_output, def_ext=".txt")).pack(side="left", padx=8)
        ttk.Button(out_row, text="Clear Output", command=lambda: self.dec_output.delete("1.0", tk.END)).pack(side="right")

        # File decrypt
        ttk.Button(f, text="Decrypt File (.gpg)...", command=self.decrypt_file).pack(pady=(6,4))

        ttk.Label(f, text="Notes: To decrypt a file, choose the .gpg file and provide the passphrase.", wraplength=760).pack(anchor="w", padx=12, pady=(6,12))

    def _toggle_dec_show(self):
        if self.dec_show_var.get():
            self.dec_pass_entry.config(show="")
        else:
            self.dec_pass_entry.config(show="*")

    def decrypt_text(self):
        passphrase = self.dec_pass_var.get()
        enc_text = self.dec_input.get("1.0", tk.END)
        if not passphrase:
            messagebox.showwarning("Missing passphrase", "Please enter passphrase for decryption.")
            return
        if not enc_text.strip():
            messagebox.showwarning("Missing encrypted text", "Paste the ASCII-armored encrypted text or load file.")
            return

        try:
            result = gpg.decrypt(enc_text, passphrase=passphrase)
            if getattr(result, "ok", False):
                # decrypted data may be bytes in .data or string in str(result)
                try:
                    # prefer bytes decoding if available
                    data = result.data.decode("utf-8")
                except Exception:
                    data = str(result)
                self.dec_output.delete("1.0", tk.END)
                self.dec_output.insert("1.0", data)
                messagebox.showinfo("Decrypted", "Text decrypted successfully.")
            else:
                messagebox.showerror("Decryption failed", result.status or "Wrong passphrase or corrupted data")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption exception: {e}")

    def _load_encrypted_file_into_decrypt_input(self):
        path = filedialog.askopenfilename(title="Open encrypted file", filetypes=[("GPG files", "*.gpg"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                txt = f.read()
            self.dec_input.delete("1.0", tk.END)
            self.dec_input.insert("1.0", txt)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")

    def decrypt_file(self):
        in_path = filedialog.askopenfilename(title="Select .gpg file to decrypt", filetypes=[("GPG files", "*.gpg"), ("All files", "*.*")])
        if not in_path:
            return
        # default output filename = input without .gpg
        base = os.path.basename(in_path)
        if base.endswith(".gpg"):
            default_out = base[:-4]
        else:
            default_out = base + ".dec"
        out_path = filedialog.asksaveasfilename(title="Save decrypted file as", initialfile=default_out)
        if not out_path:
            return

        passphrase = self.dec_pass_var.get()
        if not passphrase:
            messagebox.showwarning("Missing passphrase", "Enter passphrase for file decryption.")
            return

        try:
            with open(in_path, "rb") as f:
                result = gpg.decrypt_file(f, passphrase=passphrase, output=out_path)
            if getattr(result, "ok", False):
                messagebox.showinfo("Success", f"File decrypted and saved to:\n{out_path}")
            else:
                messagebox.showerror("Decryption failed", result.status or "Wrong passphrase or corrupted file")
        except Exception as e:
            messagebox.showerror("Error", f"File decryption exception: {e}")

    # ---------------- Utilities ----------------
    def _copy_widget_text(self, widget):
        txt = widget.get("1.0", tk.END).strip()
        if not txt:
            messagebox.showinfo("Nothing to copy", "No text available to copy.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            messagebox.showinfo("Copied", "Copied to clipboard")
        except Exception as e:
            messagebox.showerror("Clipboard error", str(e))

    def _save_widget_to_file(self, widget, def_ext=".txt"):
        txt = widget.get("1.0", tk.END)
        if not txt.strip():
            messagebox.showinfo("Nothing to save", "No text to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=def_ext)
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            messagebox.showinfo("Saved", f"Saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = GPGApp(root)
    root.mainloop()
