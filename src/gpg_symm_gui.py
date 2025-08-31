#!/usr/bin/env python3
"""
gpg_tk.py
GPG symmetric passphrase-based encryption/decryption GUI using tkinter + python-gnupg.

Requirements:
  - python-gnupg (`pip install python-gnupg`)
  - GnuPG installed on the system (gpg)
"""

import threading
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import gnupg
import sys
import textwrap
import platform

APP_TITLE = "GPG Passphrase Encrypt / Decrypt"

# ---------- Helper functions ----------
def check_gpg_installed():
    """Return path to gpg binary or None."""
    path = shutil.which("gpg") or shutil.which("gpg2")
    return path

def friendly_os_info():
    return f"{platform.system()} {platform.release()}"

# ---------- Main App ----------
class GPGTkApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("900x600")
        self.minsize(820, 520)
        # Styling
        self._setup_style()

        # Check gpg
        gpg_path = check_gpg_installed()
        if not gpg_path:
            messagebox.showerror("GPG Not Found",
                                 "GnuPG (gpg) was not found on your PATH.\n\n"
                                 "Please install GnuPG on your system (e.g. apt/brew/Gpg4win) and try again.")
            self.destroy()
            return

        # Initialize gnupg
        try:
            self.gpg = gnupg.GPG()  # uses default gnupghome (~/.gnupg)
        except Exception as e:
            messagebox.showerror("GPG Init Error", f"Failed to initialize GPG: {e}")
            self.destroy()
            return

        self._create_menu()
        self._create_widgets()
        self._create_statusbar()

        # Keyboard shortcuts
        self.bind_all("<Control-e>", lambda e: self.encrypt_action())
        self.bind_all("<Control-d>", lambda e: self.decrypt_action())
        self.bind_all("<Control-c>", lambda e: self.copy_output_current_tab())

    # ---------- UI Setup ----------
    def _setup_style(self):
        style = ttk.Style(self)
        # Use a clean theme if available
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background="#f6f8fa")
        style.configure("Card.TFrame", background="white", relief="flat")
        style.configure("Title.TLabel", font=("Segoe UI", 12, "bold"), background="#f6f8fa")
        style.configure("Note.TLabel", font=("Segoe UI", 9), foreground="#444444", background="#fff")
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        style.map("Accent.TButton",
                  foreground=[("active", "#fff"), ("!disabled", "#fff")],
                  background=[("active", "#2b6cb0"), ("!disabled", "#2b6cb0")])
        style.configure("Secondary.TButton", font=("Segoe UI", 10))

    def _create_menu(self):
        menubar = tk.Menu(self)
        filem = tk.Menu(menubar, tearoff=False)
        filem.add_command(label="Save Output...", command=self.save_output_current_tab)
        filem.add_separator()
        filem.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=filem)

        helpm = tk.Menu(menubar, tearoff=False)
        helpm.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpm)

        self.config(menu=menubar)

    def _create_widgets(self):
        container = ttk.Frame(self, padding=(10, 10, 10, 10), style="TFrame")
        container.pack(fill="both", expand=True)

        # Notebook for tabs
        self.notebook = ttk.Notebook(container)
        self.notebook.pack(fill="both", expand=True, pady=(0, 8))

        # Encrypt tab
        self.encrypt_tab = ttk.Frame(self.notebook, style="TFrame")
        self._build_encrypt_tab(self.encrypt_tab)
        self.notebook.add(self.encrypt_tab, text="🔐 Encrypt")

        # Decrypt tab
        self.decrypt_tab = ttk.Frame(self.notebook, style="TFrame")
        self._build_decrypt_tab(self.decrypt_tab)
        self.notebook.add(self.decrypt_tab, text="🔓 Decrypt")

    def _create_statusbar(self):
        status_frame = ttk.Frame(self, padding=(6, 3), style="TFrame")
        status_frame.pack(fill="x", side="bottom")
        self.status_label = ttk.Label(status_frame, text=f"GPG: {check_gpg_installed() or 'Not found'} | OS: {friendly_os_info()}",
                                      anchor="w")
        self.status_label.pack(side="left", padx=(4, 8))
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", length=150)
        self.progress.pack(side="right", padx=(0, 4))

    # ---------- Tab builders ----------
    def _build_encrypt_tab(self, parent):
        # Top frame: passphrase + reveal + encrypt button
        top = ttk.Frame(parent, padding=10, style="Card.TFrame")
        top.pack(fill="x", padx=10, pady=(12, 8))

        ttk.Label(top, text="Passphrase (used for symmetric encryption):", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.encrypt_pass_var = tk.StringVar()
        self.encrypt_pass_entry = ttk.Entry(top, textvariable=self.encrypt_pass_var, show="*", width=36)
        self.encrypt_pass_entry.grid(row=1, column=0, sticky="w", pady=(6, 8))

        self.encrypt_reveal_btn = ttk.Button(top, text="Show", width=8, command=self._toggle_encrypt_pass)
        self.encrypt_reveal_btn.grid(row=1, column=1, padx=(8, 0))

        self.encrypt_btn = ttk.Button(top, text="Encrypt ➜", style="Accent.TButton", command=self.encrypt_action)
        self.encrypt_btn.grid(row=1, column=2, padx=(12, 0))

        # Middle frame: input and output text areas
        body = ttk.Frame(parent, padding=(10, 8), style="TFrame")
        body.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        # Input box
        input_frame = ttk.Labelframe(body, text="Plain text to encrypt", padding=8)
        input_frame.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.encrypt_input = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, width=48, height=16)
        self.encrypt_input.pack(fill="both", expand=True)
        # quick load sample
        sample_btn = ttk.Button(input_frame, text="Load sample", style="Secondary.TButton",
                                command=lambda: self.encrypt_input.insert("1.0",
                                    "Hello! This is a sample plaintext. Replace with your secret message."))
        sample_btn.pack(anchor="e", pady=(6, 0))

        # Output box
        output_frame = ttk.Labelframe(body, text="Encrypted (ASCII-armored)", padding=8)
        output_frame.pack(side="right", fill="both", expand=True)
        self.encrypt_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=48, height=16)
        self.encrypt_output.pack(fill="both", expand=True)
        copy_btn = ttk.Button(output_frame, text="Copy Encrypted", command=self.copy_encrypt_output)
        copy_btn.pack(side="left", pady=(6, 0), padx=(0, 6))
        save_btn = ttk.Button(output_frame, text="Save...", command=lambda: self._save_text_widget(self.encrypt_output))
        save_btn.pack(side="left", pady=(6, 0))

        # Notes
        notes_frame = ttk.Frame(parent, padding=10)
        notes_frame.pack(fill="x", padx=10)
        notes = ("Notes / Guide:\n"
                 "• Uses GPG symmetric encryption (AES256). Output is ASCII-armored (.asc/.gpg text).\n"
                 "• Keep your passphrase secret and avoid re-using weak passphrases.\n"
                 "• Use 'Copy Encrypted' to copy to clipboard or Save... to write to a file.\n"
                 "Shortcuts: Ctrl+E (Encrypt), Ctrl+C (Copy Output)")
        ttk.Label(notes_frame, text=textwrap.fill(notes, 180), style="Note.TLabel", justify="left").pack(anchor="w")

    def _build_decrypt_tab(self, parent):
        top = ttk.Frame(parent, padding=10, style="Card.TFrame")
        top.pack(fill="x", padx=10, pady=(12, 8))

        ttk.Label(top, text="Passphrase (used to decrypt):", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self.decrypt_pass_var = tk.StringVar()
        self.decrypt_pass_entry = ttk.Entry(top, textvariable=self.decrypt_pass_var, show="*", width=36)
        self.decrypt_pass_entry.grid(row=1, column=0, sticky="w", pady=(6, 8))

        self.decrypt_reveal_btn = ttk.Button(top, text="Show", width=8, command=self._toggle_decrypt_pass)
        self.decrypt_reveal_btn.grid(row=1, column=1, padx=(8, 0))

        self.decrypt_btn = ttk.Button(top, text="Decrypt ➜", style="Accent.TButton", command=self.decrypt_action)
        self.decrypt_btn.grid(row=1, column=2, padx=(12, 0))

        body = ttk.Frame(parent, padding=(10, 8), style="TFrame")
        body.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        # Input (encrypted)
        input_frame = ttk.Labelframe(body, text="Encrypted text (paste ASCII-armored message here)", padding=8)
        input_frame.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.decrypt_input = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, width=48, height=16)
        self.decrypt_input.pack(fill="both", expand=True)
        paste_btn = ttk.Button(input_frame, text="Load From File...", style="Secondary.TButton", command=self.load_encrypted_file)
        paste_btn.pack(anchor="e", pady=(6, 0))

        # Output (decrypted)
        output_frame = ttk.Labelframe(body, text="Decrypted output", padding=8)
        output_frame.pack(side="right", fill="both", expand=True)
        self.decrypt_output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, width=48, height=16)
        self.decrypt_output.pack(fill="both", expand=True)
        copy_btn2 = ttk.Button(output_frame, text="Copy Decrypted", command=self.copy_decrypt_output)
        copy_btn2.pack(side="left", pady=(6, 0), padx=(0, 6))
        save_btn2 = ttk.Button(output_frame, text="Save...", command=lambda: self._save_text_widget(self.decrypt_output))
        save_btn2.pack(side="left", pady=(6, 0))

        notes_frame = ttk.Frame(parent, padding=10)
        notes_frame.pack(fill="x", padx=10)
        notes = ("Notes / Guide:\n"
                 "• Paste the entire ASCII-armored encrypted message produced by the Encrypt tab.\n"
                 "• The correct passphrase is required. If decryption fails, check whitespace/newlines and passphrase accuracy.")
        ttk.Label(notes_frame, text=textwrap.fill(notes, 180), style="Note.TLabel", justify="left").pack(anchor="w")

    # ---------- Actions ----------
    def _toggle_encrypt_pass(self):
        if self.encrypt_pass_entry.cget("show") == "":
            self.encrypt_pass_entry.config(show="*")
            self.encrypt_reveal_btn.config(text="Show")
        else:
            self.encrypt_pass_entry.config(show="")
            self.encrypt_reveal_btn.config(text="Hide")

    def _toggle_decrypt_pass(self):
        if self.decrypt_pass_entry.cget("show") == "":
            self.decrypt_pass_entry.config(show="*")
            self.decrypt_reveal_btn.config(text="Show")
        else:
            self.decrypt_pass_entry.config(show="")
            self.decrypt_reveal_btn.config(text="Hide")

    def _start_progress(self):
        try:
            self.progress.start(10)
        except Exception:
            pass

    def _stop_progress(self):
        try:
            self.progress.stop()
        except Exception:
            pass

    def encrypt_action(self):
        """Triggered by Encrypt button or Ctrl+E"""
        passphrase = self.encrypt_pass_var.get().strip()
        plaintext = self.encrypt_input.get("1.0", tk.END).rstrip("\n")
        if not passphrase:
            messagebox.showwarning("Missing Passphrase", "Please enter a passphrase for encryption.")
            return
        if not plaintext:
            messagebox.showwarning("Missing Text", "Please enter the plaintext to encrypt.")
            return

        # disable controls while operating
        self._set_controls_state("encrypt", "disabled")
        self.status_label.config(text="Encrypting...")
        self._start_progress()

        def worker():
            try:
                # Use symmetric AES256; recipients=None tells gpg to do symmetric encryption
                encrypted = self.gpg.encrypt(plaintext, recipients=None, symmetric="AES256", passphrase=passphrase, armor=True)
                if encrypted and encrypted.ok:
                    result = str(encrypted)
                    self.after(0, lambda: self._on_encrypt_success(result))
                else:
                    msg = encrypted.status or "Encryption failed (unknown error)."
                    self.after(0, lambda: self._on_encrypt_error(msg))
            except Exception as e:
                self.after(0, lambda: self._on_encrypt_error(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_encrypt_success(self, armored_text):
        self.encrypt_output.delete("1.0", tk.END)
        self.encrypt_output.insert(tk.END, armored_text)
        self.status_label.config(text="Encryption completed ✓")
        self._stop_progress()
        self._set_controls_state("encrypt", "normal")

    def _on_encrypt_error(self, msg):
        self._stop_progress()
        self._set_controls_state("encrypt", "normal")
        self.status_label.config(text="Encryption failed ✗")
        messagebox.showerror("Encryption Error", msg)

    def decrypt_action(self):
        """Triggered by Decrypt button or Ctrl+D"""
        passphrase = self.decrypt_pass_var.get().strip()
        encrypted_text = self.decrypt_input.get("1.0", tk.END).strip()
        if not passphrase:
            messagebox.showwarning("Missing Passphrase", "Please enter the passphrase for decryption.")
            return
        if not encrypted_text:
            messagebox.showwarning("Missing Encrypted Text", "Please paste or load the encrypted ASCII-armored text.")
            return

        self._set_controls_state("decrypt", "disabled")
        self.status_label.config(text="Decrypting...")
        self._start_progress()

        def worker():
            try:
                decrypted = self.gpg.decrypt(encrypted_text, passphrase=passphrase)
                if decrypted and decrypted.ok:
                    # decrypted.data is bytes; decode
                    try:
                        text = decrypted.data.decode("utf-8")
                    except Exception:
                        # fallback: convert to str
                        text = str(decrypted)
                    self.after(0, lambda: self._on_decrypt_success(text))
                else:
                    msg = decrypted.status or "Decryption failed (wrong passphrase or corrupted data)."
                    self.after(0, lambda: self._on_decrypt_error(msg))
            except Exception as e:
                self.after(0, lambda: self._on_decrypt_error(str(e)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_decrypt_success(self, plaintext):
        self.decrypt_output.delete("1.0", tk.END)
        self.decrypt_output.insert(tk.END, plaintext)
        self.status_label.config(text="Decryption completed ✓")
        self._stop_progress()
        self._set_controls_state("decrypt", "normal")

    def _on_decrypt_error(self, msg):
        self._stop_progress()
        self._set_controls_state("decrypt", "normal")
        self.status_label.config(text="Decryption failed ✗")
        messagebox.showerror("Decryption Error", msg)

    # ---------- Utility UI functions ----------
    def _set_controls_state(self, which, state):
        if which == "encrypt":
            self.encrypt_btn.config(state=state)
            self.encrypt_pass_entry.config(state=state)
            self.encrypt_reveal_btn.config(state=state)
            self.encrypt_input.config(state=state)
        elif which == "decrypt":
            self.decrypt_btn.config(state=state)
            self.decrypt_pass_entry.config(state=state)
            self.decrypt_reveal_btn.config(state=state)
            self.decrypt_input.config(state=state)

    def copy_encrypt_output(self):
        text = self.encrypt_output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Nothing to copy", "Encrypted output is empty.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_label.config(text="Encrypted content copied to clipboard ✓")

    def copy_decrypt_output(self):
        text = self.decrypt_output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showinfo("Nothing to copy", "Decrypted output is empty.")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_label.config(text="Decrypted content copied to clipboard ✓")

    def copy_output_current_tab(self):
        current = self.notebook.index(self.notebook.select())
        if current == 0:
            self.copy_encrypt_output()
        else:
            self.copy_decrypt_output()

    def save_output_current_tab(self):
        current = self.notebook.index(self.notebook.select())
        widget = self.encrypt_output if current == 0 else self.decrypt_output
        self._save_text_widget(widget)

    def _save_text_widget(self, widget):
        content = widget.get("1.0", tk.END).rstrip("\n")
        if not content:
            messagebox.showinfo("Nothing to save", "The selected output is empty.")
            return
        filetypes = [("Text file", "*.txt"), ("All files", "*.*")]
        fpath = filedialog.asksaveasfilename(title="Save output as...", defaultextension=".txt", filetypes=filetypes)
        if fpath:
            try:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(content)
                messagebox.showinfo("Saved", f"Saved to: {fpath}")
            except Exception as e:
                messagebox.showerror("Save error", str(e))

    def load_encrypted_file(self):
        fpath = filedialog.askopenfilename(title="Open encrypted file", filetypes=[("All files", "*.*")])
        if fpath:
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = f.read()
                self.decrypt_input.delete("1.0", tk.END)
                self.decrypt_input.insert("1.0", data)
            except Exception as e:
                messagebox.showerror("Open error", str(e))

    def show_about(self):
        about_text = (f"{APP_TITLE}\n\n"
                      "This app uses GnuPG (OpenPGP) for symmetric passphrase-based encryption and decryption.\n\n"
                      "• Algorithm: AES256 (symmetric)\n"
                      "• Output: ASCII-armored message\n\n"
                      "Shortcuts: Ctrl+E (Encrypt), Ctrl+D (Decrypt), Ctrl+C (Copy output)\n\n"
                      f"System: {friendly_os_info()}\n")
        messagebox.showinfo("About", about_text)


# ---------- Run ----------
def main():
    app = GPGTkApp()
    # If GPG not installed or failed init, app will destroy itself
    if not getattr(app, "gpg", None):
        return
    app.mainloop()

if __name__ == "__main__":
    main()
