import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64

HEADER = b"ENCRYPTEDv1"  # simple header to recognize files created by this app
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 390_000  # reasonably strong iteration count

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from password and salt using PBKDF2-HMAC-SHA256."""
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password_bytes)

def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """Return bytes: HEADER + salt + nonce + ciphertext"""
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # AES-GCM provides authentication tag
    return HEADER + salt + nonce + ciphertext

def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """Parse blob and decrypt. Raises ValueError on problems."""
    if not blob.startswith(HEADER):
        raise ValueError("File does not appear to be in the expected encrypted format.")
    offset = len(HEADER)
    salt = blob[offset:offset+SALT_SIZE]
    if len(salt) != SALT_SIZE:
        raise ValueError("Encrypted file is truncated (salt).")
    offset += SALT_SIZE
    nonce = blob[offset:offset+NONCE_SIZE]
    if len(nonce) != NONCE_SIZE:
        raise ValueError("Encrypted file is truncated (nonce).")
    offset += NONCE_SIZE
    ciphertext = blob[offset:]
    if len(ciphertext) == 0:
        raise ValueError("Encrypted file contains no ciphertext.")
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    # AESGCM.decrypt will verify tag; it raises InvalidTag from cryptography on auth failure
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

# GUI
class EncryptorGUI:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor / Decryptor")

        # File selection row
        self.file_label = tk.Label(master, text="No file selected", wraplength=480, anchor="w", justify="left")
        self.file_label.grid(row=0, column=0, columnspan=3, padx=10, pady=(10, 2), sticky="w")

        self.select_btn = tk.Button(master, text="Select File", command=self.select_file, width=12)
        self.select_btn.grid(row=1, column=0, padx=10, pady=6, sticky="w")

        self.clear_btn = tk.Button(master, text="Clear", command=self.clear_selection, width=8)
        self.clear_btn.grid(row=1, column=1, padx=6, pady=6, sticky="w")

        # Password entry row
        tk.Label(master, text="Secret key / password:").grid(row=2, column=0, padx=10, pady=(6,2), sticky="w")
        self.password_entry = tk.Entry(master, show="*", width=50)
        self.password_entry.grid(row=3, column=0, columnspan=3, padx=10, pady=(0,8), sticky="w")

        # Buttons
        self.encrypt_btn = tk.Button(master, text="Encrypt", command=self.encrypt_file, bg="#b2f0b2")
        self.encrypt_btn.grid(row=4, column=0, padx=10, pady=10, sticky="w")

        self.decrypt_btn = tk.Button(master, text="Decrypt", command=self.decrypt_file, bg="#f0b2b2")
        self.decrypt_btn.grid(row=4, column=1, padx=6, pady=10, sticky="w")

        # Status
        self.status_label = tk.Label(master, text="", fg="blue", anchor="w", justify="left", wraplength=480)
        self.status_label.grid(row=5, column=0, columnspan=3, padx=10, pady=(0,10), sticky="w")

        self.selected_path = None

    def select_file(self):
        path = filedialog.askopenfilename(title="Select file to encrypt/decrypt")
        if path:
            self.selected_path = path
            self.file_label.config(text=path)
            self.set_status("")
        else:
            self.set_status("File selection cancelled.")

    def clear_selection(self):
        self.selected_path = None
        self.file_label.config(text="No file selected")
        self.set_status("Selection cleared.")

    def set_status(self, text: str):
        self.status_label.config(text=text)
        self.master.update_idletasks()

    def encrypt_file(self):
        if not self.selected_path:
            messagebox.showwarning("No file", "Please select a file to encrypt.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("No password", "Please enter a secret key / password.")
            return

        try:
            with open(self.selected_path, "rb") as f:
                plaintext = f.read()
            self.set_status("Encrypting...")
            out_blob = encrypt_bytes(plaintext, password)
            out_path = self.selected_path + ".enc"
            # Avoid overwriting an existing file without prompt
            if os.path.exists(out_path):
                if not messagebox.askyesno("Overwrite?", f"{out_path} already exists. Overwrite?"):
                    self.set_status("Encryption cancelled (would overwrite).")
                    return
            with open(out_path, "wb") as f:
                f.write(out_blob)
            self.set_status(f"Encrypted -> {out_path}")
            messagebox.showinfo("Success", f"Encrypted file saved as:\n{out_path}")
        except Exception as e:
            self.set_status("Encryption failed.")
            messagebox.showerror("Error", f"Encryption failed:\n{e}")

    def decrypt_file(self):
        if not self.selected_path:
            messagebox.showwarning("No file", "Please select a file to decrypt.")
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("No password", "Please enter the secret key / password used to encrypt.")
            return

        try:
            with open(self.selected_path, "rb") as f:
                blob = f.read()
            self.set_status("Decrypting...")
            plaintext = decrypt_bytes(blob, password)
            # Choose output path: if name ends with .enc, remove it; otherwise add .dec
            if self.selected_path.endswith(".enc"):
                out_path = self.selected_path[:-4]  # remove .enc
                # If file without .enc exists, don't overwrite
                if os.path.exists(out_path):
                    out_path = out_path + ".dec"
            else:
                out_path = self.selected_path + ".dec"

            # Avoid overwriting an existing file without prompt
            if os.path.exists(out_path):
                if not messagebox.askyesno("Overwrite?", f"{out_path} already exists. Overwrite?"):
                    self.set_status("Decryption cancelled (would overwrite).")
                    return

            with open(out_path, "wb") as f:
                f.write(plaintext)
            self.set_status(f"Decrypted -> {out_path}")
            messagebox.showinfo("Success", f"Decrypted file saved as:\n{out_path}")
        except Exception as e:
            self.set_status("Decryption failed.")
            messagebox.showerror("Error", f"Decryption failed:\n{e}")

def main():
    root = tk.Tk()
    # give a modest minimum size
    root.minsize(520, 220)
    app = EncryptorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
