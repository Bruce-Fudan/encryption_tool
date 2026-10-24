import os
import re
import hashlib
import base64
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import multiprocessing as mp
import threading
import time
import tempfile
from queue import Empty

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

# Direct import; dependencies are guaranteed by the packaging environment
from argon2.low_level import hash_secret_raw, Type

# ==================== Constants ====================
CHUNK_SIZE = 64 * 1024            # 64 KB chunks
ENCRYPT_MAX_CHARS = 1000          # Max chars for encrypt text mode
DECRYPT_MAX_CHARS = 6000          # Max chars for decrypt text mode

# PBKDF2 parameters
SALT_SIZE = 16                    # Salt length (bytes)
PBKDF2_ITERATIONS = 600_000       # Iterations

# Argon2id parameters
ARGON2_TIME_COST = 3              # Time cost
ARGON2_MEMORY_COST = 65536        # Memory cost 64 MB
ARGON2_PARALLELISM = 4            # Parallelism

# ==================== Core key derivation functions ====================

def derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation, returns a 32-byte key"""
    return PBKDF2(password.encode(), salt, dkLen=32, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

def derive_key_argon2id(password: str, salt: bytes) -> bytes:
    """Argon2id key derivation, returns a 32-byte key, requires argon2-cffi"""
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID
    )

# ==================== Generic encryption/decryption (with progress callback, for text mode) ====================

def encrypt_stream(password: str, data: bytes, kdf_mode: str, progress_callback=None) -> bytes:
    """Encrypt data with password, returns salt(16) + nonce(12) + tag(16) + ciphertext"""
    salt = get_random_bytes(SALT_SIZE)
    if kdf_mode == 'argon2id':
        key = derive_key_argon2id(password, salt)
    else:
        key = derive_key_pbkdf2(password, salt)
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext = b""
    total = len(data)
    if total == 0:
        cipher.encrypt(b'')
        tag = cipher.digest()
        return salt + nonce + tag + b""
    last_reported = -1
    for offset in range(0, total, CHUNK_SIZE):
        chunk = data[offset:offset + CHUNK_SIZE]
        ciphertext += cipher.encrypt(chunk)
        if progress_callback:
            pct = int((offset + len(chunk)) / total * 100)
            if pct != last_reported:
                progress_callback(pct)
                last_reported = pct
    tag = cipher.digest()
    return salt + nonce + tag + ciphertext

def decrypt_stream(password: str, enc_data: bytes, kdf_mode: str, progress_callback=None) -> bytes:
    """Decrypt data (format: salt+nonce+tag+ciphertext), returns original plaintext"""
    if len(enc_data) < SALT_SIZE + 12 + 16:
        raise ValueError("Data too short to decrypt")
    salt = enc_data[:SALT_SIZE]
    nonce = enc_data[SALT_SIZE:SALT_SIZE + 12]
    tag = enc_data[SALT_SIZE + 12:SALT_SIZE + 12 + 16]
    ciphertext = enc_data[SALT_SIZE + 12 + 16:]
    if kdf_mode == 'argon2id':
        key = derive_key_argon2id(password, salt)
    else:
        key = derive_key_pbkdf2(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    total = len(ciphertext)
    if total == 0:
        cipher.decrypt(b'')
        try:
            cipher.verify(tag)
        except Exception:
            raise ValueError("Decryption failed: wrong key or data has been tampered with")
        return b""
    plaintext = b""
    last_reported = -1
    for offset in range(0, total, CHUNK_SIZE):
        chunk = ciphertext[offset:offset + CHUNK_SIZE]
        plaintext += cipher.decrypt(chunk)
        if progress_callback:
            pct = int((offset + len(chunk)) / total * 100)
            if pct != last_reported:
                progress_callback(pct)
                last_reported = pct
    try:
        cipher.verify(tag)
    except Exception:
        raise ValueError("Decryption failed: wrong key or data has been tampered with")
    return plaintext

# ==================== File encryption/decryption (streaming, KDF decided by mode/suffix) ====================

def encrypt_file(input_path: str, password: str, kdf_mode: str, progress_queue) -> str:
    """Encrypt file, produces originalname.enc or .enc2, uses atomic write to avoid leftovers"""
    salt = get_random_bytes(SALT_SIZE)
    if kdf_mode == 'argon2id':
        key = derive_key_argon2id(password, salt)
        ext = '.enc2'
    else:
        key = derive_key_pbkdf2(password, salt)
        ext = '.enc'
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    out_path = input_path + ext
    file_size = os.path.getsize(input_path)
    tmp_path = None
    try:
        # Create a temporary file in the same directory as the target file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.enc.tmp',
                                         dir=os.path.dirname(out_path) or '.') as fout:
            tmp_path = fout.name
            fout.write(salt)
            fout.write(nonce)
            if file_size == 0:
                cipher.encrypt(b'')
                tag = cipher.digest()
                fout.write(tag)
                progress_queue.put(('progress', 100))
                os.replace(tmp_path, out_path)
                return out_path
            with open(input_path, 'rb') as fin:
                processed = 0
                last_reported = -1
                while True:
                    chunk = fin.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    fout.write(cipher.encrypt(chunk))
                    processed += len(chunk)
                    pct = int(processed / file_size * 100)
                    if pct != last_reported:
                        progress_queue.put(('progress', pct))
                        last_reported = pct
                tag = cipher.digest()
                fout.write(tag)
        os.replace(tmp_path, out_path)
        progress_queue.put(('progress', 100))
        return out_path
    except Exception as e:
        # Clean up the temporary file
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise ValueError(f"File encryption failed: {e}")

def decrypt_file(input_path: str, password: str, progress_queue) -> str:
    """Decrypt .enc or .enc2 file, writes to a temp file first, atomically replaces only after verification succeeds"""
    ext = os.path.splitext(input_path)[1].lower()
    if ext == '.enc':
        kdf_mode = 'pbkdf2'
    elif ext == '.enc2':
        kdf_mode = 'argon2id'
    else:
        raise ValueError("File suffix must be .enc or .enc2")
    out_path = os.path.splitext(input_path)[0]
    file_size = os.path.getsize(input_path)
    if file_size < SALT_SIZE + 12 + 16:
        raise ValueError("Encrypted file is incomplete (length too short)")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.dec.tmp',
                                         dir=os.path.dirname(out_path) or '.') as fout:
            tmp_path = fout.name
            with open(input_path, 'rb') as fin:
                salt = fin.read(SALT_SIZE)
                nonce = fin.read(12)
                if kdf_mode == 'argon2id':
                    key = derive_key_argon2id(password, salt)
                else:
                    key = derive_key_pbkdf2(password, salt)
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                ciphertext_len = file_size - SALT_SIZE - 12 - 16
                processed = 0
                last_reported = -1
                while processed < ciphertext_len:
                    read_size = min(CHUNK_SIZE, ciphertext_len - processed)
                    chunk = fin.read(read_size)
                    if not chunk:
                        raise ValueError("Invalid encrypted file structure: unexpected truncation")
                    fout.write(cipher.decrypt(chunk))
                    processed += len(chunk)
                    pct = int(processed / ciphertext_len * 100) if ciphertext_len > 0 else 100
                    if pct != last_reported:
                        progress_queue.put(('progress', pct))
                        last_reported = pct
                tag = fin.read(16)
                if len(tag) != 16:
                    raise ValueError("Invalid encrypted file structure: missing authentication tag")
                if ciphertext_len == 0:
                    cipher.decrypt(b'')
                try:
                    cipher.verify(tag)
                except Exception:
                    raise ValueError("Decryption failed: wrong key or file corrupted (authentication failed)")

        os.replace(tmp_path, out_path)
        progress_queue.put(('progress', 100))
        return out_path

    except Exception:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        raise

# ==================== Worker process tasks ====================

def worker_process(task, *args, progress_queue, result_queue):
    try:
        if task == 'encrypt_text':
            password, text, kdf_mode = args
            if len(text) == 0:
                raise ValueError("Plaintext content is empty")
            plain_data = text.encode('utf-8')

            def cb(pct):
                progress_queue.put(('progress', pct))

            encrypted = encrypt_stream(password, plain_data, kdf_mode, cb)
            b64 = base64.b64encode(encrypted).decode()
            #result_queue.put(('ok', b64 + f'\n[KDF: {kdf_mode.upper()}]'))
            result_queue.put(('ok', b64))

        elif task == 'decrypt_text':
            password, enc_b64, kdf_mode = args
            if len(enc_b64) == 0:
                raise ValueError("Ciphertext content is empty")
            enc_b64 = re.sub(r'\s+', '', enc_b64)
            try:
                enc_data = base64.b64decode(enc_b64)
            except Exception:
                raise ValueError("Base64 decoding failed, invalid ciphertext format")

            def cb(pct):
                progress_queue.put(('progress', pct))

            # Attempt decryption; suggest switching KDF only on auth failure/wrong key
            try:
                plain = decrypt_stream(password, enc_data, kdf_mode, cb)
            except ValueError as e:
                err = str(e)
                if "wrong key" in err or "authentication failed" in err or "MAC check" in err or "tampered" in err:
                    alt = 'pbkdf2' if kdf_mode == 'argon2id' else 'argon2id'
                    raise ValueError(f"{err}\n\nIf you are using the other key derivation mode ({alt.upper()}), please switch and try again.") from None
                else:
                    raise

            try:
                result_str = plain.decode('utf-8')
            except UnicodeDecodeError:
                raise ValueError("Decryption succeeded, but the content is not valid UTF-8 text; it may be non-text data. Please use file mode.")
            result_queue.put(('ok', result_str))

        elif task == 'encrypt_file':
            in_path, password, kdf_mode = args
            out = encrypt_file(in_path, password, kdf_mode, progress_queue)
            result_queue.put(('ok', out))

        elif task == 'decrypt_file':
            in_path, password = args
            out = decrypt_file(in_path, password, progress_queue)
            result_queue.put(('ok', out))

    except Exception as e:
        result_queue.put(('error', str(e)))

# ==================== About dialog content ====================

ABOUT_TEXT = """\
AES‑256‑GCM Encryption/Decryption Tool

Author: bruce
Version: 6.0

Technical Principles
• AES‑256 is the Advanced Encryption Standard certified by
  the National Institute of Standards and Technology (NIST),
  using a 256-bit key and trusted worldwide.
• GCM (Galois/Counter Mode) generates an authentication tag
  while encrypting, ensuring data integrity—any tampering
  will be detected and decryption rejected.
• Key derivation offers two algorithms:
  • Argon2id (recommended) — winner of the 2015 Password
    Hashing Competition, with memory hardness that
    effectively resists GPU/ASIC brute force.
    In this software it uses 64 MB memory cost and 3 iterations,
    far more secure than conventional KDFs, suitable for
    long-term confidentiality needs.
  • PBKDF2‑HMAC‑SHA256 (compatibility mode) — 600,000 iterations,
    only used to stay compatible with legacy .enc files,
    not recommended for new data.

Application Modes
• Text mode: enter/paste text directly for encryption/decryption,
  output is Base64-encoded ciphertext (easy to copy and transmit)
• File mode: encrypt/decrypt files of any type,
  streaming supports large files, and generates
  .enc (PBKDF2) or .enc2 (Argon2id) suffix according to the selected KDF

Disclaimer
• This software is provided "as is", without any express or
  implied warranty, including but not limited to warranties of
  merchantability, fitness for a particular purpose, or non-infringement.
• In no event shall the author be liable for any data loss,
  damage, or other losses resulting from the use of this software.
• [WARNING] Without the correct key, AES‑256‑GCM encrypted data
  cannot be decrypted. If the key is lost, the encrypted data
  will be permanently unrecoverable. Please keep your key safe.
• This tool is for lawful purposes only. It is forbidden to use
  this tool for any illegal or criminal activities. Users must
  comply with the laws and regulations of their location.

Open Source License Notice
• PyCryptodome — BSD 2-Clause License
  (contains public domain code)
• argon2-cffi — MIT License
• Tkinter, hashlib, base64, multiprocessing, threading, os, re,
  tempfile, etc. are Python standard library, subject to
  PSF License Version 2

Copyright Notice
• Copyright © 2026 bruce
• This software is licensed under the MIT License.
  Anyone may freely use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of this software,
  provided that the above copyright notice and this license
  notice are retained in copies of the software.
"""

# ==================== GUI ====================

class Application:
    def __init__(self, root):
        self.root = root
        self.root.title("AES‑256‑GCM Encryption/Decryption Tool")
        self.root.geometry("640x750")
        self.root.minsize(640, 650)
        self.root.resizable(True, True)

        self.mode = tk.StringVar(value="Text Mode")
        self.crypto_mode = tk.StringVar(value="encrypt")
        self.kdf_mode = tk.StringVar(value="argon2id")   # Default Argon2id
        self.file_path = ""
        self.current_process = None

        self._setup_menu()
        self.create_widgets()
        self.update_mode_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _setup_menu(self):
        menubar = tk.Menu(self.root)
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def _show_about(self):
        messagebox.showinfo("About", ABOUT_TEXT)

    def create_widgets(self):
        top = ttk.Frame(self.root)
        top.pack(fill='x', padx=20, pady=10)
        ttk.Label(top, text="Mode:", font=("Consolas", 10, "bold")).pack(side='left')
        combo = ttk.Combobox(top, textvariable=self.mode,
                             values=["Text Mode", "File Mode"], state="readonly", width=10)
        combo.pack(side='left', padx=10)
        combo.bind('<<ComboboxSelected>>', lambda e: self.update_mode_ui())

        cf = ttk.Frame(self.root)
        cf.pack(fill='x', padx=20, pady=5)
        ttk.Label(cf, text="Operation:", font=("Consolas", 10, "bold")).pack(side='left')
        ttk.Radiobutton(cf, text="🔒 Encrypt", variable=self.crypto_mode,
                       value="encrypt", command=self.update_label).pack(side='left', padx=10)
        ttk.Radiobutton(cf, text="🔓 Decrypt", variable=self.crypto_mode,
                       value="decrypt", command=self.update_label).pack(side='left')

        # Key derivation algorithm selection (always shows both options, defaults to Argon2id)
        kf = ttk.Frame(self.root)
        kf.pack(fill='x', padx=20, pady=5)
        ttk.Label(kf, text="Key Derivation:", font=("Consolas", 10, "bold")).pack(side='left')
        ttk.Radiobutton(kf, text="Argon2id (Recommended)", variable=self.kdf_mode,
                       value="argon2id").pack(side='left', padx=10)
        ttk.Radiobutton(kf, text="PBKDF2 (Legacy Compatible)", variable=self.kdf_mode,
                       value="pbkdf2").pack(side='left')

        # Key input
        kw = ttk.Frame(self.root)
        kw.pack(fill='x', padx=20, pady=10)
        ttk.Label(kw, text="Key:", font=("Consolas", 10, "bold")).pack(side='left')
        self.key_entry = ttk.Entry(kw, width=50, show="*")
        self.key_entry.pack(side='left', padx=5)

        self.content_frame = ttk.Frame(self.root)
        self.content_frame.pack(fill='both', expand=True, padx=20, pady=5)

        self.text_label = ttk.Label(self.content_frame, text="Enter plaintext:", font=("Consolas", 10, "bold"))
        self.text_input = tk.Text(self.content_frame, height=10, width=70, wrap='word')

        self.file_label = ttk.Label(self.content_frame, text="Selected file:", font=("Consolas", 10, "bold"))
        self.file_info = ttk.Label(self.content_frame, text="No file selected", foreground="gray")
        self.file_btn = ttk.Button(self.content_frame, text="Select File...", command=self.select_file)

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(self.root, variable=self.progress_var,
                                           maximum=100, length=580, mode='determinate')
        self.progress_label = ttk.Label(self.root, text="0%", font=("Consolas", 9))

        self.exec_btn = ttk.Button(self.root, text="Run", command=self.start_task, width=20)
        self.exec_btn.pack(pady=5)

        result_frame = ttk.Frame(self.root)
        result_frame.pack(fill='both', expand=True, padx=20, pady=(10,15))
        ttk.Label(result_frame, text="Result / Output:", font=("Consolas", 10, "bold")).pack(anchor='w')
        self.result_text = tk.Text(result_frame, height=6, bg="#f5f5f5", state='disabled', wrap='word')
        self.result_text.pack(fill='both', expand=True)

    def update_mode_ui(self):
        for w in self.content_frame.winfo_children():
            w.pack_forget()
        if self.mode.get() == "Text Mode":
            self.text_label.pack(anchor='w')
            self.text_input.pack(fill='both', expand=True)
        else:
            self.file_label.pack(anchor='w')
            self.file_btn.pack(anchor='w', pady=5)
            self.file_info.pack(anchor='w')
            self.file_info.config(text=self.file_path if self.file_path else "No file selected")
        self.update_label()

    def update_label(self):
        if self.mode.get() == "Text Mode":
            self.text_label.config(
                text="Enter plaintext:" if self.crypto_mode.get() == "encrypt" else "Enter ciphertext (Base64):"
            )

    def select_file(self):
        if self.crypto_mode.get() == "encrypt":
            path = filedialog.askopenfilename(title="Select file to encrypt")
        else:
            path = filedialog.askopenfilename(
                title="Select file to decrypt (.enc / .enc2)",
                filetypes=[("Encrypted files", "*.enc;*.enc2")]
            )
        if path:
            self.file_path = path
            self.file_info.config(text=os.path.basename(path))

    def start_task(self):
        mode = self.mode.get()
        crypto = self.crypto_mode.get()
        kdf = self.kdf_mode.get()
        key = self.key_entry.get()
        if len(key) == 0:
            messagebox.showwarning("Warning", "Key cannot be empty!")
            return

        if mode == "Text Mode":
            content = self.text_input.get("1.0", "end")
            if content.endswith('\n'):
                content = content[:-1]
            if len(content) == 0:
                messagebox.showwarning("Warning", "Content cannot be empty!")
                return
            limit = ENCRYPT_MAX_CHARS if crypto == 'encrypt' else DECRYPT_MAX_CHARS
            if len(content) > limit:
                messagebox.showwarning(
                    "Warning",
                    f"Text length is {len(content)} characters (limit {limit}).\n"
                    "For long text, please use File Mode."
                )
                return
            task = 'encrypt_text' if crypto == 'encrypt' else 'decrypt_text'
            args = (key, content, kdf)
        else:
            if not self.file_path:
                messagebox.showwarning("Warning", "Please select a file first!")
                return
            if crypto == 'encrypt':
                ext = '.enc2' if kdf == 'argon2id' else '.enc'
                out_path = self.file_path + ext
                if os.path.exists(out_path):
                    if not messagebox.askyesno("Confirm", f"File '{os.path.basename(out_path)}' already exists. Overwrite?"):
                        return
                task = 'encrypt_file'
                args = (self.file_path, key, kdf)
            else:
                ext = os.path.splitext(self.file_path)[1].lower()
                if ext not in ('.enc', '.enc2'):
                    messagebox.showerror("Error", "Decrypt mode only accepts .enc or .enc2 files!")
                    return
                out_path = os.path.splitext(self.file_path)[0]
                if os.path.exists(out_path):
                    if not messagebox.askyesno("Confirm", f"Output file '{os.path.basename(out_path)}' already exists. Overwrite?"):
                        return
                task = 'decrypt_file'
                args = (self.file_path, key)

        self.progress_bar.pack(pady=5)
        self.progress_label.pack()
        self.progress_var.set(0)
        self.progress_label.config(text="0%")
        self.exec_btn.config(state='disabled')

        try:
            self.progress_queue = mp.Queue()
            self.result_queue = mp.Queue()
            p = mp.Process(target=worker_process,
                           args=(task,) + args,
                           kwargs={'progress_queue': self.progress_queue,
                                   'result_queue': self.result_queue})
            self.current_process = p
            p.start()
        except Exception as e:
            self.exec_btn.config(state='normal')
            self.current_process = None
            self.progress_bar.pack_forget()
            self.progress_label.pack_forget()
            messagebox.showerror("Error", f"Failed to start task: {e}")
            return

        threading.Thread(target=self.monitor_progress, args=(p,), daemon=True).start()

    def monitor_progress(self, process):
        while True:
            try:
                msg = self.progress_queue.get(timeout=0.1)
                if msg[0] == 'progress':
                    self.root.after(0, self.update_progress, msg[1])
            except Empty:
                pass
            if not process.is_alive():
                while True:
                    try:
                        msg = self.progress_queue.get_nowait()
                        if msg[0] == 'progress':
                            self.root.after(0, self.update_progress, msg[1])
                    except Empty:
                        break
                try:
                    status, data = self.result_queue.get(timeout=1)
                except Empty:
                    status, data = 'error', "Child process exited unexpectedly"
                self.root.after(0, self.task_done, status, data)
                return
            time.sleep(0.05)

    def update_progress(self, percent):
        self.progress_var.set(percent)
        self.progress_label.config(text=f"{percent}%")

    def task_done(self, status, data):
        self.current_process = None
        self.progress_bar.pack_forget()
        self.progress_label.pack_forget()
        self.exec_btn.config(state='normal')

        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)

        if status == 'ok':
            self.result_text.insert('end', data)
            if self.mode.get() == "File Mode":
                messagebox.showinfo("Success", "File operation completed!")
            else:
                messagebox.showinfo("Success", "Operation completed!")
        else:
            self.result_text.insert('end', f"❌ {data}")
            self.result_text.tag_add("error", "1.0", "end")
            self.result_text.tag_config("error", foreground="red")
            messagebox.showerror("Error", data)

        self.result_text.config(state='disabled')

    def on_closing(self):
        if self.current_process and self.current_process.is_alive():
            self.current_process.terminate()
            self.current_process.join(timeout=2)
        self.root.destroy()

if __name__ == '__main__':
    mp.freeze_support()
    root = tk.Tk()
    app = Application(root)
    root.mainloop()