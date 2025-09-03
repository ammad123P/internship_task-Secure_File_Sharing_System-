
"""
Secure File Sharing System (Local, E2E Encryption) — Tkinter GUI
----------------------------------------------------------------
Features
- Generate RSA key pairs (PEM files).
- Encrypt any file with AES‑256‑GCM; wrap the key with recipient's RSA public key (hybrid E2E).
- Package as a single .sfs bundle (ZIP with metadata + ciphertext) safe to share via email/USB/cloud.
- Decrypt .sfs bundles with recipient's RSA private key.
- Create and verify time‑limited "signed tokens" (a local, HMAC‑signed link) to simulate signed URLs.
  Tokens authorize access to a specific bundle path until expiry (even if the bundle is later moved or copied).

Encryption at rest & in transit
- Files are always AES‑GCM encrypted inside the .sfs bundle; only recipients with the private key can decrypt.
- When you "share", you send only the encrypted bundle; the secret never leaves your machine in plaintext.

Dependencies
- Python 3.10+ recommended.
- pip install cryptography
"""

import base64
import json
import os
import sys
import time
import hmac
import hashlib
import zipfile
import getpass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from tkinter import Tk, filedialog, messagebox, StringVar, Text, END, ttk


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

APP_NAME = "Secure File Sharing (Local E2E)"
BUNDLE_EXT = ".sfs"     
SECRET_FILE = Path.home() / ".sfs_app_secret"  


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def b64u_decode(data_str: str) -> bytes:
    pad = "=" * ((4 - len(data_str) % 4) % 4)
    return base64.urlsafe_b64decode(data_str + pad)


def human_dt(ts: float | None = None) -> str:
    dt = datetime.fromtimestamp(ts or time.time(), tz=timezone.utc).astimezone()
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def ensure_app_secret() -> bytes:
    if SECRET_FILE.exists():
        return SECRET_FILE.read_bytes()
    secret = os.urandom(32)
    SECRET_FILE.write_bytes(secret)
    try:
        os.chmod(SECRET_FILE, 0o600)
    except Exception:
        pass
    return secret


def sign_token(bundle_path: str, expires_epoch: int) -> str:
    """
    Create a compact signed token like "eyJ...}.SflK..."
    payload = {"bundle_path": <abs path>, "expires": <epoch seconds>}
    signature = HMAC-SHA256(secret, ascii(bundle_path|expires))
    """
    secret = ensure_app_secret()
    payload = {
        "bundle_path": str(Path(bundle_path).resolve()),
        "expires": int(expires_epoch),
    }
    payload_b64 = b64u(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{payload['bundle_path']}|{payload['expires']}".encode()
    signature = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{payload_b64}.{b64u(signature)}"


def verify_token(token: str) -> dict:
    payload_b64, sig_b64 = token.split(".", 1)
    payload = json.loads(b64u_decode(payload_b64))
    secret = ensure_app_secret()
    msg = f"{payload['bundle_path']}|{payload['expires']}".encode()
    expected = hmac.new(secret, msg, hashlib.sha256).digest()
    provided = b64u_decode(sig_b64)
    if not hmac.compare_digest(expected, provided):
        raise ValueError("Invalid token signature")
    if time.time() > int(payload["expires"]):
        raise ValueError("Token has expired")
    return payload


def gen_rsa_keypair(bits: int = 3072) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    pub = priv.public_key()
    return priv, pub


def save_private_key_pem(private_key: rsa.RSAPrivateKey, path: Path, password: bytes | None):
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    path.write_bytes(pem)


def save_public_key_pem(public_key: rsa.RSAPublicKey, path: Path):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_public_key(path: Path) -> rsa.RSAPublicKey:
    data = path.read_bytes()
    return serialization.load_pem_public_key(data, backend=default_backend())


def load_private_key(path: Path, password: bytes | None) -> rsa.RSAPrivateKey:
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=password, backend=default_backend())


def encrypt_file_for_recipient(plaintext_path: Path, recipient_pub: rsa.RSAPublicKey, sender_label: str = "") -> Path:
    
    pt = plaintext_path.read_bytes()
    
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, pt, None)  

    
    wrapped_key = recipient_pub.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    meta = {
        "alg": "AES-256-GCM",
        "nonce": b64u(nonce),
        "wrapped_key": b64u(wrapped_key),
        "orig_filename": plaintext_path.name,
        "filesize": len(pt),
        "sender": sender_label,
        "created": datetime.now(timezone.utc).isoformat(),
    }

    
    bundle_path = plaintext_path.with_suffix(plaintext_path.suffix + BUNDLE_EXT)
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("meta.json", json.dumps(meta, indent=2))
        z.writestr("data.enc", ct)
    return bundle_path


def decrypt_bundle(bundle_path: Path, recipient_priv: rsa.RSAPrivateKey, out_dir: Path | None = None) -> Path:
    with zipfile.ZipFile(bundle_path, "r") as z:
        meta = json.loads(z.read("meta.json").decode())
        ct = z.read("data.enc")

    wrapped_key = b64u_decode(meta["wrapped_key"])
    nonce = b64u_decode(meta["nonce"])

    key = recipient_priv.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, None)

    out_dir = out_dir or bundle_path.parent
    out_path = out_dir / meta["orig_filename"]
    
    if out_path.exists():
        stem = out_path.stem
        suffix = "".join(out_path.suffixes)
        i = 1
        while True:
            cand = out_dir / f"{stem} (decrypted {i}){suffix}"
            if not cand.exists():
                out_path = cand
                break
            i += 1
    out_path.write_bytes(pt)
    return out_path


class App:
    def __init__(self, root: Tk):
        self.root = root
        root.title(APP_NAME)
        root.geometry("820x640")

        self.sender_label = StringVar(value="Internee.pk")
        self.status = StringVar(value="Ready.")

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self._build_keys_tab(nb)
        self._build_encrypt_tab(nb)
        self._build_decrypt_tab(nb)
        self._build_token_tab(nb)

        statusbar = ttk.Label(root, textvariable=self.status, anchor="w")
        statusbar.pack(fill="x", padx=10, pady=(0, 8))

    
    def _build_keys_tab(self, nb: ttk.Notebook):
        frame = ttk.Frame(nb)
        nb.add(frame, text="1) Keys")

        ttk.Label(frame, text="Generate RSA Key Pair (for you or a teammate)").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 4))
        ttk.Label(frame, text="Owner / Label (optional):").grid(row=1, column=0, sticky="e", padx=8)
        entry = ttk.Entry(frame, textvariable=self.sender_label, width=40)
        entry.grid(row=1, column=1, sticky="w", padx=8, pady=4)

        ttk.Label(frame, text="Key size:").grid(row=2, column=0, sticky="e", padx=8)
        self.key_bits = ttk.Combobox(frame, values=["2048", "3072", "4096"], width=10, state="readonly")
        self.key_bits.current(1)
        self.key_bits.grid(row=2, column=1, sticky="w", padx=8, pady=4)

        ttk.Label(frame, text="Private key password (optional):").grid(row=3, column=0, sticky="e", padx=8)
        self.priv_pass = ttk.Entry(frame, show="*", width=40)
        self.priv_pass.grid(row=3, column=1, sticky="w", padx=8, pady=4)

        gen_btn = ttk.Button(frame, text="Generate & Save Keys…", command=self.on_gen_keys)
        gen_btn.grid(row=4, column=1, sticky="w", padx=8, pady=12)

        ttk.Label(frame, text="Tip: Share ONLY your PUBLIC key (.pem). Keep your PRIVATE key secret.").grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=(4, 8))

    def _build_encrypt_tab(self, nb: ttk.Notebook):
        frame = ttk.Frame(nb)
        nb.add(frame, text="2) Encrypt & Share")

        self.plain_path = StringVar()
        self.recipient_pub_path = StringVar()

        ttk.Label(frame, text="Select file to encrypt:").grid(row=0, column=0, sticky="e", padx=8, pady=(10, 4))
        e1 = ttk.Entry(frame, textvariable=self.plain_path, width=70)
        e1.grid(row=0, column=1, sticky="w", padx=8, pady=(10, 4))
        ttk.Button(frame, text="Browse…", command=self.pick_plain).grid(row=0, column=2, padx=8)

        ttk.Label(frame, text="Recipient's PUBLIC key (.pem):").grid(row=1, column=0, sticky="e", padx=8, pady=4)
        e2 = ttk.Entry(frame, textvariable=self.recipient_pub_path, width=70)
        e2.grid(row=1, column=1, sticky="w", padx=8, pady=4)
        ttk.Button(frame, text="Browse…", command=self.pick_recipient_pub).grid(row=1, column=2, padx=8)

        ttk.Button(frame, text="Encrypt → Create .sfs bundle", command=self.on_encrypt).grid(row=2, column=1, sticky="w", padx=8, pady=12)

        ttk.Separator(frame).grid(row=3, column=0, columnspan=3, sticky="ew", padx=8, pady=8)

        ttk.Label(frame, text="Create a time‑limited signed token for this bundle (simulates signed URL):").grid(row=4, column=0, columnspan=3, sticky="w", padx=8)
        self.bundle_for_token = StringVar()
        ttk.Label(frame, text="Bundle (.sfs):").grid(row=5, column=0, sticky="e", padx=8, pady=4)
        ttk.Entry(frame, textvariable=self.bundle_for_token, width=70).grid(row=5, column=1, sticky="w", padx=8, pady=4)
        ttk.Button(frame, text="Browse…", command=self.pick_bundle_for_token).grid(row=5, column=2, padx=8)

        ttk.Label(frame, text="Expires in (hours):").grid(row=6, column=0, sticky="e", padx=8, pady=4)
        self.token_hours = ttk.Combobox(frame, values=["1","6","12","24","72","168"], width=10, state="readonly")
        self.token_hours.current(3)
        self.token_hours.grid(row=6, column=1, sticky="w", padx=8, pady=4)

        self.token_output = Text(frame, height=4, width=80)
        self.token_output.grid(row=7, column=0, columnspan=3, sticky="we", padx=8, pady=6)

        ttk.Button(frame, text="Create Signed Token", command=self.on_create_token).grid(row=8, column=1, sticky="w", padx=8, pady=(0, 12))

    def _build_decrypt_tab(self, nb: ttk.Notebook):
        frame = ttk.Frame(nb)
        nb.add(frame, text="3) Verify/Decrypt")

        self.token_input = Text(frame, height=4, width=80)
        ttk.Label(frame, text="Paste a signed token (optional):").grid(row=0, column=0, sticky="w", padx=8, pady=(10,4))
        self.token_input.grid(row=1, column=0, columnspan=3, sticky="we", padx=8, pady=4)
        ttk.Button(frame, text="Verify Token", command=self.on_verify_token).grid(row=2, column=0, sticky="w", padx=8, pady=4)

        ttk.Separator(frame).grid(row=3, column=0, columnspan=3, sticky="ew", padx=8, pady=8)

        self.bundle_path = StringVar()
        self.recipient_priv_path = StringVar()
        self.priv_pass_decrypt = StringVar()

        ttk.Label(frame, text="Bundle (.sfs):").grid(row=4, column=0, sticky="e", padx=8, pady=4)
        ttk.Entry(frame, textvariable=self.bundle_path, width=70).grid(row=4, column=1, sticky="w", padx=8, pady=4)
        ttk.Button(frame, text="Browse…", command=self.pick_bundle).grid(row=4, column=2, padx=8)

        ttk.Label(frame, text="Your PRIVATE key (.pem):").grid(row=5, column=0, sticky="e", padx=8, pady=4)
        ttk.Entry(frame, textvariable=self.recipient_priv_path, width=70).grid(row=5, column=1, sticky="w", padx=8, pady=4)
        ttk.Button(frame, text="Browse…", command=self.pick_recipient_priv).grid(row=5, column=2, padx=8)

        ttk.Label(frame, text="Private key password (if set):").grid(row=6, column=0, sticky="e", padx=8, pady=4)
        ttk.Entry(frame, textvariable=self.priv_pass_decrypt, show="*", width=40).grid(row=6, column=1, sticky="w", padx=8, pady=4)

        ttk.Button(frame, text="Decrypt Bundle", command=self.on_decrypt).grid(row=7, column=1, sticky="w", padx=8, pady=12)

    def _build_token_tab(self, nb: ttk.Notebook):
        frame = ttk.Frame(nb)
        nb.add(frame, text="About / Help")
        text = Text(frame, wrap="word", height=24, width=90)
        text.pack(fill="both", expand=True, padx=8, pady=8)
        text.insert(END, """How to use

1) Keys
   - Click 'Generate & Save Keys…' to create your RSA key pair.
   - Share the PUBLIC key (.pem) with teammates; keep the PRIVATE key secure (optionally password-protect it).

2) Encrypt & Share
   - Select a file and the recipient's PUBLIC key.
   - Click 'Encrypt → Create .sfs bundle'. Send ONLY the .sfs file to the recipient.

   Signed Tokens (simulate signed URLs)
   - Pick a .sfs bundle and an expiry (e.g., 24 hours), then click 'Create Signed Token'.
   - The token authorizes access to that specific bundle path until it expires.
   - Share the token out-of-band (e.g., chat). It does NOT contain decryption keys.

3) Verify/Decrypt
   - (Optional) Paste a token and click 'Verify Token' to confirm access & prefill the bundle path.
   - Select your PRIVATE key (.pem), enter its password if set, then 'Decrypt Bundle'.

Security notes
   - AES-256-GCM provides authenticated encryption; tampering is detected during decryption.
   - RSA-OAEP (SHA-256) wraps the AES key for end-to-end confidentiality.
   - The .sfs bundle stores encrypted data only; plaintext never touches the bundle.
   - Signed tokens are HMAC-SHA256 with a local secret at ~/.sfs_app_secret and include an expiry timestamp.
""")
        text.configure(state="disabled")

    
    def on_gen_keys(self):
        try:
            bits = int(self.key_bits.get())
            priv, pub = gen_rsa_keypair(bits=bits)
            folder = filedialog.askdirectory(title="Choose folder to save keys")
            if not folder:
                return
            label = self.sender_label.get().strip() or "user"
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            base = Path(folder) / f"{label}_{bits}_{ts}"
            priv_path = base.with_suffix(".private.pem")
            pub_path = base.with_suffix(".public.pem")

            pwd_txt = self.priv_pass.get()
            password = pwd_txt.encode() if pwd_txt else None
            save_private_key_pem(priv, priv_path, password)
            save_public_key_pem(pub, pub_path)

            self.status.set(f"Saved keys: {priv_path.name}, {pub_path.name}")
            messagebox.showinfo("Keys generated", f"Private key:\n{priv_path}\n\nPublic key:\n{pub_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate keys:\n{e}")

    def pick_plain(self):
        p = filedialog.askopenfilename(title="Choose file to encrypt")
        if p:
            self.plain_path.set(p)

    def pick_recipient_pub(self):
        p = filedialog.askopenfilename(title="Choose recipient PUBLIC key (.pem)", filetypes=[("PEM files","*.pem"), ("All files","*.*")])
        if p:
            self.recipient_pub_path.set(p)

    def on_encrypt(self):
        try:
            pt = Path(self.plain_path.get())
            if not pt.exists():
                messagebox.showwarning("Missing file", "Please choose a file to encrypt.")
                return
            pub_path = Path(self.recipient_pub_path.get())
            if not pub_path.exists():
                messagebox.showwarning("Missing public key", "Please choose the recipient's PUBLIC key (.pem).")
                return
            pub = load_public_key(pub_path)
            bundle_path = encrypt_file_for_recipient(pt, pub, self.sender_label.get().strip())
            self.status.set(f"Bundle created: {bundle_path.name}")
            messagebox.showinfo("Success", f"Encrypted bundle ready:\n{bundle_path}")
            
            self.bundle_for_token.set(str(bundle_path))
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed:\n{e}")

    def pick_bundle_for_token(self):
        p = filedialog.askopenfilename(title="Choose .sfs bundle", filetypes=[("SFS bundles","*.sfs"), ("All files","*.*")])
        if p:
            self.bundle_for_token.set(p)

    def on_create_token(self):
        try:
            bp = self.bundle_for_token.get().strip()
            if not bp:
                messagebox.showwarning("Missing bundle", "Choose a .sfs bundle first.")
                return
            hours = int(self.token_hours.get())
            expires = int(time.time() + hours * 3600)
            token = sign_token(bp, expires)
            self.token_output.delete("1.0", END)
            self.token_output.insert("1.0", token + "\n")
            self.status.set(f"Token created (expires {human_dt(expires)})")
        except Exception as e:
            messagebox.showerror("Error", f"Could not create token:\n{e}")

    def on_verify_token(self):
        token = self.token_input.get("1.0", END).strip()
        if not token:
            messagebox.showwarning("No token", "Paste a token first.")
            return
        try:
            payload = verify_token(token)
            self.bundle_path.set(payload["bundle_path"])
            messagebox.showinfo("Token valid", f"Token OK.\nBundle: {payload['bundle_path']}\nExpires: {human_dt(payload['expires'])}")
            self.status.set("Token verified.")
        except Exception as e:
            messagebox.showerror("Invalid token", str(e))

    def pick_bundle(self):
        p = filedialog.askopenfilename(title="Choose .sfs bundle", filetypes=[("SFS bundles","*.sfs"), ("All files","*.*")])
        if p:
            self.bundle_path.set(p)

    def pick_recipient_priv(self):
        p = filedialog.askopenfilename(title="Choose your PRIVATE key (.pem)", filetypes=[("PEM files","*.pem"), ("All files","*.*")])
        if p:
            self.recipient_priv_path.set(p)

    def on_decrypt(self):
        try:
            bp = Path(self.bundle_path.get())
            if not bp.exists():
                messagebox.showwarning("Missing bundle", "Choose a .sfs bundle first.")
                return
            priv_path = Path(self.recipient_priv_path.get())
            if not priv_path.exists():
                messagebox.showwarning("Missing private key", "Choose your PRIVATE key (.pem).")
                return
            pwd = self.priv_pass_decrypt.get().encode() if self.priv_pass_decrypt.get() else None
            priv = load_private_key(priv_path, pwd)
            out_path = decrypt_bundle(bp, priv)
            self.status.set(f"Decrypted → {out_path.name}")
            messagebox.showinfo("Decrypted", f"File restored:\n{out_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")


def main():
    root = Tk()
    
    try:
        root.call("source", "sun-valley.tcl")
        root.call("set_theme", "dark")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
