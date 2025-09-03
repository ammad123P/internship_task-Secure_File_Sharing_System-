# **🔒 Secure File Sharing System**

A **local end-to-end encrypted file-sharing system** built with **Python & Tkinter** for **secure file exchanges** between Internee.pk and external parties.
Supports **AES-256-GCM encryption**, **RSA key management**, and **signed tokens** for secure verification.

---

## **✨ Features**

* 🔐 **End-to-End Encryption** (AES-256-GCM + RSA-2048 key wrapping)
* 💾 **Local Secure Storage** – No cloud required
* 🔑 **Key Pair Management** – Generate & store RSA keys locally
* ⏳ **Signed Tokens** – Time-limited verification tokens (HMAC-SHA256)
* 🖥 **Cross-Platform GUI** – Simple Tkinter interface

---

## **🛠️ Tech Stack**

| Component        | Technology Used                  |
| ---------------- | -------------------------------- |
| **Language**     | Python 3.10+                     |
| **GUI**          | Tkinter                          |
| **Encryption**   | AES-256-GCM (via `cryptography`) |
| **Key Wrapping** | RSA-OAEP SHA-256                 |
| **Hashing**      | HMAC-SHA256                      |

---

## **📥 Installation**

### **1️⃣ Clone the repository**

```bash
git clone https://github.com/your-username/secure-file-sharing-system.git
cd secure-file-sharing-system
```

### **2️⃣ Install dependencies**

```bash
pip install cryptography
```

### **3️⃣ Run the app**

```bash
python secure_file_sharing_tk.py
```

---

## **🚀 How It Works**

### **Step 1 – Generate Keys**

* Generate RSA **public/private** key pair.
* Share **public key** with recipients.
* Keep **private key** safe and optionally password-protected.

### **Step 2 – Encrypt & Share**

* Select the file and recipient’s public key.
* Creates a secure `.sfs` bundle for sharing.
* (Optional) Generate a **signed token** with an expiry time.

### **Step 3 – Verify & Decrypt**

* Verify the token (optional).
* Load the `.sfs` bundle and your private key.
* The original file is decrypted and restored securely.

---

## **📂 Project Structure**

```
secure-file-sharing-system/
├── secure_file_sharing_tk.py      # Main application script
├── secure_file_sharing_tk_clean.py # Clean version without comments
├── README.md                      # Project documentation
└── requirements.txt               # Dependencies
```

---

## **🔒 Security Highlights**

| Layer           | Method/Algorithm         |
| --------------- | ------------------------ |
| File Encryption | AES-256-GCM              |
| Key Wrapping    | RSA-OAEP SHA-256         |
| Token Signing   | HMAC-SHA256              |
| Integrity Check | AES-GCM Tag Verification |

---

## **🛠 Future Enhancements**

* 🌐 **Cloud Integration** with AWS S3 / GCP / Azure Blob
* 👥 **Multi-user management**
* 🔄 **Automatic key rotation**
* 📱 **Mobile interface support**

---

## **📸 Screenshots**

*Uploaded in GitHub Repository*

---

## **📜 License**

This project is licensed under the **MIT License**. Feel free to use and modify for personal or organizational purposes.

---

Would you like me to create a `requirements.txt` file for your repo as well?
