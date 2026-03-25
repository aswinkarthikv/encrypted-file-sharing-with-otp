# 🔐 Secure File Sharing System

### AES-256 Encryption + OTP Verification

## 📌 Overview

This project is a **Secure File Sharing System** designed to safely upload and share sensitive files over the internet.
Files are encrypted using **AES-256 encryption** before storage, ensuring that even if the server is compromised, the data remains unreadable.

Access to shared files is protected using **OTP-based verification**, allowing **only the intended receiver** to download the file securely.

---

## 🎯 Problem Statement

Traditional file sharing systems:

* Store files in plain or weakly protected formats
* Allow anyone with a link to download files
* Are vulnerable to server breaches and data leaks

This project solves these issues by combining **encryption, authentication, and access control**.

---

## ✅ Solution

The system enforces multiple security layers:

* Strong encryption for files at rest
* Secure OTP verification for downloads
* Expiring links and one-time access
* Temporary decryption only during download

---

## 🔄 System Workflow

### 👤 Sender

1. Registers / logs into the system
2. Uploads a file
3. File is immediately encrypted using AES-256
4. Encrypted file is stored on the server
5. Generates a secure share link
6. Shares link with receiver

### 👥 Receiver

1. Opens secure download link
2. Receives a 6-digit OTP
3. Enters OTP for verification
4. File is decrypted **in memory**
5. File is downloaded
6. Link becomes invalid after use

---

## 🔐 Security Features

* ✅ AES-256 file encryption
* ✅ OTP-based authentication
* ✅ OTP one-time use
* ✅ OTP expiry support
* ✅ Secure token-based links
* ✅ One-time file download
* ✅ Link expiration
* ✅ Encryption keys excluded from GitHub
* ✅ Database excluded from version control

---

## 🛠️ Tech Stack

| Layer          | Technology            |
| -------------- | --------------------- |
| Frontend       | HTML, CSS, JavaScript |
| Backend        | Python (Flask)        |
| Encryption     | AES-256 (Fernet)      |
| Authentication | Flask-Login           |
| Database       | SQLite                |
| ORM            | SQLAlchemy            |

---

## 🧠 Core Concepts Used

* Cryptography
* Secure File Storage
* OTP Verification
* Access Control
* Authentication & Authorization
* Secure Web Application Design

---

## 📂 Project Structure

```
secure-file-sharing-system/
│
├── app.py
├── extensions.py
├── models.py
├── utils.py
├── verify_migration.py
├── requirements.txt
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── auth.html
│   ├── dashboard.html
│   └── download.html
│
├── static/
│   └── style.css
│
├── uploads/          (ignored in GitHub)
├── secret.key        (ignored in GitHub)
├── secure_share.db   (ignored in GitHub)
├── .gitignore
└── README.md
```

---

## 🗄️ Database

* SQLite database used for simplicity
* Database file is auto-generated at runtime
* Database files are excluded from version control for security

---

## 🧪 Testing

The project includes an internal test script to verify:

* User registration & login
* File encryption
* Secure sharing
* OTP verification
* File decryption

File:

```
verify_migration.py
```

---

## ⚙️ Installation & Setup (Local)

### 1️⃣ Clone the repository
```bash
git clone https://github.com/aswinkarthikv/encrypted-file-sharing-with-otp.git
cd encrypted-file-sharing-with-otp
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py

---

## 🚀 Future Enhancements

* Real email/SMS OTP integration
* Role-based access control
* Cloud storage (AWS S3 / GCP)
* File access logs
* QR-code based secure sharing
* Multi-factor authentication

---

## 👨‍💻 Developer

**Aswin Karthik V**
🎓 Computer Science and Engineering
📧 [aswinkarthikv@gmail.com](mailto:aswinkarthikv@gmail.com)

**Niranjani A**
🎓 Computer Science and Engineering
📧 [niranjania@gmail.com](mailto:niranjania@gmail.com)

---

## 📜 License

This project is developed for **academic and educational purposes**.
