# TrustVault 🔐
### Secure Document Sharing with Access Control and Audit History

TrustVault is a web application that allows users to upload, download, manage, and securely share documents. It includes access controls and audit logs to help users track document-related activities.

## ✨ Features

- **User Authentication:** Register and log in securely.
- **Document Upload:** Upload supported documents.
- **Document Download:** Download your stored documents.
- **Document Sharing:** Share documents with other registered users.
- **Access Management:** Revoke previously granted document access.
- **Document Details:** View information about uploaded documents.
- **Audit History:** Track document-related activities.
- **CSRF Protection:** Protect supported forms against cross-site request forgery.

## 🛠️ Technologies Used

- **Backend:** Python, Flask
- **Database:** SQLite, SQLAlchemy
- **Frontend:** HTML, CSS, Jinja2
- **Security:** Password hashing, CSRF protection, access control
- **Version Control:** Git and GitHub

## 📁 Project Structure

```text
TrustVault/
├── app.py
├── audit.py
├── templates/
│   ├── audit_logs.html
│   ├── dashboard.html
│   ├── document_details.html
│   ├── documents.html
│   ├── index.html
│   ├── login.html
│   └── register.html
├── requirements.txt
└── README.md
```

## ⚙️ Installation and Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/stephenbelagubbala/TrustVault.git
   cd TrustVault
   ```

2. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

3. Activate it on Windows:

   ```powershell
   .venv\Scripts\Activate.ps1
   ```

4. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Configure the required environment variables and application settings.

6. Start the application:

   ```bash
   python app.py
   ```

7. Open `http://127.0.0.1:5000` in your browser.

## 🔒 Security Notes

TrustVault uses authentication, access control, password hashing, and CSRF protection. Additional production security checks are required before using it with sensitive documents.

## 🚀 Project Status

Under development. Deployment and additional security improvements are planned.

## 👨‍💻 Author

**Stephen Belagubbala**

- GitHub: [stephenbelagubbala](https://github.com/stephenbelagubbala)

---

*TrustVault — Your documents, your control.*
