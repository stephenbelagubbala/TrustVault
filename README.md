# TrustVault 🔐
### Secure Document Sharing with Access Control and Audit History

TrustVault is a secure document management web application built with Python and Flask. It allows users to upload, organize, search, view, download, and share documents with controlled permissions. It also maintains an audit trail of important activities to support accountability and security.

## 📌 Project Overview

Managing sensitive documents requires secure storage, controlled access, and activity tracking. TrustVault addresses these needs by providing role-based access, document-level permissions, secure file validation, and audit logging.

## ✨ Features

### 🔑 Authentication and Access Control
- User registration, login, and logout.
- Role-based access for administrators and regular users.
- Secure password handling.
- Document ownership and access restrictions.

### 📁 Document Management
- Upload and manage documents.
- View document details.
- Download authorized documents.
- Edit and delete documents according to permissions.
- Validate file types and file sizes.
- Secure filename handling.

### 🤝 Document Sharing
- Share documents with specific users.
- Grant read-only or edit permissions.
- Revoke document access.
- Set sharing expiration dates.
- Prevent access through unauthorized direct URLs.

### 🔎 Search and Filtering
- Search documents by name.
- Filter documents by owner, category, and date.

### 📋 Audit Trail
- Record document uploads and downloads.
- Track document edits and deletions.
- Record sharing and permission changes.
- Log relevant unauthorized-access attempts.
- Provide administrators with activity information.

### 🛡️ Security
- Authentication and authorization checks.
- Protection against unauthorized document access.
- File validation and upload size limits.
- CSRF protection for supported forms.
- Expired sharing links are prevented from granting access.

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Flask | Backend web framework |
| Flask-SQLAlchemy / SQLAlchemy | Database integration |
| SQLite | Local database |
| HTML and CSS | User interface |
| Flask-WTF / CSRFProtect | Form security and CSRF protection |
| Pytest | Automated testing |
| Git and GitHub | Version control and source code hosting |
| Render | Live deployment |

## 🚀 Installation and Setup

### Prerequisites

- Python installed on your computer.
- Git installed.
- Visual Studio Code or another code editor.

### 1. Clone the repository

```bash
git clone https://github.com/stephenbelagubbala/TrustVault.git
cd TrustVault
```

### 2. Create a virtual environment

**Windows PowerShell:**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Configure the application's required environment variables, including a strong secret key. Use your local development configuration and never commit real secrets or production credentials to GitHub.

### 5. Run the application

```bash
python app.py
```

Open the local address displayed by Flask in your terminal, usually:

`http://127.0.0.1:5000`

> If your local configuration uses a different port or startup command, follow the settings in your repository.

## 🧪 Automated Testing

TrustVault includes automated tests for document security, permissions, authentication, file validation, audit logging, and other application behavior.

Run the test suite using:

```bash
python -m pytest -q
```

The previously reported test run completed with **32 passing tests**. Run the command again after any code changes to confirm the current result.

## 🔒 Security Testing

The project has been tested for the following scenarios:

- Preventing unauthorized users from accessing private documents.
- Enforcing read-only and edit permissions.
- Blocking access after permission revocation.
- Rejecting invalid or oversized uploads.
- Preventing access to expired shares.
- Recording important document and permission activities.
- Restricting administrative information to authorized users.

## 🌐 Live Demo

**Live application:** https://trustvault-qn2c.onrender.com

**GitHub repository:** https://github.com/stephenbelagubbala/TrustVault

The live application can be used to explore registration, authentication, document management, sharing, permissions, and other supported features.

## 📂 Project Purpose

TrustVault demonstrates practical application development concepts, including:

- Flask web application development.
- Database integration and data management.
- Authentication and role-based authorization.
- Secure file handling.
- Document-level permission management.
- Audit logging and automated security testing.
- GitHub version control and cloud deployment.

## 🔮 Future Enhancements

- Support for additional document formats.
- More advanced security monitoring.
- Improved document organization and reporting.
- Additional automated security tests.
- Enhanced accessibility and user experience.

## 👨‍💻 Author

**Developed as a software project to demonstrate secure document management and controlled document sharing.**
