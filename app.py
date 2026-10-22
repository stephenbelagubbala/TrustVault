
import os
import uuid
from audit import log_audit
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timezone
from functools import wraps


from flask import (
    Flask, render_template, redirect, url_for,
    flash, session, abort, request, send_file
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import (
    DataRequired, Email, Length, EqualTo
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY environment variable is required.")

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///trustvault.db"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

app.config["UPLOAD_FOLDER"] = os.path.join(
    app.root_path, "private_uploads"
)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "png"}
csrf = CSRFProtect(app)

db = SQLAlchemy(app)


# Database model

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    role = db.Column(
        db.String(20),
        nullable=False,
        default="owner"
    )

    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

def admin_required(view_func):
    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_id = session.get("user_id")

        if not user_id:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))

        user = db.session.get(User, user_id)

        if user is None:
            session.clear()
            flash("Please log in again.", "error")
            return redirect(url_for("login"))

        if user.role != "admin":
            abort(403)

        return view_func(*args, **kwargs)

    return wrapped_view


# Registration form
class RegisterForm(FlaskForm):
    name = StringField(
        "Full name",
        validators=[DataRequired(), Length(min=2, max=80)]
    )
    email = StringField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=8, max=128)]
    )
    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match.")
        ]
    )
    
    submit = SubmitField("Create account")

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(100), unique=True, nullable=False)
    uploaded_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True
    )

    category = db.Column(
        db.String(80),
        nullable=False,
        default="Uncategorized"
    )


    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True
    )


# Audit trail model
class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True
    )

    action = db.Column(db.String(50), nullable=False)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=True
    )

    document_name = db.Column(
        db.String(255),
        nullable=True
    )

    timestamp = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
    )


# Document sharing model — separate from AuditLog

class DocumentShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=False
    )

    shared_with_user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    permission = db.Column(
        db.String(10),
        nullable=False,
        default="read"
    )

    shared_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "shared_with_user_id",
            name="unique_document_share"
        ),
    )



    

# Login form
class LoginForm(FlaskForm):
    email = StringField(
        "Email", validators=[DataRequired(), Email()]
    )
    password = PasswordField(
        "Password", validators=[DataRequired()]
    )
    submit = SubmitField("Log in")


@app.route("/")
def home():
    user = db.session.get(User, session.get("user_id"))
    return render_template("index.html", user=user)



@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("home"))

    form = RegisterForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        existing_user = db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one_or_none()

        if existing_user:
            flash(
                "An account with that email already exists.",
                "error"
            )
        else:
            user = User(
                name=form.name.data.strip(),
                email=email,
                password_hash=generate_password_hash(
                    form.password.data
                ),
                role="owner"
            )

            db.session.add(user)
            db.session.commit()

            flash(
                "Account created! Please log in.",
                "success"
            )
            return redirect(url_for("login"))

    return render_template("register.html", form=form)



@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("home"))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data.strip().lower()

        user = db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one_or_none()

        if user and check_password_hash(
            user.password_hash, form.password.data
        ):
            session.clear()
            session["user_id"] = user.id
            flash("Welcome back!", "success")
            return redirect(url_for("home"))

        flash("Invalid email or password.", "error")

    return render_template("login.html", form=form)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("login"))


@app.route("/documents", methods=["GET", "POST"])
def documents():
    # Require login
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to access your documents.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a file to upload.", "error")
            return redirect(url_for("documents"))

        # Validate the file extension
        safe_original_name = secure_filename(uploaded_file.filename)

        if not safe_original_name or "." not in safe_original_name:
            flash("Invalid filename.", "error")
            return redirect(url_for("documents"))

        extension = safe_original_name.rsplit(".", 1)[1].lower()

        if extension not in ALLOWED_EXTENSIONS:
            flash("Only PDF, TXT, and PNG files are allowed.", "error")
            return redirect(url_for("documents"))

        # Never use the original name as the storage path
        stored_name = f"{uuid.uuid4().hex}.{extension}"
        storage_path = os.path.join(
            app.config["UPLOAD_FOLDER"], stored_name
        )

        uploaded_file.save(storage_path)

        document = Document(
            original_filename=safe_original_name[:255],
            stored_filename=stored_name,
            user_id=user.id
        )

        try:
            db.session.add(document)
            db.session.flush()  # Get the document ID

            audit = AuditLog(
                user_id=user.id,
                action="UPLOAD",
                document_id=document.id,
                document_name=document.original_filename
            )

            db.session.add(audit)
            db.session.commit()

        except Exception:
            db.session.rollback()

            if os.path.exists(storage_path):
                os.remove(storage_path)

            app.logger.exception(
                "Could not save document and audit log"
            )

            flash("Upload failed. Please try again.", "error")
            return redirect(url_for("documents"))

    
    user_documents = db.session.execute(
        db.select(Document)
        .filter_by(user_id=user.id)
        .order_by(Document.uploaded_at.desc())
    ).scalars().all()

    # Get shared documents together with their permissions
    shared_documents = db.session.execute(
    db.select(Document, DocumentShare.permission)
    .join(
        DocumentShare,
        DocumentShare.document_id == Document.id
    )
    .filter(
        DocumentShare.shared_with_user_id == user.id
    )
    .order_by(DocumentShare.shared_at.desc())
).all()
    
    owned_shares = db.session.execute(
        db.select(DocumentShare, User, Document)
        .join(
            User,
            User.id == DocumentShare.shared_with_user_id
        )
        .join(
            Document,
            Document.id == DocumentShare.document_id
        )
        .filter(Document.user_id == user.id)
        .order_by(DocumentShare.shared_at.desc())
    ).all()


    return render_template(
    "documents.html",
    documents=user_documents,
    shared_documents=shared_documents,
    owned_shares=owned_shares
)





@app.route("/documents/<int:document_id>/download")
def download_document(document_id):
    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    # Check document ownership
    is_owner = document.user_id == user.id

    # Check sharing permission
    share = db.session.execute(
        db.select(DocumentShare).filter_by(
            document_id=document.id,
            shared_with_user_id=user.id
        )
    ).scalar_one_or_none()

    if not is_owner and (
        share is None or share.permission not in ("read", "edit")
    ):
        abort(404)

    # Check whether the file exists
    storage_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename
    )

    if not os.path.isfile(storage_path):
        abort(404)

    # Record successful download
    audit = AuditLog(
        user_id=user.id,
        action="DOWNLOAD",
        document_id=document.id,
        document_name=document.original_filename
    )

    db.session.add(audit)
    db.session.commit()

    return send_file(
        storage_path,
        as_attachment=True,
        download_name=document.original_filename
    )




@app.route("/documents/<int:document_id>/details")
def document_details(document_id):
    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    # Check document ownership
    is_owner = document.user_id == user.id

    # Check sharing permission
    share = db.session.execute(
        db.select(DocumentShare).filter_by(
            document_id=document.id,
            shared_with_user_id=user.id
        )
    ).scalar_one_or_none()

    if not is_owner and (
        share is None or share.permission not in ("read", "edit")
    ):
        abort(404)

    # Calculate file size
    storage_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename
    )

    file_size_kb = None

    if os.path.isfile(storage_path):
        file_size_kb = os.path.getsize(storage_path) / 1024

    return render_template(
        "document_details.html",
        document=document,
        file_size_kb=file_size_kb
    )


@app.route("/documents/<int:document_id>/edit", methods=["GET", "POST"])
def edit_document(document_id):
    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    # Check ownership or Edit permission
    is_owner = document.user_id == user.id

    share = db.session.execute(
        db.select(DocumentShare).filter_by(
            document_id=document.id,
            shared_with_user_id=user.id
        )
    ).scalar_one_or_none()

    if not is_owner and (
        share is None or share.permission != "edit"
    ):
        abort(403)

    if request.method == "POST":
        filename = request.form.get(
            "original_filename", ""
        ).strip()

        category = request.form.get(
            "category", ""
        ).strip()

        safe_filename = secure_filename(filename)

        if (
            not safe_filename
            or len(safe_filename) > 255
            or not category
            or len(category) > 80
            or "." not in safe_filename
            or safe_filename.rsplit(".", 1)[1].lower()
            not in ALLOWED_EXTENSIONS
        ):
            flash(
                "Enter a valid filename and category.",
                "error"
            )
            return redirect(
                url_for("edit_document", document_id=document.id)
            )

        old_filename = document.original_filename
        document.original_filename = safe_filename
        document.category = category

        try:
            audit = AuditLog(
                user_id=user.id,
                action="EDIT",
                document_id=document.id,
                document_name=safe_filename
            )
            db.session.add(audit)
            db.session.commit()

        except Exception:
            db.session.rollback()
            app.logger.exception("Document edit failed")
            flash("Could not update the document.", "error")
            return redirect(
                url_for("edit_document", document_id=document.id)
            )

        flash("Document details updated successfully.", "success")
        return redirect(url_for("document_details", document_id=document.id))

    return render_template(
        "edit_document.html",
        document=document
    )



@app.route("/documents/<int:document_id>/delete", methods=["POST"])
def delete_document(document_id):

    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    document = db.session.get(Document, document_id)

    if document is None:
        abort(404)

    # Only the document owner can delete it
    if document.user_id != user.id:
        abort(403)

    filename = document.original_filename

    # Record the deletion in the audit log
    audit = AuditLog(
        user_id=user.id,
        action="DELETE",
        document_id=document.id,
        document_name=filename
    )
    db.session.add(audit)

    # Remove sharing permissions
    db.session.execute(
        db.delete(DocumentShare).filter_by(
            document_id=document.id
        )
    )

    # Save the file path before deleting the database record
    storage_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document.stored_filename
    )

    db.session.delete(document)
    db.session.commit()

    # Delete the physical file if it exists
    if os.path.isfile(storage_path):
        os.remove(storage_path)

    flash("Document deleted successfully.", "success")
    return redirect(url_for("documents"))


@app.route("/documents/<int:document_id>/share", methods=["POST"])
def share_document(document_id):
    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # Only the document owner can share it
    document = db.session.execute(
        db.select(Document).filter_by(
            id=document_id,
            user_id=user.id
        )
    ).scalar_one_or_none()

    if document is None:
        abort(404)

    # Get the recipient's email
    recipient_email = request.form.get(
        "email", ""
    ).strip().lower()
    # Validate the requested sharing permission
    permission = request.form.get("permission", "read").strip().lower()

    if permission not in ("read", "edit"):
        flash("Invalid sharing permission.", "error")
        return redirect(url_for("documents"))

    recipient = db.session.execute(
        db.select(User).filter_by(email=recipient_email)
    ).scalar_one_or_none()

    if recipient is None:
        flash("No registered user found with that email.", "error")
        return redirect(url_for("documents"))

    if recipient.id == user.id:
        flash("You cannot share a document with yourself.", "error")
        return redirect(url_for("documents"))

    try:
        existing_share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=document.id,
                shared_with_user_id=recipient.id
            )
        ).scalar_one_or_none()

        if existing_share:
            flash("This document is already shared with that user.", "error")
            return redirect(url_for("documents"))

        share = DocumentShare(
            document_id=document.id,
            shared_with_user_id=recipient.id,
            permission=permission
        )

        audit = AuditLog(
            user_id=user.id,
            action="SHARE",
            document_id=document.id,
            document_name=document.original_filename
        )

        db.session.add(share)
        db.session.add(audit)
        db.session.commit()

        flash("Document shared successfully.", "success")

    except Exception:
        db.session.rollback()
        app.logger.exception("Document sharing failed")
        flash("Sharing failed. Please try again.", "error")

    return redirect(url_for("documents")) 

@app.route(
    "/documents/<int:document_id>/revoke/<int:recipient_id>",
    methods=["POST"]
)
def revoke_document_share(document_id, recipient_id):
    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # Only the document owner can revoke access
    document = db.session.execute(
        db.select(Document).filter_by(
            id=document_id,
            user_id=user.id
        )
    ).scalar_one_or_none()

    if document is None:
        abort(404)

    # Find the recipient's share record
    share = db.session.execute(
        db.select(DocumentShare).filter_by(
            document_id=document.id,
            shared_with_user_id=recipient_id
        )
    ).scalar_one_or_none()

    if share is None:
        flash("Sharing record not found.", "error")
        return redirect(url_for("documents"))

    try:
        audit = AuditLog(
            user_id=user.id,
            action="REVOKE_SHARE",
            document_id=document.id,
            document_name=document.original_filename
        )

        db.session.add(audit)
        db.session.delete(share)
        db.session.commit()

        flash("Document access revoked successfully.", "success")

    except Exception:
        db.session.rollback()
        app.logger.exception("Could not revoke document access")
        flash("Could not revoke access. Please try again.", "error")

    return redirect(url_for("documents"))
  




@app.route("/audit")
def audit_history():
    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # Only administrators can view global audit history.
    if user.role != "admin":
        flash(
            "Access denied. Administrator privileges are required.",
            "error"
        )
        abort(403)

    selected_action = request.args.get("action", "").strip()

    query = (
        db.select(AuditLog, User)
        .join(User, AuditLog.user_id == User.id)
        .order_by(AuditLog.timestamp.desc())
    )

    if selected_action:
        query = query.filter(AuditLog.action == selected_action)

    logs = db.session.execute(query).all()

    return render_template(
        "audit_logs.html",
        logs=logs,
        selected_action=selected_action
    )





if os.getenv("SKIP_DB_INIT") != "1":
    with app.app_context():
        db.create_all()

@app.route("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # Count documents owned by this user
    total_documents = db.session.execute(
        db.select(db.func.count(Document.id))
        .filter_by(user_id=user.id)
    ).scalar_one()

    # Count documents shared with this user
    shared_with_me = db.session.execute(
        db.select(db.func.count(DocumentShare.id))
        .filter_by(shared_with_user_id=user.id)
    ).scalar_one()

    # Count sharing permissions created for documents owned by this user
    shared_by_me = db.session.execute(
        db.select(db.func.count(DocumentShare.id))
        .join(
            Document,
            Document.id == DocumentShare.document_id
        )
        .filter(Document.user_id == user.id)
    ).scalar_one()

    # Get recent actions performed by this user
    recent_logs = db.session.execute(
        db.select(AuditLog)
        .filter_by(user_id=user.id)
        .order_by(AuditLog.timestamp.desc())
        .limit(5)
    ).scalars().all()

    return render_template(
        "dashboard.html",
        user=user,
        total_documents=total_documents,
        shared_with_me=shared_with_me,
        shared_by_me=shared_by_me,
        recent_logs=recent_logs,
        is_admin=(user.role == "admin")
    )
    
@app.route("/admin/users")
@admin_required
def admin_users():
    users = db.session.execute(
        db.select(User).order_by(User.id.desc())
    ).scalars().all()

    return render_template(
        "admin_users.html",
        users=users
    )



if __name__ == "__main__":
    app.run(debug=True)
