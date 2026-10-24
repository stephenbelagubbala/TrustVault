
from urllib import response

import pytest

from app import app, db, User, Document, DocumentShare, AuditLog


@pytest.fixture
def setup_app(tmp_path):
    database_path = tmp_path / "test_trustvault.db"
    upload_path = tmp_path / "uploads"
    upload_path.mkdir()

    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{database_path.as_posix()}",
        UPLOAD_FOLDER=str(upload_path),
        SECRET_KEY="test-only-secret",
    )

    with app.app_context():
        db.create_all()

        owner = User(
            name="Owner",
            email="owner@example.com",
            password_hash="test-hash",
        )
        reader = User(
            name="Reader",
            email="reader@example.com",
            password_hash="test-hash",
        )
        editor = User(
            name="Editor",
            email="editor@example.com",
            password_hash="test-hash",
        )
        outsider = User(
            name="Outsider",
            email="outsider@example.com",
            password_hash="test-hash",
        )

        db.session.add_all([owner, reader, editor, outsider])
        db.session.flush()

        document = Document(
            original_filename="sample.txt",
            stored_filename="sample.txt",
            user_id=owner.id,
            category="Testing",
        )
        db.session.add(document)
        db.session.flush()

        db.session.add_all([
            DocumentShare(
                document_id=document.id,
                shared_with_user_id=reader.id,
                permission="read",
            ),
            DocumentShare(
                document_id=document.id,
                shared_with_user_id=editor.id,
                permission="edit",
            ),
        ])

        db.session.commit()

        # Create a harmless test file in the temporary upload folder.
        (upload_path / "sample.txt").write_text(
            "Test document",
            encoding="utf-8",
        )

        data = {
            "owner_id": owner.id,
            "reader_id": reader.id,
            "editor_id": editor.id,
            "outsider_id": outsider.id,
            "document_id": document.id,
        }

    yield data

    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(setup_app):
    with app.test_client() as test_client:
        yield test_client


def login_as(client, user_id):
    with client.session_transaction() as session:
        session["user_id"] = user_id


def test_unauthenticated_user_is_redirected(client, setup_app):
    response = client.get(
        f"/documents/{setup_app['document_id']}/details"
    )
    assert response.status_code == 302


def test_unshared_user_cannot_view_document(client, setup_app):
    login_as(client, setup_app["outsider_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/details"
    )
    assert response.status_code == 404


def test_read_permission_allows_download(client, setup_app):
    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/download"
    )
    assert response.status_code == 200


def test_read_permission_does_not_allow_edit(client, setup_app):
    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/edit"
    )
    assert response.status_code == 403


def test_edit_permission_allows_edit_page(client, setup_app):
    login_as(client, setup_app["editor_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/edit"
    )
    assert response.status_code == 200


def test_revoked_share_cannot_view_document(client, setup_app):
    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["reader_id"],
            )
        ).scalar_one()

        db.session.delete(share)
        db.session.commit()

    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/details"
    )
    assert response.status_code == 404

def test_revoked_share_cannot_download_document(client, setup_app):
    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["reader_id"],
            )
        ).scalar_one()

        db.session.delete(share)
        db.session.commit()

    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/download"
    )
    assert response.status_code == 404

def test_owner_can_revoke_share_and_audit_it(client, setup_app):
    login_as(client, setup_app["owner_id"])

    response = client.post(
        f"/documents/{setup_app['document_id']}/revoke/"
        f"{setup_app['reader_id']}",
        follow_redirects=False,
    )

    assert response.status_code == 302

    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["reader_id"],
            )
        ).scalar_one_or_none()

        assert share is None

        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                action="REVOKE_SHARE",
                document_id=setup_app["document_id"],
                user_id=setup_app["owner_id"],
            )
        ).scalar_one_or_none()

        assert audit is not None

def test_non_owner_cannot_revoke_share(client, setup_app):
    login_as(client, setup_app["reader_id"])

    response = client.post(
        f"/documents/{setup_app['document_id']}/revoke/"
        f"{setup_app['editor_id']}",
        follow_redirects=False,
    )

    assert response.status_code == 404

    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["editor_id"],
            )
        ).scalar_one_or_none()

        assert share is not None


def test_revoked_editor_cannot_edit_document(client, setup_app):
    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["editor_id"],
            )
        ).scalar_one()

        db.session.delete(share)
        db.session.commit()

    login_as(client, setup_app["editor_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/edit"
    )

    assert response.status_code == 403

def test_editor_can_update_document_details(client, setup_app):
    login_as(client, setup_app["editor_id"])

    response = client.post(
        f"/documents/{setup_app['document_id']}/edit",
        data={
            "original_filename": "updated.txt",
            "category": "Updated Category",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302

    with app.app_context():
        document = db.session.get(Document, setup_app["document_id"])
        assert document.original_filename == "updated.txt"
        assert document.category == "Updated Category"
def test_denied_download_is_audited(client, setup_app):
    login_as(client, setup_app["outsider_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/download"
    )
    assert response.status_code == 404

    with app.app_context():
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                user_id=setup_app["outsider_id"],
                action="DENIED_DOWNLOAD",
                document_id=setup_app["document_id"],
            )
        ).scalar_one_or_none()

        assert audit is not None

def test_successful_download_is_audited(client, setup_app):
    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/download"
    )

    assert response.status_code == 200

    with app.app_context():
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                user_id=setup_app["reader_id"],
                action="DOWNLOAD",
                document_id=setup_app["document_id"],
            )
        ).scalar_one_or_none()

        assert audit is not None


def test_successful_edit_is_audited(client, setup_app):
    login_as(client, setup_app["editor_id"])

    response = client.post(
        f"/documents/{setup_app['document_id']}/edit",
        data={
            "original_filename": "audited-edit.txt",
            "category": "Audit Test",
        },
        follow_redirects=False,
    )

    assert response.status_code == 302

    with app.app_context():
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                user_id=setup_app["editor_id"],
                action="EDIT",
                document_id=setup_app["document_id"],
                document_name="audited-edit.txt",
            )
        ).scalar_one_or_none()

        assert audit is not None

def test_denied_edit_is_audited(client, setup_app):
    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/edit"
    )
    assert response.status_code == 403

    with app.app_context():
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                user_id=setup_app["reader_id"],
                action="DENIED_EDIT",
                document_id=setup_app["document_id"],
            )
        ).scalar_one_or_none()

        assert audit is not None


def test_denied_delete_is_audited(client, setup_app):
    login_as(client, setup_app["reader_id"])

    response = client.post(
        f"/documents/{setup_app['document_id']}/delete"
    )
    assert response.status_code == 403

    with app.app_context():
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                user_id=setup_app["reader_id"],
                action="DENIED_DELETE",
                document_id=setup_app["document_id"],
            )
        ).scalar_one_or_none()

        assert audit is not None
def test_csrf_rejects_post_without_token(client, setup_app):
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post(
            f"/documents/{setup_app['document_id']}/delete"
        )
        assert response.status_code == 400
    finally:
        app.config["WTF_CSRF_ENABLED"] = False

def test_expired_share_cannot_view_document(client, setup_app):
    from datetime import datetime, timedelta, timezone

    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["reader_id"],
            )
        ).scalar_one()

        share.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).replace(tzinfo=None)

        db.session.commit()

    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/details"
    )

    assert response.status_code == 404


def test_expired_share_cannot_download_document(client, setup_app):
    from datetime import datetime, timedelta, timezone

    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["reader_id"],
            )
        ).scalar_one()

        share.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).replace(tzinfo=None)

        db.session.commit()

    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/download"
    )

    assert response.status_code == 404


def test_expired_edit_share_cannot_edit_document(client, setup_app):
    from datetime import datetime, timedelta, timezone

    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["editor_id"],
            )
        ).scalar_one()

        share.expires_at = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).replace(tzinfo=None)

        db.session.commit()

    login_as(client, setup_app["editor_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/edit"
    )

    assert response.status_code == 403
def test_future_expiry_allows_document_download(client, setup_app):
    from datetime import datetime, timedelta, timezone

    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["reader_id"],
            )
        ).scalar_one()

        share.expires_at = (
            datetime.now(timezone.utc) + timedelta(days=1)
        ).replace(tzinfo=None)

        db.session.commit()

    login_as(client, setup_app["reader_id"])

    response = client.get(
        f"/documents/{setup_app['document_id']}/download"
    )

    assert response.status_code == 200


def test_past_expiry_is_rejected_when_sharing(client, setup_app):
    from datetime import datetime, timedelta, timezone

    login_as(client, setup_app["owner_id"])

    # Use the outsider, who has no existing share for this document.
    past_time = (
        datetime.now(timezone.utc) - timedelta(hours=1)
    ).strftime("%Y-%m-%dT%H:%M")

    response = client.post(
        f"/documents/{setup_app['document_id']}/share",
        data={
            "email": "outsider@example.com",
            "permission": "read",
            "expires_at": past_time,
        },
    )

    assert response.status_code == 302

    with app.app_context():
        share = db.session.execute(
            db.select(DocumentShare).filter_by(
                document_id=setup_app["document_id"],
                shared_with_user_id=setup_app["outsider_id"],
            )
        ).scalar_one_or_none()

        assert share is None
def test_document_deletion_preserves_audit_history(client, setup_app):
    login_as(client, setup_app["owner_id"])

    response = client.post(
        f"/documents/{setup_app['document_id']}/delete"
    )

    assert response.status_code == 302

    with app.app_context():
        # The document should be deleted.
        document = db.session.get(
            Document, setup_app["document_id"]
        )
        assert document is None

        # The deletion audit record should remain.
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                user_id=setup_app["owner_id"],
                action="DELETE",
                document_name="sample.txt",
            )
        ).scalar_one_or_none()

        assert audit is not None

def test_admin_dashboard_shows_global_activity(client, setup_app):
    with app.app_context():
        admin = User(
            name="Admin",
            email="admin@example.com",
            password_hash="test-hash",
            role="admin",
        )
        db.session.add(admin)
        db.session.flush()

        db.session.add_all([
            AuditLog(
                user_id=setup_app["owner_id"],
                action="UPLOAD",
                document_name="owner-activity.txt",
            ),
            AuditLog(
                user_id=setup_app["reader_id"],
                action="DOWNLOAD",
                document_name="reader-activity.txt",
            ),
        ])
        db.session.commit()
        admin_id = admin.id

    login_as(client, admin_id)
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"owner-activity.txt" in response.data
    assert b"reader-activity.txt" in response.data


def test_normal_user_dashboard_shows_only_own_activity(
    client, setup_app
):
    with app.app_context():
        db.session.add_all([
            AuditLog(
                user_id=setup_app["owner_id"],
                action="UPLOAD",
                document_name="owner-private-activity.txt",
            ),
            AuditLog(
                user_id=setup_app["reader_id"],
                action="DOWNLOAD",
                document_name="reader-private-activity.txt",
            ),
        ])
        db.session.commit()

    login_as(client, setup_app["owner_id"])
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert b"owner-private-activity.txt" in response.data
    assert b"reader-private-activity.txt" not in response.data

import io


def test_successful_upload_is_audited(client, setup_app):
    import io

    login_as(client, setup_app["owner_id"])

    response = client.post(
        "/documents",
        data={
            "file": (
                io.BytesIO(b"TrustVault audit test"),
                "audit-test.txt",
            ),
            "category": "Audit Test",
        },
        content_type="multipart/form-data",
        follow_redirects=False,
    )

    assert response.status_code == 200

    with app.app_context():
        document = db.session.execute(
            db.select(Document).filter_by(
                user_id=setup_app["owner_id"],
                original_filename="audit-test.txt",
            )
        ).scalar_one_or_none()

        assert document is not None

        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                user_id=setup_app["owner_id"],
                action="UPLOAD",
                document_id=document.id,
                document_name="audit-test.txt",
            )
        ).scalar_one_or_none()

        assert audit is not None

def test_upload_rejects_unsupported_extension(client, setup_app):
    login_as(client, setup_app["owner_id"])

    response = client.post(
        "/documents",
        data={
            "file": (io.BytesIO(b"fake executable"), "malware.exe"),
            "category": "Testing",
        },
        content_type="multipart/form-data",
    )

    print("STATUS:", response.status_code)
    print("RESPONSE:", response.get_data(as_text=True)[:1500])
    assert response.status_code == 302

    with app.app_context():
        document = db.session.execute(
            db.select(Document).filter_by(
                original_filename="malware.exe"
            )
        ).scalar_one_or_none()

        assert document is None


def test_upload_rejects_filename_without_extension(client, setup_app):
    login_as(client, setup_app["owner_id"])

    response = client.post(
        "/documents",
        data={
            "file": (io.BytesIO(b"test content"), "invalidname"),
            "category": "Testing",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302

    with app.app_context():
        document = db.session.execute(
            db.select(Document).filter_by(
                original_filename="invalidname"
            )
        ).scalar_one_or_none()

        assert document is None


def test_upload_rejects_file_larger_than_5mb(client, setup_app):
    login_as(client, setup_app["owner_id"])

    response = client.post(
        "/documents",
        data={
            "file": (
                io.BytesIO(b"A" * (5 * 1024 * 1024 + 1)),
                "large.txt",
            ),
            "category": "Testing",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 413

    with app.app_context():
        document = db.session.execute(
            db.select(Document).filter_by(
                original_filename="large.txt"
            )
        ).scalar_one_or_none()

        assert document is None
def test_upload_rejects_fake_pdf(client, setup_app):
    login_as(client, setup_app["owner_id"])

    response = client.post(
        "/documents",
        data={
            "file": (
                io.BytesIO(b"not a real PDF"),
                "fake.pdf",
            ),
            "category": "Testing",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302

    with app.app_context():
        document = db.session.execute(
            db.select(Document).filter_by(
                original_filename="fake.pdf"
            )
        ).scalar_one_or_none()

        assert document is None


def test_upload_rejects_fake_png(client, setup_app):
    login_as(client, setup_app["owner_id"])

    response = client.post(
        "/documents",
        data={
            "file": (
                io.BytesIO(b"not a real PNG"),
                "fake.png",
            ),
            "category": "Testing",
        },
        content_type="multipart/form-data",
    )

    assert response.status_code == 302

    with app.app_context():
        document = db.session.execute(
            db.select(Document).filter_by(
                original_filename="fake.png"
            )
        ).scalar_one_or_none()

        assert document is None