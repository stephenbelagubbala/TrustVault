
from app import app, db, User

def make_admin():
    email = input("Enter your registered email: ").strip().lower()

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(email=email)
        ).scalar_one_or_none()

        if user is None:
            print("User not found. Check your email.")
            return

        print(f"User: {user.name}")
        print(f"Current role: {user.role}")

        confirm = input("Make this user an admin? (yes/no): ").strip().lower()

        if confirm == "yes":
            user.role = "admin"
            db.session.commit()
            print("Success! User is now an administrator.")
        else:
            print("Cancelled. No changes made.")

if __name__ == "__main__":
    make_admin()
