
import sqlite3
from pathlib import Path

# Database location
DB_PATH = Path(__file__).resolve().parent / "instance" / "trustvault.db"


def migrate():
    connection = sqlite3.connect(DB_PATH)

    try:
        cursor = connection.cursor()

        # Required fields for TrustVault
        migrations = {
            "user": {
                "role": "VARCHAR(20) NOT NULL DEFAULT 'owner'"
            },
            "document": {
                "category": "VARCHAR(80) NOT NULL DEFAULT 'Uncategorized'"
            },
            "document_share": {
                "permission": "VARCHAR(10) NOT NULL DEFAULT 'read'",
                "expires_at": "DATETIME"
            },
        }

        for table, new_columns in migrations.items():
            existing_columns = {
                row[1]
                for row in cursor.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }

            for column, definition in new_columns.items():
                if column not in existing_columns:
                    cursor.execute(
                        f"ALTER TABLE {table} "
                        f"ADD COLUMN {column} {definition}"
                    )
                    print(f"Added {table}.{column}")
                else:
                    print(f"Already exists: {table}.{column}")

        connection.commit()
        print("\nDatabase migration completed successfully!")

    except Exception as error:
        connection.rollback()
        print(f"Migration failed: {error}")
        raise

    finally:
        connection.close()


if __name__ == "__main__":
    migrate()
