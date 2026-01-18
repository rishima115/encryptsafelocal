import sqlite3
import os

def setup_database():
    # Ensure directory exists
    os.makedirs("database", exist_ok=True)
    db_path = os.path.join("database", "password_manager.db")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create users table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
    """)

    # Create passwords table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        app_name TEXT NOT NULL,
        encrypted_password BLOB NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

    print("Database setup complete!")

# Call this function
if __name__ == "__main__":
    setup_database()
