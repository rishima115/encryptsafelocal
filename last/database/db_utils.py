import sqlite3
import os
import bcrypt

# Path to the database file
DB_PATH = os.path.join("database", "password_manager.db")

# Alias for DB_PATH for backward compatibility
DATABASE_FILE = DB_PATH

def register_user(username, password):
    """
    Registers a new user by storing their username and hashed password.
    :param username: The username to register.
    :param password: The plain-text password to hash and store.
    :return: True if registration is successful, False if username already exists.
    """
    try:
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Insert user into the database
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False
    except Exception as e:
        print(f"Error registering user: {e}")
        return False
    finally:
        conn.close()

def authenticate_user(username, password):
    """
    Authenticates the user with the given username and password.
    :param username: The username provided by the user.
    :param password: The plain-text password provided by the user.
    :return: True if authentication is successful, False otherwise.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()

        if result is None:
            return False

        # Check hashed password
        stored_hashed_password = result[0]
        return bcrypt.checkpw(password.encode("utf-8"), stored_hashed_password.encode("utf-8"))
    except Exception as e:
        print(f"Error authenticating user: {e}")
        return False
    finally:
        conn.close()
