import sqlite3
import os

class DatabaseManager:
    """Manages local SQLite connections, schemas, and data persistence layers."""
    
    def __init__(self):
        self.connection = None

    def initialize_db(self, db_path=None):
        """Establishes database connection, configures execution pragmas, and builds schemas."""
        if db_path is None:
            db_path = "olauth.db"
        elif db_path.startswith("sqlite:///"):
            db_path = db_path.replace("sqlite:///", "")

        # check_same_thread=False allows cross-thread connection sharing required by web servers
        self.connection = sqlite3.connect(db_path, check_same_thread=False)
        
        # Enable key-value row factories for clean, dict-like record lookups
        self.connection.row_factory = sqlite3.Row

        cursor = self.connection.cursor()
        
        # Write-Ahead Logging yields high-concurrency performance under concurrent web traffic
        cursor.execute("PRAGMA journal_mode=WAL;")

        # --- SCHEMA PROVISIONING ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS olauth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        """)

        self.connection.commit()
        print(f"[OL-Auth] Database initialized and secured at: {db_path}")

    # --- DATA READ/WRITE OPERATIONS ---

    def create_user(self, email, hashed_password):
        """Inserts a new secure user record. Returns False on unique constraint conflicts."""
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email.lower().strip(), hashed_password)
            )
            self.connection.commit()
            return True
        except sqlite3.IntegrityError:
            # Trap unique email errors smoothly without breaking the application runtime
            return False

    def get_user_by_email(self, email):
        """Queries the identity table for an exact email match returning a row-mapped instance."""
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT id, email, password_hash FROM users WHERE email = ?",
            (email.lower().strip(),)
        )
        return cursor.fetchone()