import sqlite3
import os
import hashlib
import bcrypt

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'passwords.db')

# Cryptographic Pepper added to the password before hashing for fingerprint creation.
# This prevents database precomputation / rainbow table attacks on the fingerprints.
# In production, set the 'SHIELD_PEPPER' environment variable to a secure value.
SERVER_PEPPER = os.environ.get("SHIELD_PEPPER", "SHIELD_DEFAULT_FALLBACK_PEPPER_2026_@!")

def get_db_connection():
    """
    Establish and return a connection to the SQLite database.
    """
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """
    Initialize the SQLite database and create the password_history table.
    Ensures a unique fingerprint index for rapid O(1) lookups.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Create an index on the fingerprint column if it doesn't automatically exist
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_fingerprint ON password_history(fingerprint)')
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        conn.close()

def get_password_fingerprint(password):
    """
    Generate a SHA-256 fingerprint of the password combined with the server pepper.
    This allows fast O(1) indexing lookup on subsequent checks.
    """
    salted_pwd = password + SERVER_PEPPER
    return hashlib.sha256(salted_pwd.encode('utf-8')).hexdigest()

def is_password_used(password):
    """
    Checks if a password has been previously analyzed and saved.
    
    Uses O(1) SHA-256 fingerprint search first. If matched, verifies with bcrypt
    to prevent false positives from potential (though highly unlikely) SHA-256 collisions.
    """
    if not password:
        return False
        
    fingerprint = get_password_fingerprint(password)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT password_hash FROM password_history WHERE fingerprint = ? LIMIT 1',
            (fingerprint,)
        )
        row = cursor.fetchone()
        if row is None:
            return False
            
        # Perform cryptographically secure bcrypt verification
        stored_hash = row['password_hash']
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    except sqlite3.Error as e:
        print(f"Database query error: {e}")
        return False
    finally:
        conn.close()

def add_password_hash(password):
    """
    Stores the password securely in the database history vault.
    
    1. Generates a peppered SHA-256 fingerprint for fast indexed lookup.
    2. Generates a slow, salted bcrypt hash of the password for verification security.
    3. Commits them both to the SQLite database.
    """
    if not password:
        return False
        
    fingerprint = get_password_fingerprint(password)
    
    # Generate a slow, salted bcrypt hash (work factor of 12 is standard and secure)
    salt = bcrypt.gensalt(rounds=12)
    bcrypt_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # INSERT OR IGNORE will fail silently if fingerprint already exists
        cursor.execute(
            'INSERT OR IGNORE INTO password_history (fingerprint, password_hash) VALUES (?, ?)',
            (fingerprint, bcrypt_hash)
        )
        conn.commit()
        # Returns True if a new row was inserted, False if ignored (already exists)
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"Database insert error: {e}")
        return False
    finally:
        conn.close()
