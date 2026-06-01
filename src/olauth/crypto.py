import bcrypt

def hash_password(password: str) -> str:
    """Derives a secure cryptographic hash from a plaintext password using bcrypt."""
    password_bytes = password.encode('utf-8')

    # Explicitly configure a standard work factor (12 rounds) to balance security and performance
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)

    return hashed_bytes.decode('utf-8')


def verify_password(password: str, hashed_password: str) -> bool:
    """Performs a constant-time cryptographic check to prevent timing attacks."""
    password_bytes = password.encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    
    # Safely extract salt properties internally from the stored hash string
    return bcrypt.checkpw(password_bytes, hashed_bytes)