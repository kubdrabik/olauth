import base64
import hashlib
import hmac
import secrets
import threading

try:
    import bcrypt
except ImportError:  # pragma: no cover - fallback when bcrypt is unavailable
    bcrypt = None

_BCRYPT_ROUNDS = 12
_BCRYPT_MAX_BYTES = 72
_PBKDF2_ITERATIONS = 600_000
_DUMMY_LOCK = threading.Lock()
_DUMMY_HASH: str | None = None


def _hash_pbkdf2(password_bytes: bytes) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, _PBKDF2_ITERATIONS)
    salt_b64 = base64.b64encode(salt).decode("ascii")
    dk_b64 = base64.b64encode(dk).decode("ascii")
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt_b64}${dk_b64}"


def _verify_pbkdf2(password_bytes: bytes, hashed_password: str) -> bool:
    try:
        scheme, iter_str, salt_b64, dk_b64 = hashed_password.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected_dk = base64.b64decode(dk_b64.encode("ascii"))
    except (ValueError, TypeError):
        return False

    actual_dk = hashlib.pbkdf2_hmac("sha256", password_bytes, salt, iterations)
    return hmac.compare_digest(actual_dk, expected_dk)


def _get_dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        with _DUMMY_LOCK:
            if _DUMMY_HASH is None:
                _DUMMY_HASH = hash_password("olauth-dummy-timing-guard")
    return _DUMMY_HASH


def hash_password(password: str) -> str:
    """Derives a secure cryptographic hash from a plaintext password."""
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")
    password_bytes = password.encode("utf-8")

    if bcrypt is None:
        return _hash_pbkdf2(password_bytes)

    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    if len(password_bytes) > _BCRYPT_MAX_BYTES:
        # Pre-hash passwords exceeding bcrypt's 72-byte limit while keeping standard <=72B compatible.
        digest = hashlib.sha256(password_bytes).hexdigest().encode("ascii")
        hashed_bytes = bcrypt.hashpw(digest, salt)
        return f"bcrypt_sha256${hashed_bytes.decode('utf-8')}"

    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes.decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    """Performs a constant-time cryptographic check to prevent timing attacks."""
    if not isinstance(password, str) or not isinstance(hashed_password, str) or not hashed_password:
        return False

    password_bytes = password.encode("utf-8")

    if hashed_password.startswith("pbkdf2_sha256$"):
        return _verify_pbkdf2(password_bytes, hashed_password)

    if bcrypt is None:
        return False

    if hashed_password.startswith("bcrypt_sha256$"):
        raw_bcrypt_hash = hashed_password[len("bcrypt_sha256$"):].encode("utf-8")
        digest = hashlib.sha256(password_bytes).hexdigest().encode("ascii")
        try:
            return bcrypt.checkpw(digest, raw_bcrypt_hash)
        except ValueError:
            return False

    if len(password_bytes) > _BCRYPT_MAX_BYTES:
        # Run a dummy check so timing remains comparable without triggering bcrypt's 72-byte ValueError.
        try:
            bcrypt.checkpw(b"olauth-oversized-guard", hashed_password.encode("utf-8"))
        except ValueError:
            pass
        return False

    try:
        return bcrypt.checkpw(password_bytes, hashed_password.encode("utf-8"))
    except ValueError:
        return False


def verify_password_constant_time(password: str, hashed_password: str | None) -> bool:
    """Verifies a password even when no user record exists to resist timing enumeration."""
    if not hashed_password:
        verify_password(password if isinstance(password, str) else "", _get_dummy_hash())
        return False
    return verify_password(password, hashed_password)


def hash_token(token: str) -> str:
    """Returns a SHA-256 hex digest for safely storing opaque session tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
