"""Password hashing. Deliberately vulnerable: unsalted MD5 (CWE-328)."""
import hashlib


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def check_password(password, stored_hash):
    return hash_password(password) == stored_hash
