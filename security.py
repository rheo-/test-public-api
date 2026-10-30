import hashlib
import secrets
import hmac
import re

USER_ID_MIN_LENGTH = 6
USER_ID_MAX_LENGTH = 20
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 20

# user_id must be alphanumeric
USER_ID_REGEX = re.compile(r"^[a-zA-Z0-9]+$")
# password must be ASCII printable characters excluding whitespace
PASSWORD_REGEX = re.compile(r"^[\x21-\x7e]+$")


def validate_signup_credentials(user_id, password) -> str | None:
    """
    Validates user_id and password according to signup constraints.
    Returns cause string if validation fails, or None if valid.
    """
    if (
        user_id is None
        or password is None
        or not isinstance(user_id, str)
        or not isinstance(password, str)
        or len(user_id) == 0
        or len(password) == 0
    ):
        return "Required user_id and password"

    if not (USER_ID_MIN_LENGTH <= len(user_id) <= USER_ID_MAX_LENGTH) or not (
        PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH
    ):
        return "Input length is incorrect"

    if not USER_ID_REGEX.match(user_id) or not PASSWORD_REGEX.match(password):
        return "Incorrect character pattern"

    return None


def hash_password(password: str):
    salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        600_000
    ).hex()

    return salt, password_hash


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        600_000
    ).hex()

    return hmac.compare_digest(actual_hash, expected_hash)