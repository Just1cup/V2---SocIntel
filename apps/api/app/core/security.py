from datetime import datetime, timedelta, timezone
import secrets

from jose import jwt
from passlib.context import CryptContext

from app.core.config import settings

password_context = CryptContext(schemes=["argon2"], deprecated="auto")


def create_access_token(subject: str, expires_delta: timedelta, extra_claims: dict | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + expires_delta).timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return password_context.verify(password, password_hash)


def generate_password_salt() -> str:
    return secrets.token_hex(16)


def hash_password_with_salt(password: str, password_salt: str) -> str:
    return hash_password(f"{password_salt}:{password}")


def verify_password_with_optional_salt(password: str, password_hash: str, password_salt: str | None) -> bool:
    if password_salt:
        return verify_password(f"{password_salt}:{password}", password_hash)
    return verify_password(password, password_hash)
