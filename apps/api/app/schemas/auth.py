import re

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.schemas.team import TeamMembershipSummary
from app.schemas.user import UserSummary


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> EmailStr:
        return value.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if len(value) < 8 or len(value) > 128:
            raise ValueError("Password must have 8 to 128 characters.")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must include a lowercase letter.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must include an uppercase letter.")
        if not re.search(r"\d", value):
            raise ValueError("Password must include a number.")
        return value


class TokenResponse(BaseModel):
    access_token: str | None = None
    token_type: str
    expires_in: int
    user: UserSummary
    memberships: list[TeamMembershipSummary]
