import re

from pydantic import BaseModel, EmailStr, Field, field_validator

NAME_REGEX = r"^[A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9 .,'_-]{2,254}$"
ALLOWED_ROLES = {"minimum", "analyst", "manager", "admin"}


class UserSummary(BaseModel):
    id: str
    tenant_id: str
    email: EmailStr
    full_name: str
    role: str
    status: str


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=3, max_length=255, pattern=NAME_REGEX)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> EmailStr:
        return value.strip().lower()

    @field_validator("full_name")
    @classmethod
    def sanitize_name(cls, value: str) -> str:
        return " ".join(value.strip().split())

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


class UserRegister(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=3, max_length=255, pattern=NAME_REGEX)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_register_email(cls, value: EmailStr) -> EmailStr:
        return value.strip().lower()

    @field_validator("full_name")
    @classmethod
    def sanitize_register_name(cls, value: str) -> str:
        return " ".join(value.strip().split())

    @field_validator("password")
    @classmethod
    def validate_register_password(cls, value: str) -> str:
        if len(value) < 8 or len(value) > 128:
            raise ValueError("Password must have 8 to 128 characters.")
        if not re.search(r"[a-z]", value):
            raise ValueError("Password must include a lowercase letter.")
        if not re.search(r"[A-Z]", value):
            raise ValueError("Password must include an uppercase letter.")
        if not re.search(r"\d", value):
            raise ValueError("Password must include a number.")
        return value


class UserRoleUpdate(BaseModel):
    role: str = Field(min_length=3, max_length=50)

    @field_validator("role")
    @classmethod
    def normalize_role(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in ALLOWED_ROLES:
            raise ValueError("Invalid role.")
        return normalized


class UserListItem(UserSummary):
    pass
