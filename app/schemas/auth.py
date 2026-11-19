from datetime import datetime

from pydantic import BaseModel, EmailStr, Field


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "UserOut"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class UserOut(BaseModel):
    id: int
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(default="", max_length=160)
    password: str = Field(min_length=10, max_length=72)
    role: str = Field(default="analyst", pattern="^(admin|analyst|viewer)$")


class UserUpdate(BaseModel):
    role: str | None = Field(default=None, pattern="^(admin|analyst|viewer)$")
    is_active: bool | None = None


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=72)
    new_password: str = Field(min_length=10, max_length=72)


Token.model_rebuild()
