"""
Database Schemas for TapPay

Each Pydantic model represents a MongoDB collection. Collection name is the
lowercase of the class name (e.g., User -> "user").
"""
from typing import Optional
from pydantic import BaseModel, Field

class User(BaseModel):
    """Users collection schema
    Collection name: "user"
    """
    name: str = Field(..., description="Full name")
    handle: str = Field(..., description="Unique @handle, lowercase, no spaces")
    profileImg: Optional[str] = Field(None, description="Profile image URL")
    qrCodeUrl: Optional[str] = Field(None, description="URL to QR code image or endpoint")
    password_hash: str = Field(..., description="BCrypt password hash")
    dateCreated: Optional[str] = Field(None, description="ISO timestamp when created")

class Transaction(BaseModel):
    """Transactions collection schema
    Collection name: "transaction"
    """
    fromUser: str = Field(..., description="Sender userId (string)")
    toUser: str = Field(..., description="Receiver userId (string)")
    amount: float = Field(..., gt=0, description="Amount sent")
    timestamp: Optional[str] = Field(None, description="ISO timestamp of transaction")
