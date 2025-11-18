import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import Response
from jose import jwt, JWTError
from passlib.context import CryptContext
from bson import ObjectId

from database import db

# ----------------------
# App & Security Setup
# ----------------------
app = FastAPI(title="TapPay API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv("JWT_SECRET", "dev-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()

# ----------------------
# Helpers
# ----------------------

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user_doc = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user_doc:
            raise HTTPException(status_code=401, detail="User not found")
        return user_doc
    except JWTError:
        raise HTTPException(status_code=401, detail="Token decode error")


# ----------------------
# Health/Test
# ----------------------
@app.get("/")
def read_root():
    return {"message": "TapPay API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            # Touch database to verify connection
            response["database"] = "✅ Connected"
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()[:10]
    except Exception as e:
        response["database"] = f"⚠️ {str(e)[:60]}"
    return response


# ----------------------
# Schemas (simple inline to avoid circular imports)
# ----------------------
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List

class UserCreate(BaseModel):
    name: str
    handle: str = Field(..., pattern=r"^[a-z0-9_]{3,20}$")
    email: EmailStr
    password: str
    profileImg: Optional[str] = None

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TransactionCreate(BaseModel):
    toHandle: Optional[str] = None
    toUserId: Optional[str] = None
    amount: float = Field(..., gt=0)

# ----------------------
# Auth Routes
# ----------------------
@app.post("/auth/signup")
def signup(payload: UserCreate):
    if db["user"].find_one({"handle": payload.handle}):
        raise HTTPException(status_code=400, detail="Handle already taken")
    if db["user"].find_one({"email": str(payload.email).lower()}):
        raise HTTPException(status_code=400, detail="Email already registered")

    password_hash = pwd_context.hash(payload.password)
    user_doc = {
        "name": payload.name,
        "handle": payload.handle,
        "email": str(payload.email).lower(),
        "password_hash": password_hash,
        "profileImg": payload.profileImg,
        "qrCodeUrl": None,
        "dateCreated": datetime.now(timezone.utc),
    }
    result_id = db["user"].insert_one(user_doc).inserted_id

    token = create_access_token({"sub": str(result_id)})
    return {
        "token": token,
        "user": {
            "id": str(result_id),
            "name": user_doc["name"],
            "handle": user_doc["handle"],
            "profileImg": user_doc.get("profileImg"),
            "qrCodeUrl": user_doc.get("qrCodeUrl"),
            "dateCreated": user_doc["dateCreated"],
        }
    }


@app.post("/auth/login")
def login(payload: UserLogin):
    user_doc = db["user"].find_one({"email": str(payload.email).lower()})
    if not user_doc:
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if not pwd_context.verify(payload.password, user_doc.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_access_token({"sub": str(user_doc["_id"])})
    return {
        "token": token,
        "user": {
            "id": str(user_doc["_id"]),
            "name": user_doc["name"],
            "handle": user_doc["handle"],
            "profileImg": user_doc.get("profileImg"),
            "qrCodeUrl": user_doc.get("qrCodeUrl"),
            "dateCreated": user_doc["dateCreated"],
        }
    }


# ----------------------
# Profile & QR Routes
# ----------------------
@app.get("/profile/{handle}")
def get_profile(handle: str):
    user_doc = db["user"].find_one({"handle": handle})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "id": str(user_doc["_id"]),
        "name": user_doc["name"],
        "handle": user_doc["handle"],
        "profileImg": user_doc.get("profileImg"),
        "qrCodeUrl": user_doc.get("qrCodeUrl"),
        "dateCreated": user_doc["dateCreated"],
    }


# Return a PNG QR code for the given handle
@app.get("/qr/{handle}")
def qr_for_handle(handle: str):
    try:
        import qrcode
        from io import BytesIO
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"QR generation unavailable: {e}")

    base = os.getenv("APP_BASE_URL", "https://tappay.me")
    link = f"{base.rstrip('/')}/{handle}"

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=2,
    )
    qr.add_data(link)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    buf = BytesIO()
    img.save(buf, format="PNG")
    png_bytes = buf.getvalue()

    return Response(content=png_bytes, media_type="image/png")


# ----------------------
# Transactions
# ----------------------
@app.post("/transaction/send")
def send_money(payload: TransactionCreate, user=Depends(get_current_user)):
    to_user = None
    if payload.toUserId:
        try:
            to_user = db["user"].find_one({"_id": ObjectId(payload.toUserId)})
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid toUserId")
    elif payload.toHandle:
        to_user = db["user"].find_one({"handle": payload.toHandle})
    else:
        raise HTTPException(status_code=400, detail="Receiver not specified")

    if not to_user:
        raise HTTPException(status_code=404, detail="Receiver not found")

    tx_doc = {
        "fromUser": str(user["_id"]),
        "toUser": str(to_user["_id"]),
        "amount": float(payload.amount),
        "timestamp": datetime.now(timezone.utc),
    }
    tx_id = db["transaction"].insert_one(tx_doc).inserted_id

    return {
        "status": "sent",
        "transaction": {"id": str(tx_id), **tx_doc}
    }


@app.get("/transaction/history/{userId}")
def get_history(userId: str, user=Depends(get_current_user)):
    if str(user["_id"]) != userId:
        raise HTTPException(status_code=403, detail="Forbidden")

    txs = list(db["transaction"].find({
        "$or": [{"fromUser": userId}, {"toUser": userId}]
    }).sort("timestamp", -1))

    for t in txs:
        t["id"] = str(t.pop("_id"))
    return txs


@app.get("/dashboard/stats")
def dashboard_stats(user=Depends(get_current_user)):
    user_id = str(user["_id"])
    pipeline = [
        {"$match": {"$or": [{"fromUser": user_id}, {"toUser": user_id}]}},
        {"$group": {
            "_id": None,
            "total_sent": {"$sum": {"$cond": [{"$eq": ["$fromUser", user_id]}, "$amount", 0]}},
            "total_received": {"$sum": {"$cond": [{"$eq": ["$toUser", user_id]}, "$amount", 0]}},
            "count_sent": {"$sum": {"$cond": [{"$eq": ["$fromUser", user_id]}, 1, 0]}},
            "count_received": {"$sum": {"$cond": [{"$eq": ["$toUser", user_id]}, 1, 0]}},
        }}
    ]

    agg = list(db["transaction"].aggregate(pipeline))
    stats = agg[0] if agg else {"total_sent": 0.0, "total_received": 0.0, "count_sent": 0, "count_received": 0}

    return {
        "total_sent": float(stats.get("total_sent", 0.0)),
        "total_received": float(stats.get("total_received", 0.0)),
        "count_sent": int(stats.get("count_sent", 0)),
        "count_received": int(stats.get("count_received", 0)),
    }


# ----------------------
# Handle validation
# ----------------------
@app.get("/handle/check/{handle}")
def check_handle(handle: str):
    exists = db["user"].find_one({"handle": handle}) is not None
    return {"handle": handle, "available": not exists}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
