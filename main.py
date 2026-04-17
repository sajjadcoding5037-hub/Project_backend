# main.py

import os
import uuid
from datetime import datetime, timedelta

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from passlib.context import CryptContext
from jose import jwt, JWTError

# ==============================
# CONFIG
# ==============================
DATABASE_URL = os.getenv("DATABASE_PUBLIC_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_key")
ALGORITHM = "HS256"

# ==============================
# DB SETUP
# ==============================
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()

# ==============================
# MODEL
# ==============================
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# ==============================
# PASSWORD HASHING
# ==============================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password_auth(password: str):
    if len(password.encode("utf-8")) > 72:
        password = password[:72]  # truncate safely
    return pwd_context.hash(password)
    
def verify_password_auth(plain_password: str, hashed_password: str):
    if len(plain_password.encode("utf-8")) > 72:
        plain_password = plain_password[:72]
    return pwd_context.verify(plain_password, hashed_password)
# ==============================
# TEST USER CREATION (MOVE UP)
# ==============================
def create_test_user_on_startup():
    db = SessionLocal()

    try:
        test_username = "admin"
        test_password = "admin123"

        existing_user = db.query(User).filter(User.username == test_username).first()

        if not existing_user:
            print("⚡ Creating test user...")

            new_user = User(
                id=str(uuid.uuid4()),
                username=test_username,
                password=hash_password_auth(test_password)
            )

            db.add(new_user)
            db.commit()

            print("✅ Test user created: admin / admin123")
        else:
            print("ℹ️ Test user already exists")

    finally:
        db.close()

# ==============================
# JWT TOKEN
# ==============================
def create_access_token_auth(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=2)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token_auth(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

# ==============================
# FASTAPI APP
# ==============================
app = FastAPI()

# ✅ SAFE CALL (NOW FUNCTION EXISTS)
create_test_user_on_startup()

# ==============================
# CORS
# ==============================
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==============================
# DB DEPENDENCY
# ==============================
def get_db_auth():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ==============================
# AUTH DEPENDENCY
# ==============================
security = HTTPBearer()

def get_current_user_auth(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db_auth)
):
    token = credentials.credentials
    payload = verify_token_auth(token)

    username = payload.get("sub")
    if not username:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user

# ==============================
# SCHEMAS
# ==============================
class SignupRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# ==============================
# SIGNUP
# ==============================
@app.post("/signup")
def signup_user_auth(data: SignupRequest, db: Session = Depends(get_db_auth)):

    existing_user = db.query(User).filter(User.username == data.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    new_user = User(
        id=str(uuid.uuid4()),
        username=data.username,
        password=hash_password_auth(data.password)
    )

    db.add(new_user)
    db.commit()

    return {"message": "User created successfully"}

# ==============================
# LOGIN
# ==============================
@app.post("/login")
def login_user_auth(data: LoginRequest, db: Session = Depends(get_db_auth)):

    print("🔍 Username:", data.username)
    print("🔍 Password:", data.password)
    print("🔍 Password length:", len(data.password))

    user = db.query(User).filter(User.username == data.username).first()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if not verify_password_auth(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token_auth({
        "sub": user.username
    })

    return {
        "access_token": token,
        "token_type": "bearer"
    }
# ==============================
# PROTECTED
# ==============================
@app.get("/protected")
def protected_route(current_user: User = Depends(get_current_user_auth)):
    return {
        "message": f"Welcome {current_user.username}, you are authenticated"
    }
