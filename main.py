# main.py

from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String
from sqlalchemy.orm import sessionmaker, declarative_base, Session
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import uuid

# ==============================
# CONFIG
# ==============================
DATABASE_URL = "postgresql://postgres:password@localhost:5432/mydb"

SECRET_KEY = "super_secret_key"
ALGORITHM = "HS256"

# ==============================
# DB SETUP
# ==============================
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

Base = declarative_base()

# ==============================
# MODEL
# ==============================
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

# ==============================
# PASSWORD HASHING
# ==============================
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password_auth(password: str):
    return pwd_context.hash(password)

def verify_password_auth(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

# ==============================
# JWT TOKEN
# ==============================
def create_access_token_auth(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=2)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ==============================
# FASTAPI APP
# ==============================
app = FastAPI()

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
# REQUEST SCHEMAS
# ==============================
class SignupRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# ==============================
# SIGNUP API
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
# LOGIN API
# ==============================
@app.post("/login")
def login_user_auth(data: LoginRequest, db: Session = Depends(get_db_auth)):

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
# PROTECTED ROUTE EXAMPLE
# ==============================
@app.get("/protected")
def protected_route():
    return {"message": "You are authenticated"}
