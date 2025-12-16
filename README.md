"""
Secure REST API with JWT Authentication and Role-Based Access
Single-file FastAPI application

Features:
- User registration & login
- JWT access tokens
- Role-based authorization (admin / user)
- CRUD for projects
- SQLite persistence
- Production-style structure

Run:
pip install fastapi uvicorn python-jose passlib[bcrypt] pydantic
uvicorn app:app --reload
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel

# --------------------
# Config
# --------------------
SECRET_KEY = "CHANGE_ME_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
DB_PATH = "secure_api.db"

app = FastAPI(title="Secure API")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --------------------
# Database
# --------------------
def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            owner_id INTEGER,
            created_at TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()

init_db()

# --------------------
# Models
# --------------------
class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"

class Token(BaseModel):
    access_token: str
    token_type: str

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None

class ProjectOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
    created_at: str

# --------------------
# Security helpers
# --------------------
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str):
    return pwd_context.verify(password, hashed)

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    conn = get_db()
    cur = conn.cursor()
    row = cur.execute(
        "SELECT id, username, role FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="User not found")

    return {"id": row[0], "username": row[1], "role": row[2]}

def admin_required(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# --------------------
# Auth Routes
# --------------------
@app.post("/register")
def register(user: UserCreate):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (user.username, hash_password(user.password), user.role, datetime.utcnow().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")
    finally:
        conn.close()
    return {"message": "User registered"}

@app.post("/token", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends()):
    conn = get_db()
    cur = conn.cursor()
    row = cur.execute(
        "SELECT username, password_hash FROM users WHERE username = ?",
        (form.username,)
    ).fetchone()
    conn.close()

    if not row or not verify_password(form.password, row[1]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"sub": row[0]})
    return {"access_token": token, "token_type": "bearer"}

# --------------------
# Project Routes
# --------------------
@app.post("/projects", response_model=ProjectOut)
def create_project(data: ProjectCreate, user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO projects (name, description, owner_id, created_at) VALUES (?, ?, ?, ?)",
        (data.name, data.description, user["id"], datetime.utcnow().isoformat())
    )
    conn.commit()
    pid = cur.lastrowid
    row = cur.execute("SELECT * FROM projects WHERE id = ?", (pid,)).fetchone()
    conn.close()
    return ProjectOut(id=row[0], name=row[1], description=row[2], created_at=row[4])

@app.get("/projects", response_model=List[ProjectOut])
def list_projects(user=Depends(get_current_user)):
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute(
        "SELECT id, name, description, created_at FROM projects WHERE owner_id = ?",
        (user["id"],)
    ).fetchall()
    conn.close()
    return [ProjectOut(id=r[0], name=r[1], description=r[2], created_at=r[3]) for r in rows]

@app.delete("/projects/{project_id}")
def delete_project(project_id: int, user=Depends(admin_required)):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM projects WHERE id = ?", (project_id,))
    conn.commit()
    conn.close()
    return {"message": "Project deleted"}
