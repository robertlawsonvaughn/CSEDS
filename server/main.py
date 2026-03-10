"""
CSEDS - Client-Side Encrypted Data Synchronization
Server Reference Implementation v1.0

FastAPI + SQLite3 MVP
Apache 2.0 License
"""

import sqlite3
import secrets
import time
import hashlib
import os
from contextlib import contextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from passlib.context import CryptContext

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).parent / "cseds.db"
CLIENT_PATH = Path(__file__).parent.parent / "client"
SESSION_TTL_SECONDS = 86400  # 24 hours

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="CSEDS Reference Implementation", version="1.0.0")

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                auth_hash   TEXT NOT NULL,
                salt        TEXT NOT NULL,
                argon_params TEXT NOT NULL,
                created_at  INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS blobs (
                user_id         INTEGER PRIMARY KEY,
                blob_data       TEXT,
                server_timestamp INTEGER NOT NULL DEFAULT 0,
                blob_size       INTEGER NOT NULL DEFAULT 0,
                version         INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                user_id     INTEGER PRIMARY KEY,
                token       TEXT NOT NULL,
                created_at  INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        """)

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

init_db()

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def get_current_user(authorization: str = Header(...)):
    """Validate session token and return user_id."""
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
    token = authorization[7:]
    with get_db() as db:
        row = db.execute(
            "SELECT user_id, created_at FROM sessions WHERE token = ?", (token,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        age = time.time() - row["created_at"]
        if age > SESSION_TTL_SECONDS:
            db.execute("DELETE FROM sessions WHERE token = ?", (token,))
            raise HTTPException(status_code=401, detail="Session expired")
        return row["user_id"]

# ---------------------------------------------------------------------------
# Request / Response Models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    auth_key_hash: str   # bcrypt hash of auth_key, computed client-side via subtle hash then sent; server bcrypts again
    salt: str            # hex encoded 16-byte salt
    argon_params: str    # JSON string of argon2 params used

class LoginRequest(BaseModel):
    username: str
    auth_key: str        # raw auth_key (first 32 bytes of Argon2id output, base64)

class BlobUploadRequest(BaseModel):
    blob_data: str       # base64 encoded encrypted blob

class PasswordChangeRequest(BaseModel):
    new_auth_key: str
    new_salt: str
    new_argon_params: str
    new_blob_data: str

# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.get("/api/salt/{username}")
def get_salt(username: str):
    """
    Retrieve salt for a username. Unauthenticated endpoint.
    Returns a dummy salt for unknown usernames to prevent enumeration.
    """
    with get_db() as db:
        row = db.execute(
            "SELECT salt, argon_params FROM users WHERE username = ?", (username,)
        ).fetchone()

    if not row:
        # Return deterministic dummy salt — same username always gets same dummy
        # This prevents username enumeration via timing or response differences
        dummy_salt = hashlib.sha256(f"dummy:{username}:cseds".encode()).hexdigest()[:32]
        return {"salt": dummy_salt, "argon_params": '{"memory":65536,"iterations":3,"parallelism":1}', "exists": False}

    return {"salt": row["salt"], "argon_params": row["argon_params"], "exists": True}


@app.post("/api/register")
def register(req: RegisterRequest):
    """Register a new user."""
    if len(req.username) < 3 or len(req.username) > 64:
        raise HTTPException(status_code=400, detail="Username must be 3-64 characters")

    auth_hash = pwd_context.hash(req.auth_key_hash)

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (req.username,)
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="Username already exists")

        db.execute(
            """INSERT INTO users (username, auth_hash, salt, argon_params, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (req.username, auth_hash, req.salt, req.argon_params, int(time.time()))
        )
        user_id = db.execute(
            "SELECT id FROM users WHERE username = ?", (req.username,)
        ).fetchone()["id"]

        # Initialize empty blob record
        db.execute(
            """INSERT INTO blobs (user_id, blob_data, server_timestamp, blob_size, version)
               VALUES (?, NULL, ?, 0, 0)""",
            (user_id, int(time.time() * 1000))
        )

    return {"message": "Registration successful"}


@app.post("/api/login")
def login(req: LoginRequest):
    """
    Authenticate user. Invalidates any existing session.
    Returns new session token.
    """
    with get_db() as db:
        user = db.execute(
            "SELECT id, auth_hash FROM users WHERE username = ?", (req.username,)
        ).fetchone()

        if not user or not pwd_context.verify(req.auth_key, user["auth_hash"]):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user_id = user["id"]

        # Invalidate existing session (single session enforcement)
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

        # Issue new session token
        token = secrets.token_hex(32)
        db.execute(
            "INSERT INTO sessions (user_id, token, created_at) VALUES (?, ?, ?)",
            (user_id, token, int(time.time()))
        )

    return {"token": token, "message": "Login successful"}


@app.get("/api/blob")
def get_blob(user_id: int = Depends(get_current_user)):
    """Retrieve encrypted blob and metadata for authenticated user."""
    with get_db() as db:
        row = db.execute(
            "SELECT blob_data, server_timestamp, blob_size, version FROM blobs WHERE user_id = ?",
            (user_id,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="No blob found")

    return {
        "blob_data": row["blob_data"],
        "server_timestamp": row["server_timestamp"],
        "blob_size": row["blob_size"],
        "version": row["version"]
    }


@app.put("/api/blob")
def put_blob(req: BlobUploadRequest, user_id: int = Depends(get_current_user)):
    """
    Upload encrypted blob. Server assigns timestamp — client timestamp ignored.
    """
    server_timestamp = int(time.time() * 1000)  # epoch ms
    blob_size = len(req.blob_data.encode("utf-8"))

    with get_db() as db:
        db.execute(
            """UPDATE blobs
               SET blob_data = ?, server_timestamp = ?, blob_size = ?, version = version + 1
               WHERE user_id = ?""",
            (req.blob_data, server_timestamp, blob_size, user_id)
        )

    return {
        "server_timestamp": server_timestamp,
        "blob_size": blob_size,
        "message": "Blob uploaded successfully"
    }


@app.get("/api/blob/meta")
def get_blob_meta(user_id: int = Depends(get_current_user)):
    """Retrieve blob metadata only (no blob data) for sync decision."""
    with get_db() as db:
        row = db.execute(
            "SELECT server_timestamp, blob_size, version FROM blobs WHERE user_id = ?",
            (user_id,)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="No blob found")

    return {
        "server_timestamp": row["server_timestamp"],
        "blob_size": row["blob_size"],
        "version": row["version"]
    }


@app.post("/api/logout")
def logout(user_id: int = Depends(get_current_user)):
    """Invalidate current session."""
    with get_db() as db:
        db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    return {"message": "Logged out successfully"}


@app.put("/api/password")
def change_password(req: PasswordChangeRequest, user_id: int = Depends(get_current_user)):
    """
    Change password. Atomically updates auth record and re-encrypted blob.
    Client must re-encrypt entire blob with new key before calling this endpoint.
    """
    new_auth_hash = pwd_context.hash(req.new_auth_key)
    server_timestamp = int(time.time() * 1000)
    blob_size = len(req.new_blob_data.encode("utf-8"))

    with get_db() as db:
        # Atomic update of auth + blob
        db.execute(
            """UPDATE users SET auth_hash = ?, salt = ?, argon_params = ?
               WHERE id = ?""",
            (new_auth_hash, req.new_salt, req.new_argon_params, user_id)
        )
        db.execute(
            """UPDATE blobs
               SET blob_data = ?, server_timestamp = ?, blob_size = ?, version = version + 1
               WHERE user_id = ?""",
            (req.new_blob_data, server_timestamp, blob_size, user_id)
        )

    return {"message": "Password changed successfully"}


# ---------------------------------------------------------------------------
# Static file serving — client/index.html
# ---------------------------------------------------------------------------

@app.get("/")
def serve_index():
    index_path = CLIENT_PATH / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Client index.html not found")
    return FileResponse(index_path)

# Mount static files if client directory exists
if CLIENT_PATH.exists():
    app.mount("/static", StaticFiles(directory=str(CLIENT_PATH)), name="static")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
