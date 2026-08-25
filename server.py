from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
import datetime
import os
import sqlite3

app = FastAPI()

# Enable CORS for Netlify and localhost
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from Netlify and all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Load from environment, not hardcoded. Set this in Render's Environment tab:
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-fallback-change-me")
ALGORITHM = "HS256"
TOKEN_LIFETIME_DAYS = 30

LATEST_VERSION = "1.2.0"
DOWNLOAD_URL = "https://gd-studios.netlify.app/#downloads"

DB_FILE = "beast_ai_users.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            last_login_ip TEXT
        )
    """)
    return conn


class AuthData(BaseModel):
    username: str
    password: str


def create_token(username: str, ip: str) -> str:
    expiration = datetime.datetime.utcnow() + datetime.timedelta(days=TOKEN_LIFETIME_DAYS)
    return jwt.encode(
        {"sub": username, "ip": ip, "exp": expiration},
        SECRET_KEY,
        algorithm=ALGORITHM,
    )


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security), request: Request = None):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired, please log in again.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token.")

    current_ip = request.client.host if request else None
    if payload.get("ip") != current_ip:
        raise HTTPException(status_code=401, detail="IP changed — please log in again.")

    return payload["sub"]


# FIX: Added Root route so GET / doesn't throw handling errors
@app.get("/")
def read_root():
    return {"status": "active", "message": "GD Studios FastAPI Backend is running!"}


# FIX: Keep-alive endpoint for UptimeRobot
@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/version")
def get_version():
    return {"latest_version": LATEST_VERSION, "download_url": DOWNLOAD_URL}


@app.post("/register")
def register(data: AuthData, request: Request):
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    conn = get_db()
    existing = conn.execute("SELECT username FROM users WHERE username = ?", (data.username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists!")

    hashed_pwd = pwd_context.hash(data.password)
    conn.execute("INSERT INTO users (username, password_hash, last_login_ip) VALUES (?, ?, ?)",
                 (data.username, hashed_pwd, request.client.host))
    conn.commit()
    conn.close()
    return {"message": "User registered successfully!"}


@app.post("/login")
def login(data: AuthData, request: Request):
    conn = get_db()
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (data.username,)).fetchone()

    if not row or not pwd_context.verify(data.password, row[0]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials!")

    client_ip = request.client.host
    conn.execute("UPDATE users SET last_login_ip = ? WHERE username = ?", (client_ip, data.username))
    conn.commit()
    conn.close()

    token = create_token(data.username, client_ip)
    return {"token": token, "message": "Login successful!"}


@app.get("/me")
def get_current_user(username: str = Depends(verify_token)):
    return {"username": username, "status": "authenticated"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
