from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt
import datetime
import os
import sqlite3
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ====================== CONFIG ======================
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-only-fallback-change-me")
ALGORITHM = "HS256"
TOKEN_LIFETIME_DAYS = 30

# Gmail settings (set these in Render Environment)
GMAIL_USER = os.environ.get("GMAIL_USER")          # yourgmail@gmail.com
GMAIL_APP_PASSWORD = os.environ.get("GMAIL_APP_PASSWORD")  # 16-char app password

LATEST_VERSION = "1.2.0"
DOWNLOAD_URL = "https://gd-studios.netlify.app/#downloads"

# Change this to your frontend domain if you want the verify link to go there
FRONTEND_URL = "https://gd-studios.netlify.app"
# ====================================================

DB_FILE = "beast_ai_users.db"


def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            last_login_ip TEXT
        )
    """)
    return conn


def get_client_ip(request: Request) -> str:
    if not request:
        return "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def send_verification_email(to_email: str, username: str, token: str):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("WARNING: Gmail credentials not set. Email not sent.")
        return

    verify_link = f"{FRONTEND_URL}/verify?token={token}"
    # Alternative (pure backend): verify_link = f"https://gd-studios-auth.onrender.com/verify?token={token}"

    subject = "Verify your GD Studios account"
    body = f"""
Hi {username},

Thanks for registering at GD Studios!

Please click the link below to verify your email:

{verify_link}

This link will expire in 24 hours.

If you didn't create this account, you can ignore this email.

— GD Studios Team
"""

    msg = MIMEMultipart()
    msg["From"] = GMAIL_USER
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)
        print(f"Verification email sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        raise HTTPException(status_code=500, detail="Failed to send verification email")


class RegisterData(BaseModel):
    username: str
    email: EmailStr
    password: str


class AuthData(BaseModel):
    username: str
    password: str


class ResendData(BaseModel):
    email: EmailStr


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

    current_ip = get_client_ip(request)
    if payload.get("ip") != current_ip:
        raise HTTPException(status_code=401, detail="IP changed — please log in again.")

    return payload["sub"]


# ====================== ROUTES ======================

@app.get("/")
def read_root():
    return {"status": "active", "message": "GD Studios API is running!"}


@app.get("/ping")
def ping():
    return {"status": "ok"}


@app.get("/version")
def get_version():
    return {"latest_version": LATEST_VERSION, "download_url": DOWNLOAD_URL}


@app.post("/register")
def register(data: RegisterData, request: Request):
    if len(data.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")

    client_ip = get_client_ip(request)
    conn = get_db()

    # Check username
    if conn.execute("SELECT 1 FROM users WHERE username = ?", (data.username,)).fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists!")

    # Check email
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (data.email,)).fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Email already registered!")

    hashed_pwd = pwd_context.hash(data.password)
    verification_token = secrets.token_urlsafe(32)

    conn.execute(
        """INSERT INTO users 
           (username, email, password_hash, is_verified, verification_token, last_login_ip) 
           VALUES (?, ?, ?, 0, ?, ?)""",
        (data.username, data.email, hashed_pwd, verification_token, client_ip)
    )
    conn.commit()
    conn.close()

    # Send verification email
    send_verification_email(data.email, data.username, verification_token)

    return {
        "message": "Registered successfully! Please check your email to verify your account.",
        "email": data.email
    }


@app.get("/verify")
def verify_email(token: str):
    conn = get_db()
    row = conn.execute(
        "SELECT username, is_verified FROM users WHERE verification_token = ?",
        (token,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

    username, is_verified = row

    if is_verified:
        conn.close()
        return {"message": "Email already verified. You can log in."}

    conn.execute(
        "UPDATE users SET is_verified = 1, verification_token = NULL WHERE username = ?",
        (username,)
    )
    conn.commit()
    conn.close()

    return {
        "message": "Email verified successfully! You can now log in.",
        "username": username
    }


@app.post("/resend-verification")
def resend_verification(data: ResendData):
    conn = get_db()
    row = conn.execute(
        "SELECT username, is_verified, verification_token FROM users WHERE email = ?",
        (data.email,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Email not found.")

    username, is_verified, token = row

    if is_verified:
        conn.close()
        raise HTTPException(status_code=400, detail="Email is already verified.")

    # Generate new token
    new_token = secrets.token_urlsafe(32)
    conn.execute(
        "UPDATE users SET verification_token = ? WHERE email = ?",
        (new_token, data.email)
    )
    conn.commit()
    conn.close()

    send_verification_email(data.email, username, new_token)
    return {"message": "Verification email resent successfully."}


@app.post("/login")
def login(data: AuthData, request: Request):
    conn = get_db()
    row = conn.execute(
        "SELECT password_hash, is_verified FROM users WHERE username = ?",
        (data.username,)
    ).fetchone()

    if not row or not pwd_context.verify(data.password, row[0]):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid credentials!")

    if not row[1]:  # is_verified == 0
        conn.close()
        raise HTTPException(
            status_code=403,
            detail="Email not verified. Please check your inbox or request a new verification email."
        )

    client_ip = get_client_ip(request)
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
