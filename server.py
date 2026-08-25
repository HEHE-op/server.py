import os
import sqlite3
import datetime
import jwt
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Locked down CORS to allow only your site
ALLOWED_ORIGINS = [
    "https://gd-studios.netlify.app",
    "https://gd-studios.netlify.app/",
    "http://localhost:3000",
    "http://127.0.0.1:5500"
]

CORS(
    app,
    resources={r"/*": {"origins": ALLOWED_ORIGINS}},
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "DELETE", "OPTIONS"]
)

SECRET_KEY = os.environ.get("JWT_SECRET", "gd-studios-super-secret-key-2026")
DB_FILE = "database.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Table 1: Users
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    
    # Table 2: Downloads & Items
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            download_url TEXT NOT NULL,
            tag TEXT DEFAULT 'Tool',
            status TEXT DEFAULT 'Active'
        )
    ''')
    
    # Create Default Admin User (ROKO)
    cursor.execute("SELECT * FROM users WHERE username = 'ROKO'")
    if not cursor.fetchone():
        default_admin_pw = generate_password_hash("Gorav@1234567890")
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES ('ROKO', ?, 'admin')", (default_admin_pw,))
    
    conn.commit()
    conn.close()

init_db()

# --- HEALTH CHECK ROUTE ---
@app.route('/', methods=['GET'])
def health_check():
    return jsonify({
        "status": "online",
        "message": "GD Studios Backend API is active and running!"
    }), 200

# --- AUTH ROUTES ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    hashed_pw = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_pw))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Account created successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 400

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '').strip()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if row and check_password_hash(row[0], password):
        role = row[1]
        token = jwt.encode({
            'username': username,
            'role': role,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=12)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({"success": True, "token": token, "username": username, "role": role})

    return jsonify({"error": "Invalid username or password"}), 401

# --- DATA & LINK MANAGEMENT ROUTES ---
@app.route('/items', methods=['GET'])
def get_items():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, category, description, download_url, tag, status FROM items")
    rows = cursor.fetchall()
    conn.close()
    
    items = []
    for r in rows:
        items.append({
            "id": r[0], "title": r[1], "category": r[2],
            "description": r[3], "download_url": r[4], "tag": r[5], "status": r[6]
        })
    return jsonify(items)

@app.route('/items', methods=['POST'])
def add_item():
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if payload.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
    except:
        return jsonify({"error": "Invalid or expired token"}), 401

    data = request.get_json() or {}
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO items (title, category, description, download_url, tag, status) VALUES (?, ?, ?, ?, ?, ?)",
        (data.get('title'), data.get('category'), data.get('description'), data.get('download_url'), data.get('tag', 'Tool'), data.get('status', 'Active'))
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Item saved permanently!"}), 201

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
