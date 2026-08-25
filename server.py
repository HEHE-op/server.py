import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import werkzeug.security as security

app = Flask(__name__)

# Allow all origins to eliminate CORS blocks from Netlify
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

# In-memory user storage
users_db = {}

@app.route("/", methods=["GET"])
def home():
    return jsonify({"status": "active", "message": "GD Studios Auth API is live!"}), 200

@app.route("/ping", methods=["GET"])
def ping():
    return jsonify({"status": "ok"}), 200

@app.route("/version", methods=["GET"])
def version():
    return jsonify({
        "status": "ok",
        "version": "1.0.0",
        "app_name": "GD Studios Auth API"
    }), 200

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    if username in users_db:
        return jsonify({"message": "User already exists"}), 400

    users_db[username] = security.generate_password_hash(password)
    return jsonify({"message": "User registered successfully"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"message": "Please enter username and password"}), 400

    user_hash = users_db.get(username)
    if not user_hash or not security.check_password_hash(user_hash, password):
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": "Login successful", "username": username}), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
