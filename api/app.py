from flask import Flask, request, abort
import sqlite3
import subprocess
import hashlib
import os
import ast
from werkzeug.utils import secure_filename

import bcrypt

app = Flask(__name__)

# Use environment variable for secret key, with a fallback for local dev
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "default-dev-key-change-me")

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    if not data:
        return {"status": "error", "message": "Missing JSON data"}, 400
    
    username = data.get("username")
    password = data.get("password")

    # FIX: Parameterized query to prevent SQL Injection
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Note: In a real app, you would fetch the hashed password for the username
    query = "SELECT password FROM users WHERE username=?"
    cursor.execute(query, (username,))

    result = cursor.fetchone()
    conn.close()

    if result:
        hashed_password = result[0].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return {"status": "success", "user": username}
    
    return {"status": "error", "message": "Invalid credentials"}, 401

@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")
    
    # FIX: Basic validation/sanitization to prevent command injection
    if not host or any(char in host for char in [';', '&', '|', '$', '>', '<', '`']):
        return {"error": "Invalid host format"}, 400

    # FIX: avoid shell=True and use a list of arguments
    try:
        result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
        return {"output": result.stdout}
    except subprocess.TimeoutExpired:
        return {"error": "Ping timed out"}, 504
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "1+1")
    try:
        if len(expression) > 20 or any(c not in "0123456789+-*/() " for c in expression):
             return {"error": "Expression too complex or invalid"}, 400
        
        result = eval(expression, {"__builtins__": {}}, {}) 
        return {"result": result}
    except Exception as e:
        return {"error": "Invalid expression"}, 400

@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")
    # FIX: Using bcrypt for secure password hashing
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd.encode('utf-8'), salt)
    return {"bcrypt": hashed.decode('utf-8')}

@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "")
    if not filename:
        return {"error": "Filename required"}, 400

    # FIX: Prevent Path Traversal
    safe_filename = secure_filename(filename)
    # Ensure file is in a specific data directory if needed, or just current dir but safe
    # Here we just use the current directory but ensure it's just the filename
    base_dir = os.getcwd()
    file_path = os.path.join(base_dir, safe_filename)

    if not os.path.exists(file_path):
         return {"error": "File not found"}, 404

    try:
        with open(file_path, "r") as f:
            content = f.read()
        return {"content": content}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/debug", methods=["GET"])
def debug():
    # FIX: Do not leak secrets or environment variables
    return {
        "status": "Running",
        "mode": "production" if os.environ.get("FLASK_ENV") == "production" else "development"
    }

@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps secured API"}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)