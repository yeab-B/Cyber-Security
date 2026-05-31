import base64
import hashlib
import os
import sqlite3

import bcrypt
from cryptography.fernet import Fernet
from flask import Flask, flash, redirect, render_template, request, url_for

# Create Flask app object.
app = Flask(__name__)
# Secret key is needed for flash messages.
app.secret_key = "beginner-friendly-password-security-demo"

# Define project folder and database path.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")


# This demo key is created from a fixed phrase so encryption/decryption is reproducible.
# In real systems, keep encryption keys in a secure secret manager.
def get_fernet() -> Fernet:
    key_seed = hashlib.sha256(b"password-security-analysis-demo-key").digest()
    fernet_key = base64.urlsafe_b64encode(key_seed)
    return Fernet(fernet_key)


# Create table if it does not already exist.
def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_value TEXT NOT NULL,
            method TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# Encrypt plain password into ciphertext.
def encrypt_password(password: str) -> str:
    return get_fernet().encrypt(password.encode("utf-8")).decode("utf-8")


# Decrypt encrypted password back into plain text.
def decrypt_password(encrypted_password: str) -> str:
    return get_fernet().decrypt(encrypted_password.encode("utf-8")).decode("utf-8")


# Hash password with bcrypt (salt is added automatically by bcrypt).
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


# Check login password against bcrypt hash.
def check_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


@app.route("/")
def home():
    # Send users to the register page first.
    return redirect(url_for("register"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        method = request.form.get("method", "plain")

        # Basic beginner-friendly validation.
        if not username or not password:
            flash("Username and password are required.", "error")
            return redirect(url_for("register"))

        # Store password based on selected method.
        if method == "plain":
            stored_password = password
        elif method == "encrypted":
            stored_password = encrypt_password(password)
        elif method == "hashed":
            stored_password = hash_password(password)
        else:
            flash("Invalid storage method selected.", "error")
            return redirect(url_for("register"))

        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT INTO users (username, password_value, method) VALUES (?, ?, ?)",
                (username, stored_password, method),
            )
            conn.commit()
            conn.close()
            flash(f"User '{username}' registered using '{method}' method.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists. Please choose another username.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT username, password_value, method FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        conn.close()

        if not user:
            message = "Login failed: user not found."
        else:
            if user["method"] == "plain":
                valid = password == user["password_value"]
            elif user["method"] == "encrypted":
                valid = password == decrypt_password(user["password_value"])
            elif user["method"] == "hashed":
                valid = check_password(password, user["password_value"])
            else:
                valid = False

            if valid:
                message = f"Login successful for {user['username']} (stored with {user['method']})."
            else:
                message = "Login failed: incorrect password."

    return render_template("login.html", message=message)


@app.route("/attacker")
def attacker():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    users = conn.execute("SELECT username, password_value, method FROM users ORDER BY id").fetchall()
    conn.close()

    leaked_data = []
    for user in users:
        if user["method"] == "plain":
            attacker_view = {
                "username": user["username"],
                "method": "plain",
                "db_value": user["password_value"],
                "attacker_result": f"Readable immediately: {user['password_value']}",
            }
        elif user["method"] == "encrypted":
            decrypted = decrypt_password(user["password_value"])
            attacker_view = {
                "username": user["username"],
                "method": "encrypted",
                "db_value": user["password_value"],
                "attacker_result": f"If key is leaked, attacker decrypts it: {decrypted}",
            }
        else:
            attacker_view = {
                "username": user["username"],
                "method": "hashed",
                "db_value": user["password_value"],
                "attacker_result": "Cannot be reversed to the original password.",
            }
        leaked_data.append(attacker_view)

    return render_template("attacker.html", leaked_data=leaked_data)


@app.route("/report")
def report():
    return render_template("report.html")


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
