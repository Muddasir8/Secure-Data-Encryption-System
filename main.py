import streamlit as st
import hashlib
import os
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

# File paths
KEY_FILE = "secret.key"
DATA_FILE = "stored_data.json"

# Load or generate encryption key
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

KEY = load_key()
cipher = Fernet(KEY)

# Load and save JSON data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

stored_data = load_data()
failed_attempts = {}
lockout_time = {}

# PBKDF2 hashing
def hash_passkey(passkey):
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), b'salt', 100000).hex()

# Encrypt file content
def encrypt_file(file):
    return cipher.encrypt(file.read()).decode()

# Decrypt file content
def decrypt_file(encrypted_text):
    return cipher.decrypt(encrypted_text.encode())

# Streamlit UI
st.set_page_config(page_title="🔐 Secure File Vault")
st.title("🔐 Secure File Vault")

menu = ["Home", "Register", "Login", "Store File", "Retrieve File"]
choice = st.sidebar.selectbox("Navigation", menu)

if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

if choice == "Home":
    st.subheader("🏠 Welcome to Secure File Vault")
    st.write("Upload and retrieve files securely with encryption and passkey protection.")

elif choice == "Register":
    st.subheader("🧾 Create Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Passkey", type="password")
    if st.button("Register"):
        if new_user and new_pass:
            if new_user in stored_data:
                st.warning("⚠️ Username already exists.")
            else:
                stored_data[new_user] = []
                save_data(stored_data)
                st.success("✅ Registered successfully. Please login.")
        else:
            st.error("⚠️ All fields required.")

elif choice == "Login":
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Passkey", type="password")

    if username in lockout_time and datetime.now() < datetime.fromisoformat(lockout_time[username]):
        st.warning(f"🔒 Locked out until {datetime.fromisoformat(lockout_time[username]).strftime('%H:%M:%S')}")
    elif st.button("Login"):
        hashed = hash_passkey(password)
        if username in stored_data and any(d["passkey"] == hashed for d in stored_data[username]):
            st.session_state.logged_in_user = username
            failed_attempts[username] = 0
            lockout_time.pop(username, None)
            st.success(f"✅ Welcome, {username}")
        else:
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            if failed_attempts[username] >= 3:
                lockout_time[username] = (datetime.now() + timedelta(seconds=30)).isoformat()
                st.error("🔒 Too many attempts. Try again later.")
            else:
                st.error(f"❌ Incorrect credentials. Attempts left: {3 - failed_attempts[username]}")

elif choice == "Store File":
    if st.session_state.logged_in_user:
        st.subheader("📂 Store File")
        uploaded_file = st.file_uploader("Choose file")
        passkey = st.text_input("Enter Passkey", type="password")

        if st.button("Encrypt & Save"):
            if uploaded_file and passkey:
                encrypted_text = encrypt_file(uploaded_file)
                hashed_passkey = hash_passkey(passkey)

                stored_data[st.session_state.logged_in_user].append({
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey,
                    "filename": uploaded_file.name
                })
                save_data(stored_data)
                st.success("✅ File encrypted and stored.")
            else:
                st.error("⚠️ File and passkey are required.")
    else:
        st.warning("🔐 Login required.")

elif choice == "Retrieve File":
    if st.session_state.logged_in_user:
        st.subheader("🔍 Retrieve File")
        user_records = stored_data.get(st.session_state.logged_in_user, [])
        filenames = [rec["filename"] for rec in user_records]
        selected = st.selectbox("Select File", filenames)
        passkey = st.text_input("Enter Passkey", type="password")

        if st.button("Decrypt & Download"):
            for record in user_records:
                if record["filename"] == selected and record["passkey"] == hash_passkey(passkey):
                    decrypted_content = decrypt_file(record["encrypted_text"])
                    st.download_button("⬇️ Download File", decrypted_content, file_name=record["filename"])
                    break
            else:
                st.error("❌ Incorrect passkey or no such file.")
    else:
        st.warning("🔐 Login required.")
