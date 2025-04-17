
import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Setup
st.set_page_config(page_title="Crypto-Shield 🔐", layout="centered")

# Global key for encryption (session-specific)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted: {encrypted_text, hashed_passkey}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    for val in st.session_state.stored_data.values():
        if val["encrypted_text"] == encrypted_text and val["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# Main UI
st.title("🔐 Crypto-Shield: Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigate", menu)

# 1. Home Page
if choice == "Home":
    st.subheader("🏠 Welcome to Crypto-Shield")
    st.markdown("Securely **store and retrieve** sensitive data using encryption + passkey.")

# 2. Store Data Page
elif choice == "Store Data":
    st.subheader("📥 Store Data")
    user_data = st.text_area("Enter your secret message:")
    passkey = st.text_input("Choose a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Both fields are required.")

# 3. Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Paste your encrypted data:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success("✅ Decrypted Message:")
                st.code(result)
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔐 Too many failed attempts. Redirecting to login.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both fields are required.")

# 4. Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    master_password = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master_password == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in! You may now retry decryption.")
        else:
            st.error("❌ Incorrect master password.")
