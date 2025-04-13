import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet


if "users" not in st.session_state:
    st.session_state.users = {}
if "logged_in_user" not in st.session_state:
    st.session_state.logged_in_user = None

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    # Generate a 32-byte key from the hashed passkey
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

def signup():
    st.subheader("🔐 Sign Up")
    new_user = st.text_input("Username", key="signup_username")
    new_pass = st.text_input("Password", type="password", key="signup_password")
    if st.button("Create Account"):
        if new_user in st.session_state.users:
            st.error("User already exists!")
        else:
            st.session_state.users[new_user] = {
                "password": hash_passkey(new_pass),
                "data": ""
            }
            st.success("Account created! Please log in.")

def login():
    st.subheader("🔑 Login")
    user = st.text_input("Username", key="login_username")
    passwd = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        if user in st.session_state.users:
            if st.session_state.users[user]["password"] == hash_passkey(passwd):
                st.session_state.logged_in_user = user
                st.success("Login successful!")
                st.rerun()  
            else:
                st.error("Incorrect password.")
        else:
            st.error("User not found.")

def logout():
    st.session_state.logged_in_user = None
    st.success("Logged out successfully.")

def encrypt_data_page():
    st.subheader("🔒 Encrypt and Store Data")
    text = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter passkey for encryption", type="password", key="encrypt_passkey")
    if st.button("Encrypt & Store"):
        if text and passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            encrypted = cipher.encrypt(text.encode()).decode()
            st.session_state.users[st.session_state.logged_in_user]["data"] = encrypted
            st.success("Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.warning("Please enter both text and passkey.")

def decrypt_data_page():
    st.subheader("🔓 Retrieve Your Data")
    encrypted = st.session_state.users[st.session_state.logged_in_user]["data"]
    passkey = st.text_input("Enter passkey for decryption", type="password", key="decrypt_passkey")
    if st.button("Decrypt"):
        if encrypted and passkey:
            try:
                key = generate_key_from_passkey(passkey)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted.encode()).decode()
                st.success("Decrypted Data:")
                st.code(decrypted, language="text")
            except Exception as e:
                st.error("Failed to decrypt data. Possibly incorrect passkey.")
        else:
            st.warning("Please enter your passkey.")

def forgot_password():
    st.subheader("🔁 Forgot Password")
    username = st.text_input("Enter your username", key="forgot_username")
    new_pass = st.text_input("Enter new password", type="password", key="forgot_password")
    if st.button("Reset Password"):
        if username in st.session_state.users:
            st.session_state.users[username]["password"] = hash_passkey(new_pass)
            st.success("Password reset successfully!")
        else:
            st.error("User not found.")

# Main App
st.title("🛡️ Secure Data Encryption System")

if st.session_state.logged_in_user:
    st.sidebar.success(f"Logged in as {st.session_state.logged_in_user}")
    menu = st.sidebar.radio("Menu", ["Encrypt", "Decrypt", "Logout"])
    if menu == "Encrypt":
        encrypt_data_page()
    elif menu == "Decrypt":
        decrypt_data_page()
    elif menu == "Logout":
        logout()
else:
    st.subheader("🔐 Login")
    login()

    with st.expander("Don't have an account? Sign Up here"):
        signup()

    with st.expander("Forgot your password? Reset here"):
        forgot_password()
st.markdown("This app is created by Shaya9ali")