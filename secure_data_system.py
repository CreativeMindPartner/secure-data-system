import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state for failed attempts and navigation
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "page" not in st.session_state:
    st.session_state.page = "Home"

# Generate a key for Fernet encryption (in production, store securely)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}

# Function to hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    if encrypted_text in st.session_state.stored_data:
        if st.session_state.stored_data[encrypted_text]["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Sidebar navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.page))

# Page logic
if choice == "Home":
    st.session_state.page = "Home"
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys. Navigate using the sidebar.")

elif choice == "Store Data":
    st.session_state.page = "Store Data"
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:", key="store_data")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.write("Copy this encrypted text for retrieval:", encrypted_text)
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.session_state.page = "Retrieve Data"
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:", key="retrieve_data")
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.session_state.page = "Login"
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.session_state.page = "Login"
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password", key="login_pass")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo; replace with secure auth in production
            st.session_state.failed_attempts = 0
            st.session_state.page = "Retrieve Data"
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.rerun()
        else:
            st.error("❌ Incorrect password!")