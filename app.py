import streamlit as st
import json
import hashlib
import os
import base64
from cryptography.fernet import Fernet



if not os.path.exists("key.key"):
    with open("key.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())

with open("key.key", "rb") as key_file:
    KEY = key_file.read()

cipher = Fernet(KEY)


def load_users(): 
    with open("data.json", "r") as file:
        return json.load(file)

def save_users(users):
    with open("data.json", "w") as file:
        json.dump(users, file)

users = load_users()
attempts = 0

def hash_passkey(passkey, salt = None):
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt, 100000)
    return {
        "salt": base64.b64encode(salt).decode(),
        "key": base64.b64encode(key).decode()
    }

def verify_passkey(stored_passkey, stored_salt, provided_passkey):
    new_key = hash_passkey(provided_passkey, base64.b64decode(stored_salt))["key"]
    return new_key == stored_passkey


def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_list):
    decrypted = []
    for encrypted in encrypted_list:
        decrypted.append(cipher.decrypt(encrypted.encode()).decode())
    return decrypted


choice = st.sidebar.radio("Navigation", ["Home", "Store Data", "Retrieve Data", "Login"])

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.passkey = ""
    st.session_state.attempts = 0


if choice == "Home":
    st.title("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    if st.session_state.logged_in:
        user_data = st.text_area("Enter Data:")
        encrypted_text = encrypt_data(user_data)
        st.session_state.passkey = st.text_input("Enter Passkey:", type = "password")

        if st.button("Store Data"):
            username = st.session_state.username
            passkey = st.session_state.passkey
            
            if encrypted_text and passkey:
                hashed_passkey = hash_passkey(passkey)
                key_hash = hashed_passkey["key"]
                salt = hashed_passkey["salt"]

                if key_hash not in users[username]:
                    users[username][key_hash] = {
                        "salt": salt,
                        "data": []
                    }
            users[username][key_hash]["data"].append(encrypted_text)
            save_users(users)
            st.success("Data stored successfully!")
    else:
        st.subheader("You have to login first to use this!")

elif choice == "Retrieve Data":
    if st.session_state.logged_in:
        st.subheader("Retrieve your data")
        passkey = st.text_input("Enter your passkey", type = "password")
        if st.button("Retrieve Data"):
            match_found = False
            for stored_key, details in users[st.session_state.username].items():
                if stored_key in ["password", "registered"]:
                    continue
                elif verify_passkey(stored_key, details["salt"], passkey):
                    decrypted_text = decrypt_data(details["data"])
                    for entry in decrypted_text:
                        st.success(f"🔓 Your data: **{entry}**")
                    match_found = True
                    break

            if not match_found:
                st.error("❌ Incorrect passkey")
                st.session_state.attempts += 1
                if st.session_state.attempts >= 3:
                    st.error("❌ Too many attempts!")
                    st.session_state.logged_in = False
                    st.session_state.username = ""
                    st.session_state.passkey = ""
                    st.warning("You have been logged out due to too many failed attempts.")
                    st.session_state.attempts = 0

    else:
        st.subheader("You have to login first to use this!")

elif choice == "Login":
    st.title("🔐 Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Register"):
        if username and password:
            if username in users:
                st.warning("User already exists!")
            else:
                users[username] = {"password": password, "registered": True}
                save_users(users)
                st.success("Registration successful! You can now log in.")

    if st.button("Login"):
        if username in users and users[username]["password"] == password:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Login successful! You can now use other pages")
        else:
            st.error("❌ Username or password incorrect")

