import os
import sys
import streamlit as st
import base64
import sqlite3
import hashlib

# ─── Page Config ───
st.set_page_config(
    page_title="OVERWATCH-APT",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# ─── Hide multipage nav, hamburger menu, deploy button, and footer ───
st.markdown("""
<style>
    [data-testid="stSidebarNav"] { display: none !important; }
    #MainMenu { visibility: hidden; }
    [data-testid="stToolbar"] { display: none !important; }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ─── Helper: base64 encode a file ───
def get_base64(bin_file):
    with open(bin_file, 'rb') as f:
        return base64.b64encode(f.read()).decode()


# ─── Minimal Red/Black Animated Theme ───
def apply_theme(bg_image_path):
    bg_b64 = get_base64(bg_image_path)
    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    @keyframes slowPan {{
        0% {{ background-position: 0% 0%; }}
        50% {{ background-position: 100% 100%; }}
        100% {{ background-position: 0% 0%; }}
    }}

    @keyframes slideUpFadeIn {{
        0% {{ opacity: 0; transform: translateY(20px); }}
        100% {{ opacity: 1; transform: translateY(0); }}
    }}
    
    .stApp > header + .main {{
        animation: slideUpFadeIn 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards;
    }}

    .stApp {{
        background-color: #050505;
        background-image: linear-gradient(rgba(5, 5, 5, 0.8), rgba(5, 5, 5, 0.8)), url("data:image/png;base64,{bg_b64}");
        background-size: 150% 150%;
        background-attachment: fixed;
        animation: slowPan 45s linear infinite;
        font-family: 'Inter', sans-serif;
    }}

    /* ── Global text ── */
    h1, h2, h3, h4, h5, h6 {{
        color: #f8fafc !important;
        font-family: 'Inter', sans-serif !important;
        font-weight: 600 !important;
    }}
    p, span, label, div {{
        color: #d1d5db !important;
    }}

    /* ── Title ── */
    .app-title {{
        text-align: center;
        font-size: 1.6rem;
        font-weight: 700;
        color: #ef4444 !important; /* Red Accent */
        letter-spacing: 2px;
        font-family: 'JetBrains Mono', monospace !important;
        margin-bottom: 0.2rem;
        text-transform: uppercase;
    }}
    .app-subtitle {{
        text-align: center;
        font-size: 0.85rem;
        color: #9ca3af !important;
        letter-spacing: 3px;
        text-transform: uppercase;
        margin-bottom: 1.5rem;
    }}

    /* ── Input fields ── */
    .stTextInput > div > div > input {{
        background: rgba(10, 10, 10, 0.8) !important;
        border: 1px solid rgba(239, 68, 68, 0.2) !important;
        border-radius: 6px !important;
        color: #f8fafc !important;
        padding: 0.7rem 1rem !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 0.95rem !important;
        transition: all 0.3s ease;
    }}
    .stTextInput > div > div > input:focus {{
        border-color: #ef4444 !important;
        box-shadow: 0 0 8px rgba(239, 68, 68, 0.3) !important;
    }}
    .stTextInput label {{
        color: #9ca3af !important;
        font-size: 0.85rem !important;
        font-weight: 500 !important;
        margin-bottom: 0.2rem !important;
    }}

    /* ── Buttons ── */
    .stButton > button {{
        background: rgba(239, 68, 68, 0.1) !important; /* Faint Red */
        color: #ef4444 !important;
        border: 1px solid rgba(239, 68, 68, 0.5) !important;
        border-radius: 6px !important;
        padding: 0.6rem 2rem !important;
        font-weight: 600 !important;
        font-size: 0.9rem !important;
        letter-spacing: 1px !important;
        text-transform: uppercase;
        width: 100% !important;
        transition: all 0.3s ease !important;
        font-family: 'Inter', sans-serif !important;
    }}
    .stButton > button:hover {{
        background: #ef4444 !important;
        color: #ffffff !important;
        border-color: #ef4444 !important;
        box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4);
        transform: translateY(-2px);
    }}
    .stButton > button:active {{
        transform: translateY(0px) scale(0.98);
    }}

    /* ── Expanders and Alerts ── */
    .stSuccess {{
        background: rgba(34, 197, 94, 0.1) !important;
        border: 1px solid rgba(34, 197, 94, 0.3) !important;
        color: #f8fafc !important;
    }}
    .stError {{
        background: rgba(239, 68, 68, 0.1) !important;
        border: 1px solid rgba(239, 68, 68, 0.3) !important;
        color: #f8fafc !important;
    }}

    /* ── Secure badge ── */
    .secure-badge {{
        text-align: center;
        margin-top: 1.5rem;
        font-size: 0.75rem;
        color: rgba(239, 68, 68, 0.6) !important;
        letter-spacing: 1px;
    }}
    </style>
    """, unsafe_allow_html=True)


apply_theme('background/bg_red_black.png')

# ─── Database (with hashed passwords) ───
def create_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                      (username TEXT PRIMARY KEY, password TEXT)''')
    conn.commit()
    conn.close()

create_db()


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def register_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                        (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                    (username, hash_password(password)))
    user = cursor.fetchone()
    conn.close()
    return user is not None


# ─── Tab Styling ───
st.markdown("""
<style>
    .stTabs [data-baseweb="tab-list"] {
        gap: 0;
        background: rgba(15, 23, 42, 0.5);
        border-radius: 10px;
        padding: 3px;
        max-width: 380px;
        margin: 0 auto 1.2rem auto;
        border: 1px solid rgba(94, 234, 212, 0.08);
    }
    .stTabs [data-baseweb="tab"] {
        flex: 1;
        border-radius: 8px;
        color: #94a3b8 !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
        padding: 0.45rem 0.9rem !important;
        background: transparent !important;
        border: none !important;
    }
    .stTabs [aria-selected="true"] {
        background: rgba(94, 234, 212, 0.1) !important;
        color: #5eead4 !important;
    }
    .stTabs [data-baseweb="tab-highlight"] { display: none !important; }
    .stTabs [data-baseweb="tab-border"] { display: none !important; }
</style>
""", unsafe_allow_html=True)

# ─── UI Layout ───
st.markdown('<div class="app-title">🛡️ OVERWATCH-APT</div>', unsafe_allow_html=True)
st.markdown('<div class="app-subtitle">Threat Detection & APT Hunting</div>', unsafe_allow_html=True)

# Inline tabs for Login / Register
tab_login, tab_register = st.tabs(["🔐 Login", "📝 Register"])

with tab_login:
    st.markdown("### Secure Login")
    username = st.text_input("Username", key="login_user", placeholder="Enter username")
    password = st.text_input("Password", type="password", key="login_pass", placeholder="Enter password")
    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state["authenticated"] = True
            st.success("✅ Access granted")
            st.switch_page("pages/app1.py")
        else:
            st.error("❌ Invalid credentials.")
    st.markdown('<div class="secure-badge">🔒 Encrypted · SHA-256</div>', unsafe_allow_html=True)

with tab_register:
    st.markdown("### Create Account")
    username = st.text_input("Username", key="reg_user", placeholder="Choose a username")
    password = st.text_input("Password", type="password", key="reg_pass", placeholder="Choose a password")
    if st.button("Register"):
        if username and password:
            if register_user(username, password):
                st.success("✅ Account created successfully!")
            else:
                st.error("Username already taken.")
        else:
            st.error("Please fill in all fields.")
    st.markdown('<div class="secure-badge">🔒 Passwords are securely hashed</div>', unsafe_allow_html=True)
