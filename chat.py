import os
import streamlit as st
import sqlite3
import bcrypt
import pandas as pd
import random
from sentence_transformers import SentenceTransformer, util
from googletrans import Translator

# ======================
# DATABASE SETUP
# ======================
DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password: str) -> bytes:
    """Return bcrypt hashed password (bytes)."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password: str, hashed) -> bool:
    """Verify a password against a stored hash (supports bytes or memoryview)."""
    if isinstance(hashed, memoryview):
        hashed = hashed.tobytes()
    if isinstance(hashed, str):
        # unlikely, but convert if stored as str
        hashed = hashed.encode('latin1')
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def register_user(username: str, email: str, password: str) -> bool:
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        pw_hash = hash_password(password)
        # store as BLOB
        c.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, sqlite3.Binary(pw_hash))
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False
    except Exception:
        return False

def authenticate_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result and result[0] is not None:
        return verify_password(password, result[0])
    return False

init_db()

# ======================
# SESSION STATE
# ======================
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "last_user_input" not in st.session_state:
    st.session_state.last_user_input = ""
if "show_health_tip" not in st.session_state:
    st.session_state.show_health_tip = False

# ======================
# LOGIN PAGE
# ======================
def show_login_page():
    st.set_page_config(page_title="AI Health Assistant - Login", layout="centered")
    st.markdown("""
    <style>
        .main { background-color: #0f0013; color: white; }
        .login-box {
            background: #15001d;
            padding: 30px;
            border-radius: 20px;
            max-width: 450px;
            margin: 50px auto;
            box-shadow: 0 8px 20px rgba(0,0,0,0.4);
            border: 1px solid #2ecc71;
        }
        .logo { text-align: center; font-size: 2.5rem; margin-bottom: 10px; }
        .title { text-align: center; font-size: 1.8rem; margin-bottom: 30px; color: #2ecc71; }
        .stButton>button {
            background: #2ecc71;
            color: white;
            border-radius: 30px;
            padding: 10px;
            font-weight: bold;
            width: 100%;
        }
        .stTextInput>div>div>input {
            background: #1a0026;
            color: white;
            border: 1px solid #34495e;
            border-radius: 30px;
            padding: 12px;
        }
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="login-box"><div class="logo">🤖</div><div class="title">AI Health Assistant</div>', unsafe_allow_html=True)
    st.markdown('<p style="text-align:center;color:#bdc3c7;">Sign in to get personalized health advice</p>', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        with st.form("login"):
            user = st.text_input("Username")
            pwd = st.text_input("Password", type="password")
            if st.form_submit_button("Login"):
                if authenticate_user(user, pwd):
                    st.session_state.logged_in = True
                    st.session_state.username = user
                    st.rerun()
                else:
                    st.error("Invalid credentials")
    
    with tab2:
        with st.form("signup"):
            new_user = st.text_input("Username")
            email = st.text_input("Email")
            pwd1 = st.text_input("Password", type="password")
            pwd2 = st.text_input("Confirm Password", type="password")
            if st.form_submit_button("Sign Up"):
                if pwd1 != pwd2:
                    st.error("Passwords don't match")
                elif len(pwd1) < 6:
                    st.error("Password must be ≥6 characters")
                elif register_user(new_user, email, pwd1):
                    st.success("Account created! Please log in.")
                else:
                    st.error("Username/email already exists or an error occurred.")
    
    st.markdown('</div>', unsafe_allow_html=True)

# ======================
# MAIN APP — FIXED HEALTH TIP LOGIC
# ======================
def show_main_app():
    st.set_page_config(page_title="AI Health Assistant", page_icon="🤖", layout="centered")
    st.markdown("""
    <style>
        .main { background-color: #0f0013; color: white; }
        .top-bar { display: flex; justify-content: flex-end; padding: 15px; }
        .header { text-align: center; margin: 20px 0; }
        .header h1 { font-size: 2.2rem; color: #2ecc71; }
        .input-section { margin: 20px 0; }
        .stButton>button {
            background: #2ecc71;
            color: white;
            border: none;
            border-radius: 30px;
            padding: 10px 20px;
            font-weight: 600;
            box-shadow: 0 4px 10px rgba(46,204,113,0.3);
        }
        .stTextInput>div>div>input {
            background: #1a0026;
            color: white;
            border: 1px solid #34495e;
            border-radius: 30px;
            padding: 12px 20px;
            font-size: 16px;
        }
        .response-box {
            background: #15001d;
            border-left: 4px solid #2ecc71;
            padding: 20px;
            border-radius: 12px;
            margin-top: 20px;
            font-size: 16px;
            line-height: 1.6;
        }
        .tip-button {
            margin-top: 15px;
            text-align: center;
        }
        .tip-button button {
            background: transparent;
            color: #2ecc71;
            border: 1px solid #2ecc71;
            border-radius: 20px;
            padding: 6px 16px;
        }
    </style>
    """, unsafe_allow_html=True)

    # Top bar with logout
    st.markdown('<div class="top-bar">', unsafe_allow_html=True)
    if st.button("Logout", key="logout_btn"):
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.last_user_input = ""
        st.session_state.show_health_tip = False
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    # Header
    st.markdown(f'''
    <div class="header">
        <h1>🤖 AI Health Assistant</h1>
        <p style="color:#bdc3c7;">Hi {st.session_state.username}! Describe your symptom below.</p>
    </div>
    ''', unsafe_allow_html=True)

    # Load dataset (use local project copy)
    BASE_DIR = os.path.dirname(__file__)
    df_path = os.path.join(BASE_DIR, 'dataset - Sheet1.csv')

    if not os.path.exists(df_path):
        st.error(f"❌ Dataset missing. Please put 'dataset - Sheet1.csv' in the project folder: {BASE_DIR}")
        return

    try:
        df = pd.read_csv(df_path)
        # basic validation
        if 'disease' not in df.columns or 'cure' not in df.columns:
            st.error("Dataset found but missing required columns 'disease' and/or 'cure'. Please fix the CSV.")
            return
    except Exception as e:
        st.error(f"Error loading dataset: {e}")
        return

    @st.cache_resource
    def load_model():
        # small model for embeddings — quick and works well for demos
        return SentenceTransformer('all-MiniLM-L6-v2')

    model = load_model()
    translator = Translator()

    # Helper functions
    health_tips = {
        "sleep": ["Try to get at least 7–8 hours of sleep each night.", "Establish a regular sleep routine.", "Avoid screens 1 hour before bed."],
        "energy": ["Eat balanced meals with complex carbs and protein.", "Exercise for 30 minutes daily.", "Stay hydrated and take short walks."],
        "stress": ["Practice 5-minute deep breathing exercises.", "Take short walks in nature.", "Write down your thoughts to clear your mind."],
        "general": ["Drink at least 8 glasses of water daily.", "Eat more fruits and vegetables.", "Limit processed sugar intake."]
    }

    medical_keywords = {
        "fever": "It sounds like you may have a fever. Stay hydrated and consider seeing a doctor if symptoms persist.",
        "cough": "A persistent cough might be due to an infection or allergy. Try warm fluids and rest. Seek medical care if breathing is difficult.",
        "headache": "Headaches can have many causes, including stress and dehydration. Consider resting and drinking water. See a doctor for severe or recurrent headaches.",
        "cold": "Common colds usually go away on their own. Stay warm, drink fluids, and rest."
    }

    def get_personalized_health_tip(user_input: str) -> str:
        u = user_input.lower()
        if any(w in u for w in ["tired", "fatigue", "low energy"]): 
            return random.choice(health_tips["energy"])
        if any(w in u for w in ["sleep", "rest", "insomnia"]): 
            return random.choice(health_tips["sleep"])
        if any(w in u for w in ["stress", "anxious", "worried"]): 
            return random.choice(health_tips["stress"])
        return random.choice(health_tips["general"])

    def find_best_cure(user_input: str) -> str:
        try:
            emb = model.encode(user_input, convert_to_tensor=True)
            disease_embs = model.encode(df['disease'].tolist(), convert_to_tensor=True)
            sims = util.pytorch_cos_sim(emb, disease_embs)[0]
            idx = sims.argmax().item()
            score = sims[idx].item()
            if score >= 0.4:
                return str(df.iloc[idx]['cure'])
            # fallback keyword matching
            for k, v in medical_keywords.items():
                if k in user_input.lower():
                    return v
            return "I'm sorry, I don't have enough information. Please consult a healthcare professional."
        except Exception:
            return "An error occurred while analyzing your input. Please try again."

    def translate_text(text: str, lang: str = 'en') -> str:
        try:
            # if target is english, return raw text; translator may throw for same-language
            if not text:
                return text
            if lang is None or lang.lower() == 'en':
                return text
            res = translator.translate(text, dest=lang)
            # googletrans may return an object; ensure .text exists
            return getattr(res, "text", str(res))
        except Exception:
            return text

    # === MAIN INPUT & FLOW ===
    user_input = st.text_input(
        "",
        placeholder="e.g., I have a headache and feel tired...",
        value=st.session_state.last_user_input
    )

    # Get Medical Advice
    if st.button("📤 Get Medical Advice", use_container_width=True):
        if user_input.strip():
            st.session_state.last_user_input = user_input.strip()
            st.session_state.show_health_tip = True
            with st.spinner("Analyzing your symptoms..."):
                resp = find_best_cure(user_input.strip())
                trans = translate_text(resp, "en")
            st.markdown(f'<div class="response-box"><strong>🩺 Medical Advice:</strong><br>{trans}</div>', unsafe_allow_html=True)
            st.info("⚠️ *This is not a substitute for professional medical advice.*")
        else:
            st.warning("Please describe your symptom first.")

    # Always show "Get Health Tip" if flag is True
    if st.session_state.show_health_tip:
        if st.button("🌱 Get Health Tip", use_container_width=True):
            with st.spinner("Generating wellness tip..."):
                tip = get_personalized_health_tip(st.session_state.last_user_input)
                trans_tip = translate_text(tip, "en")
            st.markdown(f'<div class="response-box"><strong>🌿 Wellness Tip:</strong><br>{trans_tip}</div>', unsafe_allow_html=True)

# ======================
# ROUTER
# ======================
if st.session_state.logged_in:
    show_main_app()
else:
    show_login_page()
