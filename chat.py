import random
import pandas as pd
import streamlit as st
from sentence_transformers import SentenceTransformer, util
from googletrans import Translator

# ======================
# CONFIGURATION & SETUP
# ======================

st.set_page_config(page_title="AI Health Assistant", page_icon="🤖", layout="centered")

st.markdown("""
<style>
    .main { background-color: #f8f9fa; }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: bold;
    }
    .response-box {
        background-color: white;
        padding: 18px;
        border-radius: 12px;
        box-shadow: 0 3px 10px rgba(0,0,0,0.08);
        margin-top: 15px;
        font-size: 16px;
        line-height: 1.5;
    }
    footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# 🔴 LOAD YOUR ACTUAL DATASET FILE NAME HERE
try:
    df = pd.read_csv('dataset - Sheet1.csv')  # ✅ Updated to your filename
    if 'disease' not in df.columns or 'cure' not in df.columns:
        st.error("❌ CSV must contain 'disease' and 'cure' columns.")
        st.stop()
except FileNotFoundError:
    st.error("❌ File 'dataset - Sheet1.csv' not found in the current directory.")
    st.stop()
except Exception as e:
    st.error(f"❌ Error loading dataset: {e}")
    st.stop()

@st.cache_resource
def load_model():
    return SentenceTransformer('all-MiniLM-L6-v2')

model = load_model()
translator = Translator()

# ======================
# HELPER FUNCTIONS
# ======================

health_tips = {
    "sleep": [
        "Try to get at least 7–8 hours of sleep each night.",
        "Establish a regular sleep routine to improve sleep quality.",
        "Avoid screens 1 hour before bed to help your mind relax."
    ],
    "energy": [
        "Eat balanced meals with protein, healthy fats, and complex carbs.",
        "Exercise for 30 minutes daily to boost natural energy.",
        "Stay hydrated—dehydration causes fatigue."
    ],
    "stress": [
        "Practice 5-minute deep breathing or mindfulness daily.",
        "Take short walks in nature to reduce anxiety.",
        "Write down your thoughts to clear mental clutter."
    ],
    "general": [
        "Drink at least 8 glasses of water per day.",
        "Eat more fruits, vegetables, and whole grains.",
        "Limit processed sugar and caffeine intake."
    ]
}

medical_keywords = {
    "fever": "It sounds like you may have a fever. Stay hydrated and consider seeing a doctor if symptoms persist.",
    "cough": "A persistent cough might be due to an infection or allergy. Try warm fluids and rest.",
    "headache": "Headaches can have many causes, including stress and dehydration. Consider resting and drinking water.",
    "cold": "Common colds usually go away on their own. Stay warm, drink fluids, and get rest."
}

def get_personalized_health_tip(user_input):
    user_input_lower = user_input.lower()
    if any(word in user_input_lower for word in ["tired", "fatigue", "low energy"]):
        return random.choice(health_tips["energy"])
    elif any(word in user_input_lower for word in ["sleep", "rest", "insomnia"]):
        return random.choice(health_tips["sleep"])
    elif any(word in user_input_lower for word in ["stress", "anxious", "worried"]):
        return random.choice(health_tips["stress"])
    else:
        return random.choice(health_tips["general"])

def find_best_cure(user_input):
    try:
        user_embedding = model.encode(user_input, convert_to_tensor=True)
        disease_embeddings = model.encode(df['disease'].tolist(), convert_to_tensor=True)
        similarities = util.pytorch_cos_sim(user_embedding, disease_embeddings)[0]
        best_idx = similarities.argmax().item()
        best_score = similarities[best_idx].item()

        SIMILARITY_THRESHOLD = 0.4
        if best_score >= SIMILARITY_THRESHOLD:
            return df.iloc[best_idx]['cure']

        for keyword, response in medical_keywords.items():
            if keyword in user_input.lower():
                return response

        return "I'm sorry, I don't have enough information on this. Please consult a healthcare professional."
    except Exception as e:
        return "An error occurred while analyzing your symptoms. Please try again."

def translate_text(text, dest_language='en'):
    try:
        if dest_language == 'en':
            return text
        result = translator.translate(text, dest=dest_language)
        return result.text if result.text else text
    except Exception:
        return text  # Fallback to original

language_codes = {
    "English": "en",
    "Hindi": "hi",
    "Gujarati": "gu",
    "Korean": "ko",
    "Turkish": "tr",
    "German": "de",
    "French": "fr",
    "Arabic": "ar",
    "Urdu": "ur",
    "Tamil": "ta",
    "Telugu": "te",
    "Chinese": "zh-CN",
    "Japanese": "ja",
}

# ======================
# STREAMLIT UI
# ======================

st.title("🤖 AI Health Assistant")
st.caption("Get personalized health advice in your language")

col1, col2 = st.columns([3, 1])
with col1:
    user_input = st.text_input(
        "Describe your symptom or health concern:",
        placeholder="e.g., I have a headache and fever"
    )
with col2:
    language_choice = st.selectbox("🌐 Language", list(language_codes.keys()), index=0)

col_btn1, col_btn2 = st.columns(2)
with col_btn1:
    get_response = st.button("💡 Get Medical Advice", use_container_width=True)
with col_btn2:
    get_tip = st.button("🌱 Get Health Tip", use_container_width=True)

if get_response and user_input.strip():
    with st.spinner("Analyzing your symptoms..."):
        response = find_best_cure(user_input.strip())
        translated = translate_text(response, dest_language=language_codes[language_choice])
    st.markdown(f'<div class="response-box"><strong>🩺 Medical Suggestion:</strong><br>{translated}</div>', unsafe_allow_html=True)
    st.info("⚠️ *This is not a substitute for professional medical advice. Consult a doctor for serious concerns.*")

if get_tip and user_input.strip():
    with st.spinner("Generating tip..."):
        tip = get_personalized_health_tip(user_input.strip())
        translated_tip = translate_text(tip, dest_language=language_codes[language_choice])
    st.markdown(f'<div class="response-box"><strong>🌿 Health Tip:</strong><br>{translated_tip}</div>', unsafe_allow_html=True)

st.markdown("<hr style='margin: 2rem 0;'>", unsafe_allow_html=True)
st.caption("Powered by Sentence Transformers • Multilingual support via Google Translate")