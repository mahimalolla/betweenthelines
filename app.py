import os
import re
import hmac
import base64
import hashlib
import sqlite3
from datetime import datetime

import streamlit as st

from core.analyzer import analyze
from core.text_extract import extract_text_from_upload

# -----------------------------
# Page config
# -----------------------------
st.set_page_config(page_title="Between the Lines", layout="wide", initial_sidebar_state="collapsed")

# -----------------------------
# Custom CSS
# -----------------------------
def load_custom_css():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

        * { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }

        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}

        /* True black background */
        html, body, [data-testid="stApp"] {
            background: #000000 !important;
        }

        .main {
            background: #000000 !important;
            padding: 2rem 1rem;
        }

        .product-title {
            font-size: 4.5rem;
            font-weight: 900;
            letter-spacing: -0.05em;
            background: linear-gradient(135deg, #ffffff 0%, #a0a0ff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            text-align: center;
            margin-bottom: 0.5rem;
            line-height: 1.1;
        }

        .product-subtitle {
            text-align: center;
            font-size: 1.1rem;
            color: rgba(255, 255, 255, 0.7);
            max-width: 760px;
            margin: 0 auto 2.25rem auto;
            line-height: 1.6;
        }

        .auth-container {
            max-width: 440px;
            margin: 2rem auto;
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.10);
            border-radius: 24px;
            padding: 3rem 2.5rem;
            backdrop-filter: blur(10px);
            box-shadow: 0 10px 38px rgba(0, 0, 0, 0.55);
        }

        .auth-title {
            font-size: 1.8rem;
            font-weight: 800;
            color: white;
            margin-bottom: 0.5rem;
            text-align: center;
        }

        .auth-subtitle {
            font-size: 0.95rem;
            color: rgba(255, 255, 255, 0.6);
            margin-bottom: 2rem;
            text-align: center;
        }

        .stTextInput input, .stTextArea textarea {
            background: rgba(255, 255, 255, 0.05) !important;
            border: 1px solid rgba(255, 255, 255, 0.15) !important;
            border-radius: 12px !important;
            color: white !important;
            padding: 0.75rem 1rem !important;
            font-size: 0.95rem !important;
        }

        .stTextInput input:focus, .stTextArea textarea:focus {
            border-color: #8b8bff !important;
            box-shadow: 0 0 0 3px rgba(139, 139, 255, 0.12) !important;
        }

        .stButton button {
            background: linear-gradient(135deg, #6b6bff 0%, #8b8bff 100%) !important;
            color: white !important;
            border: none !important;
            border-radius: 12px !important;
            padding: 0.75rem 1.5rem !important;
            font-weight: 600 !important;
            font-size: 0.95rem !important;
            transition: all 0.25s ease !important;
            box-shadow: 0 4px 14px rgba(107, 107, 255, 0.35) !important;
        }

        .stButton button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 7px 26px rgba(107, 107, 255, 0.45) !important;
        }

        /* Title-only cards (used above inputs) */
        .section-card {
            border: 1px solid rgba(255, 255, 255, 0.12);
            background: rgba(255, 255, 255, 0.035);
            border-radius: 20px;
            padding: 1.5rem;
            margin-bottom: 1.0rem;
            backdrop-filter: blur(10px);
        }

        .section-title {
            font-size: 1.2rem;
            font-weight: 700;
            color: white;
            margin-bottom: 0.4rem;
        }

        .section-subtitle {
            color: rgba(255, 255, 255, 0.65);
            font-size: 0.9rem;
            line-height: 1.5;
        }

        /* Content cards (used for results sections) */
        .content-card {
            border: 1px solid rgba(255, 255, 255, 0.12);
            background: rgba(255, 255, 255, 0.03);
            border-radius: 20px;
            padding: 1.25rem 1.35rem;
            margin: 0.5rem 0 1.2rem 0;
            backdrop-filter: blur(10px);
        }

        .content-card-title {
            font-size: 1.15rem;
            font-weight: 750;
            color: white;
            margin-bottom: 0.35rem;
        }

        .content-card-subtitle {
            color: rgba(255, 255, 255, 0.62);
            font-size: 0.9rem;
            line-height: 1.5;
            margin-bottom: 0.85rem;
        }

        .skill-pill {
            display: inline-block;
            padding: 8px 16px;
            margin: 4px 6px 4px 0;
            border-radius: 999px;
            border: 1px solid rgba(139, 139, 255, 0.30);
            background: rgba(107, 107, 255, 0.10);
            color: #c0c0ff;
            font-size: 0.85rem;
            font-weight: 500;
            letter-spacing: 0.2px;
        }

        .stMetric {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.10);
            border-radius: 16px;
            padding: 1rem;
        }

        .stMetric label { color: rgba(255, 255, 255, 0.7) !important; font-size: 0.9rem !important; }

        .stMetric [data-testid="stMetricValue"] {
            color: white !important;
            font-size: 2rem !important;
            font-weight: 750 !important;
        }

        .stProgress > div > div {
            background: linear-gradient(90deg, #6b6bff 0%, #8b8bff 100%);
            border-radius: 999px;
        }

        .streamlit-expanderHeader {
            background: rgba(255, 255, 255, 0.04) !important;
            border: 1px solid rgba(255, 255, 255, 0.10) !important;
            border-radius: 12px !important;
            color: white !important;
            font-weight: 600 !important;
        }

        .stFileUploader {
            background: rgba(255, 255, 255, 0.03);
            border: 2px dashed rgba(255, 255, 255, 0.15);
            border-radius: 16px;
            padding: 1.5rem;
        }

        hr {
            border-color: rgba(255, 255, 255, 0.10) !important;
            margin: 2rem 0 !important;
        }

        .stAlert { border-radius: 12px !important; border: none !important; }

        .user-greeting {
            text-align: center;
            color: rgba(255, 255, 255, 0.60);
            font-size: 0.9rem;
            margin-top: 0.75rem;
        }

        .user-name { color: #8b8bff; font-weight: 650; }

        .logout-container { text-align: right; margin-bottom: 0.75rem; }

        .rewrite-card {
            border: 1px solid rgba(255, 255, 255, 0.10);
            border-radius: 16px;
            padding: 1.1rem 1.15rem;
            margin: 0.8rem 0;
            background: rgba(255, 255, 255, 0.02);
        }

        .rewrite-title {
            font-weight: 700;
            font-size: 0.95rem;
            color: #8b8bff;
            margin-bottom: 0.75rem;
        }

        .rewrite-before { margin-top: 0.4rem; opacity: 0.7; font-size: 0.9rem; }
        .rewrite-after  { margin-top: 0.25rem; opacity: 0.95; font-size: 0.9rem; color: #c0ffc0; }

        .rewrite-rationale {
            margin-top: 0.75rem;
            opacity: 0.65;
            font-size: 0.85rem;
            line-height: 1.5;
            font-style: italic;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

load_custom_css()

# -----------------------------
# Auth: SQLite + PBKDF2-HMAC
# -----------------------------
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def init_auth_db():
    with get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()

def _pbkdf2_hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(16)
    iters = 210_000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return "pbkdf2_sha256$%d$%s$%s" % (
        iters,
        base64.b64encode(salt).decode("utf-8"),
        base64.b64encode(dk).decode("utf-8"),
    )

def _verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters_s, salt_b64, hash_b64 = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iters = int(iters_s)
        salt = base64.b64decode(salt_b64.encode("utf-8"))
        expected = base64.b64decode(hash_b64.encode("utf-8"))
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False

def valid_email(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.strip().lower()))

def create_user(email: str, name: str, password: str) -> tuple[bool, str]:
    email = email.strip().lower()
    name = name.strip()

    if not valid_email(email):
        return False, "Please enter a valid email."
    if len(name) < 2:
        return False, "Name must be at least 2 characters."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    pw_hash = _pbkdf2_hash_password(password)

    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (email, name, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (email, name, pw_hash, datetime.utcnow().isoformat()),
            )
            conn.commit()
        return True, "Account created. You can log in now."
    except sqlite3.IntegrityError:
        return False, "An account with this email already exists."
    except Exception as e:
        return False, f"Could not create account: {e}"

def authenticate(email: str, password: str) -> tuple[bool, dict | None]:
    email = email.strip().lower()
    if not valid_email(email):
        return False, None

    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, email, name, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not row:
        return False, None

    user_id, user_email, user_name, pw_hash = row
    if _verify_password(password, pw_hash):
        return True, {"id": user_id, "email": user_email, "name": user_name}
    return False, None

# -----------------------------
# UI helpers
# -----------------------------
def pill(text: str) -> str:
    return f'<span class="skill-pill">{text}</span>'

def section_card(title: str, subtitle: str = ""):
    st.markdown(
        f"""
        <div class="section-card">
            <div class="section-title">{title}</div>
            <div class="section-subtitle">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

def content_card_start(title: str, subtitle: str = ""):
    st.markdown(
        f"""
        <div class="content-card">
            <div class="content-card-title">{title}</div>
            <div class="content-card-subtitle">{subtitle}</div>
        """,
        unsafe_allow_html=True,
    )

def content_card_end():
    st.markdown("</div>", unsafe_allow_html=True)

def render_product_header():
    st.markdown(
        """
        <div class="product-title">Between the Lines</div>
        <div class="product-subtitle">
            Decode what a job description implies and improve how your resume signals evidence.
            No ATS-style score - just clarity.
        </div>
        """,
        unsafe_allow_html=True,
    )

def top_actions(direct_matches, missing, implied):
    actions = []
    if direct_matches:
        actions.append("Make your highest-signal matches visible in your top 1–2 bullets (Summary or Projects).")
    if missing:
        actions.append("Prioritize 2–3 role-critical gaps and add evidence (a project bullet or coursework). Avoid keyword dumping.")
    if implied:
        actions.append("Add one bullet that proves an implied expectation (ownership, production rigor, or cross-functional alignment).")
    if not actions:
        actions = ["Add more specific detail to the JD and resume text so the analyzer can extract stronger signals."]
    return actions[:3]

def bullet_list(items):
    for it in items:
        st.write(f"- {it}")

# -----------------------------
# Auth pages
# -----------------------------
def auth_gate():
    if "auth" not in st.session_state:
        st.session_state.auth = {"logged_in": False, "user": None}

    if "auth_mode" not in st.session_state:
        st.session_state.auth_mode = "login"

    if st.session_state.auth["logged_in"]:
        return

    render_product_header()

    st.markdown('<div class="auth-container">', unsafe_allow_html=True)

    if st.session_state.auth_mode == "login":
        st.markdown('<div class="auth-title">Welcome back</div>', unsafe_allow_html=True)
        st.markdown('<div class="auth-subtitle">Sign in to your account</div>', unsafe_allow_html=True)

        email = st.text_input("Email address", key="login_email")
        password = st.text_input("Password", type="password", key="login_password")

        if st.button("Sign in", type="primary", use_container_width=True):
            ok, user = authenticate(email, password)
            if ok:
                st.session_state.auth = {"logged_in": True, "user": user}
                st.success("Signed in successfully.")
                st.rerun()
            else:
                st.error("Invalid email or password.")

        if st.button("Switch to Sign up", key="switch_to_signup", use_container_width=True):
            st.session_state.auth_mode = "signup"
            st.rerun()

    else:
        st.markdown('<div class="auth-title">Create account</div>', unsafe_allow_html=True)
        st.markdown('<div class="auth-subtitle">Get started with Between the Lines</div>', unsafe_allow_html=True)

        name = st.text_input("Full name", key="signup_name")
        email = st.text_input("Email address", key="signup_email")
        password = st.text_input("Password (8+ characters)", type="password", key="signup_password")

        if st.button("Create account", type="primary", use_container_width=True):
            ok, msg = create_user(email, name, password)
            if ok:
                st.success(msg)
                st.session_state.auth_mode = "login"
                st.rerun()
            else:
                st.error(msg)

        if st.button("Switch to Sign in", key="switch_to_login", use_container_width=True):
            st.session_state.auth_mode = "login"
            st.rerun()

    st.markdown("</div>", unsafe_allow_html=True)
    st.stop()

# -----------------------------
# Main app
# -----------------------------
def main_app():
    user = st.session_state.auth["user"]

    # Initialize stable state keys for resume input
    if "resume_text_value" not in st.session_state:
        st.session_state["resume_text_value"] = ""

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        render_product_header()

    st.markdown(
        f'<div class="user-greeting">Signed in as <span class="user-name">{user.get("name")}</span></div>',
        unsafe_allow_html=True
    )

    st.markdown('<div class="logout-container">', unsafe_allow_html=True)
    if st.button("Log out", key="logout_btn"):
        st.session_state.auth = {"logged_in": False, "user": None}
        st.session_state.auth_mode = "login"
        st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    left, right = st.columns(2)

    with left:
        section_card("Job Description", "Paste the job description text. More specificity produces better output.")
        jd_text = st.text_area(
            "",
            height=240,
            placeholder="Paste job description text…",
            key="jd_text",
            label_visibility="collapsed",
        )

    with right:
        section_card("Resume", "Upload a PDF or DOCX, or paste text if needed.")
        upload = st.file_uploader(
            "Upload resume (.pdf or .docx)",
            type=["pdf", "docx"],
            key="resume_upload",
            label_visibility="collapsed",
        )

        if upload is not None:
            try:
                extracted, warn = extract_text_from_upload(upload.name, upload.getvalue())
                if warn:
                    st.warning(warn)
                if extracted:
                    st.session_state["resume_text_value"] = extracted
                    st.success(f"Extracted text from {upload.name}")
            except Exception as e:
                st.error(f"Could not extract text: {e}")

        resume_text = st.text_area(
            "Or paste resume text",
            height=170,
            placeholder="Paste resume text (optional fallback)…",
            value=st.session_state.get("resume_text_value", ""),
            key="resume_text_input",
            label_visibility="collapsed",
        )

        st.session_state["resume_text_value"] = resume_text

    st.markdown("<br>", unsafe_allow_html=True)
    analyze_btn = st.button("Analyze", type="primary", use_container_width=True)

    if not analyze_btn:
        return

    jd_text_val = st.session_state.get("jd_text", "")
    resume_text_final = st.session_state.get("resume_text_value", "")

    if not jd_text_val.strip():
        st.error("Please paste a job description.")
        return
    if not resume_text_final.strip():
        st.error("Please upload or paste a resume.")
        return

    result = analyze(jd_text_val, resume_text_final)

    jd_count = len(result.jd_skills)
    match_count = len(result.direct_matches)
    missing_count = len(result.missing_from_resume)
    coverage = (match_count / jd_count) if jd_count else 0.0

    st.divider()

    content_card_start("Overview", "A visibility check based on detected signals. This is not a hiring score.")
    c1, c2, c3 = st.columns(3)
    c1.metric("Signal coverage", f"{coverage:.0%}")
    c2.metric("Direct matches", match_count)
    c3.metric("Potential gaps", missing_count)

    st.progress(min(max(coverage, 0.0), 1.0))
    st.caption("Signal coverage = percent of detected job description signals that also appear in your resume text.")
    content_card_end()

    content_card_start("Recommended next steps", "Do these first to improve signal and alignment.")
    bullet_list(top_actions(result.direct_matches, result.missing_from_resume, result.implied))
    content_card_end()

    colA, colB = st.columns(2)

    with colA:
        content_card_start("Strong signals you already show", "Keep these consistent across Summary, Projects, and Experience.")
        if result.direct_matches:
            st.markdown("".join([pill(s) for s in sorted(result.direct_matches)]), unsafe_allow_html=True)
        else:
            st.info("No direct matches detected from the current skill inventory. Add terms in core/skills.py for your target roles.")
        content_card_end()

    with colB:
        content_card_start("Signals the job description expects", "Not every gap matters. Prioritize repeated and role-critical signals.")
        if result.missing_from_resume:
            st.markdown("".join([pill(s) for s in sorted(result.missing_from_resume)]), unsafe_allow_html=True)
        else:
            st.success("No missing signals detected from the current inventory.")
        content_card_end()

    content_card_start("Implied expectations", "Operating modes hiring teams often filter on implicitly.")
    if result.implied:
        for exp in result.implied:
            with st.expander(exp.jd_trigger, expanded=True):
                st.markdown("**What it implies**")
                bullet_list(exp.implies)
                st.markdown("**How to signal it on a resume**")
                st.write(exp.how_to_signal)
    else:
        st.info("No implied triggers matched. Add more mappings in core/implied_map.py to reflect your target roles.")
    content_card_end()

    content_card_start("Language upgrades", "Rewrite templates to increase signal without inventing accomplishments.")
    if result.rewrites:
        for r in result.rewrites:
            st.markdown(
                f"""
                <div class="rewrite-card">
                    <div class="rewrite-title">Upgrade suggestion</div>
                    <div class="rewrite-before">Before: {r.weak_phrase}</div>
                    <div class="rewrite-after">After: {r.stronger_phrase}</div>
                    <div class="rewrite-rationale">{r.rationale}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.success("No weak-phrase patterns detected. Add more rules in core/rewrite_rules.py if you want stricter linting.")
    content_card_end()

# -----------------------------
# Boot
# -----------------------------
init_auth_db()
auth_gate()
main_app()
