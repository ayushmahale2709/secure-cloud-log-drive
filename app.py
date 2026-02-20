import streamlit as st
import time
from datetime import datetime
import graphviz

# ---- Import Modules ----
from modules.auth import authenticate_user, register_user
from modules.blockchain import Blockchain
from modules.search_index import SearchIndex
from modules.logs import get_logs_for_user, format_log_for_display
from modules.anomaly import AnomalyDetector


# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Secure Cloud Log Drive",
    page_icon="🔐",
    layout="wide"
)

# ---------------- LOAD CSS ----------------
def load_css():
    with open("assets/styles.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()


# ---------------- SESSION INIT ----------------
def init_session():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "username" not in st.session_state:
        st.session_state.username = None

    if "blockchain" not in st.session_state:
        st.session_state.blockchain = Blockchain()

    if "search_index" not in st.session_state:
        st.session_state.search_index = SearchIndex()
        st.session_state.search_index.build_index(st.session_state.blockchain)

    if "anomaly" not in st.session_state:
        st.session_state.anomaly = AnomalyDetector()

    if "search_count" not in st.session_state:
        st.session_state.search_count = 0

    if "view_count" not in st.session_state:
        st.session_state.view_count = 0

    if "last_action_time" not in st.session_state:
        st.session_state.last_action_time = time.time()

    if "threat_level" not in st.session_state:
        st.session_state.threat_level = "LOW"

init_session()


# ---------------- LOGIN UI ----------------
def login_page():
    st.markdown("<h1>🔐 Secure Cloud Log Drive</h1>", unsafe_allow_html=True)
    st.markdown(
        "<p><b>Encrypted Storage</b> • <b>Blockchain Integrity</b> • "
        "<b>ML-based Security Monitoring</b></p>",
        unsafe_allow_html=True
    )
    st.markdown("---")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        tab1, tab2 = st.tabs(["Login", "Register"])

        with tab1:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            if st.button("Login"):
                if authenticate_user(username, password):
                    st.session_state.logged_in = True
                    st.session_state.username = username.strip().lower()
                    st.session_state.threat_level = "LOW"
                    st.rerun()
                else:
                    st.error("Invalid username or password")

        with tab2:
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")

            if st.button("Register"):
                if new_pass != confirm:
                    st.warning("Passwords do not match")
                elif register_user(new_user, new_pass):
                    st.success("Registration successful. Please login.")
                    st.rerun()
                else:
                    st.error("User already exists")


# ---------------- DASHBOARD ----------------
def dashboard():
    st.markdown(f"## 👋 Welcome, {st.session_state.username}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Blockchain Height", len(st.session_state.blockchain.chain))
    c2.metric(
        "System Integrity",
        "Secure" if st.session_state.blockchain.is_chain_valid() else "Tampered"
    )
    c3.metric("Threat Level", st.session_state.threat_level)

    st.markdown(
        "✔️ Logs are encrypted, integrity is ensured using blockchain, "
        "and abnormal user behavior is detected using Isolation Forest."
    )


# ---------------- MAIN APP ----------------
def main_app():
    st.sidebar.markdown("## 🔐 Secure Cloud Log Drive")
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"👤 **User:** {st.session_state.username}")
    st.sidebar.markdown("---")

    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    menu = st.sidebar.radio(
        "Navigation",
        [
            "Dashboard",
            "Add Log",
            "Encrypted Search",
            "My Logs",
            "View Blockchain",
            "Attack Graph"
        ]
    )

    # ---- Dashboard ----
    if menu == "Dashboard":
        dashboard()

    # ---- Add Log ----
    elif menu == "Add Log":
        st.markdown("### ➕ Add Secure Log Entry")

        log_data = st.text_area("Enter log details")

        if st.button("Encrypt & Store Log"):
            if log_data.strip():
                block = st.session_state.blockchain.add_log(
                    log_data,
                    st.session_state.username
                )
                st.session_state.search_index.index_log(log_data, block.index)
                st.success(f"Log stored securely in Block #{block.index}")
            else:
                st.warning("Log data cannot be empty")

    # ---- Encrypted Search ----
    elif menu == "Encrypted Search":
        st.markdown("### 🔍 Search Encrypted Logs")

        query = st.text_input("Enter keywords")

        if st.button("Execute Secure Search"):
            now = time.time()
            gap = now - st.session_state.last_action_time
            st.session_state.last_action_time = now
            st.session_state.search_count += 1

            st.session_state.anomaly.record_activity(
                st.session_state.search_count,
                st.session_state.view_count,
                gap
            )

            if st.session_state.anomaly.is_anomalous(
                st.session_state.search_count,
                st.session_state.view_count,
                gap
            ):
                st.session_state.threat_level = "HIGH"

                st.error(
                    "🚨 ML Security Alert: Abnormal behavior detected using "
                    "Isolation Forest. You have been logged out."
                )

                st.session_state.logged_in = False
                st.session_state.username = None
                time.sleep(1.5)
                st.rerun()

            results = st.session_state.search_index.search(query)

            if results:
                for idx in sorted(results):
                    block = st.session_state.blockchain.chain[idx]
                    st.code(f"{block.timestamp} | {block.data}")
            else:
                st.info("No matching logs found")

    # ---- My Logs ----
    elif menu == "My Logs":
        st.markdown("### 📂 My Logs (Decrypted View)")
        st.session_state.view_count += 1

        user_logs = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        if not user_logs:
            st.info("No logs found for your account")
        else:
            for block in user_logs:
                st.code(format_log_for_display(block))

    # ---- View Blockchain ----
    elif menu == "View Blockchain":
        st.markdown("### ⛓️ Blockchain Ledger")

        if st.session_state.blockchain.is_chain_valid():
            st.success("Blockchain integrity verified")
        else:
            st.error("Blockchain integrity compromised")

        rows = []
        for b in st.session_state.blockchain.chain:
            rows.append({
                "Index": b.index,
                "Owner": b.owner,
                "Time": b.timestamp,
                "Hash": b.hash[:12],
                "Prev Hash": b.previous_hash[:12]
            })

        st.table(rows)

    # ---- Attack Graph (DYNAMIC) ----
    elif menu == "Attack Graph":
        st.markdown("### 📊 Threat Visualization (Dynamic)")

        g = graphviz.Digraph()

        g.node("User", "Normal User", style="filled", fillcolor="#bbf7d0")

        if st.session_state.threat_level == "LOW":
            g.node("State", "Normal Behavior", style="filled", fillcolor="#bbf7d0")
            g.edge("User", "State")
        else:
            g.node("HF", "High Frequency Access", style="filled", fillcolor="#fed7aa")
            g.node("AN", "Anomaly Detected", style="filled", fillcolor="#fecaca")
            g.node("AB", "Potential Data Abuse", style="filled", fillcolor="#fca5a5")

            g.edge("User", "HF")
            g.edge("HF", "AN")
            g.edge("AN", "AB")

        st.graphviz_chart(g)


# ---------------- ROUTER ----------------
if st.session_state.logged_in:
    main_app()
else:
    login_page()
