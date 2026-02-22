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
    defaults = {
        "logged_in": False,
        "username": None,
        "blockchain": Blockchain(),
        "search_index": SearchIndex(),
        "anomaly": AnomalyDetector(),
        "search_count": 0,
        "view_count": 0,
        "last_action_time": time.time(),
        "threat_level": "LOW",
        "anomaly_hits": 0,
        "activity_log": []
    }

    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    st.session_state.search_index.build_index(st.session_state.blockchain)

init_session()


# ---------------- SECURITY BANNER ----------------
def security_banner():
    if st.session_state.threat_level == "LOW":
        st.success("🛡️ System Status: Secure")
    elif st.session_state.threat_level == "MEDIUM":
        st.warning("⚠️ System Status: Suspicious Activity Detected")
    else:
        st.error("🚨 System Status: High Risk – Session Restricted")


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
                    st.session_state.activity_log.append(
                        f"{datetime.now()} - User logged in"
                    )
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
                    st.success("✅ User registered successfully. Please login.")
                else:
                    st.error("User already exists")


# ---------------- DASHBOARD ----------------
def dashboard():
    security_banner()

    st.markdown(f"## 👋 Welcome, {st.session_state.username}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Blockchain Height", len(st.session_state.blockchain.chain))
    c2.metric(
        "System Integrity",
        "Secure" if st.session_state.blockchain.is_chain_valid() else "Tampered"
    )
    c3.metric("Threat Level", st.session_state.threat_level)

    risk = min(100, st.session_state.anomaly_hits * 33)
    st.progress(risk, text=f"Threat Risk: {risk}%")

    st.markdown(
        "✔️ Logs are encrypted, integrity is verified using blockchain, "
        "and user behavior is monitored using Isolation Forest."
    )


# ---------------- MAIN APP ----------------
def main_app():
    st.sidebar.markdown("## 🔐 Secure Cloud Log Drive")
    st.sidebar.markdown(f"👤 User: **{st.session_state.username}**")

    if st.session_state.username == "admin":
        st.sidebar.markdown("🛡️ Role: **Administrator**")

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
            "Attack Graph",
            "Audit Timeline"
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
                st.session_state.activity_log.append(
                    f"{datetime.now()} - Log stored in Block {block.index}"
                )
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

            is_anomaly = st.session_state.anomaly.is_anomalous(
                st.session_state.search_count,
                st.session_state.view_count,
                gap
            )

            st.info(
                f"""
ML Decision Factors:
• Search Count: {st.session_state.search_count}
• View Count: {st.session_state.view_count}
• Time Gap: {round(gap,2)} seconds
"""
            )

            if is_anomaly:
                st.session_state.anomaly_hits += 1
                st.session_state.threat_level = "MEDIUM"
            else:
                st.session_state.anomaly_hits = max(
                    0, st.session_state.anomaly_hits - 1
                )

            if st.session_state.anomaly_hits >= 3:
                st.session_state.threat_level = "HIGH"
                st.error("🚨 ML Security Alert: Session terminated")
                st.session_state.logged_in = False
                time.sleep(1)
                st.rerun()

            results = st.session_state.search_index.search(query)

            if results:
                for idx in sorted(results):
                    block = st.session_state.blockchain.chain[idx]
                    st.code(
                        f"""
Block #: {block.index}
Timestamp: {block.timestamp}
Hash: {block.hash}
Prev Hash: {block.previous_hash}
Data: {block.data}
Integrity Verified: {st.session_state.blockchain.is_chain_valid()}
"""
                    )
            else:
                st.info("No matching logs found")

    # ---- My Logs ----
    elif menu == "My Logs":
        st.markdown("### 📂 My Logs")
        st.session_state.view_count += 1

        logs = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        if not logs:
            st.info("No logs found")
        else:
            for block in logs:
                st.code(format_log_for_display(block))

    # ---- View Blockchain (IMPROVED UI) ----
    elif menu == "View Blockchain":
        st.markdown("### ⛓️ Blockchain Ledger")

        chain_valid = st.session_state.blockchain.is_chain_valid()

        if chain_valid:
            st.success("Blockchain integrity verified. All blocks are consistent.")
        else:
            st.error("Blockchain integrity check failed. Chain may be tampered.")

        st.markdown("---")

        for b in st.session_state.blockchain.chain:
            col1, col2 = st.columns([1, 3])

            with col1:
                st.markdown(f"**Block #{b.index}**")
                st.caption(f"Owner: {b.owner}")

            with col2:
                st.markdown(
                    f"""
**Timestamp:** {b.timestamp}  
**Hash:** `{b.hash[:20]}...`  
**Previous Hash:** `{b.previous_hash[:20]}...`
"""
                )

            if chain_valid:
                st.caption("✔ Block linked correctly")
            else:
                st.caption("⚠ Block link verification failed")

            st.markdown("---")

    # ---- Attack Graph ----
    elif menu == "Attack Graph":
        st.markdown("### 📊 Threat Visualization")

        g = graphviz.Digraph()
        g.node("User", "User")

        if st.session_state.threat_level == "LOW":
            g.node("Normal", "Normal Behavior", style="filled", fillcolor="lightgreen")
            g.edge("User", "Normal")
        else:
            g.node("Anomaly", "Anomaly Detected", style="filled", fillcolor="orange")
            g.node("Abuse", "Potential Abuse", style="filled", fillcolor="red")
            g.edge("User", "Anomaly")
            g.edge("Anomaly", "Abuse")

        st.graphviz_chart(g)

    # ---- Audit Timeline ----
    elif menu == "Audit Timeline":
        st.markdown("### 🕒 Session Audit Timeline")
        st.code("\n".join(st.session_state.activity_log[-20:]))

        st.download_button(
            "📄 Download Audit Report",
            data="\n".join(st.session_state.activity_log),
            file_name="audit_report.txt"
        )


# ---------------- ROUTER ----------------
if st.session_state.logged_in:
    main_app()
else:
    login_page()
