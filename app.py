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
from modules.security_state import SecurityState


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
        "is_admin": False,
        "blockchain": Blockchain(),
        "search_index": SearchIndex(),
        "anomaly": AnomalyDetector(),
        "security": SecurityState(),
        "search_count": 0,
        "view_count": 0,
        "last_action_time": time.time(),
        "warned_user": False,
        "activity_log": []
    }

    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    if hasattr(st.session_state.search_index, "build_index"):
        st.session_state.search_index.build_index(st.session_state.blockchain)

init_session()


# ---------------- HELPERS ----------------
def get_block_by_index(chain, block_index):
    for b in chain:
        if b.index == block_index:
            return b
    return None


# ---------------- SECURITY BANNER ----------------
def security_banner():
    level = st.session_state.security.threat_level

    if level == "LOW":
        st.success("🟢 System operating normally")
    elif level == "MEDIUM":
        st.warning("🟡 Suspicious activity detected")
    else:
        st.error("🔴 High-risk activity detected")


# ---------------- HERO HEADER ----------------
def hero_section():

    st.markdown(
        """
        <h1 style='text-align:center;font-size:56px'>
        🔐 Secure Cloud Log Drive
        </h1>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <p style='text-align:center;font-size:20px;color:#cbd5e1'>
        Blockchain-Based Log Storage with Real-Time Monitoring
        and Intelligent Search
        </p>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<br>", unsafe_allow_html=True)


# ---------------- LOGIN UI ----------------
def login_page():

    hero_section()

    col1, col2, col3 = st.columns([1,2,1])

    with col2:

        tab1, tab2 = st.tabs(["🔑 Sign In", "📝 Register"])

        with tab1:

            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            if st.button("Sign In"):

                if authenticate_user(username, password):

                    st.session_state.logged_in = True
                    st.session_state.username = username.strip().lower()
                    st.session_state.is_admin = (
                        st.session_state.username == "admin"
                    )

                    st.session_state.activity_log.append(
                        f"{datetime.now()} - User logged in ({st.session_state.username})"
                    )

                    st.rerun()

                else:
                    st.error("Authentication failed")

        with tab2:

            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")

            if st.button("Create Account"):

                if new_pass != confirm:
                    st.warning("Passwords do not match")

                elif register_user(new_user, new_pass):
                    st.success("Account created successfully")

                else:
                    st.error("Username already exists")


# ---------------- DASHBOARD ----------------
def dashboard():

    security_banner()

    st.markdown(f"### Welcome **{st.session_state.username}**")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Blocks",
        len(st.session_state.blockchain.chain)
    )

    col2.metric(
        "Blockchain Integrity",
        "Valid" if st.session_state.blockchain.is_chain_valid() else "Compromised"
    )

    col3.metric(
        "Threat Level",
        st.session_state.security.threat_level
    )

    st.markdown("---")

    f1, f2, f3 = st.columns(3)

    f1.info("🔐 Blockchain Secured Storage")
    f2.info("⚡ Fast Log Search")
    f3.info("🧠 AI Anomaly Detection")


# ---------------- MAIN APP ----------------
def main_app():

    st.sidebar.markdown("## 🔐 Secure Cloud Log Drive")

    st.sidebar.markdown(f"User: **{st.session_state.username}**")

    if st.session_state.is_admin:
        st.sidebar.markdown("🛡️ **Administrator**")
    else:
        st.sidebar.markdown("👤 **Standard User**")

    if st.sidebar.button("Sign Out"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.is_admin = False
        st.rerun()


    # -------- ROLE BASED MENU --------
    if st.session_state.is_admin:

        menu = st.sidebar.radio(
            "Navigation",
            [
                "Dashboard",
                "View All Logs",
                "Blockchain Ledger",
                "Threat Overview",
                "Threat Flow Visualization",
                "Audit Timeline"
            ]
        )

    else:

        menu = st.sidebar.radio(
            "Navigation",
            [
                "Dashboard",
                "Add Log",
                "Encrypted Search",
                "My Logs",
                "My Log Integrity",
                "Audit Timeline"
            ]
        )


    # -------- DASHBOARD --------
    if menu == "Dashboard":
        dashboard()


    # ================= USER FEATURES =================

    elif menu == "Add Log" and not st.session_state.is_admin:

        st.markdown("### ➕ Add Log Entry")

        log_data = st.text_area("Log details")

        if st.button("Store Log"):

            if log_data.strip():

                block = st.session_state.blockchain.add_log(
                    log_data,
                    st.session_state.username
                )

                st.session_state.search_index.index_log(
                    log_data,
                    block.index
                )

                st.session_state.activity_log.append(
                    f"{datetime.now()} - Log added by {st.session_state.username}"
                )

                st.success(f"Log stored in Block #{block.index}")

            else:
                st.warning("Log content cannot be empty")


    # ---- SEARCH ----
    elif menu == "Encrypted Search" and not st.session_state.is_admin:

        st.markdown("### 🔍 Search Logs")

        query = st.text_input("Search keywords")

        if st.button("Search"):

            results = st.session_state.search_index.search(query)

            if results:

                for idx in results:

                    block = get_block_by_index(
                        st.session_state.blockchain.chain,
                        idx
                    )

                    if block and block.owner == st.session_state.username:
                        st.code(format_log_for_display(block))

            else:
                st.info("No matching logs found")


    # ---- MY LOGS ----
    elif menu == "My Logs" and not st.session_state.is_admin:

        st.markdown("### 📂 My Logs")

        logs = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        if not logs:
            st.info("No logs found")

        else:

            for block in logs:
                st.code(format_log_for_display(block))


    # ---- INTEGRITY ----
    elif menu == "My Log Integrity" and not st.session_state.is_admin:

        st.markdown("### 🔗 My Log Integrity")

        if st.session_state.blockchain.is_chain_valid():
            st.success("Blockchain integrity verified")
        else:
            st.error("Blockchain integrity check failed")


    # ================= ADMIN FEATURES =================

    elif menu == "View All Logs" and st.session_state.is_admin:

        st.markdown("### 📄 All Logs")

        for block in st.session_state.blockchain.chain:

            st.code(
                f"""
User : {block.owner}
Block: {block.index}
Time : {block.timestamp}
Log  : {block.data}
"""
            )


    elif menu == "Blockchain Ledger" and st.session_state.is_admin:

        st.markdown("### ⛓️ Blockchain Ledger")

        for b in st.session_state.blockchain.chain:

            st.code(
                f"""
Block ID       : {b.index}
Owner          : {b.owner}
Timestamp      : {b.timestamp}
Hash           : {b.hash}
Previous Hash  : {b.previous_hash}
"""
            )


    elif menu == "Threat Overview" and st.session_state.is_admin:

        st.markdown("### 🚨 Threat Overview")

        st.metric("Search Count", st.session_state.security.search_count)
        st.metric("View Count", st.session_state.security.view_count)
        st.metric("Anomaly Hits", st.session_state.security.anomaly_hits)


    elif menu == "Threat Flow Visualization" and st.session_state.is_admin:

        st.markdown("### 📊 Threat Flow Visualization")

        g = graphviz.Digraph()

        g.node("User", "User Activity")

        if st.session_state.security.threat_level == "LOW":

            g.node("Normal", "Normal Activity")
            g.edge("User", "Normal")

        elif st.session_state.security.threat_level == "MEDIUM":

            g.node("Anomaly", "Anomaly")
            g.edge("User", "Anomaly")

        else:

            g.node("Anomaly", "Anomaly")
            g.node("Abuse", "Potential Abuse")

            g.edge("User", "Anomaly")
            g.edge("Anomaly", "Abuse")

        st.graphviz_chart(g)


    elif menu == "Audit Timeline":

        st.markdown("### 🕒 Audit Timeline")

        st.code("\n".join(st.session_state.activity_log[-30:]))

        st.download_button(
            "Download Audit Log",
            data="\n".join(st.session_state.activity_log),
            file_name="audit_log.txt"
        )


# ---------------- ROUTER ----------------
if st.session_state.logged_in:
    main_app()
else:
    login_page()
