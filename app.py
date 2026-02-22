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
        "is_admin": False,
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


# ---------------- HELPERS ----------------
def get_block_by_index(chain, block_index):
    for b in chain:
        if b.index == block_index:
            return b
    return None


# ---------------- SECURITY BANNER ----------------
def security_banner():
    if st.session_state.threat_level == "LOW":
        st.success("System operating normally.")
    elif st.session_state.threat_level == "MEDIUM":
        st.warning("Unusual access behavior detected.")
    else:
        st.error("High-risk activity detected. Session restricted.")


# ---------------- LOGIN UI ----------------
def login_page():
    st.markdown("## Secure Cloud Log Drive")
    st.markdown(
        "Secure log storage with blockchain-based integrity verification."
    )
    st.markdown("---")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        tab1, tab2 = st.tabs(["Sign In", "Register"])

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
                    st.error("Authentication failed.")

        with tab2:
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")

            if st.button("Create Account"):
                if new_pass != confirm:
                    st.warning("Passwords do not match.")
                elif register_user(new_user, new_pass):
                    st.success("Account created successfully. Please sign in.")
                else:
                    st.error("Username already exists.")


# ---------------- DASHBOARD ----------------
def dashboard():
    security_banner()

    st.markdown(f"### Welcome, **{st.session_state.username}**")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Blocks", len(st.session_state.blockchain.chain))
    c2.metric(
        "Blockchain Integrity",
        "Valid" if st.session_state.blockchain.is_chain_valid() else "Compromised"
    )
    c3.metric("Threat Level", st.session_state.threat_level)

    risk = min(100, st.session_state.anomaly_hits * 33)
    st.progress(risk, text=f"Estimated Risk Level: {risk}%")


# ---------------- MAIN APP ----------------
def main_app():
    st.sidebar.markdown("## Secure Cloud Log Drive")
    st.sidebar.markdown(f"User: **{st.session_state.username}**")

    if st.session_state.is_admin:
        st.sidebar.markdown("🛡️ Role: Administrator")
    else:
        st.sidebar.markdown("👤 Role: Standard User")

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

    # -------- USER: ADD LOG --------
    elif menu == "Add Log" and not st.session_state.is_admin:
        st.markdown("### Add Log Entry")
        log_data = st.text_area("Log details")

        if st.button("Store Log"):
            if log_data.strip():
                block = st.session_state.blockchain.add_log(
                    log_data, st.session_state.username
                )
                st.session_state.search_index.index_log(
                    log_data, block.index
                )
                st.session_state.activity_log.append(
                    f"{datetime.now()} - Log added by {st.session_state.username}"
                )
                st.success(f"Log stored in Block #{block.index}")
            else:
                st.warning("Log content cannot be empty.")

    # -------- USER: SEARCH (AND / OR / NOT) --------
    elif menu == "Encrypted Search" and not st.session_state.is_admin:
        st.markdown("### 🔍 Search Logs")

        col1, col2 = st.columns([3, 1])

        with col1:
            query = st.text_input("Search keywords")

        with col2:
            mode = st.selectbox(
                "Search Mode",
                ["AND", "OR", "NOT"]
            )

        if st.button("Search"):
            results = st.session_state.search_index.search(query, mode)

            if results:
                for idx in results:
                    block = get_block_by_index(
                        st.session_state.blockchain.chain, idx
                    )
                    if block and block.owner == st.session_state.username:
                        st.code(format_log_for_display(block))
            else:
                st.info("No matching logs found.")

    # -------- USER: MY LOGS --------
    elif menu == "My Logs" and not st.session_state.is_admin:
        st.markdown("### My Logs (Decrypted View)")

        logs = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        if not logs:
            st.info("No logs found.")
        else:
            for block in logs:
                st.code(format_log_for_display(block))

    # -------- USER: MY LOG INTEGRITY --------
    elif menu == "My Log Integrity" and not st.session_state.is_admin:
        st.markdown("### 🔗 My Log Integrity (Blockchain View)")

        if st.session_state.blockchain.is_chain_valid():
            st.success("Blockchain integrity verified.")
        else:
            st.error("Blockchain integrity check failed.")

        user_blocks = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        for b in user_blocks:
            st.markdown(f"**Block #{b.index}**")
            st.code(
                f"""
Timestamp: {b.timestamp}
Hash: {b.hash[:20]}...
Previous Hash: {b.previous_hash[:20]}...
"""
            )

    # -------- ADMIN: VIEW ALL LOGS --------
    elif menu == "View All Logs" and st.session_state.is_admin:
        st.markdown("### All User Logs")

        for block in st.session_state.blockchain.chain:
            st.code(
                f"""
User: {block.owner}
Block: {block.index}
Time: {block.timestamp}
Log: {block.data}
"""
            )

    # -------- ADMIN: BLOCKCHAIN LEDGER --------
    elif menu == "Blockchain Ledger" and st.session_state.is_admin:
        st.markdown("### Blockchain Ledger")

        if st.session_state.blockchain.is_chain_valid():
            st.success("Blockchain integrity verified.")
        else:
            st.error("Blockchain integrity compromised.")

        for b in st.session_state.blockchain.chain:
            st.markdown(f"**Block #{b.index}**")
            st.code(
                f"""
Owner: {b.owner}
Timestamp: {b.timestamp}
Hash: {b.hash}
Previous Hash: {b.previous_hash}
"""
            )

    # -------- ADMIN: THREAT OVERVIEW --------
    elif menu == "Threat Overview" and st.session_state.is_admin:
        st.markdown("### Threat Overview")

        st.metric("Search Count", st.session_state.search_count)
        st.metric("View Count", st.session_state.view_count)
        st.metric("Anomaly Hits", st.session_state.anomaly_hits)

        st.progress(
            min(100, st.session_state.anomaly_hits * 33),
            text="Estimated Threat Level"
        )

    # -------- ADMIN: GRAPH VISUALIZATION --------
    elif menu == "Threat Flow Visualization" and st.session_state.is_admin:
        st.markdown("### Threat Flow Visualization")

        g = graphviz.Digraph()
        g.node("User", "User Session")

        if st.session_state.threat_level == "LOW":
            g.node("Normal", "Normal Activity", style="filled", fillcolor="lightgreen")
            g.edge("User", "Normal")
        else:
            g.node("Observed", "Anomalous Activity", style="filled", fillcolor="orange")
            g.node("Risk", "Potential Abuse", style="filled", fillcolor="red")
            g.edge("User", "Observed")
            g.edge("Observed", "Risk")

        st.graphviz_chart(g)

    # -------- AUDIT TIMELINE --------
    elif menu == "Audit Timeline":
        st.markdown("### Session Activity Log")
        st.code("\n".join(st.session_state.activity_log[-30:]))

        st.download_button(
            "Export Activity Log",
            data="\n".join(st.session_state.activity_log),
            file_name="audit_log.txt"
        )


# ---------------- ROUTER ----------------
if st.session_state.logged_in:
    main_app()
else:
    login_page()
