```python
import streamlit as st
import time
from datetime import datetime

# ---- Import Modules ----
from modules.auth import authenticate_user, register_user
from modules.blockchain import Blockchain
from modules.search_index import SearchIndex
from modules.logs import get_logs_for_user, format_log_for_display
from modules.anomaly import AnomalyDetector
from modules.security_state import SecurityState
from modules.visualization import draw_blockchain, draw_threat_flow


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
        "user_security": {},
        "security": None,
        "search_count": 0,
        "view_count": 0,
        "last_action_time": time.time(),
        "warned_user": False,
        "activity_log": []
    }

    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_session()


# ---------------- SECURITY BANNER ----------------
def security_banner():

    if not st.session_state.security:
        return

    level = st.session_state.security.threat_level

    if level == "LOW":
        st.success("System operating normally")

    elif level == "MEDIUM":
        st.warning("Suspicious activity detected")

    else:
        st.error("High-risk activity detected")


# ---------------- USER DASHBOARD ----------------
def user_dashboard():

    security_banner()

    st.markdown(f"### Welcome **{st.session_state.username}**")

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Blocks", len(st.session_state.blockchain.chain))

    col2.metric(
        "Blockchain Integrity",
        "Valid" if st.session_state.blockchain.is_chain_valid() else "Compromised"
    )

    if st.session_state.security:
        col3.metric("Threat Level", st.session_state.security.threat_level)

    st.markdown("---")

    if st.session_state.security:

        s1, s2, s3 = st.columns(3)

        s1.metric("Search Requests", st.session_state.security.search_count)
        s2.metric("Log Views", st.session_state.security.view_count)
        s3.metric("Anomaly Hits", st.session_state.security.anomaly_hits)

    st.markdown("---")

    st.subheader("Blockchain Visualization")

    graph = draw_blockchain(st.session_state.blockchain.chain)

    st.graphviz_chart(graph)

    st.markdown("---")

    st.subheader("Recent Activity")

    if not st.session_state.activity_log:
        st.info("No activity yet")
    else:
        for event in st.session_state.activity_log[-5:]:
            st.write(event)


# ---------------- ADMIN DASHBOARD ----------------
def admin_dashboard():

    st.markdown("### Administrator Dashboard")

    total_blocks = len(st.session_state.blockchain.chain)

    total_search = sum(
        s.search_count for s in st.session_state.user_security.values()
    )

    total_views = sum(
        s.view_count for s in st.session_state.user_security.values()
    )

    total_anomaly = sum(
        s.anomaly_hits for s in st.session_state.user_security.values()
    )

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Blocks", total_blocks)
    col2.metric("Total Searches", total_search)
    col3.metric("Total Log Views", total_views)

    st.markdown("---")

    col4, col5 = st.columns(2)

    col4.metric("Total Anomalies", total_anomaly)

    if total_anomaly >= 3:
        col5.metric("System Threat Level", "HIGH")
    elif total_anomaly == 2:
        col5.metric("System Threat Level", "MEDIUM")
    else:
        col5.metric("System Threat Level", "LOW")

    st.markdown("---")

    st.subheader("Blockchain Visualization")

    graph = draw_blockchain(st.session_state.blockchain.chain)

    st.graphviz_chart(graph)

    st.markdown("---")

    st.subheader("Recent System Activity")

    if not st.session_state.activity_log:
        st.info("No activity yet")
    else:
        for event in st.session_state.activity_log[-10:]:
            st.write(event)


# ---------------- LOGIN PAGE ----------------
def login_page():

    st.markdown(
        "<h1 style='text-align:center;'>Secure Cloud Log Drive</h1>",
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns([1,2,1])

    with col2:

        tab1, tab2 = st.tabs(["Sign In","Register"])

        with tab1:

            username = st.text_input("Username")
            password = st.text_input("Password",type="password")

            if st.button("Sign In"):

                if authenticate_user(username,password):

                    st.session_state.logged_in = True
                    st.session_state.username = username.strip().lower()

                    st.session_state.is_admin = (
                        st.session_state.username == "admin"
                    )

                    user = st.session_state.username

                    if user not in st.session_state.user_security:
                        st.session_state.user_security[user] = SecurityState()

                    st.session_state.security = st.session_state.user_security[user]

                    st.session_state.search_count = 0
                    st.session_state.view_count = 0
                    st.session_state.warned_user = False

                    st.session_state.activity_log.append(
                        f"{datetime.now()} - User logged in ({user})"
                    )

                    st.rerun()

                else:
                    st.error("Authentication failed")

        with tab2:

            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password",type="password")
            confirm = st.text_input("Confirm Password",type="password")

            if st.button("Create Account"):

                if new_pass != confirm:
                    st.warning("Passwords do not match")

                elif register_user(new_user,new_pass):
                    st.success("Account created successfully")

                else:
                    st.error("Username already exists")


# ---------------- MAIN APP ----------------
def main_app():

    st.sidebar.markdown("## Secure Cloud Log Drive")
    st.sidebar.markdown(f"User: **{st.session_state.username}**")

    if st.session_state.is_admin:
        st.sidebar.markdown("Role: Administrator")
    else:
        st.sidebar.markdown("Role: Standard User")

    if st.sidebar.button("Sign Out"):

        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.security = None
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

        if st.session_state.is_admin:
            admin_dashboard()
        else:
            user_dashboard()


    # -------- ADD LOG --------
    elif menu == "Add Log" and not st.session_state.is_admin:

        st.markdown("### Add Log Entry")

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

                st.success(f"Log stored in Block #{block.index}")


    # -------- SEARCH --------
    elif menu == "Encrypted Search" and not st.session_state.is_admin:

        st.markdown("### Search Logs")

        col1,col2 = st.columns([3,1])

        query = col1.text_input("Search keywords")
        mode = col2.selectbox("Search Mode",["AND","OR","NOT"])

        if st.button("Search"):

            results = st.session_state.search_index.search(query,mode)

            if results:

                for idx in results:

                    block = next(
                        b for b in st.session_state.blockchain.chain
                        if b.index == idx
                    )

                    if block.owner == st.session_state.username:
                        st.code(format_log_for_display(block))

            else:
                st.info("No matching logs found")


    # -------- MY LOGS --------
    elif menu == "My Logs" and not st.session_state.is_admin:

        logs = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        for block in logs:
            st.code(format_log_for_display(block))


    # -------- BLOCKCHAIN LEDGER --------
    elif menu == "Blockchain Ledger" and st.session_state.is_admin:

        for b in st.session_state.blockchain.chain:

            st.code(
f"""
Block ID : {b.index}
Owner : {b.owner}
Timestamp : {b.timestamp}
Hash : {b.hash}
Previous Hash : {b.previous_hash}
"""
            )


# ---------------- ROUTER ----------------
if st.session_state.logged_in:
    main_app()
else:
    login_page()
```
