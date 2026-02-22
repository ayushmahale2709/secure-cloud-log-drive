import streamlit as st
import time
from datetime import datetime
import graphviz

# =========================================================
# Secure Cloud Log Drive
# Academic Prototype for Secure Log Storage and Monitoring
# =========================================================

from modules.auth import authenticate_user, register_user
from modules.blockchain import Blockchain
from modules.search_index import SearchIndex
from modules.logs import get_logs_for_user, format_log_for_display
from modules.anomaly import AnomalyDetector


# ---------------- PAGE CONFIGURATION ----------------
st.set_page_config(
    page_title="Secure Cloud Log Drive",
    page_icon="🔐",
    layout="wide"
)


# ---------------- LOAD STYLES ----------------
def load_css():
    with open("assets/styles.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()


# ---------------- SESSION STATE SETUP ----------------
def init_session():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "username" not in st.session_state:
        st.session_state.username = None

    if "blockchain" not in st.session_state:
        st.session_state.blockchain = Blockchain()

    if "search_index" not in st.session_state:
        st.session_state.search_index = SearchIndex()
        st.session_state.search_index.build_index(
            st.session_state.blockchain
        )

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

    if "anomaly_hits" not in st.session_state:
        st.session_state.anomaly_hits = 0

    if "activity_log" not in st.session_state:
        st.session_state.activity_log = []

init_session()


# ---------------- SECURITY STATUS ----------------
def security_banner():
    if st.session_state.threat_level == "LOW":
        st.success("System operating within normal parameters.")
    elif st.session_state.threat_level == "MEDIUM":
        st.warning("Unusual access behavior has been observed.")
    else:
        st.error(
            "Repeated abnormal access patterns detected. "
            "This session has been terminated for security reasons."
        )


# ---------------- AUTHENTICATION ----------------
def login_page():
    st.markdown("## Secure Cloud Log Drive")
    st.markdown(
        "A prototype system for secure log storage, integrity verification, "
        "and access monitoring."
    )
    st.markdown("---")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        login_tab, register_tab = st.tabs(["Sign In", "Register"])

        # ---- Sign In ----
        with login_tab:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            if st.button("Sign In"):
                if authenticate_user(username, password):
                    st.session_state.logged_in = True
                    st.session_state.username = username.strip().lower()
                    st.session_state.activity_log.append(
                        f"{datetime.now()} - User authenticated"
                    )
                    st.rerun()
                else:
                    st.error(
                        "Authentication failed. Please verify your credentials."
                    )

        # ---- Register ----
        with register_tab:
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")

            if st.button("Create Account"):
                if new_pass != confirm:
                    st.warning("The passwords entered do not match.")
                elif register_user(new_user, new_pass):
                    st.success(
                        "Account created successfully. You may now sign in."
                    )
                else:
                    st.error(
                        "The requested username is already in use."
                    )


# ---------------- DASHBOARD ----------------
def dashboard():
    security_banner()

    st.markdown(f"### Welcome, **{st.session_state.username}**")

    c1, c2, c3 = st.columns(3)
    c1.metric(
        "Stored Blocks",
        len(st.session_state.blockchain.chain)
    )
    c2.metric(
        "Integrity Status",
        "Valid" if st.session_state.blockchain.is_chain_valid() else "Compromised"
    )
    c3.metric(
        "Session Risk Level",
        st.session_state.threat_level
    )

    risk_score = min(100, st.session_state.anomaly_hits * 33)
    st.progress(risk_score, text=f"Estimated risk level: {risk_score}%")

    with st.expander("System Scope and Assumptions"):
        st.write("""
- Logs are encrypted prior to storage  
- Integrity is verified using a blockchain-style ledger  
- Behavior analysis is performed at session level  
- This system is intended for academic demonstration purposes  
""")


# ---------------- MAIN APPLICATION ----------------
def main_app():
    st.sidebar.markdown("## Secure Cloud Log Drive")
    st.sidebar.markdown(f"Signed in as: **{st.session_state.username}**")

    if st.session_state.username == "admin":
        st.sidebar.markdown("Role: Administrator")

    if st.sidebar.button("Sign Out"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    menu = st.sidebar.radio(
        "Navigation",
        [
            "Dashboard",
            "Create Log Entry",
            "Search Logs",
            "My Logs",
            "Integrity Ledger",
            "Access Pattern View",
            "Session Activity Log"
        ]
    )

    # ---- Dashboard ----
    if menu == "Dashboard":
        dashboard()

    # ---- Create Log Entry ----
    elif menu == "Create Log Entry":
        st.markdown("### Create Log Entry")
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
                    f"{datetime.now()} - Log stored (Block {block.index})"
                )

                st.success(
                    f"Log entry stored successfully. "
                    f"Reference Block: {block.index}"
                )
            else:
                st.warning("Log content must not be empty.")

    # ---- Search Logs ----
    elif menu == "Search Logs":
        st.markdown("### Search Stored Logs")
        query = st.text_input("Search criteria")

        if st.button("Execute Search"):
            now = time.time()
            gap = now - st.session_state.last_action_time
            st.session_state.last_action_time = now
            st.session_state.search_count += 1

            # Rule-based observation
            if st.session_state.search_count > 10:
                st.warning(
                    "Elevated search frequency detected "
                    "within a short time window."
                )

            # Record behavior
            st.session_state.anomaly.record_activity(
                st.session_state.search_count,
                st.session_state.view_count,
                gap
            )

            anomalous = st.session_state.anomaly.is_anomalous(
                st.session_state.search_count,
                st.session_state.view_count,
                gap
            )

            st.info(
                f"""
Access pattern indicators:
- Search count: {st.session_state.search_count}
- View count: {st.session_state.view_count}
- Time since last action: {round(gap, 2)} seconds
"""
            )

            if anomalous:
                st.session_state.anomaly_hits += 1
                st.session_state.threat_level = "MEDIUM"

            if st.session_state.anomaly_hits >= 3:
                st.session_state.threat_level = "HIGH"
                st.session_state.activity_log.append(
                    f"{datetime.now()} - Session terminated due to risk"
                )
                st.error(
                    "Repeated abnormal access patterns were detected. "
                    "The session has been terminated as a precaution."
                )
                st.session_state.logged_in = False
                time.sleep(1)
                st.rerun()

            results = st.session_state.search_index.search(query)

            if results:
                for idx in sorted(results):
                    block = st.session_state.blockchain.chain[idx]
                    st.code(
                        f"""
Block ID: {block.index}
Timestamp: {block.timestamp}
Hash: {block.hash}
Previous Hash: {block.previous_hash}
Data: {block.data}
Integrity Verified: {st.session_state.blockchain.is_chain_valid()}
"""
                    )
            else:
                st.info(
                    "No records matched the current search criteria."
                )

    # ---- My Logs ----
    elif menu == "My Logs":
        st.markdown("### My Stored Logs")
        st.session_state.view_count += 1

        logs = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        if not logs:
            st.info("No log entries are associated with this account.")
        else:
            for block in logs:
                st.code(format_log_for_display(block))

    # ---- Integrity Ledger ----
    elif menu == "Integrity Ledger":
        st.markdown("### Integrity Ledger")

        rows = []
        for b in st.session_state.blockchain.chain:
            rows.append({
                "Index": b.index,
                "Owner": b.owner,
                "Timestamp": b.timestamp,
                "Hash": b.hash[:12],
                "Previous Hash": b.previous_hash[:12]
            })

        st.table(rows)

    # ---- Access Pattern View ----
    elif menu == "Access Pattern View":
        st.markdown("### Access Pattern Overview")

        g = graphviz.Digraph()
        g.node("Session", "User Session")

        if st.session_state.threat_level == "LOW":
            g.node("Normal", "Normal Activity")
            g.edge("Session", "Normal")
        else:
            g.node("Observed", "Anomalous Activity")
            g.node("Risk", "Potential Risk")
            g.edge("Session", "Observed")
            g.edge("Observed", "Risk")

        st.graphviz_chart(g)

    # ---- Session Activity Log ----
    elif menu == "Session Activity Log":
        st.markdown("### Session Activity Log")

        st.code("\n".join(st.session_state.activity_log[-20:]))

        st.download_button(
            "Export activity log",
            data="\n".join(st.session_state.activity_log),
            file_name="session_activity_log.txt"
        )


# ---------------- ROUTER ----------------
if st.session_state.logged_in:
    main_app()
else:
    login_page()
