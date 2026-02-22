import streamlit as st
import time
from datetime import datetime
import graphviz

# -------------------------------
# Project: Secure Cloud Log Drive
# Note:
# This is an academic prototype to demonstrate
# secure log storage, integrity checking, and
# behavior-based monitoring.
# -------------------------------

# ---- Import Internal Modules ----
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

# ---------------- LOAD CUSTOM STYLES ----------------
def load_css():
    """
    Loads external CSS for UI styling.
    Styling is kept separate for cleaner code.
    """
    with open("assets/styles.css") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css()


# ---------------- SESSION INITIALIZATION ----------------
def init_session():
    """
    Initialize all required session variables.
    This avoids unexpected KeyErrors during runtime.
    """

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


# ---------------- SECURITY STATUS BANNER ----------------
def security_banner():
    """
    Displays a simple security status message
    based on current session behavior.
    """

    if st.session_state.threat_level == "LOW":
        st.success("System status looks normal")
    elif st.session_state.threat_level == "MEDIUM":
        st.warning("Unusual activity detected in this session")
    else:
        st.error("High-risk behavior detected. Session restricted")


# ---------------- LOGIN & REGISTRATION ----------------
def login_page():
    st.markdown("## 🔐 Secure Cloud Log Drive")
    st.markdown(
        "Encrypted log storage with integrity verification "
        "and basic behavior monitoring."
    )
    st.markdown("---")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        login_tab, register_tab = st.tabs(["Login", "Register"])

        # ---- Login ----
        with login_tab:
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
                    st.error("Login failed. Please check credentials.")

        # ---- Registration ----
        with register_tab:
            new_user = st.text_input("New Username")
            new_pass = st.text_input("New Password", type="password")
            confirm = st.text_input("Confirm Password", type="password")

            if st.button("Register"):
                if new_pass != confirm:
                    st.warning("Passwords do not match")
                elif register_user(new_user, new_pass):
                    st.success("User registered successfully. Please login.")
                else:
                    st.error("This username already exists")


# ---------------- DASHBOARD ----------------
def dashboard():
    security_banner()

    st.markdown(f"### Welcome, **{st.session_state.username}**")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Blocks", len(st.session_state.blockchain.chain))
    c2.metric(
        "Chain Status",
        "Valid" if st.session_state.blockchain.is_chain_valid() else "Broken"
    )
    c3.metric("Threat Level", st.session_state.threat_level)

    risk_score = min(100, st.session_state.anomaly_hits * 33)
    st.progress(risk_score, text=f"Risk estimate: {risk_score}%")

    with st.expander("ℹ️ System Notes"):
        st.write("""
        • Logs are encrypted before storage  
        • Blockchain is maintained in-memory  
        • Behavior analysis is session-based  
        """)


# ---------------- MAIN APPLICATION ----------------
def main_app():
    st.sidebar.markdown("## Secure Cloud Log Drive")
    st.sidebar.markdown(f"User: **{st.session_state.username}**")

    if st.session_state.username == "admin":
        st.sidebar.markdown("Role: Administrator")

    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.rerun()

    menu = st.sidebar.radio(
        "Navigation",
        [
            "Dashboard",
            "Add Log",
            "Search Logs",
            "My Logs",
            "Blockchain View",
            "Access Pattern View",
            "Audit Timeline"
        ]
    )

    # ---- Dashboard ----
    if menu == "Dashboard":
        dashboard()

    # ---- Add Log ----
    elif menu == "Add Log":
        st.markdown("### Add a new log entry")
        log_data = st.text_area("Log content")

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
                    f"{datetime.now()} - Log added (Block {block.index})"
                )

                st.success(f"Log saved successfully (Block {block.index})")
            else:
                st.warning("Log content cannot be empty")

    # ---- Search Logs ----
    elif menu == "Search Logs":
        st.markdown("### Search encrypted logs")
        query = st.text_input("Search keywords")

        if st.button("Search"):
            now = time.time()
            gap = now - st.session_state.last_action_time
            st.session_state.last_action_time = now
            st.session_state.search_count += 1

            # Simple rule-based check
            if st.session_state.search_count > 10:
                st.warning("High number of searches detected")

            # Record activity for ML
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
Decision factors:
- Searches: {st.session_state.search_count}
- Views: {st.session_state.view_count}
- Time gap: {round(gap, 2)} seconds
"""
            )

            if anomalous:
                st.session_state.anomaly_hits += 1
                st.session_state.threat_level = "MEDIUM"

            if st.session_state.anomaly_hits >= 3:
                st.session_state.threat_level = "HIGH"
                st.error("Session ended due to repeated abnormal activity")
                st.session_state.logged_in = False
                time.sleep(1)
                st.rerun()

            results = st.session_state.search_index.search(query)

            if results:
                for idx in sorted(results):
                    block = st.session_state.blockchain.chain[idx]
                    st.code(
                        f"""
Block: {block.index}
Time: {block.timestamp}
Hash: {block.hash}
Previous: {block.previous_hash}
Data: {block.data}
Integrity OK: {st.session_state.blockchain.is_chain_valid()}
"""
                    )
            else:
                st.info("No logs matched your search")

    # ---- My Logs ----
    elif menu == "My Logs":
        st.markdown("### My stored logs")
        st.session_state.view_count += 1

        logs = get_logs_for_user(
            st.session_state.blockchain,
            st.session_state.username
        )

        if not logs:
            st.info("No logs found for this account")
        else:
            for block in logs:
                st.code(format_log_for_display(block))

    # ---- Blockchain View ----
    elif menu == "Blockchain View":
        st.markdown("### Blockchain ledger")

        rows = []
        for b in st.session_state.blockchain.chain:
            rows.append({
                "Index": b.index,
                "Owner": b.owner,
                "Timestamp": b.timestamp,
                "Hash": b.hash[:12],
                "Prev Hash": b.previous_hash[:12]
            })

        st.table(rows)

    # ---- Access Pattern ----
    elif menu == "Access Pattern View":
        st.markdown("### Access behavior visualization")

        g = graphviz.Digraph()
        g.node("User", "User Session")

        if st.session_state.threat_level == "LOW":
            g.node("Normal", "Normal Usage")
            g.edge("User", "Normal")
        else:
            g.node("Anomaly", "Anomalous Pattern")
            g.node("Risk", "Potential Abuse")
            g.edge("User", "Anomaly")
            g.edge("Anomaly", "Risk")

        st.graphviz_chart(g)

    # ---- Audit Timeline ----
    elif menu == "Audit Timeline":
        st.markdown("### Session audit timeline")

        st.code("\n".join(st.session_state.activity_log[-20:]))

        st.download_button(
            "Download audit log",
            data="\n".join(st.session_state.activity_log),
            file_name="audit_log.txt"
        )


# ---------------- ROUTER ----------------
if st.session_state.logged_in:
    main_app()
else:
    login_page()
