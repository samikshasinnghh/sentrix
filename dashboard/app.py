import altair as alt
import pandas as pd
import requests
import streamlit as st

API_URL = "http://localhost:8000"
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

st.set_page_config(page_title="Sentrix", page_icon="🛡️", layout="wide")


def login(username, password):
    try:
        resp = requests.post(
            f"{API_URL}/auth/login",
            data={"username": username, "password": password},
            timeout=10,
        )
    except requests.exceptions.RequestException:
        return None, "Cannot reach the API. Is it running? (docker compose ps)"
    if resp.status_code == 200:
        return resp.json()["access_token"], None
    if resp.status_code == 401:
        return None, "Incorrect username or password."
    return None, f"Login failed (status {resp.status_code})."


def api_get(path, params=None):
    try:
        resp = requests.get(
            f"{API_URL}{path}",
            headers={"Authorization": f"Bearer {st.session_state.token}"},
            params=params,
            timeout=30,
        )
    except requests.exceptions.RequestException:
        return None, "Cannot reach the API. Is it running? (docker compose ps)"
    if resp.status_code == 401:
        # token expired or invalid: send the user back to the login screen
        st.session_state.token = None
        st.session_state.username = None
        st.rerun()
    if resp.status_code != 200:
        return None, f"Request failed (status {resp.status_code})."
    return resp.json(), None


if "token" not in st.session_state:
    st.session_state.token = None
    st.session_state.username = None

st.title("Sentrix Security Dashboard")

if st.session_state.token is None:
    st.subheader("Log in")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Log in")
    if submitted:
        token, error = login(username, password)
        if error:
            st.error(error)
        else:
            st.session_state.token = token
            st.session_state.username = username
            st.rerun()
    st.stop()

with st.sidebar:
    st.write(f"Logged in as **{st.session_state.username}**")
    if st.button("Log out"):
        st.session_state.token = None
        st.session_state.username = None
        st.rerun()

# ---------- Overview ----------
stats, error = api_get("/dashboard/stats")
if error:
    st.error(error)
else:
    st.subheader("Overview")
    counts = {d["severity"]: d["count"] for d in stats.get("risk_distribution", [])}

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total events", f"{stats.get('total_events', 0):,}")
    c2.metric("Total anomalies", f"{stats.get('total_anomalies', 0):,}")
    c3.metric("HIGH severity", f"{counts.get('HIGH', 0):,}")
    c4.metric("CRITICAL severity", f"{counts.get('CRITICAL', 0):,}")

    st.markdown("**Events by severity**")
    chart_df = pd.DataFrame(
        {"severity": SEVERITY_ORDER, "count": [counts.get(s, 0) for s in SEVERITY_ORDER]}
    )
    chart = (
        alt.Chart(chart_df)
        .mark_bar()
        .encode(
            x=alt.X("severity:N", sort=SEVERITY_ORDER, title=None),
            y=alt.Y("count:Q", title="Events"),
            tooltip=["severity", "count"],
        )
        .properties(height=280)
    )
    st.altair_chart(chart, use_container_width=True)

# ---------- Alerts ----------
st.subheader("Alerts")
alerts, error = api_get("/alerts")
if error:
    st.error(error)
else:
    if isinstance(alerts, list):
        rows = alerts
    else:
        rows = next((v for v in alerts.values() if isinstance(v, list)), [])
    st.caption(f"{len(rows)} rows returned by /alerts")
    if rows:
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    with st.expander("Raw response (first 3)"):
        st.json(rows[:3] if rows else alerts)