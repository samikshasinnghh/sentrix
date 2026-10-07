import os

import altair as alt
import pandas as pd
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://localhost:8000")
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_COLORS = ["#4c9be8", "#f2c14e", "#f08a4b", "#d64545"]

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
    if resp.status_code == 404:
        return None, "Not found."
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
counts = {}
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
    log_scale = st.checkbox("Log scale (makes small bars visible)", value=True)
    chart_df = pd.DataFrame(
        {"severity": SEVERITY_ORDER, "count": [counts.get(s, 0) for s in SEVERITY_ORDER]}
    )
    chart = (
        alt.Chart(chart_df)
        .mark_bar()
        .encode(
            x=alt.X("severity:N", sort=SEVERITY_ORDER, title=None,
                    axis=alt.Axis(labelAngle=0)),
            y=alt.Y("count:Q", title="Events",
                    scale=alt.Scale(type="symlog" if log_scale else "linear")),
            color=alt.Color("severity:N",
                            scale=alt.Scale(domain=SEVERITY_ORDER, range=SEVERITY_COLORS),
                            legend=None),
            tooltip=["severity", "count"],
        )
        .properties(height=280)
    )
    st.altair_chart(chart, width="stretch")

# ---------- Trends ----------
st.subheader("Trends")
t1, t2 = st.columns(2)

with t1:
    st.markdown("**HIGH and CRITICAL alerts per day**")
    timeline, error = api_get("/dashboard/timeline")
    if error:
        st.error(error)
    elif not timeline:
        st.info("No data.")
    else:
        tdf = pd.DataFrame(timeline)
        tdf["day"] = pd.to_datetime(tdf["day"])
        line = (
            alt.Chart(tdf)
            .mark_line(point=True)
            .encode(
                x=alt.X("day:T", title=None),
                y=alt.Y("count:Q", title="Alerts"),
                color=alt.Color(
                    "severity:N",
                    scale=alt.Scale(domain=["HIGH", "CRITICAL"],
                                    range=[SEVERITY_COLORS[2], SEVERITY_COLORS[3]]),
                    legend=alt.Legend(title=None, orient="top"),
                ),
                tooltip=["day:T", "severity", "count"],
            )
            .properties(height=300)
        )
        st.altair_chart(line, width="stretch")

with t2:
    st.markdown("**Top 10 users by HIGH + CRITICAL alerts**")
    top, error = api_get("/dashboard/top-users")
    if error:
        st.error(error)
    elif not top:
        st.info("No data.")
    else:
        udf = pd.DataFrame(top)
        bars = (
            alt.Chart(udf)
            .mark_bar(color=SEVERITY_COLORS[2])
            .encode(
                x=alt.X("alerts:Q", title="Alerts"),
                y=alt.Y("user_id:N", sort="-x", title=None),
                tooltip=["user_id", "alerts", "critical"],
            )
            .properties(height=300)
        )
        st.altair_chart(bars, width="stretch")

# ---------- Alerts ----------
st.subheader("Alerts")

f1, f2, f3 = st.columns(3)
severity_choice = f1.selectbox("Severity", ["All (HIGH + CRITICAL)", "CRITICAL", "HIGH"])
page_size = f2.selectbox("Rows per page", [25, 50, 100, 200], index=1)

if severity_choice == "All (HIGH + CRITICAL)":
    severity_param = None
    total = counts.get("HIGH", 0) + counts.get("CRITICAL", 0)
else:
    severity_param = severity_choice
    total = counts.get(severity_choice, 0)

max_page = max(1, -(-total // page_size))  # ceiling division
# the key changes with the filters, so the page resets to 1 when they change
page = f3.number_input(
    f"Page (of {max_page:,})", min_value=1, max_value=max_page, value=1, step=1,
    key=f"page_{severity_choice}_{page_size}",
)
offset = (page - 1) * page_size

params = {"limit": page_size, "offset": offset}
if severity_param:
    params["severity"] = severity_param

rows, error = api_get("/alerts", params=params)
if error:
    st.error(error)
elif not rows:
    st.info("No alerts for this filter.")
else:
    st.caption(f"Showing {offset + 1:,}–{offset + len(rows):,} of {total:,} alerts, "
               "highest risk first. Click a column header to sort this page.")
    st.dataframe(
        pd.DataFrame(rows),
        width="stretch",
        hide_index=True,
        column_config={
            "risk_score": st.column_config.ProgressColumn(
                "risk_score", min_value=0, max_value=100, format="%d"
            ),
        },
    )

# ---------- User risk lookup ----------
st.subheader("User risk lookup")
user_id = st.text_input("User ID", value="user_0021", help="For example: user_0021")

if user_id.strip():
    profile, error = api_get(f"/users/{user_id.strip()}/risk")
    if error == "Not found.":
        st.warning(f"No user found with ID '{user_id.strip()}'.")
    elif error:
        st.error(error)
    else:
        u1, u2, u3, u4, u5 = st.columns(5)
        u1.metric("Role", profile["role"])
        u2.metric("Total events", f"{profile['total_events']:,}")
        u3.metric("Flagged attacks", f"{profile['total_flagged_attacks']:,}")
        u4.metric("Avg risk score", profile["avg_risk_score"])
        u5.metric("Max risk score", profile["max_risk_score"])

        recent = profile.get("recent_high_severity_events", [])
        st.markdown("**Most recent HIGH / CRITICAL events**")
        if recent:
            st.dataframe(pd.DataFrame(recent), width="stretch", hide_index=True)
        else:
            st.info("This user has no HIGH or CRITICAL events.")