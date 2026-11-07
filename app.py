import pandas as pd, plotly.express as px, streamlit as st
import auth, db, detect, validate, report_pdf

st.set_page_config(page_title="NIDS Demo", layout="wide")
db.init_db()
S = st.session_state

def guard(action):
    """Server-side permission check (not just hiding buttons)."""
    if not auth.can(S.get("user"), action):
        db.log_action(S["user"]["user_id"], f"DENIED:{action}", "fail")
        st.error("You do not have permission for this action."); st.stop()

def login_page():
    st.title("Network Intrusion Detection System")
    st.caption("Prototype - not production network defence. Demo logins: admin/analyst/viewer@demo.com, password = role+123")
    email = st.text_input("Email"); pw = st.text_input("Password", type="password")
    if st.button("Log in"):
        u = auth.login(email, pw)
        if u: S["user"] = u; st.rerun()
        else: st.error("Invalid credentials")

def filter_ui(prefix):
    c = st.columns(5)
    f = {"severity": c[0].multiselect("Severity", ["High", "Medium", "Low"], key=prefix+"s"),
         "protocol": c[1].multiselect("Protocol", ["tcp", "udp", "icmp"], key=prefix+"p"),
         "status": c[2].multiselect("Status", ["New", "Reviewed", "Dismissed"], key=prefix+"st"),
         "source": c[3].text_input("Source IP contains", key=prefix+"src")}
    d = c[4].date_input("Date range", value=[], key=prefix+"d")
    if len(d) == 2: f["date_from"], f["date_to"] = d
    return f

def upload_page():
    guard("upload"); st.header("Upload & Detect")
    st.info("Required columns: " + ", ".join(validate.REQUIRED) + " (optional: label)")
    up = st.file_uploader("Traffic CSV", type=None)
    if up:
        clean, rejected, errors = validate.validate_csv(up.getvalue(), up.name)
        if errors:
            db.log_action(S["user"]["user_id"], f"upload {up.name}", "fail")
            for e in errors: st.error(e)
            return
        a, b = st.columns(2); a.metric("Accepted rows", len(clean)); b.metric("Rejected rows", len(rejected))
        if len(rejected): st.warning("Rejected rows"); st.dataframe(rejected)
        use_ml = st.checkbox("Also use classifier (needs a 'label' column in the upload to train on)",
                             disabled="label" not in clean.columns)
        if st.button("Save dataset & run detection"):
            guard("run_detection")
            uid = S["user"]["user_id"]
            ds = db.add_dataset(up.name, uid, len(clean), len(rejected)); db.log_action(uid, f"upload {up.name}")
            run = db.add_run(ds, detect.RULE_VERSION + ("+rf" if use_ml else ""))
            model = detect.train_classifier(clean) if use_ml else None
            alerts = detect.detect(clean, model)
            db.insert_alerts(run, alerts); db.finish_run(run); db.log_action(uid, f"detection run {run}")
            st.success(f"Run {run} complete: {len(alerts)} alerts from {len(clean)} records.")

def dashboard_page():
    st.header("Dashboard")
    rows = pd.DataFrame(db.get_alerts())
    total = db.total_records()
    c = st.columns(3); c[0].metric("Total records (latest dataset)", total); c[1].metric("Alerts", len(rows))
    c[2].metric("High severity", int((rows.severity == "High").sum()) if len(rows) else 0)
    if rows.empty: st.info("No alerts yet. Upload a dataset first."); return
    sev = rows.severity.value_counts().reindex(["High", "Medium", "Low"]).fillna(0).reset_index()
    sev.columns = ["severity", "count"]
    l, r = st.columns(2)
    l.plotly_chart(px.bar(sev, x="severity", y="count", title="Severity distribution"), use_container_width=True)
    rows["hour"] = pd.to_datetime(rows.event_time).dt.floor("h")
    r.plotly_chart(px.line(rows.groupby("hour").size().reset_index(name="alerts"), x="hour", y="alerts",
                           title="Alerts over time"), use_container_width=True)

def alerts_page():
    guard("alerts"); st.header("Alerts")
    rows = db.get_alerts(filter_ui("a_")); df = pd.DataFrame(rows)
    st.write(f"{len(df)} alerts")
    if df.empty: return
    st.dataframe(df, use_container_width=True)
    sel = st.selectbox("Alert detail", df.alert_id)
    st.json(df[df.alert_id == sel].iloc[0].to_dict())
    if auth.can(S["user"], "update_status"):
        new = st.selectbox("Set review status", ["New", "Reviewed", "Dismissed"])
        if st.button("Update status"):
            guard("update_status"); db.update_status(int(sel), new)
            db.log_action(S["user"]["user_id"], f"alert {sel} -> {new}"); st.rerun()

def reports_page():
    guard("export"); st.header("Reports")
    df = pd.DataFrame(db.get_alerts(filter_ui("r_")))
    if df.empty: st.info("No matching alerts."); return
    st.dataframe(df.groupby(["severity", "review_status"]).size().reset_index(name="count"))
    st.download_button("Download CSV", df.to_csv(index=False), "alert_summary.csv", "text/csv",
                       on_click=db.log_action, args=(S["user"]["user_id"], "export CSV"))
    st.download_button("Download PDF", report_pdf.build_pdf(df), "alert_summary.pdf", "application/pdf",
                       on_click=db.log_action, args=(S["user"]["user_id"], "export PDF"))

def admin_page():
    guard("admin"); st.header("Administration")
    with st.expander("Create user"):
        n = st.text_input("Name", key="nu_n"); e = st.text_input("Email", key="nu_e")
        pw = st.text_input("Temporary password (min 8 chars)", type="password", key="nu_p")
        r = st.selectbox("Role", ["viewer", "analyst", "admin"], key="nu_r")
        if st.button("Create user"):
            guard("admin"); ok, msg = db.add_user(n, e, pw, r)
            db.log_action(S["user"]["user_id"], f"create user {e} ({r})", "success" if ok else "fail")
            (st.success if ok else st.error)(msg)
    for name, label in [("users", "Users"), ("datasets", "Datasets"), ("detection_runs", "Detection runs"),
                        ("audit_log", "Audit log")]:
        st.subheader(label); st.dataframe(pd.DataFrame(db.table(name)), use_container_width=True)

if "user" not in S: login_page(); st.stop()
user = S["user"]
pages = {"Dashboard": dashboard_page, "Alerts": alerts_page}
if auth.can(user, "upload"): pages["Upload"] = upload_page
if auth.can(user, "export"): pages["Reports"] = reports_page
if auth.can(user, "admin"): pages["Admin"] = admin_page
st.sidebar.write(f"**{user['name']}** ({user['role']})")
choice = st.sidebar.radio("Page", list(pages))
if st.sidebar.button("Log out"): S.clear(); st.rerun()
pages[choice]()
