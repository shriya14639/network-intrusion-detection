# NIDS Demo (Team Nexus - Shriya Sriram)
Prototype network intrusion detection: upload CSV -> validate -> detect (rules + optional RandomForest) -> alerts -> dashboard.
**Not production defence and not proof that an attack occurred.** Use synthetic/public/approved data only.

## Setup
    python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    python generate_data.py        # creates data/sample.csv and bad_*.csv test files
    streamlit run app.py
Logins: admin@demo.com / admin123, analyst@demo.com / analyst123, viewer@demo.com / viewer123
(change these before any real use). Reset the database by deleting nids.db.

## Tests
    pytest

## Demo flow
1. Log in as analyst -> Upload `data/bad_rows.csv` (rejected rows) and `data/bad_missing_column.csv` (error).
2. Upload `data/sample.csv`, tick classifier, run detection.
3. Dashboard -> Alerts (filter, change status) -> Reports (CSV and PDF).
4. Log in as admin -> create a user, view audit log. Log in as viewer -> no Upload/Reports pages.

## Known limitations
Thresholds in detect.py are hand-tuned for synthetic data; classifier trains on the uploaded labelled file (demo only);
CSV only; single-user SQLite.
