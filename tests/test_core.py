import sys, os; sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pandas as pd, validate, detect

def read(name): return open(os.path.join(os.path.dirname(__file__), "..", "data", name), "rb").read()

def test_valid_file():
    clean, rej, err = validate.validate_csv(read("sample.csv"), "sample.csv")
    assert not err and len(clean) > 1900 and rej.empty

def test_missing_column():
    clean, _, err = validate.validate_csv(read("bad_missing_column.csv"), "x.csv")
    assert clean is None and "dst_port" in err[0]

def test_bad_rows_rejected():
    clean, rej, err = validate.validate_csv(read("bad_rows.csv"), "x.csv")
    assert not err and len(rej) == 3 and len(clean) == 47

def test_empty_and_wrong_type_and_oversize():
    assert validate.validate_csv(b"", "a.csv")[2]
    assert validate.validate_csv(b"abc", "a.txt")[2]
    assert validate.validate_csv(b"x" * (2 * 1024 * 1024), "a.csv", max_mb=1)[2]

def test_rules_find_attacks():
    clean, _, _ = validate.validate_csv(read("sample.csv"), "s.csv")
    a = detect.run_rules(clean)
    assert {"10.0.0.66", "10.0.0.77", "10.0.0.88"} <= set(a.source)
    assert not a[a.source.str.startswith("192.168.1.")].shape[0]

def test_classifier():
    clean, _, _ = validate.validate_csv(read("sample.csv"), "s.csv")
    a = detect.run_classifier(clean, detect.train_classifier(clean))
    assert len(a) > 0

def test_pdf_export():
    import report_pdf
    clean, _, _ = validate.validate_csv(read("sample.csv"), "s.csv")
    pdf = report_pdf.build_pdf(detect.run_rules(clean).assign(review_status="New"))
    assert pdf[:4] == b"%PDF"

def test_add_user(tmp_path, monkeypatch):
    import db; monkeypatch.setattr(db, "DB", str(tmp_path / "t.db")); db.init_db()
    assert db.add_user("Z", "z@demo.com", "longenough1", "viewer")[0]
    assert not db.add_user("Z", "z@demo.com", "longenough1", "viewer")[0]   # duplicate
    assert not db.add_user("Q", "q@demo.com", "short", "viewer")[0]         # weak password
    assert not db.add_user("Q", "q@demo.com", "longenough1", "root")[0]     # bad role
