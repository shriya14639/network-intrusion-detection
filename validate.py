import io, ipaddress
import pandas as pd

REQUIRED = ["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "bytes", "packets", "duration"]
NUMERIC = ["src_port", "dst_port", "bytes", "packets", "duration"]
MAX_MB = 10

def _valid_ip(x):
    try:
        ipaddress.ip_address(str(x).strip()); return True
    except ValueError:
        return False

def validate_csv(raw: bytes, filename="upload.csv", max_mb=MAX_MB):
    """Returns (clean_df, rejected_df, errors). clean_df is None if the file as a whole is rejected."""
    empty = pd.DataFrame()
    if not filename.lower().endswith(".csv"):
        return None, empty, ["File must be a .csv file."]
    if not raw or not raw.strip():
        return None, empty, ["File is empty."]
    if len(raw) > max_mb * 1024 * 1024:
        return None, empty, [f"File exceeds {max_mb} MB limit."]
    try:
        df = pd.read_csv(io.BytesIO(raw), engine="python", on_bad_lines="skip", dtype=str)
    except Exception as e:
        return None, empty, [f"Could not parse CSV: {e}"]
    df.columns = [c.strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        return None, empty, [f"Missing required columns: {', '.join(missing)}"]
    keep = REQUIRED + (["label"] if "label" in df.columns else [])
    df = df[keep].copy()
    reason = pd.Series("", index=df.index)
    for c in NUMERIC:
        df[c] = pd.to_numeric(df[c], errors="coerce")
        reason[df[c].isna()] += f"invalid {c}; "
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    reason[df["timestamp"].isna()] += "invalid timestamp; "
    for c in ["src_ip", "dst_ip"]:
        df[c] = df[c].astype(str).str.strip()
        reason[~df[c].map(_valid_ip)] += f"invalid {c}; "
    for c in ["src_port", "dst_port"]:
        reason[(df[c] < 0) | (df[c] > 65535)] += f"{c} out of range; "
    for c in ["bytes", "packets", "duration"]:
        reason[df[c] < 0] += f"negative {c}; "
    df["protocol"] = df["protocol"].astype(str).str.strip().str.lower()
    reason[df["protocol"].isin(["", "nan"])] += "missing protocol; "
    bad = reason != ""
    rejected = df[bad].copy(); rejected["reject_reason"] = reason[bad]
    clean = df[~bad].copy().reset_index(drop=True)
    clean["bytes_per_packet"] = clean["bytes"] / clean["packets"].clip(lower=1)
    return clean, rejected.reset_index(drop=True), []
