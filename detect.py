import pandas as pd
from sklearn.ensemble import RandomForestClassifier

RULE_VERSION = "rules-v1"
SCAN_PORTS, DOS_PACKETS, BRUTE_COUNT = 20, 5000, 15
BRUTE_PORTS = [21, 22, 3389]
COLS = ["event_time", "severity", "source", "destination", "protocol", "reason", "confidence"]
FEATURES = ["src_port", "dst_port", "bytes", "packets", "duration", "bytes_per_packet"]

def _alert(t, sev, s, d, proto, reason, conf):
    return dict(event_time=str(t), severity=sev, source=s, destination=d, protocol=proto,
                reason=reason, confidence=round(float(min(conf, 0.99)), 2))

def run_rules(df):
    out = []
    for src, g in df.groupby("src_ip"):  # port scan
        n = g["dst_port"].nunique()
        if n >= SCAN_PORTS:
            sev = "High" if n >= 100 else "Medium" if n >= 50 else "Low"
            out.append(_alert(g.timestamp.min(), sev, src, g.dst_ip.mode()[0], g.protocol.mode()[0],
                              f"Port scan: {n} distinct destination ports", 0.5 + n / 200))
    for _, r in df[df.packets >= DOS_PACKETS].iterrows():  # DoS-like
        sev = "High" if r.packets >= 20000 else "Medium"
        out.append(_alert(r.timestamp, sev, r.src_ip, r.dst_ip, r.protocol,
                          f"DoS-like: {int(r.packets)} packets in one flow", 0.6 + r.packets / 100000))
    b = df[df.dst_port.isin(BRUTE_PORTS)].groupby(["src_ip", "dst_ip", "dst_port"])  # brute force
    for (s, d, p), g in b:
        if len(g) >= BRUTE_COUNT:
            sev = "High" if len(g) >= 100 else "Medium" if len(g) >= 30 else "Low"
            out.append(_alert(g.timestamp.min(), sev, s, d, g.protocol.mode()[0],
                              f"Brute-force: {len(g)} attempts to port {int(p)}", 0.5 + len(g) / 200))
    return pd.DataFrame(out, columns=COLS)

def train_classifier(labelled):
    """labelled: clean dataframe with a 'label' column ('normal'/'attack')."""
    m = RandomForestClassifier(n_estimators=100, random_state=0, class_weight="balanced")
    m.fit(labelled[FEATURES], (labelled["label"] == "attack").astype(int))
    return m

def run_classifier(df, model, threshold=0.8):
    proba = model.predict_proba(df[FEATURES])[:, list(model.classes_).index(1)]
    flagged = df[proba >= threshold]
    return pd.DataFrame([_alert(r.timestamp, "High" if pr >= 0.95 else "Medium", r.src_ip, r.dst_ip, r.protocol,
                                "Classifier: predicted attack", pr)
                         for (_, r), pr in zip(flagged.iterrows(), proba[proba >= threshold])], columns=COLS)

def detect(df, model=None):
    parts = [run_rules(df)] + ([run_classifier(df, model)] if model is not None else [])
    return pd.concat(parts, ignore_index=True)
