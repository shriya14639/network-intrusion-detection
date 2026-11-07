"""Creates synthetic traffic: data/sample.csv plus bad files for validation tests."""
import random, pandas as pd
from datetime import datetime, timedelta
random.seed(42)
T0 = datetime(2026, 11, 1, 8, 0, 0)
rows = []
def row(t, s, d, proto, sp, dp, b, p, dur, label):
    rows.append(dict(timestamp=t.isoformat(sep=" "), src_ip=s, dst_ip=d, protocol=proto, src_port=sp,
                     dst_port=dp, bytes=b, packets=p, duration=dur, label=label))
for i in range(1800):  # normal
    t = T0 + timedelta(seconds=random.randint(0, 86400))
    row(t, f"192.168.1.{random.randint(2,60)}", f"10.0.0.{random.randint(2,20)}", random.choice(["tcp", "udp"]),
        random.randint(1024, 65000), random.choice([80, 443, 53, 8080]), random.randint(200, 20000),
        random.randint(2, 60), round(random.uniform(0.1, 5), 2), "normal")
t = T0 + timedelta(hours=5)  # port scan
for port in range(1, 91):
    row(t + timedelta(seconds=port), "10.0.0.66", "192.168.1.10", "tcp", 40000, port, 60, 1, 0.01, "attack")
t = T0 + timedelta(hours=9)  # DoS-like
for i in range(40):
    row(t + timedelta(seconds=i), "10.0.0.77", "192.168.1.20", "udp", 5000 + i, 80,
        random.randint(2_000_000, 6_000_000), random.randint(8000, 30000), 1.0, "attack")
t = T0 + timedelta(hours=14)  # brute force
for i in range(45):
    row(t + timedelta(seconds=i * 2), "10.0.0.88", "192.168.1.10", "tcp", 30000 + i, 22, 900, 12, 0.5, "attack")
df = pd.DataFrame(rows).sample(frac=1, random_state=1).reset_index(drop=True)
df.to_csv("data/sample.csv", index=False)
df.drop(columns=["label"]).to_csv("data/sample_nolabel.csv", index=False)
df.drop(columns=["dst_port"]).head(50).to_csv("data/bad_missing_column.csv", index=False)
bad = df.drop(columns=["label"]).head(50).astype(str)
bad.loc[3, "packets"] = "abc"; bad.loc[7, "src_ip"] = "999.1.1.1"; bad.loc[9, "dst_port"] = "70000"
bad.to_csv("data/bad_rows.csv", index=False)
open("data/bad_empty.csv", "w").close()
print("rows:", len(df))
