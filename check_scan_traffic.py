
import pandas as pd

df = pd.read_csv("reports/packet_summary.csv")
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["destination_port"] = pd.to_numeric(
    df["destination_port"], errors="coerce"
)
df["tcp_flags"] = df["tcp_flags"].fillna("").astype(str).str.upper()

tcp = df[
    (df["protocol"].str.upper() == "TCP")
    & df["timestamp"].notna()
    & df["destination_port"].between(1, 65535)
].copy()

tcp = tcp.sort_values("timestamp")

print("Checking rolling 60-second windows...\n")

results = []

for (src, dst), group in tcp.groupby(["source_ip", "destination_ip"]):
    times = group["timestamp"].tolist()
    ports = group["destination_port"].tolist()
    left = 0
    best = 0
    best_time = None

    for right in range(len(group)):
        while (times[right] - times[left]).total_seconds() > 60:
            left += 1

        count = len(set(ports[left:right + 1]))
        if count > best:
            best = count
            best_time = times[right]

    if best >= 15:
        results.append((src, dst, best, best_time))

if results:
    for src, dst, count, timestamp in sorted(
        results, key=lambda x: x[2], reverse=True
    ):
        print(
            f"{src} -> {dst}: {count} distinct ports "
            f"within 60 seconds (ending {timestamp})"
        )
else:
    print("No source/destination pair reached 15 distinct ports in 60 seconds.")
