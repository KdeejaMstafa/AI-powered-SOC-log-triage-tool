import json
import re
import pandas as pd

# ------- Load Suricata Logs ------
def load_suricata(path):
    with open(path, "r") as f:
        data = json.load(f)

    events = []
    for event in data:
        if isinstance(event, dict) and event.get("event_type") == "alert":
            events.append({
                "timestamp": event.get("timestamp"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "signature": event.get("alert", {}).get("signature"),
                "category": event.get("alert", {}).get("category"),
                "severity": event.get("alert", {}).get("severity"),
            })

    return pd.DataFrame(events)

# ------- Load Auth Logs ------
def load_auth(path):
    events = []

    pattern = re.compile(
        r'^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+(?P<process>[\w\-/]+)(?:\[\d+\])?:\s+(?P<message>.*)$'
    )

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = pattern.match(line)
            if not m:
                continue
            msg = m.group("message")
            if "Failed password" in msg or "Invalid user" in msg:
                events.append({
                    "timestamp": f"{m.group('month')} {m.group('day')} {m.group('time')}",
                    "host": m.group("host"),
                    "process": m.group("process"),
                    "message": msg
                })

    return pd.DataFrame(events)

# ------- Load Access Logs ------
def load_access(path):
    events = []

    pattern = re.compile(
        r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
    )

    with open(path, "r", errors="ignore") as f:
        for line in f:
            m = pattern.match(line)
            if not m:
                continue
            events.append({
                "ip": m.group("ip"),
                "time": m.group("time"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": int(m.group("status")),
                "agent": m.group("agent")
            })

    return pd.DataFrame(events)

# ------- Detection Rules ------
def detect_suspicious(suricata_df, auth_df, access_df):
    suspicious = []

    # Suricata alerts
    if not suricata_df.empty:
        for _, row in suricata_df.iterrows():
            try:
                sev = int(row["severity"])
            except:
                sev = 0

            if sev >= 2:
                suspicious.append({
                    "source": "suricata",
                    "description": f"Suricata alert: {row['signature']} (category: {row['category']}, severity: {sev})",
                    "context": row.to_dict()
                })

   # SSH brute force
    if not auth_df.empty:

        def extract_ip(msg):
            m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
            return m.group(1) if m else None

        auth_df["ip"] = auth_df["message"].apply(extract_ip)
        brute_counts = auth_df.groupby("ip").size().reset_index(name="fail_count")

        for _, row in brute_counts.iterrows():
            if row["ip"] and row["fail_count"] >= 5:
                suspicious.append({
                    "source": "auth",
                    "description": f"Possible SSH brute force from {row['ip']} with {row['fail_count']} failed attempts",
                    "context": auth_df[auth_df["ip"] == row["ip"]].to_dict(orient="records")
                })


    # Web scanning
    if not access_df.empty:

        errors_404 = access_df[access_df["status"] == 404]
        counts_404 = errors_404.groupby("ip").size().reset_index(name="count_404")

        for _, row in counts_404.iterrows():
            if row["count_404"] >= 10:
                suspicious.append({
                    "source": "access",
                    "description": f"Possible web scanning from {row['ip']} with {row['count_404']} 404 responses",
                    "context": errors_404[errors_404["ip"] == row["ip"]].to_dict(orient="records")
                })

        suspicious_agents = access_df[access_df["agent"].str.contains("curl|sqlmap", case=False, na=False)]

        for _, row in suspicious_agents.iterrows():
            suspicious.append({
                "source": "access",
                "description": f"Suspicious user agent detected: {row['agent']} from {row['ip']}",
                "context": row.to_dict()
            })

    return suspicious
