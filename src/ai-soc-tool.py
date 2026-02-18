## In the terminal, execute: !pip install groq
import os
import json
import pandas as pd
import re
from groq import Groq
os.environ["GROQ_API_KEY"] = "api key should be placed here"

## Load Suricata Logs ##
def load_suricata(path):
  with open(path, "r") as f:
    data = json.load(f)
  events = []
  for e in data:
    if e.get("event_type") == "alert":
      events.append({
          "timestamp": e.get("timestamp"),
          "src_ip": e.get("src_ip"),
          "dest_ip": e.get("dest_ip"),
          "signature": e.get("alert", {}).get("signature"),
          "severity": e.get("alert", {}).get("severity"),
          "category": e.get("alert", {}).get("category")
      })
  return pd.DataFrame(events)

## Load Auth Logs ##
def load_auth(path):
  pattern = re.compile(r".*Failed password.*from (\d+\.\d+\.\d+\.\d+).*")
  events = []

  with open(path, "r", errors = "ignore") as f:
    for line in f:
      m = pattern.match(line)
      if m:
        events.append({"ip": m.group(1), "raw": line.strip()})
  return pd.DataFrame(events)



## Load Web Access Logs ##
def load_access(path):
  access_pattern = re.compile(
        r'^(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] '
        r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
        r'(?P<status>\d{3}) (?P<size>\S+) '
        r'"(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
    )
  events = []

  with open(path, "r", errors = "ignore") as f:
    for line in f:
      # line = line.strip()
      m = access_pattern.match(line)
      if m:
        events.append({
            "ip": m.group("ip"),
            "status": int(m.group("status")),
            "agent": m.group("agent"),
            "raw": line.strip()
        })
  return pd.DataFrame(events)

## Apply Detection Rules ##
def detect_events(suricata_df, auth_df, access_df):
  events = []
  event_id = 1

  # Suricata: severity >= 2
  for _, row in suricata_df.iterrows():
    if int(row["severity"]) >= 2:
      events.append({
          "id": event_id,
          "source": "suricata",
          "description": f"Suricata alert: {row['signature']}",
          "context": row.to_dict()
      })
      event_id += 1

  # Auth: brute force (>= 5 failures from same IP)
  if not auth_df.empty:
    counts = auth_df.groupby("ip").size().reset_index(name="fails")
    for _, row in counts.iterrows():
      if row["fails"] >= 5:
        events.append({
            "id": event_id,
            "source": "auth",
            "description": f"SSH brute force from {row['ip']}",
            "context": auth_df[auth_df["ip"] == row["ip"]].to_dict(orient="records")
            })
        event_id += 1

  # Access: scanning for 404 / 403 / 500 and suspicious agents
  if not access_df.empty:
    # 1) 404 / 403 / 500 scanning
    errors = access_df[access_df["status"].isin([403, 404, 500])]
    counts = errors.groupby("ip").size().reset_index(name="error_count")
    for _, row in counts.iterrows():
     if row["error_count"] >= 4:   # lowered from 10 to 4
      ip = row["ip"]
      events.append({
          "id": event_id,
          "source": "access",
          "description": f"Possible web scanning or probing from {ip}",
          "context": errors[errors["ip"] == ip].to_dict(orient="records")
      })
      event_id += 1

    # 2) Suspicious user agents (sqlmap, curl, etc.)
    suspicious = access_df[access_df["agent"].str.contains("sqlmap|curl", case=False, na=False)]
    for ip in suspicious["ip"].unique():
      events.append({
          "id": event_id,
          "source": "access",
          "description": f"Suspicious tool-based probing from {ip}",
          "context": suspicious[suspicious["ip"] == ip].to_dict(orient="records")
      })
      event_id += 1
  return events


  ## Building the prompt ##
SYSTEM_PROMPT = """
You are a SOC analyst assistant.

You must output ONLY the following fields:

Summary:
- 2–3 sentence summary.

Why the activity is suspicious:
- 2–4 sentences explaining why.

MITRE Technique:
- ID: <T1046 | T1110 | T1595 | T1190 | Unknown>
- Name: <technique name or explanation>

Recommended Actions:
- Four bullet points.

RULES:
- Do NOT repeat the prompt.
- Do NOT include system or user messages.
- Do NOT explain your reasoning.
"""

def build_prompt(event):
  ctxt = json.dumps(event["context"], indent=2)[:1500]
  return f"""
  EventID: {event['id']}
  Source: {event['source']}
  Description: {event['description']}
  Context:
  {ctxt}"""

## Calling the model ##
client = Groq()

def analyze_event(event):
  prompt = build_prompt(event)
  response = client.chat.completions.create(
      model = "llama-3.1-8b-instant",
      messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
      temperature = 0.0,
      max_tokens = 400
  )

  return response.choices[0].message.content

## Run the Tool ##
suricata = load_suricata("/content/suricata-ids-alerts.json")
auth = load_auth("/content/auth-ssh-login-events.log")
access = load_access("/content/web-access-activity.log")

events = detect_events(suricata, auth, access)

results = []
for e in events:
    print(f"Analysing event {e['id']} from {e['source']}..")
    analysis = analyze_event(e)
    results.append((e["id"], e["source"], analysis))

for event_id, source, analysis in results:
    print("="*80)
    print(f"Event ID: {event_id}")
    print(f"Source: {source}")
    print("\nAI Analysis:\n")
    print(analysis)
    print("\n")
