import json

def build_prompt(event): 
    desc = event["description"]
    ctx = json.dumps(event["context"], indent=2, default=str)

    return (
        "Analyze the following suspicious security event and provide:\n\n"
        "1. A short summary (2–3 sentences).\n"
        "2. Why this activity is suspicious.\n"
        "3. A likely MITRE ATT&CK technique (ID + name).\n"
        "4. Recommended SOC actions (bullet points).\n\n"
        f"Event description:\n{desc}\n\n"
        f"Context (logs):\n{ctx}\n"
    )

