from detection import load_suricata, load_auth, load_access, detect_suspicious
from prompts import build_prompt
from model import load_model, local_llm

# Due to the limitations of the LLM, test on three events from each source.
def pick_one_per_source(events):
    suricata = [e for e in events if e["source"] == "suricata"]
    auth = [e for e in events if e["source"] == "auth"]
    access = [e for e in events if e["source"] == "access"]

    final = []
    if suricata:
        final.append(suricata[0])
    if auth:
        final.append(auth[0])
    if access:
        final.append(access[0])

    return final


def main():
    # Load logs
    suricata_df = load_suricata("datasets/suricata-ids-alerts.json")
    auth_df = load_auth("datasets/auth-ssh-login-events.log")
    access_df = load_access("datasets/web-access-activity.log")

    # Detect suspicious events
    suspicious = detect_suspicious(suricata_df, auth_df, access_df)

    # Select 1 event per source
    final_events = pick_one_per_source(suspicious)

    # Load model
    tokenizer, model = load_model()

    # Run AI
    results = []
    for event in final_events:
        prompt = build_prompt(event)
        analysis = local_llm(tokenizer, model, prompt)
        results.append({
            "source": event["source"],
            "description": event["description"],
            "ai_analysis": analysis
        })

    # Print report
    for i, entry in enumerate(results, start=1):
        print("=" * 80)
        print(f"Incident #{i}")
        print(f"Source: {entry['source']}")
        print(f"Description: {entry['description']}")
        print("\nAI Analysis:\n")
        print(entry["ai_analysis"])
        print("\n")


if __name__ == "__main__":
    main()