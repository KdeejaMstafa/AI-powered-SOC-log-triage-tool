# AI-Powered SOC Log Triage Tool
This project simulates a lightweight Security Operations Center (SOC) workflow by combining log parsing, rule‑based detection, and AI‑generated analysis.
It ingests logs from different security layers, identifies high‑risk events, and produces clear, human‑readable summaries that help analysts understand what happened and why it matters.
The goal is to demonstrate how AI can support SOC analysts by speeding up triage, reducing noise, and mapping alerts to attacker behaviors
## Supported Log Sources
The tool currently processes three common SOC log types:  
• **Suricata IDS Alerts** (eve.json)  
Extracts signatures, categories, severity, and network metadata.  
• **SSH Authentication Logs** (auth.log)  
Detects brute‑force attempts, repeated failures, and suspicious login behavior.  
• **Web Server Access Logs** (access.log)  
Identifies scanning activity, suspicious user agents, and repeated 404/403 patterns.  

## AI-Assisted Analysis
Suspicious events are sent to an anonymous HuggingFace inference endpoint. The model generates:  
• 	A plain‑language summary of the event.  
• 	Why the activity is suspicious.  
• 	Possible MITRE ATT&CK technique mapping.  
• 	Recommended next steps for a SOC analyst.  
This transforms raw logs into actionable insights.
## Python Libraries Used
- **json**  
To read and write JSON data.  
To load the Suricata JSON file and to pretty‑print context for the AI.
- **re**  
Regular expression module.   
To parse unstructured text logs (auth.log, access.log) into structured fields.
- **pandas**  
A data analysis library.  
Used to store logs in DataFrames, group them, filter them, and count events.  
- **time**  
Python module for time related functions.  
- **request**  
For making HTTP requests.  
