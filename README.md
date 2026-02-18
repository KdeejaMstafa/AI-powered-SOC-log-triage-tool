# AI-Powered SOC Log Triage Tool
This project simulates a lightweight Security Operations Center (SOC) workflow by combining log parsing, rule‑based detection, and AI‑generated analysis.
It ingests logs from different security layers, identifies high‑risk events, and produces clear, human‑readable summaries that help analysts understand what happened and why it matters.  
Basically, the goal is to demonstrate how AI can support SOC analysts by speeding up triage, reducing noise, and mapping alerts to attacker behaviors.

## Supported Log Sources
The tool currently processes three common SOC log types:  
• **Suricata IDS Alerts**    
Extracts signatures, categories, severity, source/destination IP, and timestamps.   
• **SSH Authentication Logs**   
Detects brute‑force attempts, repeated failed logins, and suspicious login behavior.    
• **Web Server Access Logs**    
Using a regex parser, the tool extracts IP address, timestamp, HTTP method and path, status code and agent.  

## AI-Assisted Analysis
Suspicious events are sent to a Groq inference API endpoint, which processes the prompt using a Groq‑hosted LLM and returns an AI‑generated analysis containing:  
• 	A plain‑language summary of the event  
• 	Why the activity is suspicious  
• 	Possible MITRE ATT&CK technique mapping  
• 	Recommended next steps for a SOC analyst  
This transforms the raw logs into actionable insights.

## How It Works
1. **Load logs**: Each log source is parsed into a structured pandas DataFrame.
2. **Apply detection rules**: The tool identifies Suricata alerts, SSH brute‑force attempts, Web scanning and suspicious user agents.
3. **Generate events**: Each suspicious activity becomes a structured “event” with context.
4. **Send events to Groq AI**: The model produces a human‑readable SOC-style analysis.
5. **Output Results**: Results are displayed in a clean structured format.

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
**groq**  
Used to send structured events to a Groq LLM for AI‑generated SOC analysis.

## Sample Output
<pre>Event ID: 1
Source: suricata

AI Analysis:

Summary:
A potential SSH scan was detected by Suricata, indicating a possible attempt to identify open SSH ports on a network. 
This activity may be a precursor to a larger attack. The source IP is unknown.

Why the activity is suspicious:
The detection of a potential SSH scan suggests that an attacker may be attempting to identify vulnerable systems on the network. 
This activity can be a precursor to a brute-force attack or other malicious activity. 
The unknown source IP adds to the suspicious nature of the activity.

MITRE Technique:
- ID: T1190
- Name: Exploit Public-Facing Application

Recommended Actions:
- Investigate the source IP to determine its origin and potential malicious intent.
- Review the network logs for any subsequent activity related to the detected SSH scan.
- Implement additional security measures to protect against brute-force attacks on SSH services.
- Consider blocking the source IP to prevent further potential attacks.</pre>

