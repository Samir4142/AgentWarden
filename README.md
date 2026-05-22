# AgentWarden — AI Security Monitoring Tool

> A Lightweight, Terminal-Based AI Agent Security Monitor.  
> Detects Prompt Injection Attempts And Credential Leaks In Real Time.

---

## Requirements

- Python 3.12+
- Groq API Key — Free At [console.groq.com](https://console.groq.com)

```bash
pip install groq
```

---

## How To Run

**Step 1 — Set Your Groq API Key**

Windows (PowerShell - Run As Administrator):
```powershell
[System.Environment]::SetEnvironmentVariable("GROQ_API_KEY", "your_key_here", "User")
```

Linux / Mac:
```bash
export GROQ_API_KEY="your_key_here"
```

**Step 2 — Add Log Files**

Place Any `.txt` Log Files Inside The `logs/` Directory.  
AgentWarden Automatically Monitors All Files In That Folder.  
Works On Any Machine — No Path Configuration Needed.

**Step 3 — Run The Watchman**

```bash
python agentwarden.py
```

Press `Q` + `Enter` To Exit Cleanly.

---

## How It Works — Three-Layer Detection

| Layer | Method                     | Detects                                     |
|-------|----------------------------|---------------------------------------------|
| 1     | Regex Pattern Matching     | Credential Leaks, Known Injection Phrases   |
| 2     | Groq LLM Semantic Analysis | Intent-Based Threats, Novel Attack Patterns |
| 3     | Keyword Hijack Detection   | Agent Manipulation Keywords                 |

Files Are Hashed On Every Cycle — Unchanged Files Are Skipped To Save Resources.  
Threats Are Logged With Timestamps To `reports/threat_report.txt`.

---

## Example Output

```
Analyzing auth_logs.txt...
[SAFE] auth_logs.txt — All Layers Clean

Analyzing system_logs.txt...
[THREAT DETECTED] system_logs.txt

[AgentWarden] Shutting Down. Stay Safe.
```

---

## Project Structure

```
AgentWarden/
├── agentwarden.py   ← Main Monitoring Script
├── validator.py     ← Three-Layer Detection Engine
├── logs/            ← Drop Log Files Here
└── reports/         ← Threat Reports Saved Here
```