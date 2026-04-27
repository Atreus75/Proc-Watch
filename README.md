# 🛡️ ProcWatch

Real-time process monitoring tool based on Sysmon events, focused on detecting suspicious behavior.

## 🇧🇷 Resumo (PT-BR)
O ProcWatch é um monitor de processos em tempo real baseado em Sysmon, 
focado em detectar comportamento suspeito usando análise contextual e heurísticas de SOC.
---

## Overview

ProcWatch listens to Windows Sysmon logs and analyzes process creation events to identify potentially malicious activity.
The approach is straightforward: observe process execution, evaluate context, and assign a risk score.


## How it works

* Subscribes to Sysmon event log (`Microsoft-Windows-Sysmon/Operational`)
* Captures events in real time
* Parses XML into structured data
* Focuses on process creation events
* Applies detection rules
* Assigns a risk score
* Writes findings to a report file



## Detection logic

### Suspicious executables

Flags known tools commonly used in offensive operations (e.g., shells, network tools).

### Command-line analysis

Detects flags associated with malicious behavior, such as:

* remote execution
* payload download
* port exposure

### Privileged users

Checks if the process was started by high-privilege groups.

### Parent-child relationships

Detects anomalous chains like:

```
winword.exe → powershell.exe
```

Typical indicator of macro-based or indirect execution.

---

## Risk scoring

Each event is scored based on context:

* **1–3** → uncommon
* **4–6** → suspicious
* **7–9** → attack indicator
* **10+** → strong attack indicator

---

## Output

Relevant events are written to `report.md`, including:

* Process details
* Detection reasons
* Risk classification


## Rule system

Detection behavior is driven by JSON files:

* `programs.json` → monitored executables
* `flags.json` → suspicious arguments
* `parents.json` → anomalous relationships
* `users_and_groups.json` → privileged groups

---

## Tech stack

* Python
* Sysmon
* win32evtlog
* xmltodict

---

## Usage

```bash
python procwatch.py
```

---

## Purpose

This project demonstrates:

* behavioral detection
* process monitoring
* SOC-oriented thinking
* practical defensive security concepts
