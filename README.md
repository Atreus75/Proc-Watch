## 🇧🇷 Resumo (PT-BR)
O ProcWatch é um monitor de processos em tempo real baseado em Sysmon, 
focado em detectar comportamento suspeito usando análise contextual e heurísticas de SOC.
<br><br>

---
# 🛡️ ProcWatch

    They won't go far unnoticed
    ██████╗ ██████╗   ██████╗   ██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗ ██╔═══██╗ ██╔════╝ ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
    ██████╔╝██████╔╝ ██║   ██║ ██║      ██║ █╗ ██║███████║   ██║   ██║     ███████║
    ██╔═══╝ ██╔══██╗ ██║   ██║ ██║      ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
    ██║     ██║  ██║ ╚██████╔╝ ╚██████╗ ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝  ╚═════╝   ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
                                                        by Rodrigo Soares Ferreira

Real-time process monitoring tool based on Sysmon events, focused on detecting suspicious behavior.

## Overview

ProcWatch listens to Windows Sysmon logs and analyzes process creation events to identify potentially malicious activity.
The approach is straightforward: observe process execution, evaluate context, and assign a risk score.


## How it works

* Subscribes to Sysmon event log (`Microsoft-Windows-Sysmon/Operational`)
* Captures events in real time
* Parses XML into structured data
* Analyzes process creation and termination events
* Applies detection rules
* Assigns a risk score
* Writes findings to a report file

## Features

- Real-time Sysmon event monitoring
- Process creation analysis (Event ID 1)
- Security-critical process termination detection (Event ID 5)
- Command-line flag inspection
- Parent-child anomaly detection
- Privileged user context analysis
- Risk scoring and Markdown reporting
- Markdown report generation
- Optional anomaly detection with Isolation Forest

## Machine Learning Support

ProcWatch optionally supports anomaly detection using Isolation Forest.

The model learns process execution baselines and can flag unusual behavior patterns as an additional signal in the final risk score.

ML is used as a complementary layer and never overrides high-confidence heuristic detections.

## Risk scoring

Each event is scored based on context:

* **1–3** → uncommon
* **4–6** → suspicious
* **7–9** → attack indicator
* **10+** → strong attack indicator

## Rule system

Detection behavior is driven by JSON files:

* `programs.json` → monitored executables
* `flags.json` → suspicious arguments
* `parents.json` → anomalous relationships
* `users_and_groups.json` → privileged groups
These files can also be modified for a more customized use at any Windows security scenario

## Sample Detection
### Terminal Output
```
[+] New Event: Process Create at 2026-05-15T03:29:01
    Binary Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    PID: 3544
```
### Markdown Report File
<img width="1021" height="587" alt="image" src="https://github.com/user-attachments/assets/996931d4-8d9a-4e84-b8d1-228130db0dc6" />


---

## Tech stack

* Python
* Sysmon
* scikit-learn
* win32evtlog
* xmltodict

## Installation

```bash
pip install pywin32 xmltodict scikit-learn
```

[Sysmon](https://learn.microsoft.com/pt-br/sysinternals/downloads/sysmon) must be installed and configured on the target machine.

## Usage
### Normal
```bash
python procwatch.py
```
### Collect Telemetry Data for ML Training
```
python procwatch.py -t
```
### Use ML Anomaly Detection
```
python procwatch.py -a
```
---

## Purpose

ProcWatch was built as a lightweight host-based monitoring prototype inspired by SOC workflows.

The project focuses on process telemetry, behavioral detection and practical Windows event analysis.
