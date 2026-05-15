# Detection Engine Breakdown

## Overview

ProcWatch is a real-time process monitoring tool built on top of Sysmon logs.  
It focuses on detecting suspicious behavior through contextual analysis rather than static signatures.

------

## Threat Model

The system focuses on detecting early-stage attack behaviors, such as:

- Execution of offensive tools
- Abuse of legitimate binaries (LOLBins)
- Suspicious parent-child process chains
- Privileged execution contexts

ProcWatch is not intended to replace a full EDR software. Instead, it offers a lightweight host-based alternative, having a more didatical approach.

## Data Source

ProcWatch relies on Sysmon event logs, specifically:

- Event ID 1: Process Creation<br>
    Used as information source for detecting the very start of malicious activities in the system.
    <img width="553" height="220" alt="image" src="https://github.com/user-attachments/assets/b57527ea-6fbc-4262-a586-a7275a927631" />

- Event ID 5: Process Termination<br>
    Used to detect security-critical processes termination, like Windows Defender.
    <img width="661" height="114" alt="image" src="https://github.com/user-attachments/assets/73778cca-489c-468a-a051-96e94ed1d620" />


## Process Context Extraction

Each process event is transformed into a meaningfull structured class, containing:

- Executable name
- Parent process
- Command-line arguments
- Execution time
- User context
And many other data that may be usefull to precisely determine the risk score of the event.
This contextual representation enables behavioral analysis rather than isolated inspection.

<img width="720" height="436" alt="image" src="https://github.com/user-attachments/assets/82ffce4c-209b-403c-a46a-e60d587519ac" />

------

## Detection Engine

The detection logic is based on multiple independent and also related signals.

### Suspicious Executables

Known offensive tools increase the risk score. <br>
This is detected by the executable's name pre-stored at `rules/programs.json`.<br>
Examples include:

- PowerShell
- Network tools
- Reverse shell tools
- Port listeners
- Common offensive utilities
The program names are separated by their area and level of impact in the system, with some of them being considered more suspicious and dangerous than other ones.

This approach allows quick extensibility without code changes.

### Command-Line Analysis

Flags associated with malicious activity are detected and scored.
Instead of seeing it as a single malicious activity, each malicious flag detection increses the final risk score, decreasing the number of false positives in the report.
Examples:

- Encoded commands
- Remote downloads
- Port exposure
- Network listeners
- Suspicious scripting parameters

### Privileged Execution

Processes running/spawning under privileged groups are treated with higher scrutiny.<br>
Examples:

- Administrators
- Other high-authority local groups

As priviledged groups and users are often specifically built for an environment, it is recommended to customize this JSON with your own entities.

### Parent-Child Anomalies

Unexpected process chains are flagged, such as:

`winword.exe → powershell.exe`

These patterns are commonly associated with macro-based, trojans and many other types of attacks.<br>
Some few examples are seem below:<br>
<img width="347" height="565" alt="image" src="https://github.com/user-attachments/assets/357f66e5-58df-4963-b6e6-634fbace95c7" />

### Security-Critical Process Termination

Termination of important security-related processes increases the risk score.

Examples include attempts to terminate:

- antivirus processes
- monitoring tools
- security services

This behavior may indicate:

- defense evasion
- malware pre-execution hardening
- monitoring disruption

-----

## Risk Scoring

Each detection contributes to a cumulative risk score.

Example scoring logic:

- Suspicious executable: +3
- Dangerous flags: +3
- Privileged context: +3
- Suspicious parent-child relation: +3
- Critical process termination: +4

Final classification:

- **Low** → uncommon behavior
- **Medium** → potentially malicious
- **High** → attack indicator
- **Critical** → strong attack indicator

This scoring model allows analysts to prioritize investigation.

## Machine Learning Extension

ProcWatch has an optional anomaly detection feature using Isolation Forest.
The idea is for the model to learn what normal process behavior looks like and flag anything unusual.

ML is just an extra signal here.
The heuristic rules are still in charge — whatever they flag is final, and anomaly results don't override them.
This keeps us from relying too heavily on unsupervised models in environments that might already be compromised.

## Reporting

Suspicious events are written to a structured markdown report, including:

- Process metadata
- Detection reasons
- Final risk classification

------

## Design Decisions

- Heuristic-based detection was chosen for transparency and analyst control
- JSON rule system allows fast extensibility
- Event-driven architecture enables real-time monitoring
- Markdown reporting improves readability and documentation
- Optional anomaly detection provides behavioral enrichment without replacing heuristics


## Limitations

- Detection is partially rule-based
- No cross-event correlation yet
- No persistence analysis
- No network telemetry correlation
- Behavioral baselines depend on training quality

Additionally, anomaly detection assumes mostly benign training data.
Training on compromised systems may normalize malicious behavior.


## Future Improvements

Planned improvements:

- Behavioral baseline refinement with Isolation Forest
- Cross-event correlation
- Persistence detection
- Network telemetry correlation
- Improved anomaly feature extraction
- Detection timeline reconstruction

A complementary network telemetry tool is planned as a future project, integrating a lightweight security monitoring suite.

## Example Detection

<img width="821" height="387" alt="Captura de tela 2026-05-15 011024" src="https://github.com/user-attachments/assets/20d1d436-2d0e-47a5-8d89-d8f2ce97d587" />

------
