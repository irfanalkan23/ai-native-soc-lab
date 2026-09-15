# AI-Native SOC & Agentic Security Engineering Lab

A hands-on, defensible engineering lab demonstrating AI-assisted security operations (SOC) and deterministic agentic security engineering across enterprise telemetry.

> **Project Scope & Status Notice**  
> This repository represents an ongoing engineering lab built in an isolated virtualized environment.  
> It distinguishes strictly between what is **implemented and tested**, what is **implemented but unvalidated**, and what is **planned**.  
> This project demonstrates practical security engineering concepts; it does not claim to represent production enterprise deployments.

---

## 1. Project Purpose

Modern Security Operations Centers face high alert volumes and context fragmentation. This project demonstrates how an AI agent can assist human analysts during alert triage, telemetry analysis, and IOC enrichment while remaining bound by strict deterministic security policies.

### Core Runtime Security Principle

To ensure safety and auditability, the runtime architecture follows a strict unidirectional control loop:

```
[ Telemetry Alert ] 
         │
         ▼
[ AI Proposes Actions / Hypothesis ]
         │
         ▼
[ Deterministic Policy Gate Evaluates ]
         │
         ▼
[ Human Approves Consequential Actions ]
         │
         ▼
[ System Executes Controlled Action ]
         │
         ▼
[ Runtime Audit Log & Evaluation ]
```

* **No Unrestricted Autonomous Agents**: The system does not have arbitrary shell execution, endpoint isolation capabilities, firewall management, or destructive access.
* **Least Privilege**: All programmatic access (e.g., SIEM queries, threat intelligence lookups) is read-only and restricted to explicit tool allowlists.
* **Human-in-the-Loop**: Consequential actions require explicit human authorization and remain simulated in initial phases.

---

## 2. Version 1 Scenario Workflow

The initial incident scenario covers an execution attempt using obfuscated PowerShell:

1. **Adversary Activity**: Execution of base64-encoded command line on an internal host.
2. **Telemetry Generation**: Microsoft Sysmon captures Process Create (Event ID 1).
3. **SIEM Ingestion**: Splunk Universal Forwarder delivers events to a dedicated Splunk indexer.
4. **Detection**: Custom SPL detection identifies the encoded execution.
5. **AI Investigation *(Planned)***: Automated triage parsing command line parameters and parent process ancestry.
6. **IOC Enrichment *(Planned)***: Automated reputation checks on extracted artifacts.
7. **MITRE Mapping**: Automatic mapping to ATT&CK Technique T1059.001.
8. **Risk & Confidence Assessment *(Planned)***: Scoring severity based on execution context.
9. **Policy Gate *(Planned)***: Deterministic evaluation of recommended actions.
10. **Human Approval *(Planned)***: Operator review before executing response workflows.
11. **Simulated Response *(Planned)***: Mock containment action record without live endpoint disruption.
12. **Incident Record *(Planned)***: Comprehensive auditable incident artifact generated.

---

## 3. Current Implementation Status

| Milestone / Component | Type | Status | Details |
| :--- | :--- | :--- | :--- |
| **Lab Infrastructure** | Virtual Network & Hosts | **VERIFIED** | VirtualBox LabNet (`192.168.1.0/24`), pfSense, DC01, Kali, Splunk Server. |
| **Sysmon Telemetry Ingestion** | Data Pipeline | **VERIFIED** | DC01 Sysmon Event ID 1 forwarded to Splunk index `main`. |
| **Splunk Detection (`.spl`)** | Detection Engineering | **IMPLEMENTED + TESTED** | Verified against benign encoded PowerShell test on DC01. |
| **Sigma Rule (`.yml`)** | Detection Engineering | **IMPLEMENTED, UNVALIDATED** | Rule defined; automated pipeline conversion pending. |
| **AI Investigator Agent** | Automation & LLM | **PLANNED** | Read-only Splunk REST API integration not yet built. |
| **Policy Engine & Gate** | Security Controls | **PLANNED** | Deterministic rule-checking framework not yet built. |
| **Response Actions** | SOAR / Containment | **PLANNED (SIMULATED)** | No real containment exists; future response actions will be simulated. |

---

## 4. Current Verified Lab Infrastructure

The physical/virtual infrastructure exists outside this repository in an isolated VirtualBox environment:

* **Hypervisor**: VirtualBox
* **Internal Network**: LabNet (`192.168.1.0/24`)
* **Firewall / Gateway**: pfSense
* **Attacker / Audit VM**: Kali Linux
* **Domain Controller (DC01)**:
  * Windows Server 2022 (Active Directory)
  * Microsoft Sysmon installed and generating operational event logs
  * Splunk Universal Forwarder forwarding logs to dedicated SIEM
* **SIEM (Splunk Server)**:
  * Dedicated instance (`192.168.1.101`)
  * Splunk Enterprise running under Free License
  * Accessible from management workstation at `http://192.168.1.101:8000`

---

## 5. Telemetry & Detection Status

### Splunk Telemetry Profile
* **Index**: `main`
* **Sourcetype**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Host**: `DC01`

Because Sysmon operational events currently arrive as raw XML in this environment, extraction of `EventID`, `Image`, `CommandLine`, `ParentImage`, and `User` is accomplished using search-time regex (`rex`) patterns.

### Tested SPL Query
Located in [`detections/splunk/suspicious_encoded_powershell.spl`](detections/splunk/suspicious_encoded_powershell.spl):
* Filters for Sysmon Process Create (`<EventID>1</EventID>`).
* Extracts process execution metadata from raw XML.
* Matches PowerShell binaries executing with `-encodedcommand` or `-enc` flags.
* Successfully returned the controlled benign test executed on DC01.

### Sigma Detection Rule
Located in [`detections/sigma/suspicious_encoded_powershell.yml`](detections/sigma/suspicious_encoded_powershell.yml):
* Equivalent generic process-creation rule for cross-platform detection repositories.
* Status: **Implemented, not yet validated** against the live conversion pipeline.

### MITRE ATT&CK Mapping
* **Technique**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
* **Tactic**: Execution (`TA0002`)

---

## 6. High-Level Project Roadmap

- [x] **Milestone 1**: Lab environment deployment, Sysmon telemetry verification, controlled attack simulation, and SPL detection engineering.
- [ ] **Milestone 2**: Read-only programmatic Splunk connector (Python) operating under least-privilege principles.
- [ ] **Milestone 3**: AI investigation engine with structured tool calling (triage, decoding, and MITRE mapping).
- [ ] **Milestone 4**: Deterministic policy enforcement layer and human-approval workflow.
- [ ] **Milestone 5**: Simulated response executor and structured incident report generator.
- [ ] **Milestone 6**: Prompt injection testing, adversarial robustness evaluation, and audit logging.
