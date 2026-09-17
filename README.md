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
* **Least Privilege**: Programmatic security-tool access is restricted through explicit, least-privilege interfaces. The current Splunk integration is bounded and read-only; future integrations such as threat-intelligence lookups will follow the same model.
* **Human-in-the-Loop**: Consequential actions require explicit human authorization and remain simulated in initial phases.

---

## 2. Version 1 Scenario Workflow

The initial incident scenario covers an execution attempt using obfuscated PowerShell:

1. **Controlled Test Activity**: Execution of a benign base64-encoded command line on an internal host (DC01) to simulate adversary tradecraft.
2. **Telemetry Generation**: Microsoft Sysmon captures Process Create (Event ID 1).
3. **SIEM Ingestion**: Splunk Universal Forwarder delivers events to a dedicated Splunk indexer.
4. **Detection**: Custom SPL detection identifies the encoded execution.
5. **AI Investigation**: **IMPLEMENTED / TESTED** — Bounded AI investigator and deterministic ToolRouter for process and command-line triage.
6. **IOC Enrichment *(Planned)***: Threat-intelligence enrichment not yet implemented.
7. **MITRE Mapping**: **IMPLEMENTED** — Deterministic local mapping of detections to ATT&CK techniques (broader enrichment remains future work).
8. **Risk & Confidence Assessment**: **IMPLEMENTED / TESTED** — Advisory model confidence combined with deterministic policy risk scoring.
9. **Policy Gate**: **IMPLEMENTED / TESTED** — Deterministic risk evaluation and allowlisted action recommendation engine.
10. **Human Approval**: **IMPLEMENTED / TESTED** — Interactive CLI approval gate requiring explicit authorization for consequential actions.
11. **Simulated Response**: **IMPLEMENTED / TESTED (SIMULATED ONLY)** — Deterministic response simulation recording mock endpoint isolation; zero real containment.
12. **Incident Record *(Planned)***: Comprehensive auditable incident artifact generator.

---

## 3. Current Implementation Status

| Milestone / Component | Type | Status | Details |
| :--- | :--- | :--- | :--- |
| **Lab Infrastructure** | Virtual Network & Hosts | **VERIFIED** | VirtualBox LabNet (`192.168.1.0/24`), pfSense, DC01, Kali, Splunk Server. |
| **Sysmon Telemetry Ingestion** | Data Pipeline | **VERIFIED** | DC01 Sysmon Event ID 1 forwarded to Splunk index `main`. |
| **Splunk Detection (`.spl`)** | Detection Engineering | **IMPLEMENTED + TESTED** | Verified against benign encoded PowerShell test on DC01. |
| **Sigma Rule (`.yml`)** | Detection Engineering | **IMPLEMENTED, UNVALIDATED** | Rule defined; automated pipeline conversion pending. |
| **Bounded Splunk Search Client** | Local Integration & Python Gateway | **IMPLEMENTED + TESTED** | Hardened local client; 29 unit tests pass; verified live against Splunk Free localhost export endpoint. |
| **Investigator Scaffolding & Tool Router** | Triage Scaffolding & Routing | **IMPLEMENTED + UNIT TESTED** | Deterministic schemas, UTF-16LE Base64 decoder, static MITRE mapper, allowlisted tool router. |
| **AI Investigator Agent & Orchestrator** | Automation & LLM | **IMPLEMENTED + TESTED** | Bounded orchestrator, FakeModel, OpenAI Responses API adapter; offline test coverage. |
| **Audit Logging (JSONL)** | Audit & Observability | **IMPLEMENTED + TESTED** | Local append-only JSONL audit trail with strict field allowlist and exact-type checks. |
| **Policy Engine & Gate** | Security Controls | **IMPLEMENTED + TESTED** | Deterministic risk and action-policy evaluation; bounded scoring and action mapping. |
| **Human Approval Gate** | Security Controls / HITL | **IMPLEMENTED + TESTED** | CLI approval gate for consequential actions; bounded retries, exact-type checks, fail-closed denial. |
| **Simulated Response Executor** | SOAR / Simulation | **IMPLEMENTED + TESTED** | Deterministic authorization binding; records simulated endpoint isolation; zero live execution. |
| **Response Actions** | Containment Safety | **SIMULATED ONLY** | No real containment exists; endpoint isolation is simulated; zero subprocess, shell, or system mutation. |

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

- [x] **Milestone 1**: Lab environment deployment, Sysmon telemetry verification, controlled adversary-tradecraft simulation (benign test), and SPL detection engineering.
- [x] **Milestone 2**: Bounded read-only Splunk search client (Python) operating under least-privilege principles and verified end-to-end against live telemetry.
- [x] **Milestone 3**: AI investigation engine (3A: deterministic tools/router; 3B: bounded orchestration + OpenAI provider; 3C: persistent local JSONL audit; 3D: deterministic risk and action policy).
- [x] **Milestone 4**: Human-in-the-loop approval workflow and simulated response execution.
- [ ] **Milestone 5**: Structured incident report generator and workflow integration.
- [ ] **Milestone 6**: Adversarial robustness evaluation and prompt injection testing.
