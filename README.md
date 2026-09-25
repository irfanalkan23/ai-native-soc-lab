# AI-Native SOC & Agentic Security Engineering Lab

A hands-on, defensible engineering lab demonstrating AI-assisted security operations (SOC) and deterministic agentic security engineering across enterprise telemetry.

> **Project Scope & Status Notice**  
> This repository represents an ongoing engineering lab built in an isolated virtualized environment.  
> It distinguishes strictly between what is **implemented and tested**, what is **implemented but unvalidated**, and what is **planned**.  
> This project demonstrates practical security engineering concepts; it does not claim to represent production enterprise deployments.

---

### Executive Status Summary

* **Live benign SOC pipeline**: **LIVE TESTED** (DC01 Sysmon $\rightarrow$ Splunk $\rightarrow$ Bounded Investigation $\rightarrow$ Decoded Command $\rightarrow$ MITRE $\rightarrow$ Deterministic Policy $\rightarrow$ JSONL Audit $\rightarrow$ IncidentRecord $\rightarrow$ Jira Cloud `KAN-5`)
* **Real Jira Cloud create-issue**: **LIVE TESTED with KAN-5**
* **Human approval DENY**: **INTERACTIVELY DEMONSTRATED**
* **Human approval APPROVE**: **INTERACTIVELY DEMONSTRATED**
* **Endpoint isolation**: **SIMULATED ONLY**
* **OpenAI + real Splunk + real Jira**: **NOT YET TESTED** (components tested individually; single integrated trio run pending)
* **Real endpoint containment**: **NOT IMPLEMENTED**

> **Core Architectural & Safety Disclosures**:
> 1. **Live E2E Validation Used FakeModel**: The full live Splunk-to-Jira validation was conducted with `FakeModel` (deterministic test fixture). OpenAI Responses API integration has been tested offline and via standalone live smoke test, but has **NOT** yet been executed in a single integrated live run alongside real Splunk and real Jira.
> 2. **Downstream-Only Ticketing Authority**: Jira issue creation (`KAN-5`) acts strictly as a downstream external tracking and reporting sink. Jira possesses **zero response authority** over risk scoring, policy evaluation, approval gates, or endpoint actions.
> 3. **Human Approval Scope**: There is exactly one human approval gate: `deterministic policy -> approval required -> human approve/deny -> bounded simulated action`. Downstream Jira ticket creation does **not** require human approval because ticketing is reporting/tracking, not a consequential response action.
> 4. **Ephemeral Credential Lifecycle**: Temporary Jira API tokens used during live validation were injected strictly via process environment variables, Jira credential environment variables were unset from the active shell/process environment after testing, temporary tokens were revoked through the Atlassian account API-token management page, and credentials were never committed to version control.
> 5. **Truthful Engineering Boundaries**: This project is an ongoing engineering lab, not a production-ready enterprise SOC deployment. Response containment is strictly simulated (`SIMULATED` vs `NOT_EXECUTED`); zero live endpoint containment or host state modification is implemented.
>
> *For detailed walkthrough and evidence, see the [Encoded PowerShell Case Study](docs/case-studies/encoded-powershell-end-to-end.md).*

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
10. **Human Approval**: **INTERACTIVELY DEMONSTRATED** — Interactive CLI approval gate requiring explicit authorization for consequential actions (both APPROVE and DENY paths demonstrated).
11. **Simulated Response**: **SIMULATED ONLY** — Deterministic response simulation recording mock endpoint isolation; zero real containment.
12. **Incident Record**: **IMPLEMENTED / LIVE TESTED (Milestone 5A)** — Deterministic, bounded, local structured incident-record reporting artifact (`artifacts/incidents/<incident_id>.json`). Reporting artifact only; zero response authority.
13. **Downstream Jira Ticketing**: **LIVE TESTED (Milestone 5B-2)** — Downstream external tracking via Jira Cloud REST API v3 (ticket **KAN-5** created during live E2E run). Reporting only; zero response authority.

---

## 3. Current Implementation Status

| Milestone / Component | Type | Status | Details |
| :--- | :--- | :--- | :--- |
| **Lab Infrastructure** | Virtual Network & Hosts | **VERIFIED** | VirtualBox LabNet (`192.168.1.0/24`), pfSense, DC01, Kali, Splunk Server. |
| **Sysmon Telemetry Ingestion** | Data Pipeline | **VERIFIED** | DC01 Sysmon Event ID 1 forwarded to Splunk index `main`. |
| **Splunk Detection (`.spl`)** | Detection Engineering | **IMPLEMENTED + TESTED** | Verified against benign encoded PowerShell test on DC01. |
| **Sigma Rule (`.yml`)** | Detection Engineering | **IMPLEMENTED, UNVALIDATED** | Rule defined; automated pipeline conversion pending. |
| **Bounded Splunk Search Client** | Local Integration & Python Gateway | **IMPLEMENTED + LIVE TESTED** | Hardened local client; 40 unit tests pass; verified live against Splunk Free localhost export endpoint with raw XML extraction. |
| **Investigator Scaffolding & Tool Router** | Triage Scaffolding & Routing | **IMPLEMENTED + UNIT TESTED** | Deterministic schemas, UTF-16LE Base64 decoder, static MITRE mapper, allowlisted tool router. |
| **AI Investigator Agent & Orchestrator** | Automation & LLM | **IMPLEMENTED + TESTED** | Bounded orchestrator, FakeModel, OpenAI Responses API adapter; offline + live model tested. |
| **Audit Logging (JSONL)** | Audit & Observability | **IMPLEMENTED + LIVE TESTED** | Local append-only JSONL audit trail with strict field allowlist and exact-type checks. |
| **Policy Engine & Gate** | Security Controls | **IMPLEMENTED + LIVE TESTED** | Deterministic risk and action-policy evaluation; bounded scoring and action mapping. |
| **Human Approval Gate** | Security Controls / HITL | **INTERACTIVELY DEMONSTRATED** | CLI approval gate for consequential actions; bounded retries, exact-type checks, fail-closed denial; APPROVE and DENY demonstrated. |
| **Simulated Response Executor** | SOAR / Simulation | **IMPLEMENTED + TESTED (SIMULATED ONLY)** | Deterministic authorization binding; records simulated endpoint isolation; zero live execution. |
| **End-to-End Demo Harness** | Integration / Demo | **IMPLEMENTED + LIVE TESTED** | Complete pipeline script (`scripts/run_end_to_end_demo.py`); 35 integration tests pass; verified live. |
| **Structured Incident Artifact** | Reporting Artifact | **IMPLEMENTED + LIVE TESTED** | Local structured JSON artifact generator (`investigator/incident_record.py`); 36 unit tests pass; verified live with no-overwrite protection; reporting only with zero action authority. |
| **Response Actions** | Containment Safety | **SIMULATED ONLY** | No real containment exists; endpoint isolation is simulated; zero subprocess, shell, or system mutation. |
| **Ticketing Integration (Local Contract / Fake Client)** | SOAR / Reporting | **IMPLEMENTED + TESTED** | Deterministic contract (`investigator/ticketing.py`) & fake client; 49 unit tests pass; offline simulation only; zero response authority. |
| **Threat-Intelligence Contract & Fake Client** | Threat Intelligence / Advisory | **IMPLEMENTED + TESTED OFFLINE** | Provider-neutral IP schema (`investigator/threat_intel.py`) & `FakeThreatIntelClient`; 40 unit tests pass; advisory evidence only; zero response authority. |
| **VirusTotal Threat-Intelligence Adapter** | Threat Intelligence / Advisory | **IMPLEMENTED + TESTED OFFLINE** | Provider-specific REST API v3 IP adapter (`investigator/providers/virustotal_provider.py`); 44 offline unit/lifecycle/security tests pass; advisory evidence only; zero response authority. |
| **Live Threat-Intelligence Enrichment (VirusTotal)** | Threat Intelligence | **NOT YET TESTED** | Real adapter implemented and offline-tested; live enrichment smoke test deferred to Milestone 5C-2b. |
| **Jira Cloud Create-Issue Adapter** | SOAR / Case Management | **LIVE TESTED with KAN-5** | Downstream tracking adapter (`investigator/providers/jira_provider.py`); 39 offline tests pass; verified live via smoke script (`KAN-4`) and live E2E demo (`KAN-5`); zero response authority. |
| **OpenAI + Real Splunk + Real Jira** | Full Integrated Pipeline | **NOT YET TESTED** | Components tested individually; integrated trio run pending. |
| **Real Endpoint Containment** | Containment Safety | **NOT IMPLEMENTED** | Destructive containment actions explicitly excluded from V1 scope. |

---

## 4. End-to-End Demo Integration Harness

The integration harness (`scripts/run_end_to_end_demo.py`) stitches together all implemented components into a single interview-friendly workflow without adding new authority or changing existing security boundaries:

```
detection / incident input
    -> bounded Splunk evidence retrieval (localhost:8089 on Splunk-Server)
    -> deterministic decoding & MITRE mapping
    -> AI investigation (governed by ToolRouter)
    -> deterministic risk & action policy
    -> human approval gate (when required)
    -> simulated response only
    -> structured audit events
    -> safe final summary
    -> downstream Jira ticket (optional reporting sink)
```

### Supported Execution Modes

1. **Deterministic Synthetic-Critical Mode** (Run anywhere / offline):
   ```bash
   python scripts/run_end_to_end_demo.py --mode synthetic-critical
   ```
   * Exercises `ToolRouter`, `RiskPolicyEngine` (deterministic score 80, `CRITICAL`, `APPROVAL_REQUIRED`, `SIMULATE_ENDPOINT_ISOLATION`), interactive human approval (`[approve/deny]`), and response simulation (`SIMULATED` on approve, `NOT_EXECUTED` on deny).
   * Optional persistence: `--persist-audit` appends the session trail to `artifacts/audit/agent_audit.jsonl`.
   * Optional incident record: `--write-incident` generates and persists a deterministic `IncidentRecord` artifact to `artifacts/incidents/<incident_id>.json`.
   * Optional ticketing: `--create-ticket` generates and dispatches a bounded ticket. Defaults to `--ticket-provider fake` (offline simulation).
   * Live Jira Cloud dispatch: `--create-ticket --ticket-provider jira [--jira-project SEC] [--jira-issue-type Task]` (verified live with ticket `KAN-5`).
   * Standalone live smoke test: `python scripts/run_jira_smoke.py --project <KEY> --issue-type <TYPE>` (verified live with ticket `KAN-4`).

2. **Live Benign Lab Mode** (Run locally on Splunk-Server):
   ```bash
   python scripts/run_end_to_end_demo.py --mode live-benign --provider fake
   python scripts/run_end_to_end_demo.py --mode live-benign --provider openai
   ```
   * Queries `https://localhost:8089` for up to 5 events from DC01 within lookback window (`--minutes 15`).
   * Extracts raw Sysmon XML attributes and selects the exact benign fixture (`Write-Host 'AI-NativeSOC-LAB-TEST'`).
   * Evaluates to `risk_score = 0`, `LOW`, `NO_ACTION`. Never prompts for human approval.
   * Fails closed with exit code 1 if the exact fixture is not found in the bounded window.
   * Full live run verified: created Jira Cloud ticket **KAN-5** and persisted local audit/incident records.

---

## 5. Current Verified Lab Infrastructure

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

## 6. Telemetry & Detection Status

### Splunk Telemetry Profile
* **Index**: `main`
* **Sourcetype**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Host**: `DC01`

Because Sysmon operational events currently arrive as raw XML in this environment, extraction of `EventID`, `Image`, `CommandLine`, `ParentImage`, and `User` is accomplished using search-time regex (`rex`) patterns.

### Tested SPL Query
Located in [`detections/splunk/suspicious_encoded_powershell.spl`](detections/splunk/suspicious_encoded_powershell.spl):
* Filters for Sysmon Process Create (`<EventID>1</EventID>`).
* Extracts process execution metadata from raw XML attributes.
* Matches PowerShell binaries executing with bounded `-encodedcommand` or `-enc` flags.
* Successfully returned the controlled benign test executed on DC01.

### Sigma Detection Rule
Located in [`detections/sigma/suspicious_encoded_powershell.yml`](detections/sigma/suspicious_encoded_powershell.yml):
* Equivalent generic process-creation rule for cross-platform detection repositories.
* Status: **Implemented, not yet validated** against the live conversion pipeline.

### MITRE ATT&CK Mapping
* **Technique**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)
* **Tactic**: Execution (`TA0002`)

---

## 7. High-Level Project Roadmap

- [x] **Milestone 1**: Lab environment deployment, Sysmon telemetry verification, controlled adversary-tradecraft simulation (benign test), and SPL detection engineering.
- [x] **Milestone 2**: Bounded read-only Splunk search client (Python) operating under least-privilege principles and verified end-to-end against live telemetry.
- [x] **Milestone 3**: AI investigation engine (3A: deterministic tools/router; 3B: bounded orchestration + OpenAI provider; 3C: persistent local JSONL audit; 3D: deterministic risk and action policy).
- [x] **Milestone 4**: Human-in-the-loop approval workflow and simulated response execution.
- [x] **Milestone 5A**: Deterministic structured incident-record reporting artifact (reporting only, zero action authority).
- [x] **Milestone 5B-1**: Deterministic ticketing contract and local fake ticket workflow (reporting only, zero action authority).
- [x] **Milestone 5B-2**: Live Jira Cloud REST API v3 create-issue adapter (downstream external tracking/reporting sink, zero response authority; adapter implemented, offline-tested, and verified live with tickets KAN-4 and KAN-5).
- [x] **Milestone 5C-1**: Provider-neutral threat intelligence contract and local fake client (advisory evidence only, zero response authority; public IP validation, offline-tested).
- [x] **Milestone 5C-2**: VirusTotal REST API v3 IP provider adapter (advisory evidence only, zero response authority; offline mocked + tested; live smoke test deferred to 5C-2b).
- [ ] **Milestone 6**: Adversarial robustness evaluation and prompt injection testing.
