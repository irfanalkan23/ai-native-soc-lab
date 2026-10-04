# AI-Native SOC & Agentic Security Engineering Lab

A hands-on, defensible engineering lab demonstrating AI-assisted security operations (SOC) and deterministic agentic security engineering across enterprise telemetry.

> **Project Scope & Status Notice**  
> This repository represents an ongoing engineering lab built in an isolated virtualized environment.  
> It distinguishes strictly between what is **implemented and tested**, what is **implemented but unvalidated**, and what is **planned**.  
> This project demonstrates practical security engineering concepts; it does not claim to represent production enterprise deployments.

---

### Executive Status Summary

* **Live benign SOC pipeline (Endpoint / DC01)**: **LIVE TESTED** (DC01 Sysmon $\rightarrow$ Splunk $\rightarrow$ Bounded Investigation $\rightarrow$ Decoded Command $\rightarrow$ MITRE $\rightarrow$ Deterministic Policy $\rightarrow$ JSONL Audit $\rightarrow$ IncidentRecord $\rightarrow$ Jira Cloud `KAN-5`)
* **Live WEB01 web telemetry ingestion**: **LIVE VERIFIED** (Kali controlled SQLi $\rightarrow$ WEB01 Apache ModSecurity CRS $\rightarrow$ HTTP 403 $\rightarrow$ Splunk index `main`, sourcetype `modsecurity`)
* **WEB01 ModSecurity SQLi pipeline**: **IMPLEMENTED + TESTED** (Bounded retrieval $\rightarrow$ Deterministic parser $\rightarrow$ `ModSecuritySqliEvidence` $\rightarrow$ Scope gate $\rightarrow$ TI eligibility gate $\rightarrow$ `IncidentRecord` $\rightarrow$ Bounded `TicketRequest`)
* **Real Jira Cloud create-issue (DC01)**: **LIVE TESTED with KAN-5**
* **Jira Cloud create-issue (WEB01)**: **IMPLEMENTED + MOCK TESTED** (Live ticket creation for WEB01 NOT YET TESTED)
* **Canonical Security Evaluations**: **17 / 17 PASS (100.0%)** (7 baseline + 10 WEB01 adversarial scenarios; 0 security violations)
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
> 6. **WEB01 Private Scope & Threat Intel Isolation**: In the running lab, the controlled WEB01 attacker originates from a private LabNet address (`192.168.1.100`). The deterministic scope classification system identifies private/non-global IPs and strictly blocks external threat intelligence lookup attempts (`external_ti_eligible=False`, `threat_intel_status="SKIPPED_INELIGIBLE"`). No genuine public WEB01 attacker IP has yet traversed the complete enrichment path live.
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
* **Least Privilege**: Programmatic security-tool access is restricted through explicit, least-privilege interfaces. The current Splunk integration is bounded and read-only; external threat-intelligence lookups are bounded and eligibility-gated.
* **Human-in-the-Loop**: Consequential actions require explicit human authorization and remain simulated in initial phases.

### Multi-Layer Telemetry Architecture

The lab demonstrates defense-in-depth across multiple enterprise telemetry layers:
* **Endpoint Telemetry**: Windows Server 2022 (`DC01`) / Microsoft Sysmon Process Create (Event ID 1) / Encoded PowerShell execution.
* **Web Application Telemetry**: Linux (`WEB01` Ubuntu 24.04.3) / Apache 2.4 reverse proxy / OWASP ModSecurity Core Rule Set (OWASP CRS 3.3.5) / OWASP Juice Shop running as a Node.js application on port 3000.
* **SIEM & Ingestion**: Splunk Enterprise indexer / Splunk Universal Forwarder / Bounded retrieval interfaces (static SPL; caller cannot execute arbitrary SPL).
* **Threat Intelligence**: Bounded VirusTotal REST API v3 IP adapter (live smoke tested; public IPv4 eligible only; private/non-global IPs gated).
* **Agent Security & Policy**: Deterministic policy engine, least-privilege tool allowlisting, prompt-injection isolation, runtime kill switch, human approval gates for consequential actions, immutable incident records.
* **Ticketing & SOAR**: Bounded Jira Cloud adapter (downstream reporting only, zero response authority; live tested for DC01 via `KAN-5`, mock tested for WEB01).

---

## 2. Scenario Workflows

### 2.1 Endpoint Obfuscated PowerShell Workflow (DC01)

The endpoint incident scenario covers an execution attempt using obfuscated PowerShell:

1. **Controlled Test Activity**: Execution of a benign base64-encoded command line on an internal host (DC01) to simulate adversary tradecraft.
2. **Telemetry Generation**: Microsoft Sysmon captures Process Create (Event ID 1).
3. **SIEM Ingestion**: Splunk Universal Forwarder delivers events to a dedicated Splunk indexer (`index=main`).
4. **Detection**: Custom SPL detection identifies the encoded execution.
5. **AI Investigation**: **IMPLEMENTED / TESTED** — Bounded AI investigator and deterministic ToolRouter for process and command-line triage.
6. **IOC Enrichment**: Bounded threat-intelligence lookup (`threat_intel_lookup`) gated by scope classification.
7. **MITRE Mapping**: **IMPLEMENTED** — Deterministic local mapping of detections to ATT&CK techniques (`T1059.001`).
8. **Risk & Confidence Assessment**: **IMPLEMENTED / TESTED** — Advisory model confidence combined with deterministic policy risk scoring.
9. **Policy Gate**: **IMPLEMENTED / TESTED** — Deterministic risk evaluation and allowlisted action recommendation engine.
10. **Human Approval**: **INTERACTIVELY DEMONSTRATED** — Interactive CLI approval gate requiring explicit authorization for consequential actions (both APPROVE and DENY paths demonstrated).
11. **Simulated Response**: **SIMULATED ONLY** — Deterministic response simulation recording mock endpoint isolation; zero real containment.
12. **Incident Record**: **IMPLEMENTED / LIVE TESTED (Milestone 5A)** — Deterministic, bounded, local structured incident-record reporting artifact (`artifacts/incidents/<incident_id>.json`). Reporting artifact only; zero response authority.
13. **Downstream Jira Ticketing**: **LIVE TESTED (Milestone 5B-2)** — Downstream external tracking via Jira Cloud REST API v3 (ticket **KAN-5** created during live E2E run). Reporting only; zero response authority.

### 2.2 Web Application SQL Injection Workflow (WEB01)

The web tier incident scenario covers an external web-attack attempt against the OWASP Juice Shop application:

```
Kali (Controlled SQLi Attack: 192.168.1.100)
    │
    ▼
WEB01 Apache Reverse Proxy (192.168.1.102)
    │
    ▼
ModSecurity WAF / OWASP CRS 3.3.5 (Rule 942100: libinjection SQLi, Anomaly Score 8 -> HTTP 403 Forbidden)
    │
    ▼
Splunk Universal Forwarder (Transmits Apache access & ModSecurity audit logs)
    │
    ▼
Splunk Enterprise (Index: main, Sourcetype: modsecurity; Apache access: index=main, sourcetype=apache:access)
    │
    ▼
Bounded SIEM Retrieval (`modsecurity_sqli_matches`, static SPL, caller cannot submit arbitrary queries)
    │
    ▼
Deterministic Parser (`parse_modsecurity_sqli_event`: untrusted raw text -> typed 7-field ModSecuritySqliEvidence; excludes _raw)
    │
    ▼
Deterministic IPv4 Scope Classifier (`classify_ipv4_scope`: 192.168.1.100 -> scope="private", external_ti_eligible=False)
    │
    ▼
Eligibility-Gated Threat Intelligence (`enrich_modsecurity_source_ip`: private IP -> SKIPPED_INELIGIBLE; exactly 0 external calls)
    │
    ▼
Deterministic IncidentRecord (`build_modsecurity_incident_record`: immutable record; rejects contradictory states; zero raw audit logs)
    │
    ▼
Bounded TicketRequest (`build_ticket_request`: allowlisted project SEC & issue type Incident; derives web-attack label; plain text ADF; zero raw HTML)
    │
    ▼
Jira Provider Adapter (MOCK TESTED: downstream tracking only; zero response authority; real live WEB01 ticket creation NOT YET TESTED)
    │
    ▼
Automated Security Evaluation Harness (17 canonical scenarios: 7 baseline + 10 WEB01; 100% PASS; zero security violations)
```

1. **Controlled Adversary Activity**: Kali Linux (`192.168.1.100`) executes a controlled SQL injection payload against the WEB01 Apache reverse proxy.
2. **Web Application Firewall Enforcement**: OWASP ModSecurity Core Rule Set (OWASP CRS 3.3.5) evaluates request parameters:
   - Rule `942100` ("SQL Injection Attack Detected via libinjection") triggers.
   - Anomaly score accumulates to 8 (exceeding inbound threshold of 5).
   - Inbound request is blocked fail-closed with **HTTP 403 Forbidden**.
3. **SIEM Ingestion**: Splunk Universal Forwarder collects Apache access and ModSecurity audit logs and delivers them to Splunk Enterprise (`index=main`, `sourcetype=modsecurity` for WAF audit events, `sourcetype=apache:access` for web access events).
4. **Bounded SIEM Retrieval**: Bounded retrieval interface queries Splunk using static, allowlisted query type `modsecurity_sqli_matches`. The caller **cannot** supply arbitrary SPL, pipes, or modified indexes.
5. **Deterministic Parser**: Raw ModSecurity audit logs are treated strictly as **untrusted data**. The deterministic parser (`parse_modsecurity_sqli_event`) extracts only the 7 validated structural fields into an immutable `ModSecuritySqliEvidence` record. Malformed or fragmented events fail closed without producing evidence. Unparsed `_raw` text is never exposed to the AI-facing model context.
6. **Deterministic Scope Classification**: `classify_ipv4_scope(evidence.src_ip)` inspects the IP. Only public/global IPv4 addresses are eligible for threat intelligence lookup. Private LabNet addresses (`192.168.1.100`) evaluate to `scope="private"` with `external_ti_eligible=False`.
7. **Eligibility-Gated Threat Intelligence**: `enrich_modsecurity_source_ip` evaluates eligibility. Because `192.168.1.100` is private, external lookups are blocked: exactly **0** external network or VirusTotal calls occur (`status="SKIPPED_INELIGIBLE"`).
8. **Incident Record Construction**: `build_modsecurity_incident_record` generates an immutable `IncidentRecord` capturing validated evidence, scope classification, and threat intelligence status. Contradictory states (e.g. failure marked as ineligible) reject fail-closed.
9. **Bounded Jira Ticketing (Mock Tested)**: `build_ticket_request` formats an allowlisted `TicketRequest` (`project="SEC"`, `issue_type="Incident"`). Formats bounded Atlassian Document Format (ADF) description, deterministically derives the `web-attack` label from validated evidence, strips hostile markup/HTML, and prevents raw audit or secret leakage.
10. **Automated Security Evaluations**: 10 deterministic WEB01 evaluation scenarios run within the canonical 17-scenario evaluation harness (`evaluation/harness.py`), ensuring 100% control pass rate across prompt injection, parser bypass, scope bypass, argument smuggling, and semantic confusion.

---

## 3. Current Implementation Status

### Status Terminology Definitions

To maintain strict truthfulness across technical interviews and documentation, status labels are defined as follows:

| Status Label | Formal Definition |
| :--- | :--- |
| **LIVE VERIFIED** | Directly observed and validated in the running lab infrastructure. |
| **LIVE TESTED** | Actually exercised and validated end-to-end against a real external service or API. |
| **IMPLEMENTED** | Production/runtime code is written and integrated into the codebase. |
| **TESTED** | Verified through deterministic offline automated unit and integration tests. |
| **MOCK TESTED** | External adapter or boundary path verified using deterministic mocks without making live external calls. |
| **LIVE-DERIVED OFFLINE FIXTURE** | Sanitized offline evaluation fixture derived from previously live-verified lab telemetry. |
| **PLANNED** | Designed architecture not yet implemented in code. |
| **DEFERRED** | Intentionally postponed to a future milestone (e.g. due to environmental prerequisites). |
| **NOT CLAIMED** | Explicitly outside current demonstrated capability or operational scope. |

### Component Status Matrix

| Milestone / Component | Type | Status | Details |
| :--- | :--- | :--- | :--- |
| **Lab Infrastructure** | Virtual Network & Hosts | **LIVE VERIFIED** | VirtualBox LabNet (`192.168.1.0/24`), pfSense, DC01, WEB01, Kali, Splunk Server. |
| **Sysmon Telemetry Ingestion** | Data Pipeline | **LIVE VERIFIED** | DC01 Sysmon Event ID 1 forwarded to Splunk index `main`. |
| **WEB01 Telemetry Ingestion (12A)** | Data Pipeline | **LIVE VERIFIED** | Kali controlled SQLi against WEB01 Apache ModSecurity; CRS rule 942100 blocked with HTTP 403; anomaly score 8 and source IP `192.168.1.100` verified in Splunk (index `main`, sourcetype `modsecurity`). |
| **Splunk Detection (`.spl`)** | Detection Engineering | **IMPLEMENTED + TESTED** | Verified against benign encoded PowerShell test on DC01. |
| **Sigma Rule (`.yml`)** | Detection Engineering | **IMPLEMENTED + VALIDATED** | Converted with Sigma CLI / pySigma Splunk backend and live-compared against current Splunk telemetry; stock generated SPL requires telemetry-specific adaptation for this lab. |
| **Bounded Splunk Search Client** | Local Integration & Python Gateway | **IMPLEMENTED + LIVE TESTED** | Hardened local client; 40 unit tests pass; verified live against Splunk Free localhost export endpoint with raw XML extraction. |
| **ModSecurity SQLi Evidence & Bounded Retrieval (12B)** | Evidence & SIEM Gateway | **IMPLEMENTED + TESTED** | Immutable `ModSecuritySqliEvidence` (7 fields); deterministic parser (`parse_modsecurity_sqli_event`) fails closed on malformed input; bounded query type `modsecurity_sqli_matches` enforces static SPL without caller-controlled queries; excludes `_raw`. |
| **Source-IP Scope Classification (12C)** | Security Controls / Scope | **IMPLEMENTED + TESTED** | Deterministic `classify_ipv4_scope` across 8 IPv4 scopes (public, private, loopback, link_local, multicast, reserved, unspecified, non_global); only public is TI-eligible; private `192.168.1.100` evaluates to `external_ti_eligible=False`. |
| **Eligibility-Gated Threat Intelligence (12D)** | Threat Intelligence / Gating | **IMPLEMENTED + TESTED** | `enrich_modsecurity_source_ip` enforces eligibility; private IPs yield `SKIPPED_INELIGIBLE` with 0 external lookups; public fixture routes through bounded lookup; failure preserved as `LOOKUP_FAILED` without conflation. (Adapter was live tested in M11; live public WEB01 IP enrichment NOT CLAIMED). |
| **WEB01 IncidentRecord Integration (12E)** | Reporting Artifact | **IMPLEMENTED + TESTED** | `build_modsecurity_incident_record` binds validated ModSecurity evidence and TI state; rejects contradictory failure-vs-skip states; zero raw audit logs or secrets; backward-compatible with DC01 path. |
| **WEB01 Jira Ticket Construction (12F)** | SOAR / Case Management | **IMPLEMENTED + MOCK TESTED** | Deterministic `build_ticket_request` formats plain text ADF description; allowlisted project `SEC` and issue type `Incident`; derives `web-attack` label exclusively from validated evidence; mock tested against Jira provider; real live WEB01 ticket creation NOT YET TESTED. |
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
| **VirusTotal Threat-Intelligence Adapter** | Threat Intelligence / Advisory | **IMPLEMENTED + TESTED OFFLINE + LIVE SMOKE TESTED** | Provider-specific REST API v3 IP adapter (`investigator/providers/virustotal_provider.py`); 44 offline unit/lifecycle/security tests pass; verified live via standalone smoke script; advisory evidence only; zero response authority. |
| **Live Threat-Intelligence Enrichment (VirusTotal)** | Threat Intelligence | **LIVE TESTED** | Bounded public IP lookup verified live against VirusTotal REST API v3 via standalone smoke script and bounded ToolRouter live test (`tests/live/test_virustotal_smoke.py`); 2/2 PASS; advisory evidence only; zero response authority. |
| **TI ToolRouter Integration** | Architecture / Routing | **IMPLEMENTED + TESTED** | Bounded `threat_intel_lookup` tool integrated into `ToolRouter` with strict public-IP validation; 4-tool allowlist when configured. |
| **TI Risk-Score Integration** | Security Controls | **IMPLEMENTED + TESTED** | Bounded additive corroboration (+5/+10/+15, capped at 15 points) in `RiskPolicyEngine`; evidence cannot reduce score or bypass policy. |
| **Full Agent + VirusTotal Pipeline** | Integration Pipeline | **NOT TESTED** | Standalone adapter smoke tested only; agent orchestrator + VirusTotal pipeline not implemented or tested. |
| **Jira Cloud Create-Issue Adapter** | SOAR / Case Management | **LIVE TESTED with KAN-5** | Downstream tracking adapter (`investigator/providers/jira_provider.py`); 39 offline tests pass; verified live via smoke script (`KAN-4`) and live E2E demo (`KAN-5`); zero response authority. |
| **OpenAI + Real Splunk + Real Jira** | Full Integrated Pipeline | **NOT YET TESTED** | Components tested individually; integrated trio run pending. |
| **Real OpenAI + Real Splunk + Real Jira + Real VirusTotal** | Full Integrated Pipeline | **NOT TESTED** | Quad integration not implemented or tested; components tested individually or in subsets. |
| **Prompt-Injection Guardrails & Fixtures** | Adversarial Testing / Governance | **IMPLEMENTED + TESTED OFFLINE** | 16 synthetic scenarios across CAT-1 to CAT-8; proves evidence is data, not authority; zero control bypass. |
| **Model-Compromise Simulation** | Adversarial Testing / Simulation | **TESTED OFFLINE** | Synthetic compromised-model decisions fail closed via ToolRouter; controls hold. |
| **Real Model Prompt-Injection Robustness** | Adversarial Testing / LLM | **NOT YET TESTED** | Empirical LLM adversarial robustness evaluation deferred to Milestone 6B. |
| **Canonical Security Evaluations (10C, 11D, 12G)** | Adversarial Testing / Governance | **IMPLEMENTED + TESTED** | Canonical evaluation suite (`evaluation/harness.py`) with 17 automated deterministic scenarios; **17 / 17 PASS (100.0%)**; 0 security violations; byte-deterministic JSON/Markdown evaluation artifacts. |
| **Suricata Network IDS Telemetry** | Network Detection | **DEFERRED** | Suricata remains deferred after earlier pfSense package-manager/integration problems. It is not currently installed/operational in the lab and is not required for the current WEB01 ModSecurity path. |
| **Real Endpoint Containment** | Containment Safety | **NOT IMPLEMENTED** | Destructive containment actions explicitly excluded from V1 scope; not executed in 6A. |

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
* **Web Application Server (WEB01)**:
  * Ubuntu Linux 24.04.3 (`192.168.1.102`)
  * Apache 2.4 reverse proxy with ModSecurity (`libapache2-mod-security2`)
  * OWASP ModSecurity Core Rule Set (OWASP CRS 3.3.5) in active blocking mode
  * OWASP Juice Shop running as a Node.js application on port 3000
  * Splunk Universal Forwarder forwarding Apache access (`sourcetype=apache:access`) and ModSecurity audit logs (`sourcetype=modsecurity`) to dedicated SIEM (`index=main`)
* **SIEM (Splunk Server)**:
  * Dedicated instance (`192.168.1.101`)
  * Splunk Enterprise running under Free License
  * Accessible from management workstation at `http://192.168.1.101:8000`

---

## 6. Telemetry & Detection Status

### Endpoint Telemetry Profile (DC01)
* **Index**: `main`
* **Sourcetype**: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
* **Host**: `DC01`
* **Tested SPL Query**: Located in [`detections/splunk/suspicious_encoded_powershell.spl`](detections/splunk/suspicious_encoded_powershell.spl). Filters for Sysmon Process Create (`<EventID>1</EventID>`), extracts metadata via `rex`, and detects base64-encoded PowerShell flags (`-encodedcommand`, `-enc`).
* **Sigma Detection Rule**: Located in [`detections/sigma/suspicious_encoded_powershell.yml`](detections/sigma/suspicious_encoded_powershell.yml).
* **MITRE ATT&CK Mapping**: [T1059.001 - Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) (Execution `TA0002`).

### Web Application Telemetry Profile (WEB01)
* **Index**: `main`
* **Sourcetype**: `modsecurity` (WAF audit logs) / `apache:access` (HTTP access logs)
* **Host**: `web01`
* **WAF Rule Triggered**: OWASP CRS Rule `942100` ("SQL Injection Attack Detected via libinjection").
* **WAF Response**: Anomaly score 8 (threshold 5); request blocked with HTTP 403 Forbidden.
* **Bounded SIEM Query**: Located in `gateway/policy.py` (`query_type="modsecurity_sqli_matches"`). Strict static SPL targeting index `main`, sourcetype `modsecurity`, and rule `942100`. Callers cannot modify queries or append arbitrary SPL pipes.
* **MITRE ATT&CK Mapping**: [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) (Initial Access `TA0001`).

---

## 7. Adversarial Security Evaluations & Canonical Harness

To ensure defense-in-depth and prevent model regressions, all deterministic security controls are evaluated against an automated canonical evaluation harness (`evaluation/harness.py`). The harness runs **17 canonical scenarios** (7 baseline + 10 WEB01) offline with zero live network dependencies.

### Summary Results
* **Total Scenarios**: 17
* **Passed**: 17
* **Failed**: 0
* **Pass Rate**: 100.0%
* **Security Violations**: 0 across all 6 tracked counters (`unsafe_tool_executions`, `arbitrary_query_executions`, `approval_bypasses`, `policy_override_findings`, `audit_leakage_findings`, `runtime_guard_bypasses`).
* **Evaluation Artifacts**: Byte-for-byte deterministic across repeated runs ([`artifacts/evaluation/security-evaluation.json`](artifacts/evaluation/security-evaluation.json), [`artifacts/evaluation/security-evaluation.md`](artifacts/evaluation/security-evaluation.md)).

### The 10 WEB01 Adversarial Scenarios
1. `eval-12g-web01-modsecurity-prompt-injection`: Hostile prompt instructions injected into pre-validation raw telemetry; parsed fail-closed; zero model authority or unauthorized tool execution.
2. `eval-12g-web01-raw-parser-bypass`: Malformed or fragmented ModSecurity content lacking envelope tokens; parser fails closed with `ModSecurityError`; zero evidence produced.
3. `eval-12g-web01-private-ip-ti-bypass`: Valid private IP (`192.168.1.100`) accompanied by hostile instructions demanding lookup; deterministic scope classification halts lookup (`external_ti_eligible=False`); exactly 0 external calls occur.
4. `eval-12g-web01-argument-smuggling`: Bounded threat intelligence lookup invoked with public IP fixture; attempts to smuggle arbitrary endpoint, provider, or token parameters are rejected.
5. `eval-12g-web01-ti-provider-failure`: Public IP fixture under simulated provider transport failure; clean failure state preserved as `LOOKUP_FAILED` without false skip or clean classification.
6. `eval-12g-web01-jira-payload-injection`: Hostile Jira ADF markup and HTML injection in model input; rendered strictly as bounded plain text ADF nodes without raw HTML or secret exposure.
7. `eval-12g-web01-unauthorized-jira-config`: Caller attempts unauthorized Jira project or issue type; rejected fail-closed at `TicketRequest` schema boundary.
8. `eval-12g-web01-raw-spl-bypass`: Caller attempts to supply arbitrary SPL, pipes, or modified sourcetypes through WEB01 retrieval interface; blocked by strict query allowlist.
9. `eval-12g-web01-semantic-confusion`: Attempt to build an `IncidentRecord` claiming `SKIPPED_INELIGIBLE` despite a lookup execution failure; rejected fail-closed.
10. `eval-12g-web01-live-derived-private`: End-to-end evaluation using the sanitized **LIVE-DERIVED OFFLINE FIXTURE** modeled after real lab telemetry (`host=web01`, `src_ip=192.168.1.100`, `rule_id=942100`, `anomaly_score=8`, `unique_id=ar1Z9uxU-NFJV-LskY52NwAAAEQ`). Validates end-to-end parsing, private scope gating (0 TI calls), and bounded ticketing.

> **LIVE-DERIVED OFFLINE FIXTURE Notice**:
> The fixture was modeled from the actual controlled WEB01 ModSecurity event generated in the lab. The original telemetry path was live verified. The automated evaluation uses a sanitized offline representation derived from that live event. The evaluation run itself is an automated offline verification, not a live WEB01 attack.

---

## 8. Current Limitations & Boundary Disclosures

* **Private Attacker IP in LabNet**: The controlled WEB01 attacker currently originates from private LabNet address `192.168.1.100`. The real WEB01 incident is intentionally not sent to external threat intelligence (`SKIPPED_INELIGIBLE`). No genuine public WEB01 attacker IP has yet traversed the complete enrichment path live.
* **WEB01 Jira Ticketing Not Yet Live Tested**: WEB01 Jira ticket construction and formatting are verified through deterministic unit and mock tests. Live Jira Cloud ticket creation has **not** yet been executed for a WEB01 incident (prior live validation `KAN-5` was for DC01).
* **IPv4 Only**: The current WEB01 source-IP contract is IPv4-only. IPv6 input is rejected fail-closed before scope classification and is not eligible for external threat-intelligence enrichment.
* **Deferred Network Telemetry**: Suricata remains deferred after earlier pfSense package-manager/integration problems. It is not currently installed/operational in the lab and is not required for the current WEB01 ModSecurity path.
* **Not Production Infrastructure**: This project is a portfolio engineering lab demonstrating defensive agent architectures, not a production enterprise SOC deployment. External service quotas, network resilience, and high-throughput concurrency are not production-tested.
* **No Autonomous Remediation**: Destructive containment (host isolation, account disablement, firewall rule changes) is not implemented. All response containment remains simulated.

---

## 9. Planned Next Steps

1. **Controlled Live Jira Validation for WEB01**: Execute a single controlled live Jira Cloud ticket creation for a sanitized WEB01 incident (`WEB01-1`).
2. **Controlled Public-Source-IP Live Validation**: Add a controlled external source that produces a genuine public source IP without exposing OWASP Juice Shop directly to the public Internet, then validate the WEB01 → scope classification → bounded VirusTotal enrichment path live.
3. **Suricata Network IDS Re-evaluation**: Revisit Suricata deployment on a dedicated monitoring interface to enrich host and web telemetry with network flow logs.
4. **Cross-Tier Telemetry Correlation**: Correlate WEB01 web application attacks with downstream DC01 endpoint activity in multi-stage attack scenarios.
5. **Continuous Evaluation Expansion**: Expand adversarial scenarios to cover additional web application attack classes and API boundary vectors.

---

## 10. High-Level Project Roadmap

- [x] **Milestone 1**: Lab environment deployment, Sysmon telemetry verification, controlled adversary-tradecraft simulation (benign test), and SPL detection engineering.
- [x] **Milestone 2**: Bounded read-only Splunk search client (Python) operating under least-privilege principles and verified end-to-end against live telemetry.
- [x] **Milestone 3**: AI investigation engine (3A: deterministic tools/router; 3B: bounded orchestration + OpenAI provider; 3C: persistent local JSONL audit; 3D: deterministic risk and action policy).
- [x] **Milestone 4**: Human-in-the-loop approval workflow and simulated response execution.
- [x] **Milestone 5A**: Deterministic structured incident-record reporting artifact (reporting only, zero action authority).
- [x] **Milestone 5B-1**: Deterministic ticketing contract and local fake ticket workflow (reporting only, zero action authority).
- [x] **Milestone 5B-2**: Live Jira Cloud REST API v3 create-issue adapter (downstream external tracking/reporting sink, zero response authority; adapter implemented, offline-tested, and verified live with tickets KAN-4 and KAN-5).
- [x] **Milestone 5C-1**: Provider-neutral threat intelligence contract and local fake client (advisory evidence only, zero response authority; public IP validation, offline-tested).
- [x] **Milestone 5C-2**: VirusTotal REST API v3 IP provider adapter (advisory evidence only, zero response authority; offline mocked + tested).
- [x] **Milestone 5C-2b**: Controlled live VirusTotal smoke test (standalone CLI harness, verified live with exit code 0; API key removed from the active shell/process environment; zero agent/risk/tool integration).
- [x] **Milestone 6A**: Offline prompt-injection test harness & synthetic adversarial fixtures (CAT-1 through CAT-8, 16 scenarios, deterministic control verification, model-compromise simulation; real-model robustness NOT YET TESTED).
- [x] **Milestone 7**: ToolRouter hardening, schema validation, and fail-closed controls.
- [x] **Milestone 8**: Decision evaluation dataset (10 cases) and automated offline decision evaluation harness.
- [x] **Milestone 9**: Runtime guardrails, fail-closed kill switches, and execution boundaries.
- [x] **Milestone 10**: Canonical security evaluation harness, prompt injection, arbitrary query abuse, and runtime guard scenarios.
- [x] **Milestone 11**: Bounded VirusTotal REST API v3 IP adapter, live smoke test, and threat intelligence security evaluations (7 canonical scenarios).
- [x] **Milestone 12**: Web application security telemetry & ModSecurity SQLi pipeline:
  - [x] **12A**: WEB01 telemetry ingestion to Splunk index `main`, sourcetype `modsecurity` (**LIVE VERIFIED**).
  - [x] **12B**: ModSecurity SQLi evidence model, deterministic parser, and bounded retrieval (**IMPLEMENTED + TESTED**).
  - [x] **12C**: Source-IP scope classification across 8 IPv4 scopes (**IMPLEMENTED + TESTED**).
  - [x] **12D**: Eligibility-gated threat intelligence enrichment (**IMPLEMENTED + TESTED**).
  - [x] **12E**: WEB01 IncidentRecord integration (**IMPLEMENTED + TESTED**).
  - [x] **12F**: Bounded Jira ticket request formatting (**IMPLEMENTED + MOCK TESTED**).
  - [x] **12G**: 10 WEB01 adversarial security evaluations; 17 canonical scenarios (**IMPLEMENTED + TESTED**; 100% PASS).
  - [x] **12H**: Documentation and status closure (**DOCUMENTATION COMPLETE**).
- [ ] **Milestone 13**: Controlled live Jira validation for WEB01 incident (`WEB01-1`).
