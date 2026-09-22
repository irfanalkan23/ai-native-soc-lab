# Case Study: Encoded PowerShell Detection to Jira

## Objective

This case study documents the end-to-end validation of a controlled Security Operations Center (SOC) pipeline in an isolated lab environment. The objective was to validate the complete workflow from endpoint telemetry generation through bounded SIEM investigation, deterministic governance, persistent audit artifacts, and downstream Jira ticketing, while demonstrating strict security boundaries where AI is restricted to an advisory role and all containment actions remain simulated.

---

## Architecture Path

### Primary Telemetry, Investigation & Ticketing Flow

```
+------------------------------------------------------------+
|                          DC01                              |
|   (Controlled Benign Encoded PowerShell Test Execution)    |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|                  Microsoft Sysmon (Event ID 1)             |
|                 (Process Create Raw XML Logs)              |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|                Splunk Universal Forwarder                  |
|                 (Forwarded via port 9997)                  |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|                      Splunk Server                         |
|         (XmlWinEventLog:Microsoft-Windows-Sysmon)          |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|               Bounded Python Investigation                 |
|       (localhost:8089 REST Export, Raw XML Regex)          |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|              Deterministic Decoding & MITRE                |
|      (UTF-16LE Base64 Decoding -> T1059.001 Mapping)       |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|            Deterministic Risk & Policy Engine              |
|        (Rule-based 0-100 Scoring, Action Governance)       |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|                 Persistent Local Artifacts                 |
|      (JSONL Audit Trail + Structured IncidentRecord)       |
+------------------------------------------------------------+
                             │
                             ▼
+------------------------------------------------------------+
|                     Jira Cloud API                         |
|        (Downstream Reporting Only - Ticket KAN-5)          |
+------------------------------------------------------------+
```

### Action Governance & Human Approval Branch

```
               Deterministic Policy Evaluation
                             │
                             ▼
                 Is Approval Required?
                    │                 │
             NO     │                 │   YES
        ┌───────────┘                 └───────────┐
        ▼                                         ▼
   NO_ACTION /                              Interactive
     MONITOR                               Human Review
 (e.g. Benign Test)                      (CLI Approve/Deny)
                                           │            │
                                  DENY     │            │    APPROVE
                              ┌────────────┘            └────────────┐
                              ▼                                      ▼
                        NOT_EXECUTED                             SIMULATED
                 (simulation_blocked_denied)           (simulated_endpoint_isolation)
                              │                                      │
                              ▼                                      ▼
                        Zero Endpoint                          Zero Endpoint
                           Mutation                               Mutation
                     (Logged to Audit)                     (Logged to Audit)
```

---

## Scenario 1 — Live Benign End-to-End Validation

### Context & Telemetry
A controlled, benign test command was executed on the Windows Domain Controller (`DC01`):
```powershell
powershell.exe -NoProfile -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcAQQBJAC0ATgBhAHQAaQB2AGUAUwBPAEMALQBMAEEAQgAtAFQARQBTAFQAJwA=
```
This payload decoded to:
```text
Write-Host 'AI-NativeSOC-LAB-TEST'
```

Sysmon on `DC01` generated Event ID 1 (Process Create). The event was forwarded by the Splunk Universal Forwarder to the dedicated Splunk indexer.

### Real vs. Advisory/Simulated Components
* **Real Components**:
  * Real Windows Server 2022 domain controller (`DC01`).
  * Real Sysmon operational event log ingestion.
  * Real Splunk indexer running under Splunk Free.
  * Real bounded Python REST search client against `https://localhost:8089`.
  * Real local Base64 UTF-16LE decoder.
  * Real deterministic MITRE mapper (`T1059.001`).
  * Real deterministic risk policy evaluation.
  * Real append-only JSONL audit persistence (`artifacts/audit/agent_audit.jsonl`).
  * Real structured incident record file creation (`artifacts/incidents/INC-LIVE-DC01-20260922T165326031TUTC.json`).
  * Real Jira Cloud REST API v3 create-issue call creating ticket **KAN-5**.
* **Advisory / Simulated Components**:
  * AI investigator agent was configured with `FakeModel` (zero live LLM API calls).
  * No endpoint containment actions were executed or attempted.

### Outcome & Governance
1. The bounded search query retrieved **1 real event** matching the Sysmon Event ID 1 criteria within the lookback window.
2. The decoder extracted the exact string `Write-Host 'AI-NativeSOC-LAB-TEST'`.
3. The deterministic policy engine evaluated the trusted benign lab conjunction:
   * `verified_detection_id == "DET-POWERSHELL-001"`
   * `deterministic_decoded_command == "Write-Host 'AI-NativeSOC-LAB-TEST'"`
   * Complete evidence without tool failures.
4. **Policy Decision**:
   * Risk Score: `0 / 100` (`LOW`)
   * Disposition: `NO_ACTION`
   * Proposed Action: `no_action`
   * Approval Required: `False`
   * Reason: `benign_lab_fixture_matched`
5. **Approval Gate**: Correctly **skipped** because no consequential response action was proposed.
6. **Ticketing**: Dispatched downstream to Jira Cloud, creating ticket **KAN-5** with detail code `ticket_created_jira`.

---

## Scenario 2 — Human Approval DENY

### Context & Synthetic Threat Scenario
To validate the safety boundary when a high-risk adversary execution is detected, the pipeline was executed in synthetic-critical mode (`INC-DEMO-CRIT-2026-001`) using a sanitized local synthetic fixture simulating malicious encoded PowerShell activity.

### Governance & Decision Flow
1. **Evidence Evaluation**:
   * Encoded PowerShell detected on target host.
   * Decoded command contained suspicious indicators.
   * Deterministic scoring evaluated the evidence to **Score: 80 / 100 (`CRITICAL`)**.
2. **Policy Decision**:
   * Disposition: `APPROVAL_REQUIRED`
   * Proposed Action: `simulate_endpoint_isolation`
   * Requires Human Approval: `True`
3. **Interactive Human Gate**:
   The interactive CLI prompt presented the alert details, risk score, and proposed action:
   ```text
   Action: simulate_endpoint_isolation
   Approve action? [approve/deny]: deny
   ```
   The operator entered `deny`.
4. **Outcome**:
   * Approval Decision: `DENIED` (`approval_denied`)
   * Simulation Status: `NOT_EXECUTED` (`simulation_blocked_denied`)
   * Endpoint Action: **Zero endpoint action executed**.

### Audit Sequence
The audit log captured the exact fail-closed lifecycle:
```text
Seq 10: POLICY_EVALUATED
Seq 11: APPROVAL_REQUIRED
Seq 12: APPROVAL_REQUESTED
Seq 13: APPROVAL_DENIED
Seq 14: SIMULATION_NOT_EXECUTED
```

---

## Scenario 3 — Human Approval APPROVE

### Context & Execution
Using the same synthetic critical scenario (`INC-DEMO-CRIT-2026-001`), the interactive human gate was exercised with an affirmative response.

### Governance & Decision Flow
1. **Interactive Human Gate**:
   ```text
   Action: simulate_endpoint_isolation
   Approve action? [approve/deny]: approve
   ```
   The operator entered `approve`.
2. **Outcome**:
   * Approval Decision: `APPROVED` (`approval_granted`)
   * Simulation Status: `SIMULATED` (`simulated_endpoint_isolation`)
   * Endpoint Action: **Simulated only**. The simulation engine recorded that an isolation request was authorized; **no actual network disconnect, firewall rule, or host isolation occurred**. Endpoint state remained completely unchanged.

### Audit Sequence
```text
Seq 10: POLICY_EVALUATED
Seq 11: APPROVAL_REQUIRED
Seq 12: APPROVAL_REQUESTED
Seq 13: APPROVAL_GRANTED
Seq 14: SIMULATION_COMPLETED
```

### IncidentRecord Overwrite Protection Observation
During this validation sequence:
* The DENY run persisted `artifacts/incidents/INC-DEMO-CRIT-2026-001.json`.
* When the subsequent APPROVE run was executed with `--write-incident`, the persistence engine correctly **failed closed** because the file already existed, preventing silent overwrites of prior incident records.
* The APPROVE demonstration was re-executed cleanly without `--write-incident`, preserving the original DENY audit and incident record intact.

---

## Security Controls Demonstrated

1. **Least-Privilege SIEM Boundary**:
   * The Python gateway connects strictly to `https://localhost:8089/services/search/jobs/export`.
   * Queries are bounded by fixed temporal windows (1–60 minutes), fixed limits (1–50 results), and an explicit host allowlist (`DC01`).
   * No arbitrary SPL input, no remote API exposure, and no administrative endpoint access.
2. **Tool Allowlisting & Input Sanitization**:
   * The `ToolRouter` dispatches only to allowlisted local functions.
   * Telemetry fields are treated strictly as untrusted text and never executed as code or shell commands.
3. **Deterministic Governance Over AI**:
   * LLMs propose hypotheses and summaries only.
   * Risk scoring (0–100), thresholds, and action policies are evaluated deterministically in Python code.
4. **Human-in-the-Loop Gate for Consequential Actions**:
   * Any action with containment potential (`SIMULATE_ENDPOINT_ISOLATION`) mandates interactive human approval.
   * If approval is denied, timed out, or unconfirmed, the system fails closed (`NOT_EXECUTED`).
5. **Downstream-Only Ticketing Authority**:
   * Jira Cloud integration is strictly a reporting sink.
   * Ticket creation does not require human approval and possesses zero authority over containment or policy.
6. **Simulated Response Safety**:
   * All containment actions in Version 1 are simulated. Zero destructive shell commands or host modifications are possible.
7. **Append-Only / No-Overwrite Local Persistence**:
   * Audit events are appended to local JSONL with strict schema validation.
   * IncidentRecord uses atomic/no-overwrite persistence; existing incident files fail closed rather than being silently overwritten.
   * Local persistence is NOT claimed to be cryptographically tamper-evident or tamper-proof.
8. **Ephemeral Credential Lifecycle**:
   * API tokens were injected via process environment variables only.
   * Jira credential environment variables were unset from the active shell/process environment after testing.
   * Temporary API tokens were revoked through the Atlassian account API-token management page after validation and never stored in files or Git.

---

## What Was Real

* **DC01 Endpoint Execution**: Real Windows Server 2022 Active Directory Domain Controller running benign encoded PowerShell.
* **Telemetry Forwarding**: Real Microsoft Sysmon Service forwarding Event ID 1 through Splunk Universal Forwarder.
* **SIEM Indexing & Retrieval**: Real Splunk Enterprise instance (Free License) ingesting logs and serving bounded REST search queries.
* **Telemetry Parsing**: Real regex extraction of raw Sysmon XML attributes and Base64 decoding.
* **MITRE ATT&CK Mapping**: Real mapping to Technique `T1059.001`.
* **Deterministic Policy**: Real rule-based risk evaluation and action gating.
* **Audit Persistence**: Real local JSONL audit trail recording every state transition.
* **Incident Record Persistence**: Real local structured JSON incident record generation.
* **Jira Cloud Issue**: Real issue **KAN-5** created in live Atlassian Jira Cloud via REST API v3.

---

## What Was Simulated / Synthetic

* **High-Risk Adversary Activity**: Evaluated using local synthetic fixtures (`INC-DEMO-CRIT-2026-001`) rather than executing actual malware on domain controllers.
* **Endpoint Isolation**: Simulated only (`SIMULATED` vs `NOT_EXECUTED`). Zero host network disconnection or process termination occurred.
* **AI Provider in Live E2E Run**: The live Splunk-to-Jira validation was executed using `FakeModel` (deterministic test fixture) to isolate infrastructure behavior from model nondeterminism.

---

## Not Yet Demonstrated

* **Integrated Multi-Service Run**: OpenAI Responses API + real Splunk + real Jira Cloud in a single combined execution.
* **Real Endpoint Containment**: Live host isolation or automated firewall rule manipulation (intentionally excluded from V1 scope).
* **External Threat Intelligence**: Dynamic IOC lookups against VirusTotal, AbuseIPDB, or AlienVault OTX.
* **Adversarial Robustness Evaluation**: Systematic automated prompt injection benchmarks against the agent orchestrator (scheduled for Milestone 6).
* **SOC Analyst UI**: Dedicated web frontend or analyst dashboard.

---

## Interview Talking Points

1. **Deterministic Controls Over Agent Autonomy**:
   "We intentionally separated reasoning from authority. The LLM can hypothesize about an alert, but it cannot make policy decisions, assign final risk scores, or trigger containment. Those boundaries are enforced in deterministic Python code."
2. **Engineering for Real SIEM Constraints**:
   "During live testing on Windows Server with Sysmon and Splunk Free, we found that Sysmon fields were not pre-extracted from raw XML. Instead of weakening our query allowlist to let arbitrary queries run, we updated our bounded query generator to extract attributes directly from raw XML while preserving strict detection bounds."
3. **Downstream Reporting vs. Consequential Actions**:
   "Jira ticketing is treated as an external reporting sink, not an action authority. Creating a ticket does not require human approval because it has no containment effect. Conversely, host isolation—even in simulation—strictly requires human approval."
4. **Fail-Closed Architecture**:
   "Every integration point fails closed. If Splunk returns unexpected fields, if the decoder encounters invalid bytes, if incident JSON already exists, or if the human denies approval, the pipeline halts or falls back to human review without executing unauthorized actions."
5. **Honest Scope Demarcation**:
   "We clearly demarcate what is live tested versus simulated. Telemetry ingestion, SIEM search, decoding, policy, and Jira ticketing were tested live. Host containment was strictly simulated to maintain safety in an isolated engineering environment."
