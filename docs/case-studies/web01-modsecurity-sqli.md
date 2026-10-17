# DET-WEB-001 — ModSecurity SQL Injection Attempt

## 1. Executive Summary

This case study documents the web application detection engineering, telemetry ingestion, AI-assisted advisory investigation, deterministic threat-intelligence gating, and downstream ticketing governance for **`DET-WEB-001`** (ModSecurity SQL Injection Attempt).

SQL injection (SQLi) against public-facing web applications remains one of the most critical enterprise threat vectors, mapped to MITRE ATT&CK **`T1190`** (Exploit Public-Facing Application). Successful exploitation can lead to unauthorized data exfiltration, database takeover, and server compromise. However, high-volume web application firewalls (WAFs) frequently detect automated scanners and malicious probes that are actively blocked at the edge and never succeed.

The objective of this implementation was to:
1. Ingest Linux web application security telemetry from `WEB01` (Apache reverse proxy with OWASP ModSecurity Core Rule Set CRS 3.3.5 protecting an OWASP Juice Shop application).
2. Author bounded programmatic SIEM retrieval and deterministic 7-field parsing that normalizes WAF transactions without ingesting arbitrary raw logs.
3. Enforce strict, privacy-preserving threat-intelligence scope gating: evaluate source IPs across 8 IPv4 scopes to ensure private internal addresses are never disclosed to third-party threat-intelligence providers.
4. Execute an AI-assisted advisory investigation constrained strictly to bounded tool calls and immutable evidence parsing.
5. Demonstrate downstream Atlassian Document Format (ADF) ticketing in Jira Cloud while strictly preserving that ticketing carries zero response authority and real endpoint containment remains completely unimplemented.

> **Operational Scope Notice**: This case study documents controlled detection and automated triage in an isolated virtualized lab environment (`LabNet`). Detecting blocked SQL injection behavior does **not** prove host compromise, web application breach, or database exfiltration. In the verified lab exercise, the malicious probe was actively blocked at the WAF tier with **HTTP 403 Forbidden**.

---

## 2. Web Detection Engineering

### 2.1 Web Tier Architecture & ModSecurity Ingestion
The lab incorporates cross-platform telemetry by pairing Windows Active Directory endpoint logs (`DC01`) with Linux web server telemetry (`WEB01`):
* **Host Platform**: Ubuntu 24.04.3 LTS (`WEB01` at `192.168.1.20`, interface `enp0s3`)
> **Live Interface Verification**: Re-verified directly on the active WEB01 VM (`ifconfig enp0s3`) confirming IPv4 `192.168.1.20`, netmask `255.255.255.0`, broadcast `192.168.1.255`. Stale documentation references to `192.168.1.102` have been corrected.
* **Web Server**: Apache 2.4 HTTP Server configured as a reverse proxy
* **Protected Application**: OWASP Juice Shop running as a Node.js service on port 3000
* **WAF Engine**: ModSecurity v2.9 / OWASP ModSecurity Core Rule Set (CRS 3.3.5) in blocking mode
* **SIEM Forwarder**: Splunk Universal Forwarder transmitting ModSecurity audit logs to `Splunk-Server` (`index=main`, `sourcetype=modsecurity`) and Apache access logs (`sourcetype=apache:access`)

### 2.2 Authoritative ModSecurity Detection Rule
The attack was detected natively by OWASP CRS Rule **`942100`**:
* **Rule ID**: `942100`
* **Rule Message**: `SQL Injection Attack Detected via libinjection`
* **Severity**: `CRITICAL`
* **Anomaly Scoring**: Inbound anomaly score accumulated to `8` (exceeding the standard CRS blocking threshold of `5`)
* **WAF Disposition**: Request blocked with **HTTP 403 Forbidden**

### 2.3 Artifact Architecture: Programmatic vs. Static Detection
Unlike endpoint detections (`DET-POWERSHELL-001`, `DET-POWERSHELL-002`, `DET-TASK-001`) which utilize standalone `.spl` and `.yml` files in `detections/`:
* `DET-WEB-001` is implemented **natively** through web-tier ModSecurity CRS rules (`942100`), gateway query policy ([`gateway/policy.py`](../../gateway/policy.py)), and bounded programmatic retrieval ([`gateway/splunk_search.py`](../../gateway/splunk_search.py)).
* There is no standalone `.spl` or `.yml` file for `DET-WEB-001` in the repository; the query construction and parameter boundaries are defined in [`gateway/policy.py`](../../gateway/policy.py) (`build_bounded_splunk_query`) and executed via [`gateway/splunk_search.py`](../../gateway/splunk_search.py) under query type `query_type="modsecurity_sqli_matches"`.

### 2.4 Normalized Evidence Contract (`ModSecuritySqliEvidence`)
To isolate the control plane and AI investigator from raw, unparsed log transactions, telemetry is parsed into an immutable, frozen Python dataclass ([`investigator/modsecurity.py`](../../investigator/modsecurity.py)) with 7 strictly validated fields:

| Field Name | Type | Validation & Boundary Rules |
| :--- | :--- | :--- |
| `host` | `str` | Must be a non-empty string matching validated inventory (`web01`). |
| `src_ip` | `str` | Strict IPv4 validation using Python `ipaddress`; CIDR and URI schemes rejected. |
| `rule_id` | `int` | Strictly allowlisted to CRS Rule `942100`. |
| `rule_msg` | `str` | Strictly allowlisted to `"SQL Injection Attack Detected via libinjection"`. |
| `severity` | `str` | Allowlisted to `CRITICAL`, `ERROR`, `WARNING`, or `NOTICE`. |
| `anomaly_score` | `int` | Must be a positive integer $\ge 1$. |
| `unique_id` | `str` | Unique transaction ID matching Apache ModSecurity format; `"-"` rejected. |

*(Raw event text `_raw` is deliberately stripped and excluded from the returned evidence to prevent prompt injection and log bloat).*

---

## 3. Controlled Live Web Attack Fixture

To validate telemetry ingestion, SIEM forwarding, and automated investigation without exposing external infrastructure or sensitive data, a controlled SQL injection probe was generated inside the virtualized `LabNet`.

### 3.1 Live Telemetry Generation
* **Attacker System**: Kali Linux VM (`192.168.1.100`)
* **Target System**: Apache reverse proxy on `WEB01` (`192.168.1.20:80`)
* **Target Application**: OWASP Juice Shop (`http://192.168.1.20:3000`)
* **Attack Method**: Controlled HTTP request containing SQL injection syntax designed to trigger `libinjection` within ModSecurity CRS 3.3.5.
* **WAF Response**: ModSecurity intercepted the probe, logged rule `942100`, assigned an anomaly score of `8`, and returned **HTTP 403 Forbidden**.

### 3.2 Validated Ingested Splunk Event
Forwarded by the Splunk Universal Forwarder and verified in Splunk Enterprise (`index=main`, `sourcetype=modsecurity`):

```json
{
  "host": "web01",
  "src_ip": "192.168.1.100",
  "rule_id": 942100,
  "rule_msg": "SQL Injection Attack Detected via libinjection",
  "severity": "CRITICAL",
  "anomaly_score": 8,
  "unique_id": "ar1Z9uxU-NFJV-LskY52NwAAAEQ",
  "http_status": 403,
  "detection_id": "DET-WEB-001",
  "mitre_technique_id": "T1190"
}
```

### 3.3 Safety & Non-Compromise Invariants
* **Zero Host Compromise**: The request was blocked at the reverse proxy layer before reaching application backend logic.
* **No Sensitive Data**: Telemetry contains only lab network metadata and standard Juice Shop testing endpoints.
* **No Outbound Leakage**: Attack traffic remained entirely contained within the host-only VirtualBox network `LabNet` (`192.168.1.0/24`).

---

## 4. Detection & Investigation Pipeline

The incident is processed across distinct trust boundaries:

```
[ Kali Attacker (192.168.1.100) ]
  │  (Controlled SQLi probe: HTTP GET /rest/products/search?q=' OR 1=1--)
  ▼
[ WEB01 Apache 2.4 + ModSecurity CRS 3.3.5 ]
  │  (Rule 942100 triggered, Anomaly Score 8, Blocked with HTTP 403)
  ▼
[ Splunk Universal Forwarder -> Splunk Enterprise (index=main) ]
  │
  ▼
[ Bounded Search Client (query_type="modsecurity_sqli_matches") ]
  │  (Bounded SPL in gateway/policy.py targeting Rule 942100 / libinjection; caller-supplied SPL rejected)
  ▼
[ Deterministic Parser (parse_modsecurity_sqli_event) ]
  │  (Extracts 7 strict fields -> ModSecuritySqliEvidence; strips _raw)
  ▼
[ Deterministic Source IP Scope Classification (classify_ipv4_scope) ]
  │  (192.168.1.100 classified as RFC 1918 private -> external_ti_eligible=False)
  ▼
[ Threat Intelligence Scope Gate (enrich_modsecurity_source_ip) ]
  │  (Lookup bypassed -> SKIPPED_INELIGIBLE; ZERO external VirusTotal calls)
  ▼
[ AI Advisory Investigation (Web01InvestigationRequest -> Web01InvestigationAssessment) ]
  │  (OpenAI gpt-5.6-sol or ScriptedModel; bounded_splunk_search only; advisory only)
  ▼
[ Deterministic Incident Record Construction (build_modsecurity_incident_record) ]
  │  (Binds evidence, MITRE T1190, score=80, HIGH, HUMAN_REVIEW)
  ▼
[ Append-Style JSONL Audit Logger (agent_audit.jsonl) ]
  │  (Logs full ordered lifecycle with strict field allowlist)
  ▼
[ Downstream Jira Cloud Adapter (build_ticket_request) ]
     (Creates ticket KAN-8; verified hardened ADF layout in KAN-9; zero response authority)
```

### Architectural Guarantees:
* **Untrusted Content Boundary**: Raw HTTP URIs, headers, and SQL injection strings are treated strictly as inert data and isolated from system command execution.
* **Model Cannot Authorize Actions**: The AI model evaluates WAF context and generates hypotheses, but has zero authority over risk scoring, ticketing destination, or containment.
* **Downstream Reporting Only**: Jira Cloud acts solely as a tracking sink.

---

## 5. Threat-Intelligence Enrichment & Private-IP Gating

A critical defensive control demonstrated in this case study is **deterministic source-IP scope classification**. Enterprise SOC automation must never blindly send internal IP addresses to public SaaS threat-intelligence providers.

### 5.1 Deterministic IPv4 Scope Classification
Implemented in [`investigator/modsecurity_enrichment.py`](../../investigator/modsecurity_enrichment.py) using the Python standard library `ipaddress`. The classifier evaluates all incoming addresses against 8 mutually exclusive scopes:

| IPv4 Scope | Address Range / Definition | External TI Eligible? | Handled In Lab |
| :--- | :--- | :--- | :--- |
| **`public`** | Globally routable unicast IPv4 (`!is_private`, `!is_loopback`, etc.) | **`True`** | Synthetic `8.8.8.8` fixture (Milestone 13F-3) |
| **`private`** | RFC 1918 addresses (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) | **`False`** | Real lab attacker `192.168.1.100` |
| **`loopback`** | `127.0.0.0/8` | **`False`** | Localhost services |
| **`link_local`**| `169.254.0.0/16` (RFC 3927) | **`False`** | Unconfigured interfaces |
| **`multicast`** | `224.0.0.0/4` (RFC 5771) | **`False`** | Multicast streams |
| **`reserved`**  | `240.0.0.0/4` (RFC 1112) | **`False`** | Reserved space |
| **`unspecified`**| `0.0.0.0` | **`False`** | Default routing targets |
| **`non_global`**| Carrier-grade NAT (RFC 6598), benchmarking, testnets | **`False`** | CGNAT / test networks |

### 5.2 The Semantic Tri-State Model
Threat intelligence lookups evaluate to one of three strictly enforced states:
1. **`SKIPPED_INELIGIBLE`**: For non-public IPs (such as `192.168.1.100`). The lookup is completely bypassed. Returns `ModSecurityEnrichmentResult(enriched=False, skip_reason="ineligible_scope:private")` with **exactly zero external API calls**.
2. **`ENRICHED`**: For valid public IPs. A bounded lookup is executed via `ToolRouter` and `RuntimeGuard`, returning a normalized `ThreatIntelObservation`.
3. **`LOOKUP_FAILED`**: For eligible public IPs where the external provider fails (e.g. timeout or HTTP 500). Fails closed without fabricating benign observations or converting failures into skips.

---

## 6. Live Validation Runs

To maintain rigorous technical truthfulness, **separate live validation runs are documented individually**. The repository does not merge these exercises into a fictional single simultaneous run.

### 6.1 Live WEB01 Detection Validation (Milestone 12A)
Exercised during Milestone 12A to validate physical telemetry forwarding from Linux to Splunk:
* **Attack Source**: Kali Linux VM (`192.168.1.100`)
* **Detection Rule**: ModSecurity CRS Rule `942100`
* **WAF Action**: Intercepted and blocked with **HTTP 403 Forbidden**
* **Splunk Ingestion**: Successfully delivered to `index=main`, `sourcetype=modsecurity`
* **Evidence Extraction**: Deterministic parser verified all 7 fields matching transaction `ar1Z9uxU-NFJV-LskY52NwAAAEQ`
* **TI Scope Decision**: `192.168.1.100` evaluated to `SKIPPED_INELIGIBLE` (0 external calls)
* **Containment Execution**: Zero containment action taken

### 6.2 Live OpenAI Advisory Investigation (Milestone 13F-1)
Exercised during Milestone 13F-1 to validate live model decision loops against WAF evidence:
* **Test Suite**: [`tests/live/test_web01_openai_live.py`](../../tests/live/test_web01_openai_live.py)
* **Model Used**: OpenAI API `gpt-5.6-sol` via the OpenAI Responses API
* **Evidence Provided**: Normalized 7-field `ModSecuritySqliEvidence` (zero raw transaction logs)
* **Model Tool Calling**: Restricted strictly to `bounded_splunk_search` (zero arbitrary SPL)
* **Assessment Output**: Produced structured `Web01InvestigationAssessment` correctly identifying SQL injection technique `T1190`
* **Policy Invariant**: The AI assessment remained strictly advisory; it possessed zero authority to mutate risk scores or authorize remediation
* **Containment Execution**: None (`NOT IMPLEMENTED / NOT EXECUTED`)

### 6.3 Live Jira Cloud Ticketing & Hardened ADF Rendering (Milestone 13F-2)
Exercised during Milestone 13F-2 to validate downstream tracking and prevent stored XSS:
* **Target Project / Type**: Bounded routing to Project `KAN`, Issue Type `Incident`
* **Live Incident Ticket**: Created real Jira Cloud ticket **`KAN-8`**
* **Hardened Atlassian Document Format (ADF) Live Verification**: Visually inspected and verified under ticket **`KAN-9`**
* **ADF Structural Enforcements**:
  * Headings rendered as level-2 headers (`heading` level 2).
  * Field lines rendered as bullet lists (`bulletList`).
  * Untrusted payload fragments isolated inside inert code blocks (`codeBlock`).
  * Zero raw HTML, Markdown links, mentions, or arbitrary wiki formatting emitted.
* **Authority Invariant**: Ticket creation acts strictly as an external tracking sink with zero authority over policy or response execution

### 6.4 Controlled Live Threat-Intelligence Validation (Milestone 13F-3)
Exercised during Milestone 13F-3 to validate external VirusTotal REST API v3 enrichment:
* **Test Suite**: [`tests/live/test_web01_threat_intel_live.py`](../../tests/live/test_web01_threat_intel_live.py)
* **Controlled Synthetic Public IP**: `8.8.8.8` (used strictly as a sanitized test fixture; **does not represent actual attacker traffic**)
* **Execution Bounds**:
  * Mocked Splunk telemetry
  * Deterministic `ScriptedModel` (zero OpenAI calls)
  * Exactly one live VirusTotal REST API v3 lookup (`GET /api/v3/ip_addresses/8.8.8.8`)
  * Zero Jira tickets created
  * Zero containment actions
* **Outcome**: Verified that `RuntimeGuard` permitted the lookup within its execution budget, `ToolRouter` validated the public IP, VirusTotal returned HTTP 200, and the incident record was created with `threat_intel_status="ENRICHED"`

---

## 7. Deterministic Policy & Authority Boundary

The triage outcome for `DET-WEB-001` is governed exclusively by deterministic Python logic in [`investigator/incident_record.py`](../../investigator/incident_record.py) and [`investigator/policy.py`](../../investigator/policy.py).

### 7.1 Authoritative Web Incident Record Construction
When `build_modsecurity_incident_record` executes:
* **Detection ID**: Bound deterministically to `"DET-WEB-001"`
* **Detection Name**: `"ModSecurity SQL Injection Attack (Rule 942100)"`
* **Target Host**: `"web01"`
* **Target User**: `"www-data"`
* **MITRE ATT&CK Mapping**: Hardcoded to `"T1190"` (Exploit Public-Facing Application)
* **Deterministic Risk Score**: Fixed at `80 / 100` (`CRITICAL` severity + WAF rule match)
* **Risk Level**: `"HIGH"`
* **Action Disposition**: `ActionDisposition.HUMAN_REVIEW`
* **Proposed Action**: `ProposedAction.REQUEST_HUMAN_REVIEW`
* **Human Approval Required**: `False` (reporting and human review do not require approval gates; approval is reserved for consequential containment)
* **Simulation Status**: `SimulationStatus.NOT_EXECUTED` (`"simulation_not_required"`)

### 7.2 Threat-Intelligence Corroboration Bounds
* **Additive Only**: Positive threat-intelligence reputation can corroborate an incident by adding +5, +10, or +15 points to the risk score (capped at 15 points total).
* **Cannot Lower Risk**: A clean or benign reputation verdict from VirusTotal cannot reduce the base risk score or cancel a WAF alert.
* **Cannot Override Policy**: A threat intelligence lookup cannot alter the action disposition from `HUMAN_REVIEW` to `NO_ACTION`.

---

## 8. Security Controls Demonstrated

| Security Control | Implementation Mechanism | Defensive Purpose |
| :--- | :--- | :--- |
| **Web-Tier WAF Enforcement** | Apache ModSecurity CRS Rule `942100`. | Blocks SQL injection attempts at the perimeter with HTTP 403. |
| **Bounded Splunk Retrieval** | Static query type `modsecurity_sqli_matches` built in `gateway/policy.py` and executed via `gateway/splunk_search.py`. | Prevents arbitrary SPL authoring and injection into the SIEM. |
| **Strict Event Parsing** | Deterministic parser `parse_modsecurity_sqli_event` in `investigator/modsecurity.py`. | Validates all 7 transaction fields and strips raw event bodies (`_raw`). |
| **Untrusted Content Boundary** | Telemetry treated strictly as inert data. | Protects the AI investigator from prompt injection embedded in HTTP payloads. |
| **Deterministic IP Scope Gating** | `classify_ipv4_scope` in `investigator/modsecurity_enrichment.py`. | Prevents disclosure of private internal network IPs to public TI providers. |
| **Tool Allowlisting** | Static allowlist enforced by `ToolRouter`. | Restricts the investigator model strictly to allowlisted search and lookup tools. |
| **Hardened Jira ADF Rendering** | Structured ADF builder in `investigator/providers/jira_provider.py`. | Prevents stored XSS and markup injection in downstream ticketing consoles. |
| **Audit Logging Lifecycle** | Append-only JSONL logger with strict 4-field allowlisting. | Captures an immutable record of all investigative actions and decisions. |
| **Simulated Response Boundary** | `investigator/simulated_response.py`. | Guarantees zero real host isolation, firewall modification, or system mutation. |

---

## 9. Testing & Validation Evidence

The `DET-WEB-001` pipeline is validated across automated unit tests, adversarial evaluation suites, and live environment exercises.

### 9.1 Evidence Classification Matrix

| Component / Test Suite | Primary File | Scope & Result | Operational Status |
| :--- | :--- | :--- | :--- |
| **ModSecurity Parser Tests** | `tests/test_modsecurity_parser.py` | 15 unit tests verifying field validation, IP checks, and fail-closed syntax errors. | **TESTED OFFLINE** |
| **Source IP Scope Tests** | `tests/test_source_ip_scope.py` | 20 unit tests verifying 8 IPv4 scopes and private IP gating. | **TESTED OFFLINE** |
| **TI Enrichment Tests** | `tests/test_modsecurity_ti_enrichment.py` | 18 unit tests verifying the `SKIPPED_INELIGIBLE`, `ENRICHED`, and `LOOKUP_FAILED` tri-state model. | **TESTED OFFLINE** |
| **WEB01 Incident Record Tests** | `tests/test_web01_incident_record.py` | 14 unit tests verifying immutable dataclass binding and contradictory state rejection. | **TESTED OFFLINE** |
| **WEB01 Jira Integration Tests** | `tests/test_web01_jira_integration.py` | 16 unit tests verifying ADF formatting, `web-attack` label derivation, and error handling. | **TESTED OFFLINE** |
| **WEB01 Adversarial Evaluations** | `tests/test_web01_security_evaluations.py` | 10 deterministic adversarial scenarios in `evaluation/scenarios.py`; 10/10 PASS (0 violations). | **TESTED OFFLINE** |
| **Repository Evaluation Harness** | `evaluation/harness.py` | **21 / 21 PASS (100%)** across canonical security evaluation scenarios. | **TESTED OFFLINE** |
| **Live WAF Telemetry Ingestion** | WEB01 Apache ModSecurity forwarder | Verified real HTTP 403 SQLi event delivered to Splunk `index=main`. | **LIVE LAB VALIDATED** |
| **Live OpenAI Advisory Path** | `tests/live/test_web01_openai_live.py` | Verified live model triage loop using `gpt-5.6-sol`. | **LIVE TESTED** |
| **Live Jira Ticket Creation** | `tests/live/test_web01_jira_live.py` | Created real Jira Cloud incident ticket `KAN-8`. | **LIVE TESTED** |
| **Hardened Jira ADF Verification** | Visual inspection in Jira Cloud | Inspected and verified inert structured ADF formatting in ticket `KAN-9`. | **LIVE VERIFIED** |
| **Controlled Public TI Lookup** | `tests/live/test_web01_threat_intel_live.py` | Executed 1 live VirusTotal REST API v3 lookup with synthetic fixture `8.8.8.8`. | **LIVE TESTED** |
| **Private IP Threat Intel Gating** | Real lab telemetry (`192.168.1.100`) | Gated before external lookup; evaluated to `SKIPPED_INELIGIBLE` (0 external calls). | **LIVE LAB VALIDATED** |
| **Consequential Action Containment** | `investigator/simulated_response.py` | Real host containment explicitly excluded; response actions strictly simulated. | **NOT IMPLEMENTED / NOT EXECUTED** |

---

## 10. Interview Takeaways

When discussing this case study with security engineering interviewers, this implementation demonstrates:

1. **Cross-Platform Defense-in-Depth**: Integrated enterprise Linux web application security telemetry (Apache, ModSecurity CRS 3.3.5, OWASP Juice Shop) alongside Windows Server Active Directory Sysmon telemetry into a unified investigation control plane.
2. **Defensive Data Normalization**: Engineered strict, fail-closed parsers that normalize raw WAF logs into immutable 7-field evidence dataclasses, deliberately excluding raw logs to prevent prompt injection and token bloat.
3. **Data Privacy & Threat-Intelligence Gating**: Enforced deterministic IPv4 scope classification across 8 address types, ensuring private RFC 1918 internal addresses are never leaked to external threat intelligence providers.
4. **Advisory LLM Safety Boundaries**: Bounded the AI model strictly to an advisory investigation role with schema validation and read-only tool permissions, ensuring the LLM cannot authorize actions, author arbitrary SPL, or alter risk scoring.
5. **Deterministic Policy Precedence**: Established authoritative Python policy engines that calculate risk scores and action dispositions independently of model suggestions.
6. **Injection-Proof External Integration**: Designed a hardened Atlassian Document Format (ADF) generator for Jira Cloud that isolates untrusted decoded evidence inside inert code blocks and strips executable markup to prevent stored XSS.
7. **Transparent Engineering Truthfulness**: Accurately separated individual live test runs (OpenAI, Jira `KAN-8`/`KAN-9`, synthetic VirusTotal `8.8.8.8`) rather than fabricating a simultaneous end-to-end live pipeline.

---

## 11. Limitations & Explicit Non-Claims

To ensure complete technical integrity across interviews and documentation:
* **Detection Does Not Prove Exploitation**: Detecting a SQL injection attempt in WAF logs does not prove that the web application was breached. The controlled probe was blocked at the perimeter with **HTTP 403 Forbidden**.
* **Isolated Lab Environment**: `WEB01` and OWASP Juice Shop run inside an isolated VirtualBox host-only network (`LabNet`). No live Internet traffic or production systems were targeted.
* **No Customer or Production Data**: The database and application contain exclusively synthetic demonstration fixtures.
* **Private IP Non-Disclosure**: Real lab attack traffic originating from private address `192.168.1.100` was never queried against public threat intelligence APIs. Public TI lookups were validated exclusively with sanitized synthetic fixtures (`8.8.8.8`).
* **No Real Endpoint Containment**: The system contains no execution primitives to modify iptables, disable web application accounts, or isolate network adapters. All response actions remain strictly simulated (`SIMULATED`).
* **No Autonomous Remediation**: The AI investigator does not autonomously block IP addresses or alter firewall configurations.
* **Separate Live Validation Pipelines**: Live OpenAI investigation, Jira ticket creation (`KAN-8`/`KAN-9`), and VirusTotal public IP enrichment were executed as separate live test exercises. They were not executed simultaneously in a single live pipeline.
* **No Production SOC Scale Claim**: The pipeline was evaluated against discrete synthetic fixtures and controlled single-incident attacks; it is not benchmarked for high-concurrency enterprise web traffic.
