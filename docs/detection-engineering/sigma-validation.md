# Sigma Validation — Suspicious Encoded PowerShell

## Status

IMPLEMENTED + VALIDATED WITH SIGMA TOOLING + LIVE COMPARED AGAINST SPLUNK

## Objective

Validate the existing Sigma representation of the encoded-PowerShell detection using real Sigma tooling, convert it to Splunk SPL, and compare the generated query with the live-tested Splunk implementation used by the lab.

## Detection

Sigma rule:

`detections/sigma/suspicious_encoded_powershell.yml`

Operational Splunk rule:

`detections/splunk/suspicious_encoded_powershell.spl`

MITRE ATT&CK:

T1059.001 — Command and Scripting Interpreter: PowerShell

## Sigma Toolchain

Validation environment:

- Python 3.12.4
- sigma-cli 3.1.0
- pySigma 1.5.1
- pysigma-backend-splunk 2.1.0
- isolated virtual environment: `.venv-sigma/`

The Sigma tooling is used only for detection-development and validation. It is not part of the AI investigator runtime dependency set.

## Sigma Rule Semantics

The Sigma rule detects:

- Windows process creation
- `Image` ending with `\powershell.exe`
- `CommandLine` containing either:
  - ` -EncodedCommand `
  - ` -enc `

The rule maps to MITRE ATT&CK T1059.001.

## Conversion Results

The rule was converted using Sigma CLI with three configurations.

### No Processing Pipeline

Command:

```text
sigma convert -t splunk --without-pipeline detections\sigma\suspicious_encoded_powershell.yml
```

Generated query:

```spl
Image="*\\powershell.exe" CommandLine IN ("* -EncodedCommand *", "* -enc *")
```

### Splunk Windows Pipeline

Command:

```text
sigma convert -t splunk -p splunk_windows detections\sigma\suspicious_encoded_powershell.yml
```

Generated query:

```spl
Image="*\\powershell.exe" CommandLine IN ("* -EncodedCommand *", "* -enc *")
```

### Splunk Sysmon Acceleration Pipeline

Command:

```text
sigma convert -t splunk -p splunk_sysmon_acceleration detections\sigma\suspicious_encoded_powershell.yml
```

Generated query:

```spl
Image="*\\powershell.exe" CommandLine IN ("* -EncodedCommand *", "* -enc *")
```

All three conversions produced the same detection expression.

## Telemetry Difference Identified

The generated Sigma query assumes that `Image` and `CommandLine` already exist as searchable Splunk fields.

The current lab ingests Sysmon events using:
- index: `main`
- sourcetype: `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- host: `DC01`

In this environment, event-specific Sysmon XML values such as `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, and `User` are not automatically exposed as top-level searchable fields.

The operational SPL therefore performs deterministic extraction from `_raw` using `rex`.

## Live A/B Validation

A fresh controlled encoded-PowerShell event was generated on DC01.

Controlled payload:

```powershell
Write-Host 'AI-NativeSOC-LAB-TEST'
```

The PowerShell process used `-EncodedCommand` and produced the expected benign output.

### Test A — Sigma-Generated Query

The generated field-level query was executed against:

```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
Image="*\\powershell.exe"
CommandLine IN ("* -EncodedCommand *", "* -enc *")
```

Result:

```text
0 events
```

### Test B — Operational Lab SPL

The live-tested repository SPL was executed against the same 15-minute window.

Result:

```text
1 event
```

Observed event:
- `_time`: 2026-09-28 07:16:38.071
- `host`: DC01
- `user`: SOCLAB\Administrator
- `image`: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- `command line` contained `-NoProfile -EncodedCommand`

## Engineering Conclusion

The Sigma rule correctly expresses the intended encoded-PowerShell detection semantics and converts successfully using current Sigma tooling.

However, the stock generated Splunk query is not operationally equivalent to the live-tested lab SPL because the lab's current Sysmon ingestion does not expose the required event fields as top-level Splunk fields.

The operational lab SPL therefore includes telemetry-specific adaptation:
- explicit index and sourcetype scoping
- Sysmon Event ID 1 filtering
- `_raw` XML extraction
- case-insensitive PowerShell image matching
- bounded encoded-command argument matching

This demonstrates the difference between vendor-neutral detection logic and SIEM-specific operational implementation.

## Current Design Decision

For Version 1:
- Sigma remains the portable detection-intent artifact.
- The handcrafted SPL remains the authoritative operational implementation for the current lab telemetry.
- Generated Sigma-to-Splunk output is retained as portability/reference evidence.
- A custom pySigma processing pipeline is not implemented at this stage because it would add complexity without materially improving the single-scenario V1 demonstration.

## Limitations

- Only the current encoded-PowerShell scenario has been validated this way.
- The Sigma rule currently covers `powershell.exe`, `-EncodedCommand`, and `-enc`.
- Additional PowerShell abbreviation, obfuscation, and evasion variants are not claimed.
- No CIM-normalized Splunk data model is currently used.
- No custom pySigma processing pipeline is implemented.
- Sigma translation equivalence is not claimed across other SIEM products.

## Truthful Status

- Sigma rule: IMPLEMENTED
- Sigma CLI validation/conversion: TESTED
- Splunk backend conversion: TESTED
- Live comparison against current Splunk telemetry: TESTED
- Operational equivalence of stock generated SPL: NOT ACHIEVED
- Telemetry-specific SPL adaptation: IMPLEMENTED + LIVE TESTED
- Custom pySigma pipeline: NOT IMPLEMENTED
