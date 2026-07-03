# Sentinel Pulse Mobile Threat Ingestion Workflows

This document outlines the workflows, state transitions, and automated pipeline events triggered when a smartphone threat is ingested.

## Workflow Pipeline Sequence

```mermaid
sequenceDiagram
    autonumber
    actor User as Smartphone User
    participant Web as Web Ingestion Console
    participant AI as AI Scam Analyzer
    participant DB as SQLite Database
    participant SOC as Alert & Notification Pipeline

    User->>Web: Submits threat snippet (Link, SMS, Email)
    Web->>AI: Scans indicators & evaluates heuristics
    alt Indicator has appeared previously
        AI->>DB: Saves to ThreatIntel Blocklist
    end
    AI->>DB: Records MobileSubmission row
    alt Risk Score >= 35 (High/Critical Threat)
        AI->>DB: Instantiates Threat Indicator
        AI->>SOC: Generates Alert & broadcasts Notification
    end
    Web->>User: Displays scan verdict and remediation steps
```

## State Machine: AI Decision Verdicts

- **`ALLOW` (Score 0-19):** Safe indicator. No alerts are generated.
- **`QUARANTINE` (Score 20-34):** Low-risk anomaly. Saved for inspection.
- **`WARN` (Score 35-59):** Medium-risk warning. Triggers Threat/Alert creation.
- **`BLOCK` (Score 60-79):** High-risk malware or scam. Immediate alert generated.
- **`ESCALATE` (Score 80-100):** Critical campaign. Immediately alerts SOC and dispatches notification.
