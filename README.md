# Threat Response Pipeline

A unified threat response pipeline that demonstrates the core functions of a modern Security Operations Center (SOC) through detection, alerting, enrichment, response, logging, and reporting.

## Architecture

The pipeline consists of six integrated layers:

```
Detection → Alerting → Enrichment → Response → Logging → Reporting
```

### 1. Detection Layer
- Simulates osquery and Sysmon log ingestion
- Pattern-based detection rules
- MITRE ATT&CK mapping
- Severity scoring (CRITICAL, HIGH, MEDIUM, LOW)

### 2. Alerting Layer
- Structured alert generation
- Slack webhook notification simulation
- SIEM forwarding (Splunk HEC simulation)
- Escalation workflows

### 3. Enrichment Layer
- VirusTotal API integration simulation
- Threat intelligence caching
- Verdict determination

### 4. Response Layer
- Risk-based action selection
- Automated containment via MDM API simulation
- Human escalation workflows

### 5. Logging Layer
- SQLite database for audit trail
- Event and alert persistence
- Performance metrics collection

### 6. Reporting Layer
- Console reports for operational visibility
- HTML reports for management
- CSV exports for compliance
- JSON exports for SIEM integration

## Features

| Feature | Description |
|---------|-------------|
| Detection Rules | 10+ detection rules mapped to MITRE ATT&CK |
| Risk Scoring | Quantitative risk scoring (0-10 scale) |
| Auto-Containment | Automated device quarantine at risk score ≥ 7.0 |
| Threat Intelligence | Simulated VirusTotal integration with caching |
| SIEM Integration | Splunk HEC and structured output formats |
| Database Logging | Complete audit trail with SQLite |
| Multiple Reports | HTML, JSON, CSV, and console reports |

## Detection Rules Library

| Rule Name | Severity | MITRE Technique | Tactic |
|-----------|----------|-----------------|--------|
| PowerShell Abuse | HIGH | T1059.001 | Execution |
| Local Account Creation | MEDIUM | T1136.001 | Persistence |
| Privilege Escalation | CRITICAL | T1068 | Privilege Escalation |
| Persistence Mechanism | HIGH | T1547 | Persistence |
| Lateral Movement | HIGH | T1021 | Lateral Movement |
| Data Exfiltration | CRITICAL | T1048 | Exfiltration |
| Credential Dumping | CRITICAL | T1003 | Credential Access |
| Command and Control | CRITICAL | T1071 | C2 |
| Defense Evasion | HIGH | T1562 | Defense Evasion |
| Discovery Activity | MEDIUM | T1082 | Discovery |

## Installation

### Prerequisites
- Python 3.6 or higher

### Steps

```bash
git clone https://github.com/berinabraham-sec/threat-response-pipeline.git
cd threat-response-pipeline
python threat_response_pipeline.py
```

## Usage

```bash
python threat_response_pipeline.py
```

### Menu Options

1. Run Pipeline Cycle
2. Generate Reports
3. View Statistics
4. Export for SIEM
5. Run Demo
6. Exit

## Project Structure

```
threat-response-pipeline/
├── threat_response_pipeline.py   # Main application
├── README.md                     # Documentation
├── .gitignore                    # Git ignore file
├── threat_pipeline.db            # SQLite database
└── reports/                      # Generated reports
    ├── pipeline_report_*.html
    ├── pipeline_report_*.csv
    └── pipeline_report_*.json
```

## Risk Scoring Methodology

- **CRITICAL**: Risk score ≥ 8.0, Auto-containment triggered
- **HIGH**: Risk score 6.0 - 7.9, Escalation required
- **MEDIUM**: Risk score 4.0 - 5.9, Monitoring with possible escalation
- **LOW**: Risk score < 4.0, Routine monitoring

## Author

**berinabraham-sec**

GitHub: [berinabraham-sec](https://github.com/berinabraham-sec)

## License

MIT License