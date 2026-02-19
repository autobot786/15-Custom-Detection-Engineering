#  Custom Detection Engineering

<div align="center">

**Production-ready SIEM detection rules, response playbooks, and automation scaffolding for modern Security Operations Centers**

[![License](https://img.shields.io/badge/License-Other-blue.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT&CK-v14-red.svg)](https://attack.mitre.org/)
[![Sigma Rules](https://img.shields.io/badge/Sigma-15%20Rules-orange.svg)](sigma/)
[![Platform Support](https://img.shields.io/badge/Platform-Splunk%20%7C%20Sentinel%20%7C%20Elastic-green.svg)](platform/)

</div>

---

##  Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Detection Coverage](#-detection-coverage)
- [Repository Structure](#-repository-structure)
- [Quick Start](#-quick-start)
- [Detection Rules](#-detection-rules)
- [Playbooks & Response](#-playbooks--response)
- [SIEM/SOAR Integration](#-siemsoar-integration)
- [Metrics & Impact](#-metrics--impact)
- [Documentation](#-documentation)
- [Contributing](#-contributing)
- [Version History](#-version-history)

---

##  Overview

This repository provides **15 enterprise-grade detection rules** covering critical threat scenarios, from credential abuse to ransomware indicators. Built for **Detection Engineers**, **SOC Analysts**, and **Incident Responders**, this project includes:

✅ **Vendor-agnostic Sigma rules** (Splunk SPL, Microsoft Sentinel KQL, Elastic EQL)  
✅ **Incident response playbooks** (Markdown + Jupyter notebooks)  
✅ **SIEM/SOAR automation scaffolding** (Sentinel Logic Apps, Splunk SOAR, Elastic actions)  
✅ **Real-world tuning guidance** and metrics templates  
✅ **MITRE ATT&CK mapping** for threat coverage validation

> **Perfect for portfolios, SOC modernization, or testing detection pipelines with synthetic data.**

---

##  Key Features

| Feature | Description |
|---------|-------------|
|  **15 High-Fidelity Detections** | Covering authentication abuse, lateral movement, exfiltration, and defense evasion |
|  **Multi-Platform Support** | Native queries for Splunk, Microsoft Sentinel, and Elastic Security |
|  **Ready-to-Use Playbooks** | Markdown guides + interactive Jupyter notebooks with investigation queries |
|  **SOAR Scaffolding** | Pre-built Logic App workflows, Splunk SOAR playbooks, and webhook templates |
|  **SOC Lab Environment** | Mock data generators for safe testing without production impact |
|  **Metrics Templates** | Track MTTA, MTTR, false positives, and detection precision |
|  **MITRE ATT&CK Aligned** | Full technique mapping from T1078 (Valid Accounts) to T1567 (Exfiltration) |

---

##  Detection Coverage

### MITRE ATT&CK Techniques

This project covers **15 distinct MITRE ATT&CK techniques** across multiple tactics:

<table>
<tr>
<td width="50%">

**Initial Access & Persistence**
- T1078 - Valid Accounts (Impossible Travel)
- T1133 - External Remote Services (VPN)
- T1136 - Create Account (Rapid Admin Creation)

**Privilege Escalation**
- T1098 - Account Manipulation
- T1078.003 - Local Accounts

**Defense Evasion**
- T1562.001 - Disable Security Tools
- T1059.001 - PowerShell Encoded Commands

</td>
<td width="50%">

**Credential Access**
- T1621 - Multi-Factor Authentication Request Generation

**Lateral Movement**
- T1021.002 - SMB/Windows Admin Shares

**Exfiltration**
- T1567 - Exfiltration to Cloud Storage
- T1114 - Email Collection (Forwarding Rules)

**Impact**
- T1486 - Data Encrypted for Impact (Ransomware)

</td>
</tr>
</table>

[ Full MITRE Mapping Table →](docs/mitre_mapping.md)

---

##  Repository Structure

```plaintext
Custom-Detection-Engineering/
│
├──  sigma/                                    # Sigma detection rules
│   ├── README.md                               # Sigma rules overview
│   └── rules/
│       └── custom_detection_rules.yml          # 15 vendor-agnostic Sigma rules
│
├──  platform/                                 # Platform-specific SIEM queries
│   ├── splunk/                                 # Splunk SPL queries
│   ├── sentinel/                               # Microsoft Sentinel KQL queries
│   └── elastic/                                # Elastic Security EQL/KQL queries
│
├──  playbooks/                                # Incident response playbooks
│   ├── 01_impossible_travel.md                # Quick-reference Markdown guides
│   ├── 02_mfa_fatigue_attack.md
│   ├── ...                                     # (15 total playbooks)
│   └── custom-detection-engineering_jupyter_playbooks/
│       ├── 01_impossible_travel_privileged.ipynb
│       ├── ...                                 # Interactive Jupyter notebooks with queries
│       └── 15_dormant_user_sensitive_access.ipynb
│
├──  siem_soar_scaffolding_pack/              # SIEM/SOAR automation scaffolding
│   ├── README.md                               # Integration guide
│   ├── sentinel_logic_app/                     # Microsoft Sentinel Logic Apps
│   │   ├── playbook_actions.json
│   │   └── workflow_definition_template.json
│   ├── splunk_soar/                            # Splunk SOAR (Phantom) playbooks
│   │   ├── playbook_scaffold.py
│   │   └── playbook_metadata.json
│   └── elastic_actions/                        # Elastic Security rule actions
│       ├── rule_actions_examples.json
│       └── webhook_payload_templates.json
│
├──  custom-detection-engineering_soc_labs_with_mock_data/
│   ├── README.md                               # Lab setup instructions
│   ├── mock_data_generators/                   # Python scripts to generate test events
│   │   ├── generate_auth_events.py
│   │   ├── generate_process_events.py
│   │   └── ...
│   └── screenshots/                            # Synthetic SIEM alert screenshots
│
├──  docs/                                     # Documentation
│   ├── data_sources.md                         # Required log sources & enrichment
│   ├── tuning_guidelines.md                    # Allowlists, thresholds, baselines
│   ├── mitre_mapping.md                        # MITRE ATT&CK technique mapping
│   └── metrics.md                              # Metrics template (MTTA/MTTR/FP rate)
│
├──  assets/                                   # Images, diagrams, badges
│
├── README.md                                    # This file
├── CHANGELOG.md                                 # Version history
├── LICENSE                                      # License information
└── .gitignore                                   # Git ignore rules
```

---

##  Quick Start

### 1️ Clone the Repository

```bash
git clone https://github.com/autobot786/Custom-Detection-Engineering.git
cd Custom-Detection-Engineering
```

### 2️ Choose Your Platform

Navigate to the platform-specific directory:

```bash
# For Splunk
cd platform/splunk/

# For Microsoft Sentinel
cd platform/sentinel/

# For Elastic Security
cd platform/elastic/
```

### 3️ Deploy Detection Rules

- **Sigma Rules**: Convert using `sigmac` or platform-specific converters
- **Platform Queries**: Import directly into your SIEM
- **Playbooks**: Reference during incident response

### 4️ Test with Mock Data (Optional)

```bash
cd custom-detection-engineering_soc_labs_with_mock_data/mock_data_generators/
python generate_auth_events.py --output sample_auth.json
```

### 5️ Integrate SOAR (Optional)

Follow the guides in `siem_soar_scaffolding_pack/` to deploy:
- **Sentinel Logic Apps** for automated containment
- **Splunk SOAR playbooks** for orchestrated response
- **Elastic rule actions** for webhook-based automation

---

##  Detection Rules

### Summary Table

| # | Detection Name | MITRE Technique | Severity | Data Sources |
|---|----------------|-----------------|----------|--------------|
| 1 | Impossible Travel (Privileged Accounts) | T1078 | High | Authentication logs, GeoIP |
| 2 | MFA Fatigue Attack | T1621 | High | Authentication logs |
| 3 | PowerShell Encoded Command Execution | T1059.001 | Medium | Process creation (Sysmon, EDR) |
| 4 | Service Account Interactive Login | T1078.003 | Medium | Authentication logs |
| 5 | Privileged Role Assignment Outside Change Window | T1098 | High | IAM audit logs |
| 6 | Suspicious Scheduled Task Creation | T1053 | Medium | Windows Event Logs, Sysmon |
| 7 | Ransomware Behavior Indicators | T1486 | Critical | File system events, EDR |
| 8 | Cloud Storage Exfiltration Spike | T1567 | High | Proxy logs, DLP/CASB |
| 9 | Security Tool Tampering (AV/EDR Disabled) | T1562.001 | Critical | Service control events |
| 10 | SMB Lateral Movement Burst | T1021.002 | High | Network logs, SMB traffic |
| 11 | New Admin Account Created Quickly | T1136 | High | IAM audit logs |
| 12 | DNS Queries to Newly Registered Domains | T1071.004 | Medium | DNS logs, threat intel |
| 13 | External Email Forwarding Rule (BEC) | T1114 | High | Email audit logs (M365) |
| 14 | VPN Access from Non-Compliant Device | T1133 | Medium | VPN logs, device compliance |
| 15 | Dormant User Accessing Sensitive Resources | T1087 | Medium | Authentication, file access logs |

[ View All Sigma Rules →](sigma/rules/)

---

##  Playbooks & Response

Each detection has **two playbook formats**:

###  Markdown Guides (Quick Reference)

One-page summaries with:
- **Triage steps** (context gathering, validation)
- **Containment actions** (account/session isolation, host isolation)
- **Eradication & Recovery** (credential rotation, persistence removal)
- **Lessons Learned** (tuning recommendations)

**Example**: [Playbook 01 - Impossible Travel →](playbooks/01_impossible_travel.md)

###  Jupyter Notebooks (Interactive Investigation)

Executable notebooks with:
- **Triage checklists**
- **Investigation queries** (KQL, SPL, EQL)
- **Containment commands** (PowerShell, MDE, Azure AD)
- **Placeholder examples** (replace `<USER>`, `<HOST>`, etc.)

**Example**: [Jupyter Playbook 07 - Ransomware →](playbooks/custom-detection-engineering_jupyter_playbooks/07_ransomware_behavior_indicator.ipynb)

[ Browse All Playbooks →](playbooks/)

---

##  SIEM/SOAR Integration

### Microsoft Sentinel

- **Logic App workflows** for automated response
- **Webhook payload examples** for alert ingestion
- **KQL queries** for hunting and analytics rules

[ Sentinel Integration Guide →](siem_soar_scaffolding_pack/sentinel_logic_app/)

### Splunk SOAR (Phantom)

- **Python playbook scaffolds** for custom actions
- **Metadata templates** for app integration
- **SPL correlation searches**

[ Splunk SOAR Guide →](siem_soar_scaffolding_pack/splunk_soar/)

### Elastic Security

- **Rule action examples** (webhook, index, email)
- **NDJSON rule snippets** for detection rules
- **EQL/KQL query templates**

[ Elastic Integration Guide →](siem_soar_scaffolding_pack/elastic_actions/)

>  **Important**: Replace placeholders (`<TENANT_ID>`, `<WEBHOOK_URL>`, etc.) with your environment values before deployment.

---

##  Metrics & Impact

### What to Track

Use the [metrics template](docs/metrics.md) to measure detection effectiveness:

| Metric | Description | Target |
|--------|-------------|--------|
| **MTTA** (Mean Time to Acknowledge) | How quickly alerts are triaged | < 15 min |
| **MTTR** (Mean Time to Respond) | End-to-end incident resolution | < 2 hours (P1) |
| **False Positive Rate** | Alerts requiring tuning vs. legitimate | < 10% |
| **Detection Precision** | True positives / total alerts | > 70% |
| **Playbook Adoption** | % of incidents using standardized playbooks | > 80% |

### Example Results (Replace with Your Data)

> _"Reduced false positives by **38%** after implementing VPN egress allowlists and baselining admin tooling."_
> _"Improved MTTR by **22%** using standardized containment steps for account compromise scenarios."_

[ Full Metrics Template →](docs/metrics.md)

---

##  Documentation

| Document | Purpose |
|----------|---------|
| [Data Sources](docs/data_sources.md) | Required log sources and enrichment (GeoIP, domain age, etc.) |
| [Tuning Guidelines](docs/tuning_guidelines.md) | How to reduce false positives (allowlists, thresholds, baselines) |
| [MITRE Mapping](docs/mitre_mapping.md) | Complete ATT&CK technique coverage table |
| [Metrics Template](docs/metrics.md) | Track alert volume, MTTA, MTTR, and precision |

---

##  Contributing

Contributions are welcome! Please:

1. **Fork** this repository
2. **Create a feature branch** (`git checkout -b feature/new-detection`)
3. **Commit your changes** (`git commit -m 'Add new detection for X'`)
4. **Push to the branch** (`git push origin feature/new-detection`)
5. **Open a Pull Request**

### Contribution Ideas

- Add new detection rules (Sigma format preferred)
- Improve playbook response steps
- Add platform-specific queries (QRadar, Chronicle, etc.)
- Contribute mock data generators
- Improve documentation

---

##  Version History

### v1.1.0 (Latest)
✅ Added complete SIEM queries (Splunk/Sentinel/Elastic) for all 15 detections  
✅ Added metrics template and synthetic SIEM screenshots  
✅ Enhanced SOAR scaffolding with webhook payloads

### v1.0.0
 Initial release: 15 Sigma detections + response playbooks

[ Full Changelog →](CHANGELOG.md)

---

##  License

This project is licensed under the **Other** license. See [LICENSE](LICENSE) for details.

---

##  Acknowledgments

Built with insights from:
- **MITRE ATT&CK Framework** (threat modeling)
- **Sigma Project** (vendor-agnostic detection rules)
- **Detection Engineering community** (best practices)

---

##  Contact

**Author**: [@autobot786](https://github.com/autobot786)

For questions, feedback, or collaboration opportunities, please open an issue or reach out via GitHub.

---

<div align="center">

** Star this repository if you find it useful!**

[![GitHub stars](https://img.shields.io/github/stars/autobot786/Custom-Detection-Engineering?style=social)](https://github.com/autobot786/Custom-Detection-Engineering/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/autobot786/Custom-Detection-Engineering?style=social)](https://github.com/autobot786/Custom-Detection-Engineering/network/members)

Made with  for the Security Operations Community

</div>
