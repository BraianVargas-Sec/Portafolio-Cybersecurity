# Wazuh SIEM Lab

This project focuses on building and configuring a Security Information and Event Management (SIEM) environment using Wazuh.

---

## Objectives

- Centralized log monitoring
- Threat detection
- Security event correlation
- Windows event analysis
- Sysmon integration
- MITRE ATT&CK mapping
- Incident visibility
- Security monitoring automation

---

## Lab Architecture

```text
Windows Server
│
├── Sysmon
├── Winlogbeat
└── Active Directory

Wazuh Server
│
├── Wazuh Manager
├── Elastic Stack
└── Kibana Dashboard

Kali Linux
│
└── Attack Simulation
