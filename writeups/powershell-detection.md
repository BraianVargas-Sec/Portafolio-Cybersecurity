# Suspicious PowerShell Detection

## Objective

Detect suspicious PowerShell execution using Sysmon and Wazuh SIEM.

---

## Environment

- Windows Server
- Sysmon
- Wazuh
- Elastic Stack

---

## Attack Simulation

```powershell
powershell -enc SQBFAFgA...
