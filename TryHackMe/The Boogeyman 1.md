# Challenge: Boogeyman 1

**Platform:** TryHackMe  
**Path:** SOC Level 1  
**Status:** Completed

---

# Objective

Investigate a phishing attack against a finance employee and reconstruct the attack chain from the initial malicious email to endpoint compromise and data exfiltration.

The investigation uses:

- Email analysis
- PowerShell logs
- Windows endpoint artifacts
- Wireshark / Tshark
- PCAP analysis
- DNS traffic analysis

---

# Attack Scenario

The victim, Julianne, is a finance employee who receives an email pretending to be related to an unpaid invoice.

The attachment is malicious and leads to the compromise of the workstation.

The investigation follows the attacker through:

```text
Phishing Email
      ↓
Malicious LNK
      ↓
PowerShell Execution
      ↓
C2 Communication
      ↓
Credential / Data Discovery
      ↓
Data Exfiltration
```

---

# 1. Email Analysis

The first step was analysing the phishing email (`dump.eml`).

Important things to investigate:

- Sender address
- Email headers
- Attachment
- Domain
- Attachment type

The attachment was disguised as an invoice but contained a malicious `.lnk` file.

The LNK file can be analysed using:

```bash
lnkparse <file>
```

This helps reveal information such as the command executed by the shortcut.

### Key Finding

The phishing email was the initial access vector.

The attacker used a malicious shortcut file to execute commands on the victim's workstation.

---

# 2. Endpoint Investigation

The provided PowerShell logs were analysed using `jq`.

Format the JSON logs:

```bash
cat powershell.json | jq
```

View available fields:

```bash
jq -r 'keys[]' powershell.json | sort | uniq
```

Sort events by timestamp:

```bash
cat powershell.json | jq -s -c 'sort_by(.Timestamp) | .[]'
```

The investigation revealed suspicious PowerShell activity originating from the malicious attachment.

The PowerShell commands helped identify:

- Attacker activity
- Commands executed
- Downloaded tools
- C2 communication
- Data discovery

---

# 3. Network Traffic Analysis

The PCAP file was investigated using Wireshark/Tshark.

Main objectives:

- Identify attacker infrastructure
- Identify C2 communication
- Understand attacker activity
- Identify data exfiltration

A suspicious external domain was identified as part of the attack infrastructure.

Network traffic showed communication between the compromised workstation and the attacker's infrastructure.

---

# 4. Data Exfiltration

One of the most important findings was that the attacker used **DNS traffic for data exfiltration**.

The attacker encoded data and transferred it through DNS queries.

This is suspicious because DNS is normally used for name resolution rather than transferring sensitive information.

A useful Tshark command is:

```bash
tshark -r capture.pcapng -Y 'dns' -T fields -e dns.qry.name
```

The suspicious domain can then be filtered:

```bash
grep ".bpakcaging.xyz"
```

The extracted DNS data can then be reconstructed and decoded.

---

# 5. Important Investigation Concepts

## Phishing

The attacker used a convincing invoice-themed email to trick the victim into opening a malicious attachment.

## LNK Abuse

The `.lnk` file was used as an execution mechanism to launch malicious commands.

## PowerShell

PowerShell was used to execute commands and perform attacker activity on the compromised workstation.

## C2 Communication

The compromised machine communicated with attacker-controlled infrastructure.

## DNS Exfiltration

The attacker abused DNS queries to exfiltrate encoded data from the environment.

---

# Attack Chain

The complete attack can be summarised as:

```text
Phishing Email
      ↓
Malicious Invoice Attachment
      ↓
LNK File Execution
      ↓
PowerShell
      ↓
C2 Communication
      ↓
Host / Data Discovery
      ↓
Data Collection
      ↓
DNS Exfiltration
```

---

# SOC Analyst Perspective

The important lesson from this challenge is that a SOC analyst should not investigate each artifact separately.

Instead, correlate everything:

```text
Email
  ↓
Endpoint Logs
  ↓
PowerShell
  ↓
Network Traffic
  ↓
C2
  ↓
Exfiltration
```

Each artifact provides another piece of the attack story.

The combination of email analysis, endpoint telemetry, and network traffic allowed the complete attack chain to be reconstructed.

---

# Key Takeaways

- Phishing emails can be used as an initial access vector.
- LNK files can be abused to execute malicious commands.
- PowerShell logs are valuable for investigating endpoint activity.
- PCAP analysis can reveal C2 communication.
- DNS can be abused for data exfiltration.
- Correlating multiple sources is more effective than analysing a single log.
- Always follow the evidence and build the attack timeline step by step.
