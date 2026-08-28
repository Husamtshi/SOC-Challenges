# Challenge: Boogeyman 2

**Platform:** TryHackMe  
**Path:** SOC Level 1  
**Status:** Completed

---

# Objective

Investigate a spear-phishing attack against an HR employee and reconstruct the compromise using email analysis, malicious Office macro analysis, and Windows memory forensics with Volatility.

The investigation covers:

- Phishing email analysis
- Malicious Word document
- VBA macro analysis
- Stage 2 payload
- Process analysis
- C2 communication
- File analysis
- Scheduled task persistence

---

# Attack Scenario

The Boogeyman returns with a new attack against Quick Logistics LLC.

This time, the attacker targets **Maxine Beck**, a Human Resources employee, using a malicious resume disguised as a job application.

The attack chain can be summarised as:

```text
Spear Phishing Email
        ↓
Malicious Word Document
        ↓
VBA Macro Execution
        ↓
Stage 2 Payload
        ↓
Malicious Binary
        ↓
C2 Communication
        ↓
Scheduled Task Persistence
```

---

# 1. Phishing Email Analysis

The investigation starts with the phishing email located in the `Artefacts` directory.

The email reveals the sender, victim, and malicious attachment.

### Findings

**Attacker email:**

```text
westaylor23@outlook.com
```

**Victim email:**

```text
maxine.beck@quicklogisticsorg.onmicrosoft.com
```

**Malicious attachment:**

```text
Resume_WesleyTaylor.doc
```

The resume was disguised as a legitimate job application but contained malicious VBA macros.

---

# 2. File Hash Analysis

The MD5 hash of the malicious document can be calculated with:

```bash
md5sum Resume_WesleyTaylor.doc
```

Result:

```text
52c4384a0b9e248b95804352ebec6c5b
```

This hash can be used as an IOC when investigating the file across other systems.

---

# 3. VBA Macro Analysis

The malicious Word document contains an `AutoOpen` macro.

We can analyse the macros using `olevba`:

```bash
olevba Resume_WesleyTaylor.doc
```

The macro performs several suspicious actions:

- Downloads a remote file.
- Saves it as `update.js`.
- Executes it using `wscript.exe`.

The stage 2 download URL is:

```text
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png
```

Although the downloaded file uses a `.png` extension, the macro saves it as:

```text
C:\ProgramData\update.js
```

It then executes:

```text
wscript.exe C:\ProgramData\update.js
```

This demonstrates how attackers can disguise malicious payloads and abuse legitimate Windows components.

---

# 4. Memory Analysis with Volatility

The next stage of the investigation uses the Windows memory dump.

Volatility can be used to identify processes and their relationships.

Example:

```bash
vol -f WKSTN-2961.raw windows.psscan.PsScan
```

Searching for the process that executed the stage 2 payload:

```bash
vol -f WKSTN-2961.raw windows.psscan.PsScan | grep "wscript.exe"
```

### Findings

Stage 2 was executed by:

```text
wscript.exe
```

PID:

```text
4260
```

Parent PID:

```text
1124
```

The stage 2 payload was:

```text
C:\ProgramData\update.js
```

---

# 5. Downloading the Malicious Binary

The stage 2 payload downloads another malicious binary.

Because the memory dump contains useful strings, we can search it using:

```bash
strings WKSTN-2961.raw | grep "files.boogeymanisback.lol"
```

The malicious binary was downloaded from:

```text
https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.exe
```

This represents the next stage of the attack.

---

# 6. Malicious Process and C2

The process tree can be investigated using:

```bash
vol -f WKSTN-2961.raw windows.pstree.PsTree
```

The malicious process associated with the stage 2 process was:

```text
updater.exe
```

PID:

```text
6216
```

The command line can be investigated with:

```bash
vol -f WKSTN-2961.raw windows.cmdline.CmdLine --pid 6216
```

The malicious binary was located at:

```text
C:\Windows\Tasks\updater.exe
```

---

# 7. C2 Connection

Network connections can be investigated with:

```bash
vol -f WKSTN-2961.raw windows.netscan.NetScan
```

Filtering for the malicious PID:

```bash
vol -f WKSTN-2961.raw windows.netscan.NetScan | grep "6216"
```

The malicious process established a C2 connection to:

```text
128.199.95.189:8080
```

This confirms that the malware was communicating with attacker-controlled infrastructure.

---

# 8. Locate the Malicious Attachment in Memory

Volatility's `filescan` plugin can search memory for file objects:

```bash
vol -f WKSTN-2961.raw windows.filescan.FileScan | grep "Resume_WesleyTaylor"
```

The malicious attachment was found at:

```text
C:\Users\maxine.beck\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\WQHGZCFI\Resume_WesleyTaylor (002).doc
```

This is useful because memory can preserve evidence of files that may no longer be visible through normal filesystem analysis.

---

# 9. Persistence

After establishing the C2 connection, the attacker created a scheduled task to maintain persistence.

The memory dump can be searched for `schtasks`:

```bash
strings WKSTN-2961.raw | grep "schtasks"
```

The persistence command was:

```text
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))"'
```

This scheduled task executes PowerShell with a hidden window and decodes a Base64-encoded payload stored in the registry.

---

# Attack Chain

The complete attack can be reconstructed as:

```text
Spear Phishing Email
        ↓
Resume_WesleyTaylor.doc
        ↓
Malicious VBA AutoOpen Macro
        ↓
Download update.png
        ↓
Save as C:\ProgramData\update.js
        ↓
wscript.exe
        ↓
Download update.exe
        ↓
updater.exe
        ↓
C:\Windows\Tasks\updater.exe
        ↓
C2: 128.199.95.189:8080
        ↓
Scheduled Task Persistence
        ↓
PowerShell / Registry Payload
```

---

# Important IOCs

| Type | Indicator |
|---|---|
| Sender | `westaylor23@outlook.com` |
| Attachment | `Resume_WesleyTaylor.doc` |
| MD5 | `52c4384a0b9e248b95804352ebec6c5b` |
| Stage 2 URL | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png` |
| Stage 2 | `C:\ProgramData\update.js` |
| Malicious Binary | `C:\Windows\Tasks\updater.exe` |
| C2 | `128.199.95.189:8080` |
| Persistence | Scheduled Task `Updater` |

---

# SOC Analyst Perspective

This challenge demonstrates why analysts should correlate multiple evidence sources instead of investigating a single artifact.

The phishing email identifies the initial access vector.

The malicious Word document reveals the VBA macro and stage 2 download.

Volatility reveals:

- Process execution
- Parent-child relationships
- Malicious files
- C2 communication
- Persistence

The complete investigation therefore becomes:

```text
Email
 ↓
Malicious Document
 ↓
Macro
 ↓
Process Execution
 ↓
Memory Analysis
 ↓
C2
 ↓
Persistence
```

---

# Key Takeaways

- Phishing attacks can be highly targeted toward specific departments such as HR.
- Malicious Office documents can use `AutoOpen` macros for execution.
- Attackers can disguise payloads using misleading file extensions.
- `wscript.exe` can be abused to execute malicious JavaScript.
- Volatility can reveal processes that were active during a compromise.
- `pstree` helps reconstruct parent-child process relationships.
- `netscan` can reveal C2 connections from a memory dump.
- `filescan` can recover evidence of files present in memory.
- Scheduled tasks are commonly abused for persistence.
- Correlating email, file, process, memory, network, and persistence artifacts provides a much clearer attack timeline.
