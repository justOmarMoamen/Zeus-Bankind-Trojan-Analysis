# Zeus-Bankind-Trojan-Analysis

## Simulate Malware Execution & Detection

### Environment
- **Operating System:** Windows 10 Enterprise Virtual Machine (VirtualBox)
- **Tools Used:** Suricata (HIDS), Sysmon, Splunk Forwarder, SIEM, VirusTotal, Any.Run Sandbox, Volatility, Yara.

---

## Incident Overview

An incident was detected through threat hunting rules tuned by the SOC team. It originated from a user violating organizational policies by downloading a malicious file from an untrusted source. 

Key indicators:
- Malicious IP interactions.
- High data transmission volumes to North America.
- Detection of malicious processes and files (`.pdf.exe` extensions).

### Detection Workflow
1. **Alert Monitoring:**
   - Suricata HIDS dashboard flagged suspicious activities.
   - Geo-map and traffic analysis highlighted anomalies.
2. **Logs & Process Investigation:**
   - Retrieved Sysmon logs related to the malicious host (`DESKTOP-9QMM40J`).
   - Identified suspicious processes with `.pdf.exe` extensions.
   - Process hash analysis via VirusTotal confirmed malware.

---

## Malware Analysis

### File Details
- **Filename:** `invoice_2318362983713_823931342io.pdf.exe`
- **Hash:** `69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169`
- **VirusTotal Detection:** 63/72 vendors flagged the file as a Trojan (e.g., ZAccess, Sirefef).
- **Behaviors:** Persistence mechanisms, suspicious UDP activity, anti-debugging techniques.

### Sandboxing
- Identified process `InstallFlashPlayer.exe` as highly malicious.
- Malware established persistence, deleted itself, and initiated lateral movement.

---

## Incident Response Process

1. **Preparation:**
   - Maintain updated Incident Response Plan (IRP).
   - Conduct regular training and deploy monitoring tools.
2. **Identification:**
   - Detected and analyzed alerts using SIEM and endpoint logs.
   - Classified as a high-priority Trojan incident.
3. **Containment:**
   - Isolated affected systems.
   - Blocked malicious IPs and domains.
4. **Eradication:**
   - Removed malware and patched vulnerabilities.
5. **Recovery:**
   - Restored from backups and monitored systems post-incident.
6. **Lessons Learned:**
   - Strengthened user policies and added new HIDS rules.

---

## Memory Dump Analysis

### Tools: Volatility
1. **Identified Suspicious Processes:**
   - `nifek_locked.ex`, `vaelh.exe`, `anaxu.exe`.
   - Verified malicious hashes via VirusTotal.
2. **Network Interactions:**
   - Malicious IPs detected (`193.43.134.14`).
3. **Process Dump:**
   - Transferred dump files for further analysis (ExifTool, Binwalk, etc.).
   - Confirmed malicious processes.

---

## Yara Rule Development

### Steps
1. Generated custom Yara rules using `yarGen`.
2. Scanned malware to identify anomalies.
3. Applied rules to enhance detection mechanisms.

---

## Key Findings

- Incident highlighted gaps in user behavior and security configurations.
- Proactive threat detection mechanisms successfully identified the breach.
- Improved policies and HIDS rules will mitigate future risks.

---

## Future Steps

1. Simulate similar attacks to improve detection capabilities.
2. Integrate findings into SOC playbooks and training sessions.
3. Regularly update threat intelligence and HIDS configurations.

---

For additional details, please refer to the full incident analysis report.
