USB Connection Forensic Investigator 🔍

A Python-based forensic analysis tool that simulates and analyzes USB device connection history to support incident response and insider threat detection.
Built as part of my Digital Forensics coursework to understand how USB-based data exfiltration occurs and how security analysts detect it.

📌 Overview
USB devices are a common vector for insider threats and data exfiltration. This tool models realistic Windows USB connection logs and applies IOC-based detection logic to flag suspicious activity — the same kind of analysis performed during real incident response investigations.

⚙️ Features

Device Fingerprinting — identifies unknown or suspicious vendors by VID/PID
IOC Detection — flags devices matching known indicators of compromise
Rapid Connection Analysis — detects abnormal connection frequency patterns
Missing Serial Detection — identifies devices attempting to avoid logging
Timeline Analysis — reconstructs a 30-day device activity timeline
Forensic Report Generation — outputs structured .txt report for documentation


🛠️ Tech Stack
ToolPurposePython 3Core languagePandasData manipulation and analysisdatetimeTimestamp handling and timeline constructionCSVStructured data output



💡 Why Simulated Data?
Real USB logs are tied to specific machines and contain private system information. Simulating realistic data — including intentional noise like missing values and inconsistent timestamps — allowed me to:

Model real-world data quality issues analysts face
Practice handling malformed forensic evidence
Avoid privacy issues while still building meaningful detection logic


🧠 What I Learned

How Windows stores USB device history (FILETIME format, registry patterns)
IOC-based detection and the challenge of reducing false positives
The balance between thorough analysis and alert fatigue in forensic reporting
How insider threats use USB devices and what behavioral patterns they leave behind


🔭 Future Improvements

 Parse actual Windows Registry SYSTEM\CurrentControlSet\Enum\USBSTOR entries
 Add YARA rule support for device matching
 Build a simple dashboard for visual timeline analysis
 Integrate with known-bad VID/PID threat intelligence feeds
