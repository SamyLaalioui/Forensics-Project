# Forensics-Project
# USB Connection Forensic Investigator

## Project Idea
I wanted to create a tool that analyzes USB device connection history to help with incident response. In class, we talked about how USB devices can be used for data theft, but I wanted to actually build something that could analyze the patterns.

## What This Does
Simulates Windows USB connection logs and analyzes them for:
- Unknown/suspicious devices
- Rapid connection patterns (possible data exfiltration)
- Device fingerprinting
- Timeline analysis

## Why I Simulated Data
I tried to find real USB logs but they're tied to specific machines (privacy issues).Simulated data is okay if we make it realistic and handle "real world" data problems.

## Tools I Used
- **Python** - because I'm most comfortable with it
- **Pandas** - 
- **datetime** - for timeline work
- **CSV** - simple output format

## How I Built It
1. First, I researched actual USB device IDs (some are known bad)
2. Created functions to simulate normal vs suspicious patterns
3. Added "real world" data issues (missing values, weird formats)
4. Wrote detection logic based on known IOCs (Indicators of Compromise)
5. Made it output both console results and a detailed report

## Challenges I Hit
1. **Timestamp headaches** - Windows uses FILETIME format, took me a while to get right
2. **False positives** - My first version flagged EVERY unknown vendor
3. **Data validation** - Handling missing/invalid data without crashing
4. **Making it useful** - Balancing detailed output vs overwhelming information

## Did It Work?
Yes, the tool successfully:
- Identified 2 high-risk USB devices in test data
- Created a timeline of connections
- Generated a professional forensic report
- Handled messy data without errors

## Screenshot of My Results
![My USB Analysis](my_screenshot.png)
\

## Would I Use This In Real Life?
For learning? Definitely. For actual investigations? It would need more features, but the core logic is solid. It taught me a lot about what to look for in USB logs.

## How to Run My Project
```bash
# Clone my repo
git clone https://github.com/YOURNAME/Forensics-Project

# Run the analyzer
python usb_forensics.py

# Check the outputs:
- forensic_report.txt (main findings)
- usb_connections.csv (generated sample data)
- analysis_log.txt (detailed process log)


