#!/usr/bin/env python3
"""
USB Forensic Analyzer - Short Version
Digital Forensics Project
"""

import pandas as pd
from datetime import datetime, timedelta
import random

print("="*50)
print("USB FORENSIC ANALYZER - STUDENT PROJECT")
print("="*50)

# Generate sample data
print("\n[1] Generating USB connection data...")

base_time = datetime.now() - timedelta(days=30)

for i in range(30):
    # Mix normal and suspicious
    if i in [3, 10, 22]:
        vid, pid, vendor = 'AAAA', 'BBBB', 'Unknown'
        risk = 'HIGH'
    else:
        vid, pid = f"{random.randint(1000,9999):04X}", f"{random.randint(1000,9999):04X}"
        vendor = random.choice(['SanDisk', 'Kingston', 'Generic'])
        risk = 'LOW'
    
    # Add data issues
    serial = "" if random.random() < 0.1 else f"SN{random.randint(100000,999999)}"
    
    data.append({
        'timestamp': base_time + timedelta(hours=random.randint(0, 720)),
        'device_id': f"USB\\VID_{vid}&PID_{pid}",
        'vendor': vendor,
        'serial': serial,
        'connections': random.randint(1, 20)
    })

df = pd.DataFrame(data)
df.to_csv('usb_data.csv', index=False)
print(f"Created {len(df)} records in usb_data.csv")

# Analysis
print("\n[2] Analyzing for suspicious patterns...")
df['suspicious'] = False
df.loc[df['vendor'] == 'Unknown', 'suspicious'] = True
df.loc[df['device_id'].str.contains('AAAA|0000'), 'suspicious'] = True
df.loc[df['connections'] > 10, 'suspicious'] = True
df.loc[df['serial'] == '', 'missing_serial'] = True

# Results
suspicious = df[df['suspicious']]
missing = df[df['serial'] == '']

print(f"\n[3] RESULTS:")
print(f"Total devices analyzed: {len(df)}")
print(f"Suspicious devices found: {len(suspicious)}")
print(f"Devices missing serials: {len(missing)}")

if len(suspicious) > 0:
    print("\nSUSPICIOUS DEVICES:")
    for idx, row in suspicious.head(3).iterrows():
        print(f"  - {row['device_id']} ({row['vendor']})")

# Create report
report = f"""
USB FORENSIC REPORT
===================
Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}
Analyst: Student Project

SUMMARY:
- Total events: {len(df)}
- Suspicious: {len(suspicious)}
- Missing serials: {len(missing)}
- Time range: {df['timestamp'].min().date()} to {df['timestamp'].max().date()}

FINDINGS:
{suspicious.to_string() if len(suspicious) > 0 else 'No high-risk devices found'}

RECOMMENDATIONS:
1. Investigate unknown vendor devices
2. Check devices with high connection counts
3. Validate devices missing serial numbers
"""

with open('forensic_report.txt', 'w') as f:
    f.write(report)

print(f"\n[4] Report saved to forensic_report.txt")
print("\n✅ Analysis complete!")
