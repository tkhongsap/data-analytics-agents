# Enhanced Cyber Data Analysis - Anomaly Description Generator

## Overview

The `enhance_anomaly_descriptions.py` script transforms the original cyber security anomaly detection dataset into a comprehensive threat intelligence resource with detailed descriptions, classifications, and actionable recommendations for each detected anomaly.

## Generated Files

- **`enhanced_data_v2.csv`** - The primary enhanced dataset with 6 new analytical columns
- **`analyze_enhanced_results.py`** - Example analysis script demonstrating usage patterns

## New Enhanced Columns

### 1. `detailed_description`
Comprehensive multi-part description with:
- **PRIMARY**: Anomaly type classification
- **PATTERN**: Statistical deviation analysis based on z-scores
- **INDICATORS**: Specific z-score triggers and values
- **CONTEXT**: User context, timing, IP information
- **THREAT**: Mapped potential attack scenarios  
- **ACTION**: Investigation urgency and focus areas

### 2. `anomaly_type`
Primary anomaly classification:
- Authentication Anomaly
- Volume-based Anomaly  
- Process Behavior Anomaly
- Privilege Escalation
- Network Behavior Anomaly
- Temporal Pattern Anomaly

### 3. `attack_stage`
MITRE ATT&CK framework mapping:
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Exfiltration
- Impact

### 4. `investigation_priority`
Risk-based priority scoring (1-5):
- **5 (Critical)**: Anonymous logons, coordinated attacks, extreme deviations
- **4 (High)**: Service account compromises, high z-scores, external access
- **3 (Medium)**: Off-hours activity, moderate deviations
- **2 (Normal)**: Standard anomaly patterns
- **1 (Low)**: Minor deviations requiring monitoring

### 5. `threat_indicators`
Specific indicators triggering the anomaly:
- Z-score values and thresholds
- Anonymous/service account flags
- Off-hours activity markers
- External IP indicators
- Maximum deviation scores

### 6. `recommended_action`
Prioritized investigation and response steps:
- System isolation requirements
- Account management actions
- Log analysis priorities
- Threat hunting focus areas
- Remediation recommendations

## Key Features & Intelligence

### Special Detection Rules
- **ANONYMOUS LOGON**: Always flagged as critical (Priority 5)
- **Service Accounts ($)**: Elevated priority for user-like activities
- **Multiple High Z-Scores**: Indicates coordinated attack patterns
- **Off-Hours Activity (2-4 AM)**: Increased risk scoring
- **External IPs**: Enhanced scrutiny for lateral movement

### Statistical Analysis Integration
- **Volume Anomalies** (logcount_z_loss): Unusual activity volumes
- **Host Behavior** (hostincrement_z_loss): Abnormal host interaction patterns
- **Network Patterns** (ipincrement_z_loss): Suspicious IP access patterns
- **Process Behavior** (processincrement_z_loss): Unusual process execution

### Threat Intelligence Mapping
- Maps anomalies to specific attack scenarios
- Provides context-aware threat assessment
- Links statistical deviations to security implications
- Offers targeted investigation guidance

## Dataset Statistics

**Total Records**: 1,429 enhanced anomaly events

**Priority Distribution**:
- Priority 5 (Critical): 2 records (0.1%) - Anonymous logons
- Priority 4 (High): 1,427 records (99.9%) - Service account and high-deviation events

**Anomaly Types**:
- Volume-based Anomaly: 644 records (45.1%)
- Authentication Anomaly: 608 records (42.5%)
- Process Behavior Anomaly: 164 records (11.5%)
- Privilege Escalation: 12 records (0.8%)
- Network Behavior Anomaly: 1 record (0.1%)

**Attack Stages**:
- Privilege Escalation: 659 incidents (46.1%)
- Credential Access: 331 incidents (23.2%)
- Lateral Movement: 326 incidents (22.8%)
- Execution: 111 incidents (7.8%)
- Initial Access: 2 incidents (0.1%)

## Usage Examples

### 1. Find Critical Incidents
```python
import csv

# Load enhanced data
with open('enhanced_data_v2.csv', 'r') as f:
    reader = csv.DictReader(f)
    critical_incidents = [row for row in reader if row['investigation_priority'] == '5']

for incident in critical_incidents:
    print(f"CRITICAL: {incident['username']} on {incident['hostname']}")
    print(f"Description: {incident['detailed_description']}")
    print(f"Actions: {incident['recommended_action']}")
```

### 2. Analyze Service Account Anomalies
```python
# Filter service account events
service_incidents = [row for row in data if row['username'].endswith('$')]
print(f"Service account anomalies: {len(service_incidents)}")
```

### 3. Hunt for Attack Progression
```python
# Group by attack stages
from collections import defaultdict
stages = defaultdict(list)
for row in data:
    stages[row['attack_stage']].append(row)
    
# Look for progression patterns
for stage, incidents in stages.items():
    print(f"{stage}: {len(incidents)} incidents")
```

### 4. Time-based Analysis
```python
# Find off-hours activities
night_activities = [row for row in data if 'off-hours' in row['threat_indicators']]
print(f"Suspicious off-hours activities: {len(night_activities)}")
```

## Investigation Workflow

### 1. **Triage by Priority**
   - Start with Priority 5 (Critical) incidents
   - Process Priority 4 (High) incidents systematically
   - Use `investigation_priority` for queue management

### 2. **Context Analysis**
   - Review `detailed_description` for anomaly context
   - Check `threat_indicators` for specific triggers
   - Correlate with `attack_stage` for threat progression

### 3. **Investigation Actions**  
   - Follow `recommended_action` guidance
   - Focus on authentication logs and system access patterns
   - Monitor affected hosts for continued anomalous behavior

### 4. **Pattern Recognition**
   - Group incidents by `anomaly_type` for trend analysis
   - Track `attack_stage` progression for campaign detection
   - Monitor repeat offenders (users/hosts with multiple incidents)

## Advanced Analytics

The enhanced dataset enables sophisticated security analytics:

- **Behavioral Baselines**: Use z-score patterns to establish normal vs. anomalous behavior
- **Attack Campaign Detection**: Correlate incidents by timing, users, and attack stages
- **Risk Scoring**: Leverage priority rankings for resource allocation
- **Threat Intelligence**: Map anomalies to known attack techniques and TTPs
- **Automated Response**: Use priority and action fields for SOAR integration

## Files and Dependencies

- **Input**: `data/dfp_detections_azure7Days_samplepercentfiltered.csv`
- **Output**: `enhanced_data_v2.csv` 
- **Dependencies**: Python 3.x with standard library (csv, datetime, os, sys)
- **No external packages required** - Uses only Python standard library

## Running the Enhancement

```bash
python3 enhance_anomaly_descriptions.py
```

This processes all 1,429 records and generates the enhanced dataset with detailed threat intelligence for each anomaly detection event.