# Windows Security Event Log Quick Reference Guide

## Event ID Quick Lookup

### 🔐 Authentication Events

**Event 4624 - Successful Logon**
- 👤 **What**: Someone logged in successfully  
- ✅ **Normal**: Business hours login from known location
- ⚠️ **Suspicious**: Multiple locations, unusual IPs, off-hours access
- 🎯 **Attack**: Credential stuffing, lateral movement, account takeover

**Event 4625 - Failed Logon** 
- 👤 **What**: Someone failed to log in
- ✅ **Normal**: Occasional typos or forgotten passwords
- ⚠️ **Suspicious**: Multiple rapid failures, unusual locations
- 🎯 **Attack**: Brute force, password spraying, account enumeration

**Event 4634 - Account Logoff**
- 👤 **What**: Someone logged out
- ✅ **Normal**: End of work session logoffs  
- ⚠️ **Suspicious**: Logoffs without logons, unusual timing
- 🎯 **Attack**: Session cleanup after malicious activity

### 🔧 System Events

**Event 4688 - Process Created**
- ⚙️ **What**: New program/service started
- ✅ **Normal**: Standard applications during normal use
- ⚠️ **Suspicious**: Unusual programs, suspicious command lines
- 🎯 **Attack**: Malware execution, living off the land techniques

**Event 4689 - Process Terminated**
- ⚙️ **What**: Program/service stopped
- ✅ **Normal**: Regular program closure
- ⚠️ **Suspicious**: Security tools killed, critical processes ended
- 🎯 **Attack**: Defense evasion, anti-forensics

**Event 4672 - Special Privileges Assigned**
- 🛡️ **What**: Someone given admin rights
- ✅ **Normal**: Authorized admin privilege grants
- ⚠️ **Suspicious**: Regular users getting admin, off-hours assignment
- 🎯 **Attack**: Privilege escalation, persistence

## Account Types Guide

### 💻 Computer Accounts (ending with $)
**Examples**: STBVADC01$, TBQPF45YEK2$
- **Purpose**: Service-to-service communication
- **Normal**: Quiet background authentication
- **Suspicious**: Interactive logons, unusual IPs, high frequency

### 👤 User Accounts  
**Examples**: i1013572, john.doe, administrator
- **Purpose**: Human user access
- **Normal**: Business hours logons from known locations
- **Suspicious**: Multiple locations, off-hours, failed logons

### 🔧 Service Accounts
**Examples**: LOCAL SERVICE, NETWORK SERVICE
- **Purpose**: System service operations  
- **Normal**: Automated system tasks
- **Suspicious**: Interactive logons, remote authentication

### ❓ Anonymous Logon
**Examples**: ANONYMOUS LOGON
- **Purpose**: Limited system access
- **Risk**: HIGH - Anonymous access often suspicious

## Risk Score Interpretation

| Z-Score | Risk Level | Meaning | Action Required |
|---------|------------|---------|-----------------|
| 0-10 | 🟢 Low | Normal baseline | Monitor |
| 10-20 | 🟡 Medium | Some deviation | Watch closely |
| 20-30 | 🟠 Medium-High | Significant deviation | Investigate |
| 30-50 | 🔴 High | Extreme deviation | Urgent review |
| 50+ | 🚨 Critical | Never seen before | Immediate action |

## Logon Types Explained

| Type | Name | Description | Normal Use |
|------|------|-------------|------------|
| 2 | Interactive | Keyboard/Console | Physical computer access |
| 3 | Network | Remote Access | File shares, admin tools |
| 4 | Batch | Scheduled Task | Automated scripts |
| 5 | Service | Service Account | Windows services |
| 7 | Unlock | Screen Unlock | Returning from screensaver |
| 10 | RemoteInteractive | RDP | Remote desktop |
| 11 | CachedInteractive | Cached Credentials | Offline domain login |

## Risk Clusters Explained

### 🚨 Critical Risk
- **Critical_User_Breach**: Strong evidence of account compromise
- **Critical_Persistent_Threats**: Advanced persistent threat activity  
- **Outlier_Extreme_Risk**: Never-before-seen behavior

### 🔴 High Risk
- **Suspicious_Authentication_Pattern**: Unusual login behaviors
- **Lateral_Movement_Indicators**: System-to-system movement
- **High_Risk_Authentication**: Multiple risk factors present

### 🟠 Medium Risk  
- **Session_Management_Issues**: Unusual session characteristics
- **Suspicious_User_Behavior**: Deviating but possibly benign
- **System_Process_Anomalies**: Unusual system behavior

### 🟢 Low Risk
- **Normal_User_Activity**: Expected user patterns
- **Baseline_User_Behavior**: Standard behavioral baselines
- **Baseline_Activity**: Normal system operations

## Investigation Priorities

### 🚨 Immediate Action (Z-Score 50+)
1. Anonymous logons from external sources
2. Computer account privilege escalations  
3. Critical system process anomalies

### 🔴 High Priority (Z-Score 30-50)
1. Lateral movement patterns
2. Suspicious authentication sequences
3. Persistent threat indicators

### 🟠 Medium Priority (Z-Score 20-30)
1. Session management issues
2. Process execution anomalies
3. Baseline behavior deviations

## Common Suspicious Patterns

### 🔍 Authentication Red Flags
- Same user logging in from multiple locations simultaneously
- Service accounts logging in interactively  
- High frequency login attempts (credential stuffing)
- Successful logins after many failures (successful brute force)
- Logins from unusual geographic locations

### 🔍 Process Red Flags
- System processes running from unusual locations
- High privilege processes started by low privilege users
- Critical security processes being terminated
- Suspicious command line arguments
- Unsigned or recently created executables

### 🔍 Network Red Flags
- Internal systems authenticating from external IPs
- Unusual network logon patterns
- Anonymous access from external sources
- Service accounts accessing from user workstations

## MITRE ATT&CK Mapping

| Technique | Description | Events |
|-----------|-------------|--------|
| T1078 | Valid Accounts | 4624, 4634 |
| T1110 | Brute Force | 4625, 4624 |
| T1021 | Remote Services | 4624 |
| T1059 | Command/Script Interpreter | 4688 |
| T1055 | Process Injection | 4688 |
| T1562 | Impair Defenses | 4689 |
| T1068 | Exploit for Privilege Escalation | 4672 |

---

*For detailed analysis and specific event descriptions, refer to the complete JSON output file.*