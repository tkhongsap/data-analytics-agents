# System/Computer Accounts Security Analysis Report

**Generated:** 2025-09-04  
**Data Source:** Computer accounts clustered analysis (1,371 events)  
**Account Type:** System/Service accounts (usernames ending with $)

---

## Executive Summary

### 🔴 **CRITICAL SECURITY SITUATION**

The analysis of **1,371 system account events** reveals a severe security breach with **439 CRITICAL anomalies** (32% of all events). The infrastructure shows clear signs of Advanced Persistent Threat (APT) activity with systematic compromise across multiple domain controllers.

**Overall Risk Level:** **CRITICAL - Immediate action required**

---

## Key Findings

### 1. Threat Distribution by Cluster

| Cluster Type | Events | Risk Level | Avg Anomaly Score |
|-------------|---------|------------|-------------------|
| **Lateral Movement Indicators** | 300 | HIGH | 12.08 |
| **Suspicious Authentication Pattern** | 260 | CRITICAL | 23.94 |
| **Moderate Risk Events** | 248 | MEDIUM | 12.12 |
| **Critical Persistent Threats** | 199 | CRITICAL | 23.19 |
| **Baseline Activity** | 141 | LOW | 8.73 |
| **Outlier Extreme Risk** | 82 | CRITICAL | 18.70 |
| **High Risk Authentication** | 71 | HIGH | Variable |
| **System Process Anomalies** | 61 | MEDIUM | Variable |
| **Network Reconnaissance** | 9 | HIGH | Variable |

### 2. Top Threat Actors (System Accounts)

| Rank | Account | Threat Score | Events | Max Anomaly | Hosts Affected |
|------|---------|--------------|--------|-------------|----------------|
| 1 | **TBQPF45YEK2$** | 554.72 | 1106 | 32.17 | 1 |
| 2 | **STBVADC04$** | 34.40 | 31 | 50.29 | 1 |
| 3 | **STBVDRADC01$** | 33.88 | 68 | 32.17 | 1 |
| 4 | **STBVADC02$** | 27.41 | 25 | 50.29 | 1 |
| 5 | **STBVADC01$** | 26.50 | 55 | 50.65 | 1 |

**Critical Finding:** `TBQPF45YEK2$` accounts for **80.7%** of all system account threats, indicating a massively compromised service account.

### 3. Infrastructure Vulnerability Assessment

| Host | Vulnerability Score | Critical Events | Max Anomaly | Unique Users |
|------|-------------------|-----------------|-------------|--------------|
| **STBVDRADC01** | 4462.85 | 438 | 32.17 | 2 |
| **STBVADC01** | 90.24 | 3 | 50.65 | 2 |
| **STBVADC04** | 30.37 | 1 | 50.29 | 1 |
| **STBVADC02** | 30.12 | 1 | 50.29 | 1 |
| **STBVADC05** | 14.37 | 0 | 41.18 | 3 |

**Infrastructure Impact:** Domain controller `STBVDRADC01` is severely compromised with 438 critical events.

### 4. Risk Level Distribution

```
CRITICAL (z≥20):  439 events (32.0%) ████████████████ 
HIGH (10≤z<20):   562 events (41.0%) ████████████████████
MEDIUM (3≤z<10):  370 events (27.0%) █████████████
LOW (z<3):          0 events (0.0%)  
```

### 5. Temporal Attack Pattern

| Date | Events | Critical | Criticality Rate |
|------|--------|----------|-----------------|
| 2025-08-25 | 1195 | 394 | 33.0% |
| 2025-08-26 | 119 | 35 | 29.4% |
| 2025-08-27 | 57 | 10 | 17.5% |

**Pattern Analysis:** Massive attack concentration on August 25th with gradual decline, suggesting initial compromise followed by persistence establishment.

---

## Critical Security Incidents

### 🚨 **EXTREME RISK EVENTS** (Z-score > 40)

1. **STBVADC01$** - Z-score: **50.65**
   - Event: Special privilege login (Event ID 4672)
   - Timestamp: 2025-08-26T10:05:17
   - **Impact:** Complete system-level compromise

2. **STBVADC04$** - Z-score: **50.29**
   - Event: Process creation anomaly
   - Multiple occurrences indicating persistent backdoor

3. **STBVADC02$** - Z-score: **50.29**
   - Event: Similar pattern to STBVADC04$
   - Suggests coordinated multi-host compromise

---

## Attack Techniques Observed

Based on cluster analysis and event patterns:

### 1. **Lateral Movement (300 events)**
- Systematic movement across domain controllers
- Network-based authentication (Type 3 logons)
- Sequential host targeting

### 2. **Credential Harvesting**
- Multiple authentication anomalies
- Special privilege abuse (Event ID 4672)
- Service account exploitation

### 3. **Persistence Mechanisms**
- Process creation anomalies (Event ID 4688)
- Continuous re-authentication patterns
- 199 events classified as "Critical Persistent Threats"

### 4. **Reconnaissance Activity**
- 9 dedicated reconnaissance events
- IP diversity suggesting network mapping
- Host enumeration patterns

---

## Immediate Actions Required

### Priority 1: Containment (0-4 hours)
1. **ISOLATE** account `TBQPF45YEK2$` immediately
2. **DISABLE** all accounts with Z-score > 40:
   - STBVADC01$, STBVADC02$, STBVADC04$
3. **BLOCK** network access to STBVDRADC01
4. **ROTATE** all service account credentials

### Priority 2: Investigation (4-24 hours)
1. **FORENSIC ANALYSIS** of STBVDRADC01 (438 critical events)
2. **AUDIT** all Event ID 4672 (special privileges) occurrences
3. **TRACE** lateral movement from initial compromise
4. **REVIEW** process creation logs for backdoors

### Priority 3: Remediation (24-72 hours)
1. **REBUILD** compromised domain controllers
2. **IMPLEMENT** privileged access management (PAM)
3. **DEPLOY** enhanced monitoring on all DCs
4. **UPDATE** security baselines for service accounts

---

## Security Recommendations

### Immediate Hardening
- Enable MFA for all service accounts
- Implement network segmentation between DCs
- Deploy EDR on all domain controllers
- Enable PowerShell logging and command line auditing

### Detection Improvements
- Alert threshold: Any service account with Z-score > 10
- Monitor for Event ID 4672 on service accounts
- Track lateral movement patterns between DCs
- Baseline normal service account behavior

### Long-term Security Strategy
1. **Zero Trust Architecture** for service accounts
2. **Privileged Access Workstations** (PAWs) for DC management
3. **Regular service account audits** (monthly)
4. **Automated threat response** for anomaly scores > 20

---

## Compliance & Regulatory Impact

- **Data Breach Risk:** HIGH - Domain controller compromise
- **Regulatory Exposure:** CRITICAL - Complete AD compromise
- **Business Impact:** SEVERE - Identity infrastructure at risk
- **Recovery Time Objective:** 24-48 hours for full remediation

---

## Conclusion

The system account analysis reveals a **critical security breach** with clear evidence of:
- Advanced Persistent Threat activity
- Systematic domain controller compromise
- Service account exploitation at scale
- Established persistence mechanisms

**Immediate intervention is required** to prevent complete Active Directory takeover and potential ransomware deployment.

---

**Report Classification:** CONFIDENTIAL  
**Distribution:** Security Operations, CISO, Infrastructure Team  
**Next Review:** Within 4 hours of initial response