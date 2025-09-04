# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A comprehensive cybersecurity data analysis platform that processes Windows security event logs, performs ML-based clustering for threat detection, and visualizes insights through a React dashboard. The system analyzes anomalous behaviors using z-score statistics and MITRE ATT&CK framework mappings.

## Common Development Commands

### Data Processing Pipeline
```bash
# Main analysis pipeline (run in order)
python3 process_data.py                    # Generate risk scores and descriptions
python3 split_csv_by_username.py           # Segment computer vs user accounts
python3 clustering_implementation.py        # Apply ML clustering
python3 enhance_anomaly_descriptions.py     # Add MITRE ATT&CK mappings

# Analysis tools
python3 analyze_enhanced_results.py        # Post-processing analysis
python3 basic_statistical_analysis.py      # Statistical modeling
```

### Dashboard Development
```bash
cd dashboard/

# Development
npm install          # Install dependencies
npm run dev         # Start dev server (http://localhost:3000)

# Production
npm run build       # Build for production
npm run preview     # Preview production build
./deploy.sh         # Automated deployment
```

## Architecture Overview

### Data Processing Pipeline
```
Raw CSV (1,429 events) → process_data.py → Enhanced with risk scores
    ↓
split_csv_by_username.py → Computer accounts (1,371) | User accounts (58)
    ↓
clustering_implementation.py → ML clustering with threat patterns
    ↓
enhance_anomaly_descriptions.py → MITRE ATT&CK mappings & analysis
    ↓
enhanced_data_v2.csv → React Dashboard
```

### Key Components

**Core Processing Scripts:**
- `process_data.py`: Windows Event ID interpretation, z-score anomaly detection, risk categorization (Critical ≥20, High 10-20, Normal <10)
- `clustering_implementation.py`: Hybrid DBSCAN+K-means for computer accounts, K-means for user accounts, generates cluster descriptions
- `enhance_anomaly_descriptions.py`: MITRE ATT&CK framework mapping, investigation priorities, recommended actions

**React Dashboard (`dashboard/`):**
- Components: MetricsCard, TimelineChart, RiskDistribution, TopThreats, CriticalEvents, LogsViewer
- Data loader expects `enhanced_data_v2.csv` or `enhanced_data.csv` in public directory
- Tech stack: React 18, Vite, Tailwind CSS, Recharts, Framer Motion

**Specialized Claude Agents (`.claude/agents/`):**
- `anomaly-analyzer`: Z-score interpretation and risk assessment
- `react-visualizer`: Dashboard visualization expert
- `data-statistician`: Statistical analysis specialist
- `security-log-interpreter`: Windows Event ID expert
- `anomaly-explainer`: Detailed threat explanations with MITRE mappings

### Critical Data Files
- **Input**: `data/dfp_detections_azure7Days_samplepercentfiltered.csv`
- **Processed**: `enhanced_data.csv`, `enhanced_data_v2.csv`
- **Clustered**: `data/dfp_detections_*_accounts_clustered.csv`
- **Dashboard**: `dashboard/public/enhanced_data*.csv`

## Security Analysis Methodology

### Risk Classification
- **Critical**: z-score ≥ 20, immediate investigation required
- **High Risk**: z-score 10-20, elevated threat level
- **Normal/Moderate**: z-score < 10, baseline activity

### Clustering Approach
- **Computer Accounts**: 6 clusters including Outlier_Extreme_Risk, Critical_Persistent_Threats, Lateral_Movement_Indicators
- **User Accounts**: 4 clusters including Critical_User_Breach, Suspicious_User_Behavior, Baseline_User_Behavior

### Windows Event IDs Analyzed
- 4624: Login events
- 4634: Logout events
- 4672: Special privileges assigned
- 4688: Process creation
- 4689: Process termination

## Important Implementation Notes

- Dashboard requires CSV data in `dashboard/public/` directory
- All timestamps are in UTC format
- Clustering uses normalized features with weighted Euclidean distance
- MITRE ATT&CK tactics mapped: Initial Access, Privilege Escalation, Credential Access, Lateral Movement
- Investigation priorities range from 1 (lowest) to 5 (highest)
- Dashboard auto-refreshes data every 30 seconds when in development mode