# Outputs Directory

This directory contains all processed data outputs and analysis results from the cybersecurity data pipeline.

## Data Files

### Primary Clustered Data
- `dfp_detections_clustered.csv` - Original clustered security events (1,428 rows)
- `dfp_detections_system_accounts_clustered.csv` - System accounts only ($ suffix, 1,371 rows)
- `dfp_detections_user_accounts_clustered.csv` - User accounts only (58 rows)

### Dashboard-Ready Data
- `unified_dashboard_data.csv` - Consolidated data for dashboard visualization
  - Merges both system and user account data
  - Properly formatted risk categories for frontend compatibility
  - Contains all enhanced fields for detailed analysis

### Enhanced Analysis Data
- `enhanced_data_v2.csv` - Enhanced security data with MITRE ATT&CK mappings
- `enhanced_clustered_data.csv` - Clustered data with threat categorization

## Data Processing Pipeline

1. **Initial Processing**: `process_data.py` → Base anomaly detection
2. **Account Separation**: `split_csv_by_username.py` → System vs User accounts
3. **Clustering**: `clustering_implementation.py` → ML-based threat groups
4. **Enhancement**: `enhance_anomaly_descriptions.py` → MITRE mappings
5. **Dashboard Prep**: `unified_dashboard_data.py` → Frontend-ready format

## Key Statistics

### Account Distribution
- **System Accounts**: 1,371 events (96% of data)
- **User Accounts**: 58 events (4% of data)

### Risk Levels
- **Critical**: 30.9% anomaly rate
- **High Risk**: Events with Z-score > 10
- **Normal/Moderate**: Baseline activity

## Data Schema

Common fields across all CSV files:
- `timestamp`: Event occurrence time
- `username`: Account name ($ suffix for system accounts)
- `hostname`: Target system
- `event_id`: Windows Event ID
- `max_abs_z`: Z-score for anomaly detection
- `risk_level`: CRITICAL/HIGH/MEDIUM/LOW
- `cluster_id`: ML cluster assignment
- `account_type`: System/User classification