# Scripts Directory

This directory contains all Python data processing and analysis scripts for the cybersecurity analysis platform.

## Core Processing Scripts
- `process_data.py` - Main Windows security event log processor with z-score anomaly detection
- `split_csv_by_username.py` - Separates system accounts ($) from user accounts
- `unified_dashboard_data.py` - Consolidates data for dashboard visualization
- `prepare_dashboard_data.py` - Prepares enhanced data with proper formatting

## Clustering & Analysis Scripts
- `clustering_implementation.py` - ML-based threat clustering
- `separated_cluster_analysis.py` - Analyzes system vs user account clusters
- `cybersecurity_cluster_analysis.py` - Comprehensive cluster analysis
- `cybersecurity_clustering_analysis.py` - Statistical clustering analysis

## Enhancement Scripts
- `enhance_anomaly_descriptions.py` - Adds MITRE ATT&CK mappings and detailed descriptions
- `analyze_enhanced_results.py` - Post-processing analysis of enhanced data
- `basic_statistical_analysis.py` - Statistical analysis utilities

## Usage Order
1. Run `process_data.py` first
2. Then `split_csv_by_username.py` 
3. Apply clustering with `clustering_implementation.py`
4. Generate dashboard data with `unified_dashboard_data.py`