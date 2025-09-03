# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a comprehensive cybersecurity data analysis platform that analyzes Windows security event logs for anomaly detection and threat identification. It consists of a Python-based analysis engine that processes security events using statistical methods and a React dashboard for real-time SOC (Security Operations Center) monitoring.

## Project Structure

```
cyber-data-analysis/
├── data/                           # Raw security event data (CSV format)
├── dashboard/                      # React-based SOC dashboard
│   ├── src/                       # Dashboard React components
│   └── public/                    # Static assets
├── .claude/agents/                # Specialized analysis agents
├── process_data.py                # Main Python analysis script
├── enhanced_data.csv              # Processed data with risk scores
├── analysis_summary.txt           # Statistical analysis output
└── SECURITY_REPORT.md             # Executive security report
```

## Common Development Commands

### Python Analysis
```bash
# Run the main security analysis
python3 process_data.py

# The script will:
# 1. Load data from data/dfp_detections_azure7Days_samplepercentfiltered.csv
# 2. Calculate z-scores and anomaly scores
# 3. Generate enhanced_data.csv with human-readable descriptions
# 4. Create analysis_summary.txt with statistics
```

### Dashboard Development
```bash
# Navigate to dashboard
cd dashboard/

# Install dependencies
npm install

# Run development server (http://localhost:3000)
npm run dev

# Build for production
npm run build

# Preview production build
npm run preview

# Deploy to production
./deploy.sh
```

## Architecture Overview

### Data Processing Pipeline
1. **Input**: Windows Event Logs (CSV) containing Event IDs (4624, 4634, 4672, 4688, 4689)
2. **Analysis**: `process_data.py` performs:
   - Z-score normalization for anomaly detection
   - Risk categorization (Normal <10, High 10-20, Critical ≥20)
   - Event description generation
   - Statistical summaries by user, host, and event type
3. **Output**: Enhanced CSV with risk scores and human-readable descriptions
4. **Visualization**: React dashboard displays real-time security metrics

### Key Components

**process_data.py** (486 lines)
- Main analysis engine using pandas, numpy, statistics
- Windows Event ID interpretation and logon type translation
- Anomaly scoring algorithm based on z-scores
- Generates both technical and executive reports

**Dashboard Components** (dashboard/src/components/)
- MetricsCard: Key security metrics display
- TimelineChart: Temporal threat visualization
- RiskDistribution: Risk level pie charts
- TopThreats: Most frequent security events
- CriticalEvents: High-priority alerts table

### Specialized Claude Agents (.claude/agents/)
- `anomaly-analyzer`: Statistical anomaly detection
- `data-statistician`: Comprehensive statistical analysis
- `security-log-interpreter`: Windows Event ID interpretation
- `report-writer`: Executive report generation
- `react-visualizer`: Dashboard visualization
- `review-planner`: Analysis workflow coordination

## Security Analysis Methodology

The system uses statistical z-score analysis to identify anomalous behavior:
- Calculates mean and standard deviation for each metric
- Computes z-scores for user activity, host events, and event types
- Aggregates scores into overall anomaly score
- Categorizes risk levels based on thresholds

## Important Implementation Notes

- The dashboard expects `enhanced_data.csv` in the parent directory
- Dashboard uses Vite for fast development and building
- Tailwind CSS with custom cybersecurity theme colors
- Recharts library for data visualizations
- All timestamps are in UTC format
- Critical events are highlighted with visual indicators