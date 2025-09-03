# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a cybersecurity data analysis project focused on analyzing and processing security-related data. The project currently has a minimal structure with a `data` directory for storing datasets and analysis results.

## Project Structure

```
cyber-data-analysis/
├── data/           # Directory for storing datasets, logs, and analysis outputs
└── CLAUDE.md       # This file - guidance for Claude Code
```

## Development Guidelines

### Data Processing
- When processing security data, ensure sensitive information is properly handled and not exposed in logs or outputs
- Use appropriate data sanitization techniques when dealing with potentially malicious content
- Consider memory efficiency when processing large log files or datasets

### Code Organization
- Place Python scripts for data analysis in the root directory or create appropriate subdirectories (e.g., `scripts/`, `analysis/`, `src/`)
- Store raw data files in `data/raw/` and processed outputs in `data/processed/` when the project grows
- Create notebooks in a `notebooks/` directory if using Jupyter for exploratory analysis

### Security Considerations
- This is a defensive security analysis project - focus on detection, analysis, and reporting capabilities
- Do not include any offensive security tools or exploits
- Validate and sanitize all inputs when processing external data sources
- Use appropriate libraries for parsing security logs (e.g., python-evtx for Windows logs, pyshark for packet analysis)

## Common Tasks

### Setting up Python environment (when needed)
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
pip install -r requirements.txt  # Once requirements.txt exists
```

### Typical Python libraries for cyber data analysis
- pandas: Data manipulation and analysis
- numpy: Numerical computing
- matplotlib/seaborn: Data visualization
- scikit-learn: Machine learning for anomaly detection
- python-evtx: Windows event log parsing
- pyshark/scapy: Network packet analysis
- yara-python: Pattern matching for malware analysis

## Future Development Notes

As this project grows, consider:
1. Adding a `requirements.txt` or `pyproject.toml` for Python dependencies
2. Creating subdirectories for different analysis types (network, endpoint, logs)
3. Implementing a configuration system for analysis parameters
4. Adding unit tests for data processing functions
5. Creating documentation for analysis workflows and methodologies