#!/usr/bin/env python3
"""
Windows Security Event Log Analysis Script
==========================================

This script analyzes Windows security event logs with anomaly detection scores
and creates human-readable descriptions for each event.

Author: Claude Code Analysis
Date: 2025-09-03
"""

import csv
import statistics
from datetime import datetime
import os
from collections import defaultdict, Counter


def get_event_description(event_id, event_action, process_name, max_abs_z):
    """
    Generate human-readable descriptions for Windows security events.
    
    Args:
        event_id: Windows Event ID
        event_action: Action type (logged-in, logged-out, etc.)
        process_name: Name of process (if applicable)
        max_abs_z: Maximum absolute z-score for anomaly detection
        
    Returns:
        String description of the event
    """
    # Base event descriptions
    event_descriptions = {
        4624: "Successful account logon",
        4634: "Account logoff", 
        4689: "Process terminated",
        4672: "Special privileges assigned to new logon",
        4688: "New process created"
    }
    
    # Get base description
    base_desc = event_descriptions.get(event_id, f"Windows security event {event_id}")
    
    # Add process information if available
    if process_name and process_name.strip() and process_name != '-':
        base_desc += f" (Process: {process_name})"
    
    # Add risk assessment based on z-score
    if max_abs_z >= 20:
        risk_level = "CRITICAL anomaly detected"
        severity = "🚨 CRITICAL"
    elif max_abs_z >= 10:
        risk_level = "HIGH risk event" 
        severity = "⚠️ HIGH RISK"
    else:
        risk_level = "Normal to moderate risk"
        severity = "ℹ️ NORMAL"
        
    return f"{base_desc} - {risk_level} (Score: {max_abs_z:.2f})"


def get_logon_type_description(logon_type):
    """
    Translate logon type codes to human-readable descriptions.
    
    Args:
        logon_type: Numeric logon type code
        
    Returns:
        String description of logon type
    """
    logon_types = {
        2: "Interactive (console logon)",
        3: "Network (remote access)", 
        4: "Batch (scheduled task)",
        5: "Service (service account)",
        7: "Unlock (workstation unlock)",
        8: "NetworkCleartext (network with clear password)",
        9: "NewCredentials (run as different user)",
        10: "RemoteInteractive (RDP/Terminal Services)",
        11: "CachedInteractive (cached credentials)"
    }
    
    if not logon_type or logon_type == '':
        return "Not applicable"
    
    try:
        logon_code = int(float(logon_type))
        return logon_types.get(logon_code, f"Unknown logon type ({logon_code})")
    except (ValueError, TypeError):
        return "Invalid logon type"


def get_risk_category(max_abs_z):
    """Categorize risk based on anomaly score."""
    if max_abs_z >= 20:
        return "Critical"
    elif max_abs_z >= 10:
        return "High Risk"
    else:
        return "Normal/Moderate"


def analyze_security_events(csv_file_path):
    """
    Main analysis function to process Windows security event logs.
    
    Args:
        csv_file_path: Path to the CSV file containing event data
        
    Returns:
        Tuple of (data, top_anomalous, user_stats, host_stats)
    """
    
    print("🔍 Loading and analyzing Windows security event data...")
    print(f"📂 Reading file: {csv_file_path}")
    
    # Load the data
    try:
        data = []
        with open(csv_file_path, 'r', encoding='utf-8') as file:
            csv_reader = csv.DictReader(file)
            headers = csv_reader.fieldnames
            for row in csv_reader:
                # Convert numeric fields
                try:
                    row['max_abs_z'] = float(row['max_abs_z']) if row['max_abs_z'] else 0.0
                    row['event_id'] = int(float(row['event_id'])) if row['event_id'] else 0
                    row['logon_type'] = row['logon_type'] if row['logon_type'] else ''
                except (ValueError, TypeError):
                    continue
                data.append(row)
        
        print(f"✅ Successfully loaded {len(data):,} security events")
        
    except Exception as e:
        print(f"❌ Error loading file: {e}")
        return None
    
    # Basic statistics
    timestamps = [row['timestamp'] for row in data if row['timestamp']]
    usernames = set(row['username'] for row in data if row['username'])
    hostnames = set(row['hostname'] for row in data if row['hostname'])
    max_abs_z_values = [row['max_abs_z'] for row in data]
    
    print(f"\n📊 Dataset Overview:")
    print(f"   • Total events: {len(data):,}")
    print(f"   • Date range: {min(timestamps)} to {max(timestamps)}")
    print(f"   • Unique users: {len(usernames):,}")
    print(f"   • Unique hosts: {len(hostnames):,}")
    
    # Event type distribution
    print(f"\n📈 Event Type Distribution:")
    event_counts = Counter(row['event_id'] for row in data if row['event_id'])
    for event_id, count in event_counts.most_common():
        event_name = {
            4624: "Successful Logons",
            4634: "Account Logoffs", 
            4689: "Process Terminations",
            4672: "Special Privileges",
            4688: "New Processes"
        }.get(event_id, f"Event {event_id}")
        print(f"   • {event_name}: {count:,} ({count/len(data)*100:.1f}%)")
    
    # Generate enhanced descriptions
    print(f"\n🔧 Generating human-readable descriptions...")
    for row in data:
        row['event_description'] = get_event_description(
            row['event_id'], 
            row['event_action'], 
            row['process_name'], 
            row['max_abs_z']
        )
        row['logon_type_description'] = get_logon_type_description(row['logon_type'])
        row['risk_category'] = get_risk_category(row['max_abs_z'])
    
    # Calculate key statistics
    print(f"\n📊 Anomaly Detection Statistics:")
    mean_score = statistics.mean(max_abs_z_values)
    median_score = statistics.median(max_abs_z_values)
    max_score = max(max_abs_z_values)
    stdev_score = statistics.stdev(max_abs_z_values) if len(max_abs_z_values) > 1 else 0
    
    print(f"   • Mean anomaly score: {mean_score:.2f}")
    print(f"   • Median anomaly score: {median_score:.2f}")
    print(f"   • Maximum anomaly score: {max_score:.2f}")
    print(f"   • Standard deviation: {stdev_score:.2f}")
    
    # Risk distribution
    print(f"\n⚠️ Risk Level Distribution:")
    risk_counts = Counter(row['risk_category'] for row in data)
    for risk_level in ['Critical', 'High Risk', 'Normal/Moderate']:
        count = risk_counts[risk_level]
        percentage = count / len(data) * 100
        print(f"   • {risk_level}: {count:,} events ({percentage:.1f}%)")
    
    # Top 10 most anomalous events
    print(f"\n🚨 Top 10 Most Anomalous Events:")
    top_anomalous = sorted(data, key=lambda x: x['max_abs_z'], reverse=True)[:10]
    
    for idx, row in enumerate(top_anomalous):
        print(f"   {idx+1:2d}. Score {row['max_abs_z']:6.2f} | {row['timestamp'][:19]} | "
              f"{row['username']:15s} | {row['hostname']:15s} | Event {row['event_id']}")
    
    # User-based analysis
    print(f"\n👤 User Activity Analysis:")
    user_stats = defaultdict(lambda: {'events': [], 'event_ids': set()})
    
    for row in data:
        username = row['username']
        user_stats[username]['events'].append(row['max_abs_z'])
        user_stats[username]['event_ids'].add(row['event_id'])
    
    # Calculate user statistics
    user_summary = {}
    for user, stats in user_stats.items():
        user_summary[user] = {
            'Total_Events': len(stats['events']),
            'Avg_Anomaly_Score': statistics.mean(stats['events']),
            'Max_Anomaly_Score': max(stats['events']),
            'Event_Types': len(stats['event_ids'])
        }
    
    # Top 5 users by max anomaly score
    top_users = sorted(user_summary.items(), key=lambda x: x[1]['Max_Anomaly_Score'], reverse=True)[:5]
    
    for user, stats in top_users:
        print(f"   • {user:20s}: {stats['Total_Events']:4d} events, "
              f"max score {stats['Max_Anomaly_Score']:6.2f}, "
              f"avg score {stats['Avg_Anomaly_Score']:5.2f}")
    
    # Host-based analysis  
    print(f"\n🖥️ Host Activity Analysis:")
    host_stats = defaultdict(lambda: {'events': [], 'users': set()})
    
    for row in data:
        hostname = row['hostname']
        host_stats[hostname]['events'].append(row['max_abs_z'])
        host_stats[hostname]['users'].add(row['username'])
    
    # Calculate host statistics
    host_summary = {}
    for host, stats in host_stats.items():
        host_summary[host] = {
            'Total_Events': len(stats['events']),
            'Avg_Anomaly_Score': statistics.mean(stats['events']),
            'Max_Anomaly_Score': max(stats['events']),
            'Unique_Users': len(stats['users'])
        }
    
    # Top 5 hosts by max anomaly score
    top_hosts = sorted(host_summary.items(), key=lambda x: x[1]['Max_Anomaly_Score'], reverse=True)[:5]
    
    for host, stats in top_hosts:
        print(f"   • {host:20s}: {stats['Total_Events']:4d} events, "
              f"max score {stats['Max_Anomaly_Score']:6.2f}, "
              f"{stats['Unique_Users']:2d} users")
    
    return data, top_anomalous, user_summary, host_summary


def save_enhanced_data(data, output_file):
    """
    Save the enhanced dataset with descriptions to a new CSV file.
    
    Args:
        data: List of dictionaries containing event data
        output_file: Path for the output CSV file
    """
    
    # Select and reorder columns for better readability
    output_columns = [
        'timestamp', 'username', 'hostname', 'host_os_name',
        'event_id', 'event_description', 'logon_type_description', 
        'event_action', 'source_ip', 'process_name',
        'max_abs_z', 'mean_abs_z', 'risk_category',
        'logcount', 'hostincrement', 'ipincrement', 'processincrement',
        'logcount_z_loss', 'hostincrement_z_loss', 'ipincrement_z_loss', 
        'processincrement_z_loss'
    ]
    
    # Sort data by anomaly score (highest first)
    sorted_data = sorted(data, key=lambda x: x['max_abs_z'], reverse=True)
    
    # Save to CSV
    try:
        with open(output_file, 'w', encoding='utf-8', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=output_columns, extrasaction='ignore')
            writer.writeheader()
            for row in sorted_data:
                # Only write columns that exist in the data
                filtered_row = {col: row.get(col, '') for col in output_columns}
                writer.writerow(filtered_row)
        
        print(f"✅ Enhanced data saved to: {output_file}")
        print(f"   • Total records: {len(sorted_data):,}")
        print(f"   • Columns included: {len(output_columns)}")
    except Exception as e:
        print(f"❌ Error saving file: {e}")


def generate_summary_report(data, top_anomalous, user_stats, host_stats, output_file):
    """
    Generate a comprehensive summary report of the analysis findings.
    
    Args:
        data: List of dictionaries with analysis results
        top_anomalous: List of top 10 anomalous events
        user_stats: User-based statistics dictionary
        host_stats: Host-based statistics dictionary
        output_file: Path for the output summary file
    """
    
    # Calculate basic statistics
    timestamps = [row['timestamp'] for row in data if row['timestamp']]
    usernames = set(row['username'] for row in data if row['username'])
    hostnames = set(row['hostname'] for row in data if row['hostname'])
    max_abs_z_values = [row['max_abs_z'] for row in data]
    
    mean_score = statistics.mean(max_abs_z_values)
    median_score = statistics.median(max_abs_z_values)
    max_score = max(max_abs_z_values)
    
    report = f"""
Windows Security Event Log Analysis Summary
==========================================

Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Dataset: dfp_detections_azure7Days_samplepercentfiltered.csv

EXECUTIVE SUMMARY
-----------------
This analysis processed {len(data):,} Windows security events to identify anomalous behavior
and potential security threats. The analysis focuses on logon/logoff activities, 
process events, and privilege assignments across multiple Windows servers.

KEY FINDINGS
------------
• Total Events Analyzed: {len(data):,}
• Date Range: {min(timestamps)} to {max(timestamps)}
• Unique Users: {len(usernames):,}
• Unique Hosts: {len(hostnames):,}

ANOMALY STATISTICS
------------------
• Maximum Anomaly Score: {max_score:.2f}
• Mean Anomaly Score: {mean_score:.2f}
• Median Anomaly Score: {median_score:.2f}

RISK LEVEL DISTRIBUTION
-----------------------
"""
    
    # Add risk distribution
    risk_counts = Counter(row['risk_category'] for row in data)
    for risk_level in ['Critical', 'High Risk', 'Normal/Moderate']:
        count = risk_counts[risk_level]
        percentage = count / len(data) * 100
        report += f"• {risk_level}: {count:,} events ({percentage:.1f}%)\n"
    
    report += f"""
EVENT TYPE BREAKDOWN
--------------------
"""
    
    # Add event type distribution
    event_counts = Counter(row['event_id'] for row in data if row['event_id'])
    for event_id, count in event_counts.most_common():
        event_name = {
            4624: "Successful Logons",
            4634: "Account Logoffs", 
            4689: "Process Terminations",
            4672: "Special Privileges Assigned",
            4688: "New Processes Created"
        }.get(event_id, f"Event {event_id}")
        percentage = count / len(data) * 100
        report += f"• {event_name}: {count:,} ({percentage:.1f}%)\n"
    
    report += f"""
TOP 10 MOST ANOMALOUS EVENTS
-----------------------------
"""
    
    for idx, row in enumerate(top_anomalous):
        report += f"{idx + 1:2d}. Score: {row['max_abs_z']:6.2f} | {row['timestamp'][:19]} | {row['username']:15s} | Event {row['event_id']}\n"
    
    report += f"""
TOP 5 USERS BY MAXIMUM ANOMALY SCORE
-------------------------------------
"""
    
    top_users = sorted(user_stats.items(), key=lambda x: x[1]['Max_Anomaly_Score'], reverse=True)[:5]
    for user, stats in top_users:
        report += f"• {user:20s}: {stats['Total_Events']:4d} events, max score {stats['Max_Anomaly_Score']:6.2f}\n"
    
    report += f"""
TOP 5 HOSTS BY MAXIMUM ANOMALY SCORE  
-------------------------------------
"""
    
    top_hosts = sorted(host_stats.items(), key=lambda x: x[1]['Max_Anomaly_Score'], reverse=True)[:5]
    for host, stats in top_hosts:
        report += f"• {host:20s}: {stats['Total_Events']:4d} events, max score {stats['Max_Anomaly_Score']:6.2f}\n"
    
    report += f"""
RECOMMENDATIONS
---------------
1. Investigate events with Critical risk scores (≥20) immediately
2. Review High risk events (10-20) for potential security threats  
3. Focus on users and hosts with highest anomaly scores
4. Consider implementing additional monitoring for network logons (Type 3)
5. Review special privilege assignments (Event 4672) carefully

TECHNICAL NOTES
---------------
• Anomaly scores are based on z-score normalization of multiple metrics
• Events are classified using Windows Event IDs and logon type codes
• Risk categories: Normal/Moderate (<10), High Risk (10-20), Critical (≥20)
• Analysis includes logon patterns, host activity, IP addresses, and process behavior

For questions about this analysis, please refer to the enhanced dataset:
enhanced_data.csv
"""
    
    # Save the report
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"✅ Summary report saved to: {output_file}")
    except Exception as e:
        print(f"❌ Error saving report: {e}")


def main():
    """Main execution function."""
    
    print("=" * 70)
    print("🔐 Windows Security Event Log Analysis")
    print("=" * 70)
    
    # File paths
    input_file = '/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_azure7Days_samplepercentfiltered.csv'
    output_file = '/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/enhanced_data.csv'
    summary_file = '/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/analysis_summary.txt'
    
    # Check if input file exists
    if not os.path.exists(input_file):
        print(f"❌ Input file not found: {input_file}")
        return
    
    # Perform analysis
    result = analyze_security_events(input_file)
    
    if result is None:
        print("❌ Analysis failed. Exiting.")
        return
    
    data, top_anomalous, user_stats, host_stats = result
    
    # Save enhanced data
    print(f"\n💾 Saving Results...")
    save_enhanced_data(data, output_file)
    
    # Generate summary report
    generate_summary_report(data, top_anomalous, user_stats, host_stats, summary_file)
    
    print(f"\n✅ Analysis Complete!")
    print(f"📁 Files created:")
    print(f"   • Enhanced dataset: {output_file}")
    print(f"   • Analysis summary: {summary_file}")
    print(f"\n🎯 Key Insights:")
    
    # Calculate critical and high-risk counts
    critical_count = sum(1 for row in data if row['max_abs_z'] >= 20)
    high_risk_count = sum(1 for row in data if row['max_abs_z'] >= 10)
    max_score = max(row['max_abs_z'] for row in data)
    
    print(f"   • {critical_count:,} critical anomalies detected (score ≥20)")
    print(f"   • {high_risk_count:,} high-risk events identified (score ≥10)")
    print(f"   • Maximum anomaly score: {max_score:.2f}")
    print("=" * 70)


if __name__ == "__main__":
    main()