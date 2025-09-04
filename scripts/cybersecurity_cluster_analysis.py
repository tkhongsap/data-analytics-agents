#!/usr/bin/env python3
"""
Comprehensive Cybersecurity Cluster Analysis
============================================

This script performs comprehensive anomaly detection and security posture analysis
on clustered cybersecurity data, analyzing both computer/system accounts and user accounts
to identify critical security threats, threat actors, and provide actionable intelligence.
"""

import pandas as pd
import numpy as np
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

def load_and_validate_data():
    """Load and validate the clustered cybersecurity data files."""
    try:
        # Load computer/system accounts data
        computer_df = pd.read_csv('/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_computer_accounts_clustered.csv')
        
        # Load user accounts data
        user_df = pd.read_csv('/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_user_accounts_clustered.csv')
        
        print(f"✓ Loaded {len(computer_df):,} computer/system account events")
        print(f"✓ Loaded {len(user_df):,} user account events")
        print(f"✓ Total events analyzed: {len(computer_df) + len(user_df):,}")
        
        return computer_df, user_df
    
    except Exception as e:
        print(f"❌ Error loading data: {e}")
        return None, None

def analyze_anomaly_distribution(df, account_type):
    """Analyze anomaly score distribution and risk levels."""
    print(f"\n{'='*60}")
    print(f"ANOMALY SCORE ANALYSIS - {account_type.upper()}")
    print(f"{'='*60}")
    
    # Define risk thresholds based on z-scores
    def classify_risk(z_score):
        if z_score >= 20:
            return "CRITICAL"
        elif z_score >= 10:
            return "HIGH"
        elif z_score >= 3:
            return "MEDIUM"
        else:
            return "LOW"
    
    df['risk_level'] = df['max_abs_z'].apply(classify_risk)
    
    # Risk distribution
    risk_counts = df['risk_level'].value_counts()
    print(f"\nRISK LEVEL DISTRIBUTION:")
    for risk, count in risk_counts.items():
        percentage = (count / len(df)) * 100
        print(f"  {risk:<8}: {count:>5} events ({percentage:5.1f}%)")
    
    # Top 10 highest anomaly events
    print(f"\nTOP 10 CRITICAL ANOMALIES (Z-Score ≥ 20):")
    critical_events = df[df['max_abs_z'] >= 20].nlargest(10, 'max_abs_z')
    
    for idx, row in critical_events.iterrows():
        print(f"  ⚠️  CRITICAL ANOMALY DETECTED")
        print(f"      User: {row['username']}")
        print(f"      Host: {row['hostname']}")
        print(f"      Action: {row['event_action']}")
        print(f"      Z-Score: {row['max_abs_z']:.2f}")
        print(f"      Cluster: {row['cluster_description']}")
        print(f"      Source IP: {row.get('source_ip', 'N/A')}")
        print()
    
    return df

def analyze_clusters(df, account_type):
    """Analyze cluster distribution and characteristics."""
    print(f"\n{'='*60}")
    print(f"CLUSTER ANALYSIS - {account_type.upper()}")
    print(f"{'='*60}")
    
    cluster_analysis = df.groupby(['cluster_id', 'cluster_description']).agg({
        'max_abs_z': ['count', 'mean', 'max', 'std'],
        'username': 'nunique',
        'hostname': 'nunique'
    }).round(2)
    
    cluster_analysis.columns = ['Event_Count', 'Avg_Z_Score', 'Max_Z_Score', 'Z_Std_Dev', 'Unique_Users', 'Unique_Hosts']
    cluster_analysis = cluster_analysis.sort_values('Max_Z_Score', ascending=False)
    
    print(f"\nCLUSTER DISTRIBUTION AND RISK PROFILE:")
    for (cluster_id, desc), row in cluster_analysis.iterrows():
        risk_level = "CRITICAL" if row['Max_Z_Score'] >= 20 else "HIGH" if row['Max_Z_Score'] >= 10 else "MEDIUM" if row['Max_Z_Score'] >= 3 else "LOW"
        
        print(f"\n🔍 CLUSTER {cluster_id}: {desc}")
        print(f"    Risk Level: {risk_level}")
        print(f"    Events: {row['Event_Count']:,}")
        print(f"    Unique Users: {row['Unique_Users']}")
        print(f"    Unique Hosts: {row['Unique_Hosts']}")
        print(f"    Avg Z-Score: {row['Avg_Z_Score']:.2f}")
        print(f"    Max Z-Score: {row['Max_Z_Score']:.2f}")
        
        # Get sample events from this cluster
        cluster_events = df[df['cluster_id'] == cluster_id].nlargest(3, 'max_abs_z')
        print(f"    Top Events:")
        for _, event in cluster_events.iterrows():
            print(f"      - {event['username']} @ {event['hostname']}: {event['event_action']} (Z={event['max_abs_z']:.1f})")
    
    return cluster_analysis

def analyze_threat_actors(df, account_type):
    """Identify and analyze top threat actors."""
    print(f"\n{'='*60}")
    print(f"THREAT ACTOR ANALYSIS - {account_type.upper()}")
    print(f"{'='*60}")
    
    # Analyze users by max anomaly score and event count
    threat_analysis = df.groupby('username').agg({
        'max_abs_z': ['max', 'mean', 'count'],
        'hostname': 'nunique',
        'cluster_description': lambda x: list(x.unique())
    }).round(2)
    
    threat_analysis.columns = ['Max_Z_Score', 'Avg_Z_Score', 'Event_Count', 'Hosts_Affected', 'Clusters_Involved']
    threat_analysis = threat_analysis.sort_values('Max_Z_Score', ascending=False)
    
    print(f"\nTOP 10 THREAT ACTORS:")
    top_threats = threat_analysis.head(10)
    
    for username, row in top_threats.iterrows():
        risk_level = "CRITICAL" if row['Max_Z_Score'] >= 20 else "HIGH" if row['Max_Z_Score'] >= 10 else "MEDIUM" if row['Max_Z_Score'] >= 3 else "LOW"
        
        print(f"\n🎯 THREAT ACTOR: {username}")
        print(f"    Risk Level: {risk_level}")
        print(f"    Max Z-Score: {row['Max_Z_Score']:.2f}")
        print(f"    Avg Z-Score: {row['Avg_Z_Score']:.2f}")
        print(f"    Events: {row['Event_Count']}")
        print(f"    Hosts Affected: {row['Hosts_Affected']}")
        print(f"    Clusters: {', '.join(row['Clusters_Involved'])}")
        
        # Show most critical events for this actor
        actor_events = df[df['username'] == username].nlargest(3, 'max_abs_z')
        print(f"    Critical Events:")
        for _, event in actor_events.iterrows():
            print(f"      - {event['event_action']} @ {event['hostname']} (Z={event['max_abs_z']:.1f}) [{event['cluster_description']}]")
    
    return threat_analysis

def analyze_vulnerable_hosts(df, account_type):
    """Analyze most vulnerable/targeted hosts."""
    print(f"\n{'='*60}")
    print(f"VULNERABLE HOSTS ANALYSIS - {account_type.upper()}")
    print(f"{'='*60}")
    
    host_analysis = df.groupby('hostname').agg({
        'max_abs_z': ['max', 'mean', 'count'],
        'username': 'nunique',
        'cluster_description': lambda x: list(x.unique())
    }).round(2)
    
    host_analysis.columns = ['Max_Z_Score', 'Avg_Z_Score', 'Event_Count', 'Users_Involved', 'Clusters_Involved']
    host_analysis = host_analysis.sort_values('Max_Z_Score', ascending=False)
    
    print(f"\nTOP 10 VULNERABLE HOSTS:")
    top_hosts = host_analysis.head(10)
    
    for hostname, row in top_hosts.iterrows():
        risk_level = "CRITICAL" if row['Max_Z_Score'] >= 20 else "HIGH" if row['Max_Z_Score'] >= 10 else "MEDIUM" if row['Max_Z_Score'] >= 3 else "LOW"
        
        print(f"\n🏠 HOST: {hostname}")
        print(f"    Risk Level: {risk_level}")
        print(f"    Max Z-Score: {row['Max_Z_Score']:.2f}")
        print(f"    Events: {row['Event_Count']}")
        print(f"    Users Involved: {row['Users_Involved']}")
        print(f"    Threat Clusters: {', '.join(row['Clusters_Involved'])}")

def analyze_temporal_patterns(df, account_type):
    """Analyze temporal attack patterns."""
    print(f"\n{'='*60}")
    print(f"TEMPORAL PATTERN ANALYSIS - {account_type.upper()}")
    print(f"{'='*60}")
    
    # Convert timestamp to datetime
    df['timestamp_dt'] = pd.to_datetime(df['timestamp'])
    df['date'] = df['timestamp_dt'].dt.date
    df['hour'] = df['timestamp_dt'].dt.hour
    
    # Daily attack distribution
    daily_attacks = df.groupby('date').agg({
        'max_abs_z': ['count', 'max', 'mean']
    }).round(2)
    daily_attacks.columns = ['Event_Count', 'Max_Z_Score', 'Avg_Z_Score']
    
    print(f"\nDAILY ATTACK DISTRIBUTION:")
    for date, row in daily_attacks.iterrows():
        print(f"  {date}: {row['Event_Count']:>3} events, Max Z-Score: {row['Max_Z_Score']:>6.1f}, Avg: {row['Avg_Z_Score']:>5.2f}")
    
    # Hourly distribution of critical events (Z >= 10)
    critical_events = df[df['max_abs_z'] >= 10]
    if len(critical_events) > 0:
        hourly_critical = critical_events.groupby('hour').size()
        print(f"\nCRITICAL EVENTS BY HOUR (Z-Score ≥ 10):")
        for hour in sorted(hourly_critical.index):
            print(f"  Hour {hour:02d}: {hourly_critical[hour]} critical events")

def generate_security_recommendations(computer_df, user_df):
    """Generate actionable security recommendations based on analysis."""
    print(f"\n{'='*80}")
    print(f"ACTIONABLE SECURITY RECOMMENDATIONS")
    print(f"{'='*80}")
    
    # Identify immediate critical threats
    critical_computer = computer_df[computer_df['max_abs_z'] >= 20]
    critical_user = user_df[user_df['max_abs_z'] >= 20]
    
    print(f"\n🚨 IMMEDIATE ACTION REQUIRED:")
    
    if len(critical_computer) > 0 or len(critical_user) > 0:
        print(f"  • {len(critical_computer)} CRITICAL computer account anomalies detected")
        print(f"  • {len(critical_user)} CRITICAL user account anomalies detected")
        
        # Top critical threats
        all_critical = pd.concat([critical_computer, critical_user])
        top_critical = all_critical.nlargest(5, 'max_abs_z')
        
        print(f"\n  TOP 5 CRITICAL THREATS:")
        for idx, event in top_critical.iterrows():
            print(f"    ⚠️  {event['username']} @ {event['hostname']}")
            print(f"        Action: {event['event_action']}")
            print(f"        Z-Score: {event['max_abs_z']:.1f}")
            print(f"        Recommendation: IMMEDIATE INVESTIGATION REQUIRED")
            
            # Specific recommendations based on event type
            if event['event_action'] == 'logged-in' and pd.notna(event['source_ip']):
                print(f"        → Block source IP: {event['source_ip']}")
            if 'ANONYMOUS LOGON' in event['username']:
                print(f"        → Review anonymous logon policies")
            if event['username'].endswith('$'):
                print(f"        → Computer account compromise - check for lateral movement")
            print()
    
    print(f"\n📋 STRATEGIC RECOMMENDATIONS:")
    
    # Analyze cluster-based recommendations
    computer_clusters = computer_df['cluster_description'].value_counts()
    user_clusters = user_df['cluster_description'].value_counts()
    
    print(f"\n  COMPUTER ACCOUNT SECURITY:")
    if 'Outlier_Extreme_Risk' in computer_clusters.index:
        count = computer_clusters['Outlier_Extreme_Risk']
        print(f"    • {count} extreme risk events detected - implement emergency response protocol")
    
    if 'Critical_Persistent_Threats' in computer_clusters.index:
        count = computer_clusters['Critical_Persistent_Threats']
        print(f"    • {count} persistent threat indicators - deploy advanced threat hunting")
        
    if 'Lateral_Movement_Indicators' in computer_clusters.index:
        count = computer_clusters['Lateral_Movement_Indicators']
        print(f"    • {count} lateral movement events - segment network and monitor east-west traffic")
    
    print(f"\n  USER ACCOUNT SECURITY:")
    if 'Critical_User_Breach' in user_clusters.index:
        count = user_clusters['Critical_User_Breach'] if 'Critical_User_Breach' in user_clusters.index else 0
        count += user_clusters.get('Critical_User_Breach', 0)  # Handle multiple entries
        print(f"    • User account breaches detected - force password resets and MFA")
        
    if 'Suspicious_User_Behavior' in user_clusters.index:
        count = user_clusters['Suspicious_User_Behavior']
        print(f"    • {count} suspicious behavior patterns - enhance user behavior analytics")
    
    print(f"\n  INFRASTRUCTURE HARDENING:")
    
    # Analyze most targeted hosts
    computer_hosts = computer_df['hostname'].value_counts().head(3)
    user_hosts = user_df['hostname'].value_counts().head(3)
    
    print(f"    • Most targeted hosts (Computer accounts): {', '.join(computer_hosts.index)}")
    print(f"    • Most targeted hosts (User accounts): {', '.join(user_hosts.index)}")
    print(f"    • Recommendation: Deploy additional monitoring on high-risk hosts")
    
    print(f"\n  MONITORING ENHANCEMENTS:")
    print(f"    • Implement real-time alerting for Z-scores > 10")
    print(f"    • Set up automated response for Z-scores > 20")
    print(f"    • Deploy behavior-based analytics for service accounts")
    print(f"    • Monitor for ANONYMOUS LOGON and LOCAL SERVICE anomalies")

def generate_executive_summary(computer_df, user_df):
    """Generate executive summary of security posture."""
    print(f"\n{'='*80}")
    print(f"EXECUTIVE SECURITY POSTURE SUMMARY")
    print(f"{'='*80}")
    
    # Overall statistics
    total_events = len(computer_df) + len(user_df)
    critical_events = len(computer_df[computer_df['max_abs_z'] >= 20]) + len(user_df[user_df['max_abs_z'] >= 20])
    high_risk_events = len(computer_df[computer_df['max_abs_z'] >= 10]) + len(user_df[user_df['max_abs_z'] >= 10])
    
    print(f"\n📊 SECURITY METRICS:")
    print(f"  • Total Security Events Analyzed: {total_events:,}")
    print(f"  • Critical Anomalies (Z ≥ 20): {critical_events:,} ({critical_events/total_events*100:.1f}%)")
    print(f"  • High Risk Events (Z ≥ 10): {high_risk_events:,} ({high_risk_events/total_events*100:.1f}%)")
    
    # Risk assessment
    if critical_events > 50:
        risk_level = "CRITICAL"
        risk_color = "🔴"
    elif critical_events > 10:
        risk_level = "HIGH"
        risk_color = "🟠"
    elif high_risk_events > 20:
        risk_level = "MEDIUM"
        risk_color = "🟡"
    else:
        risk_level = "LOW"
        risk_color = "🟢"
    
    print(f"\n{risk_color} OVERALL SECURITY POSTURE: {risk_level}")
    
    # Key findings
    print(f"\n🔍 KEY FINDINGS:")
    
    # Computer account findings
    max_computer_z = computer_df['max_abs_z'].max()
    top_computer_threat = computer_df.loc[computer_df['max_abs_z'].idxmax(), 'username']
    
    print(f"  COMPUTER ACCOUNTS:")
    print(f"    • Highest threat: {top_computer_threat} (Z-Score: {max_computer_z:.1f})")
    print(f"    • Primary threat pattern: {computer_df['cluster_description'].mode().iloc[0]}")
    
    # User account findings  
    max_user_z = user_df['max_abs_z'].max()
    top_user_threat = user_df.loc[user_df['max_abs_z'].idxmax(), 'username']
    
    print(f"  USER ACCOUNTS:")
    print(f"    • Highest threat: {top_user_threat} (Z-Score: {max_user_z:.1f})")
    print(f"    • Primary threat pattern: {user_df['cluster_description'].mode().iloc[0]}")
    
    # Correlation analysis
    print(f"\n🔗 THREAT CORRELATION:")
    common_hosts = set(computer_df['hostname'].unique()) & set(user_df['hostname'].unique())
    print(f"  • {len(common_hosts)} hosts show both computer and user account anomalies")
    print(f"  • Shared infrastructure indicates potential coordinated attack")
    
    if len(common_hosts) > 0:
        print(f"  • High-risk hosts: {', '.join(list(common_hosts)[:5])}")

def main():
    """Main analysis function."""
    print("🔒 COMPREHENSIVE CYBERSECURITY CLUSTER ANALYSIS")
    print("=" * 80)
    print("Analyzing anomaly patterns and security threats...")
    
    # Load data
    computer_df, user_df = load_and_validate_data()
    if computer_df is None or user_df is None:
        return
    
    # Perform comprehensive analysis
    
    # 1. Analyze computer/system accounts
    computer_df = analyze_anomaly_distribution(computer_df, "Computer/System Accounts")
    analyze_clusters(computer_df, "Computer/System Accounts")
    analyze_threat_actors(computer_df, "Computer/System Accounts")
    analyze_vulnerable_hosts(computer_df, "Computer/System Accounts")
    analyze_temporal_patterns(computer_df, "Computer/System Accounts")
    
    # 2. Analyze user accounts
    user_df = analyze_anomaly_distribution(user_df, "User Accounts")
    analyze_clusters(user_df, "User Accounts")
    analyze_threat_actors(user_df, "User Accounts")
    analyze_vulnerable_hosts(user_df, "User Accounts")
    analyze_temporal_patterns(user_df, "User Accounts")
    
    # 3. Combined analysis and recommendations
    generate_security_recommendations(computer_df, user_df)
    generate_executive_summary(computer_df, user_df)
    
    print(f"\n{'='*80}")
    print("✅ ANALYSIS COMPLETE")
    print("Review the findings above and implement recommended security measures immediately.")
    print(f"{'='*80}")

if __name__ == "__main__":
    main()