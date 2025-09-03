#!/usr/bin/env python3
"""
Example analysis script for the enhanced anomaly dataset

This demonstrates how to use the enhanced cyber data analysis results
to identify and investigate security incidents.
"""

import csv
import sys
from collections import defaultdict

def load_enhanced_data(filename="enhanced_data_v2.csv"):
    """Load the enhanced anomaly dataset"""
    data = []
    with open(filename, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        data = list(reader)
    return data

def find_critical_incidents(data):
    """Find the most critical security incidents"""
    critical = []
    high_priority = []
    
    for row in data:
        priority = int(row['investigation_priority'])
        if priority == 5:
            critical.append(row)
        elif priority == 4:
            high_priority.append(row)
    
    return critical, high_priority

def analyze_attack_patterns(data):
    """Analyze attack patterns by stage and type"""
    stage_counts = defaultdict(int)
    type_counts = defaultdict(int)
    
    for row in data:
        stage_counts[row['attack_stage']] += 1
        type_counts[row['anomaly_type']] += 1
    
    return stage_counts, type_counts

def find_repeated_targets(data):
    """Find systems and users that appear frequently in anomalies"""
    user_counts = defaultdict(int)
    host_counts = defaultdict(int)
    
    for row in data:
        user_counts[row['username']] += 1
        host_counts[row['hostname']] += 1
    
    # Sort by frequency
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
    top_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)
    
    return top_users[:10], top_hosts[:10]

def main():
    """Main analysis function"""
    print("=== Enhanced Cyber Data Analysis Report ===\n")
    
    # Load data
    try:
        data = load_enhanced_data()
        print(f"Loaded {len(data)} enhanced anomaly records\n")
    except FileNotFoundError:
        print("Error: enhanced_data_v2.csv not found. Please run enhance_anomaly_descriptions.py first.")
        sys.exit(1)
    
    # Find critical incidents
    critical, high_priority = find_critical_incidents(data)
    print(f"🚨 CRITICAL INCIDENTS (Priority 5): {len(critical)}")
    print(f"⚠️  HIGH PRIORITY INCIDENTS (Priority 4): {len(high_priority)}\n")
    
    # Show critical incidents in detail
    if critical:
        print("=== IMMEDIATE ACTION REQUIRED ===")
        for i, incident in enumerate(critical, 1):
            print(f"\n🔴 CRITICAL INCIDENT #{i}")
            print(f"User: {incident['username']}")
            print(f"Host: {incident['hostname']}")
            print(f"Event: {incident['event_action']} ({incident['event_id']})")
            print(f"Time: {incident['timestamp']}")
            print(f"Type: {incident['anomaly_type']}")
            print(f"Attack Stage: {incident['attack_stage']}")
            print(f"Threat Indicators: {incident['threat_indicators']}")
            print(f"Immediate Actions: {incident['recommended_action'][:200]}...")
            print("-" * 80)
    
    # Analyze attack patterns
    stage_counts, type_counts = analyze_attack_patterns(data)
    
    print("\n=== ATTACK PATTERN ANALYSIS ===")
    print("\nTop Attack Stages (MITRE ATT&CK):")
    for stage, count in sorted(stage_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {stage}: {count} incidents")
    
    print("\nTop Anomaly Types:")
    for atype, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {atype}: {count} incidents")
    
    # Find repeated targets
    top_users, top_hosts = find_repeated_targets(data)
    
    print("\n=== FREQUENT TARGETS ===")
    print("\nMost Targeted Users:")
    for user, count in top_users[:5]:
        user_incidents = [r for r in data if r['username'] == user]
        priorities = [int(r['investigation_priority']) for r in user_incidents]
        avg_priority = sum(priorities) / len(priorities)
        print(f"  {user}: {count} incidents (avg priority: {avg_priority:.1f})")
    
    print("\nMost Targeted Hosts:")
    for host, count in top_hosts[:5]:
        host_incidents = [r for r in data if r['hostname'] == host]
        priorities = [int(r['investigation_priority']) for r in host_incidents]
        avg_priority = sum(priorities) / len(priorities)
        print(f"  {host}: {count} incidents (avg priority: {avg_priority:.1f})")
    
    # Service account analysis
    service_accounts = [r for r in data if r['username'].endswith('$')]
    print(f"\n=== SERVICE ACCOUNT ANOMALIES ===")
    print(f"Service account incidents: {len(service_accounts)}")
    
    if service_accounts:
        sa_types = defaultdict(int)
        for sa in service_accounts:
            sa_types[sa['anomaly_type']] += 1
        
        print("Service account anomaly types:")
        for sa_type, count in sorted(sa_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  {sa_type}: {count} incidents")
    
    # Time-based analysis
    night_incidents = [r for r in data if 'off-hours' in r['threat_indicators']]
    print(f"\n=== TEMPORAL ANALYSIS ===")
    print(f"Off-hours incidents (2-4 AM): {len(night_incidents)}")
    
    if night_incidents:
        night_priorities = [int(r['investigation_priority']) for r in night_incidents]
        avg_night_priority = sum(night_priorities) / len(night_priorities)
        print(f"Average priority of off-hours incidents: {avg_night_priority:.1f}")
    
    print("\n=== RECOMMENDATIONS ===")
    print("1. Immediately investigate all Priority 5 (Critical) incidents")
    print("2. Focus on service accounts with repeated anomalies")
    print("3. Monitor off-hours activities more closely")
    print("4. Implement additional controls for top targeted systems")
    print("5. Review and correlate incidents by attack stage progression")
    
    print(f"\n📊 Full enhanced dataset available in: enhanced_data_v2.csv")
    print("🔍 Use the detailed_description field for investigation guidance")
    print("⚡ Sort by investigation_priority for incident triage")

if __name__ == "__main__":
    main()