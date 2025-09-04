#!/usr/bin/env python3
"""
Prepare Enhanced Dashboard Data with Account Type Separation
============================================================
Combines clustered data and adds account type labels for dashboard visualization.

Author: Claude Code
Date: 2025-09-04
"""

import csv
from datetime import datetime

def load_and_merge_data():
    """Load both clustered datasets and merge with account type labels"""
    print("="*60)
    print("PREPARING ENHANCED DASHBOARD DATA")
    print("="*60)
    
    all_data = []
    
    # Load computer accounts
    print("\nLoading computer accounts...")
    with open('data/dfp_detections_computer_accounts_clustered.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Add account type and risk level
            row['account_type'] = 'System'
            row['account_category'] = 'Computer/Service Account'
            row['risk_level'] = get_risk_level(row)
            row['investigation_priority'] = get_priority(row)
            all_data.append(row)
    
    computer_count = len(all_data)
    print(f"✓ Loaded {computer_count} computer account events")
    
    # Load user accounts
    print("\nLoading user accounts...")
    with open('data/dfp_detections_user_accounts_clustered.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Add account type and risk level
            row['account_type'] = 'User'
            row['account_category'] = get_user_category(row['username'])
            row['risk_level'] = get_risk_level(row)
            row['investigation_priority'] = get_priority(row)
            all_data.append(row)
    
    user_count = len(all_data) - computer_count
    print(f"✓ Loaded {user_count} user account events")
    
    return all_data

def get_risk_level(row):
    """Determine risk level based on z-score and cluster"""
    try:
        z_score = float(row.get('max_abs_z', 0))
        cluster_desc = row.get('cluster_description', '')
        
        # Check cluster-based risk first
        critical_clusters = ['Critical', 'Extreme', 'Breach', 'Outlier']
        high_clusters = ['Suspicious', 'High_Risk', 'Escalation', 'Lateral']
        
        for keyword in critical_clusters:
            if keyword in cluster_desc:
                return 'CRITICAL'
        
        for keyword in high_clusters:
            if keyword in cluster_desc:
                return 'HIGH'
        
        # Use z-score if no cluster match
        if z_score >= 20:
            return 'CRITICAL'
        elif z_score >= 10:
            return 'HIGH'
        elif z_score >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'
    except:
        return 'UNKNOWN'

def get_user_category(username):
    """Categorize user account type"""
    if not username:
        return 'Unknown'
    
    username_upper = username.upper()
    
    if 'ANONYMOUS' in username_upper:
        return 'Anonymous Access'
    elif 'LOCAL' in username_upper or 'SERVICE' in username_upper:
        return 'Service Account'
    elif 'ADMIN' in username_upper:
        return 'Administrative Account'
    elif username.startswith('i') and username[1:].isdigit():
        return 'Employee Account'
    elif username.isdigit():
        return 'Numeric ID Account'
    else:
        return 'Standard User Account'

def get_priority(row):
    """Calculate investigation priority (1-5, 5 being highest)"""
    try:
        z_score = float(row.get('max_abs_z', 0))
        cluster_desc = row.get('cluster_description', '')
        
        # Special cases
        if 'ANONYMOUS' in row.get('username', '').upper():
            return '5'
        
        if 'Extreme' in cluster_desc or 'Breach' in cluster_desc:
            return '5'
        
        if z_score >= 40:
            return '5'
        elif z_score >= 20:
            return '4'
        elif z_score >= 10:
            return '3'
        elif z_score >= 5:
            return '2'
        else:
            return '1'
    except:
        return '3'

def add_event_descriptions(row):
    """Add human-readable event descriptions"""
    event_id = row.get('event_id', '')
    event_action = row.get('event_action', '')
    
    event_descriptions = {
        '4624': 'Account Login',
        '4634': 'Account Logout',
        '4672': 'Special Privilege Assigned',
        '4688': 'Process Created',
        '4689': 'Process Terminated'
    }
    
    row['event_description'] = event_descriptions.get(event_id, f'Event {event_id}')
    
    # Add detailed description based on risk
    risk_level = row.get('risk_level', '')
    z_score = float(row.get('max_abs_z', 0))
    
    if risk_level == 'CRITICAL':
        row['alert_description'] = f"CRITICAL: {row['event_description']} with extreme anomaly (Z={z_score:.1f})"
    elif risk_level == 'HIGH':
        row['alert_description'] = f"HIGH: Suspicious {row['event_description']} detected (Z={z_score:.1f})"
    elif risk_level == 'MEDIUM':
        row['alert_description'] = f"MEDIUM: Unusual {row['event_description']} pattern (Z={z_score:.1f})"
    else:
        row['alert_description'] = f"LOW: {row['event_description']} within normal range"
    
    return row

def calculate_statistics(data):
    """Calculate summary statistics for dashboard"""
    stats = {
        'total_events': len(data),
        'system_events': len([d for d in data if d['account_type'] == 'System']),
        'user_events': len([d for d in data if d['account_type'] == 'User']),
        'critical_events': len([d for d in data if d['risk_level'] == 'CRITICAL']),
        'high_events': len([d for d in data if d['risk_level'] == 'HIGH']),
        'unique_hosts': len(set(d['hostname'] for d in data)),
        'unique_users': len(set(d['username'] for d in data)),
        'timestamp': datetime.now().isoformat()
    }
    
    # Calculate percentages
    if stats['total_events'] > 0:
        stats['system_percentage'] = round(stats['system_events'] / stats['total_events'] * 100, 1)
        stats['user_percentage'] = round(stats['user_events'] / stats['total_events'] * 100, 1)
        stats['critical_rate'] = round(stats['critical_events'] / stats['total_events'] * 100, 1)
    
    return stats

def save_enhanced_data(data, stats):
    """Save enhanced data for dashboard"""
    # Save main data file
    output_file = 'enhanced_clustered_data.csv'
    
    if data:
        fieldnames = list(data[0].keys())
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"\n✓ Saved enhanced data to {output_file}")
    
    # Save to dashboard public directory
    dashboard_file = 'dashboard/public/enhanced_clustered_data.csv'
    try:
        with open(dashboard_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"✓ Saved dashboard data to {dashboard_file}")
    except:
        print(f"⚠ Could not save to dashboard directory (may not exist yet)")
    
    # Save statistics
    import json
    with open('dashboard_statistics.json', 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"✓ Saved statistics to dashboard_statistics.json")

def main():
    """Main execution"""
    # Load and merge data
    data = load_and_merge_data()
    
    # Enhance each row
    print("\nEnhancing data...")
    for row in data:
        add_event_descriptions(row)
    
    # Calculate statistics
    print("\nCalculating statistics...")
    stats = calculate_statistics(data)
    
    print("\n" + "="*60)
    print("DASHBOARD DATA SUMMARY")
    print("="*60)
    print(f"Total Events: {stats['total_events']}")
    print(f"System Accounts: {stats['system_events']} ({stats.get('system_percentage', 0)}%)")
    print(f"User Accounts: {stats['user_events']} ({stats.get('user_percentage', 0)}%)")
    print(f"Critical Events: {stats['critical_events']} ({stats.get('critical_rate', 0)}%)")
    print(f"High Risk Events: {stats['high_events']}")
    print(f"Affected Hosts: {stats['unique_hosts']}")
    print(f"Unique Accounts: {stats['unique_users']}")
    
    # Risk distribution
    risk_dist = {}
    for row in data:
        risk = row['risk_level']
        risk_dist[risk] = risk_dist.get(risk, 0) + 1
    
    print("\nRisk Distribution:")
    for risk in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        if risk in risk_dist:
            percentage = round(risk_dist[risk] / len(data) * 100, 1)
            print(f"  {risk}: {risk_dist[risk]} ({percentage}%)")
    
    # Cluster distribution
    cluster_dist = {}
    for row in data:
        cluster = row.get('cluster_description', 'Unknown')
        cluster_dist[cluster] = cluster_dist[cluster] + 1 if cluster in cluster_dist else 1
    
    print("\nTop 5 Clusters:")
    sorted_clusters = sorted(cluster_dist.items(), key=lambda x: x[1], reverse=True)
    for cluster, count in sorted_clusters[:5]:
        percentage = round(count / len(data) * 100, 1)
        print(f"  {cluster}: {count} ({percentage}%)")
    
    # Save enhanced data
    save_enhanced_data(data, stats)
    
    print("\n" + "="*60)
    print("✓ Dashboard data preparation complete!")
    print("="*60)

if __name__ == "__main__":
    main()