#!/usr/bin/env python3
"""
Unified Dashboard Data Preparation
==================================
Consolidates system and user account data for dashboard visualization
with proper field mapping and risk categorization.
"""

import csv
import json
from datetime import datetime

def load_and_consolidate():
    """Load both clustered datasets and consolidate them properly"""
    print("="*60)
    print("PREPARING UNIFIED DASHBOARD DATA")
    print("="*60)
    
    all_data = []
    
    # Load computer accounts
    print("\nLoading system/computer accounts...")
    computer_file = 'data/dfp_detections_computer_accounts_clustered.csv'
    with open(computer_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Add proper categorization
            row['account_type'] = 'System'
            row['account_category'] = 'Computer/Service Account'
            all_data.append(row)
    
    computer_count = len(all_data)
    print(f"✓ Loaded {computer_count} system account events")
    
    # Load user accounts
    print("\nLoading user accounts...")
    user_file = 'data/dfp_detections_user_accounts_clustered.csv'
    with open(user_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Add proper categorization
            row['account_type'] = 'User'
            row['account_category'] = get_user_category(row['username'])
            all_data.append(row)
    
    user_count = len(all_data) - computer_count
    print(f"✓ Loaded {user_count} user account events")
    
    return all_data, computer_count, user_count

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
    elif username.startswith('i') and len(username) > 1 and username[1:].isdigit():
        return 'Employee Account'
    elif username.isdigit():
        return 'Numeric ID Account'
    else:
        return 'Standard User Account'

def map_risk_category(row):
    """Map risk levels to dashboard-compatible categories"""
    risk_level = row.get('risk_level', 'UNKNOWN')
    z_score = float(row.get('max_abs_z', 0))
    cluster = row.get('cluster_description', '')
    
    # Map based on multiple factors
    if risk_level == 'CRITICAL' or z_score >= 20 or 'Critical' in cluster or 'Extreme' in cluster:
        return 'Critical'
    elif risk_level == 'HIGH' or z_score >= 10 or 'High' in cluster or 'Suspicious' in cluster:
        return 'High Risk'
    elif risk_level == 'MEDIUM' or z_score >= 3:
        return 'Medium Risk'
    else:
        return 'Normal/Moderate'

def get_event_description(event_id):
    """Get human-readable event description"""
    event_map = {
        '4624': 'Account Login',
        '4634': 'Account Logout',
        '4672': 'Special Privileges Assigned',
        '4688': 'Process Created',
        '4689': 'Process Terminated'
    }
    return event_map.get(str(event_id), f'Event {event_id}')

def enhance_row(row):
    """Enhance each row with dashboard-required fields"""
    # Map risk category
    row['risk_category'] = map_risk_category(row)
    
    # Add risk score (use max_abs_z)
    row['risk_score'] = float(row.get('max_abs_z', 0))
    
    # Add event description
    event_id = row.get('event_id', '')
    row['event_description'] = get_event_description(event_id)
    
    # Add detailed description based on cluster and risk
    cluster = row.get('cluster_description', '')
    risk_cat = row['risk_category']
    z_score = row['risk_score']
    
    if risk_cat == 'Critical':
        row['alert_description'] = f"CRITICAL: {cluster} - {row['event_description']} (Z={z_score:.1f})"
    elif risk_cat == 'High Risk':
        row['alert_description'] = f"HIGH: {cluster} - {row['event_description']} (Z={z_score:.1f})"
    elif risk_cat == 'Medium Risk':
        row['alert_description'] = f"MEDIUM: {cluster} - {row['event_description']} (Z={z_score:.1f})"
    else:
        row['alert_description'] = f"{row['event_description']} - Normal activity"
    
    # Add investigation priority
    if z_score >= 40 or 'ANONYMOUS' in row.get('username', '').upper():
        row['investigation_priority'] = '5'
    elif z_score >= 20:
        row['investigation_priority'] = '4'
    elif z_score >= 10:
        row['investigation_priority'] = '3'
    elif z_score >= 5:
        row['investigation_priority'] = '2'
    else:
        row['investigation_priority'] = '1'
    
    # Ensure timestamp format is consistent
    if 'timestamp' in row and row['timestamp']:
        # Already in ISO format, just ensure it's there
        pass
    else:
        row['timestamp'] = datetime.now().isoformat()
    
    return row

def calculate_statistics(data):
    """Calculate dashboard statistics"""
    stats = {
        'total_events': len(data),
        'system_events': len([d for d in data if d['account_type'] == 'System']),
        'user_events': len([d for d in data if d['account_type'] == 'User']),
        'critical_count': len([d for d in data if d['risk_category'] == 'Critical']),
        'high_count': len([d for d in data if d['risk_category'] == 'High Risk']),
        'medium_count': len([d for d in data if d['risk_category'] == 'Medium Risk']),
        'normal_count': len([d for d in data if d['risk_category'] == 'Normal/Moderate']),
        'unique_hosts': len(set(d['hostname'] for d in data if d.get('hostname'))),
        'unique_users': len(set(d['username'] for d in data if d.get('username'))),
        'highest_risk_score': max(float(d['risk_score']) for d in data),
        'average_risk_score': sum(float(d['risk_score']) for d in data) / len(data) if data else 0
    }
    
    # Calculate percentages
    if stats['total_events'] > 0:
        stats['critical_rate'] = round(stats['critical_count'] / stats['total_events'] * 100, 1)
        stats['high_rate'] = round(stats['high_count'] / stats['total_events'] * 100, 1)
        stats['system_percentage'] = round(stats['system_events'] / stats['total_events'] * 100, 1)
        stats['user_percentage'] = round(stats['user_events'] / stats['total_events'] * 100, 1)
    
    return stats

def save_unified_data(data, stats):
    """Save unified data for dashboard"""
    # Save to main project directory
    output_file = 'unified_dashboard_data.csv'
    
    if data:
        fieldnames = list(data[0].keys())
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"\n✓ Saved unified data to {output_file}")
    
    # Save to dashboard public directory
    dashboard_file = 'dashboard/public/unified_dashboard_data.csv'
    try:
        with open(dashboard_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        print(f"✓ Saved to dashboard: {dashboard_file}")
    except Exception as e:
        print(f"⚠ Could not save to dashboard: {e}")
    
    # Save statistics
    stats_file = 'dashboard_statistics.json'
    with open(stats_file, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"✓ Saved statistics to {stats_file}")

def main():
    """Main execution"""
    # Load and consolidate data
    data, computer_count, user_count = load_and_consolidate()
    
    # Enhance each row
    print("\nEnhancing data with dashboard fields...")
    for row in data:
        enhance_row(row)
    
    # Calculate statistics
    print("\nCalculating statistics...")
    stats = calculate_statistics(data)
    
    # Print summary
    print("\n" + "="*60)
    print("UNIFIED DASHBOARD DATA SUMMARY")
    print("="*60)
    print(f"Total Events: {stats['total_events']}")
    print(f"System Accounts: {stats['system_events']} ({stats.get('system_percentage', 0)}%)")
    print(f"User Accounts: {stats['user_events']} ({stats.get('user_percentage', 0)}%)")
    print("\nRisk Distribution:")
    print(f"  Critical: {stats['critical_count']} ({stats.get('critical_rate', 0)}%)")
    print(f"  High Risk: {stats['high_count']} ({stats.get('high_rate', 0)}%)")
    print(f"  Medium Risk: {stats['medium_count']}")
    print(f"  Normal: {stats['normal_count']}")
    print(f"\nSecurity Metrics:")
    print(f"  Highest Risk Score: {stats['highest_risk_score']:.2f}")
    print(f"  Average Risk Score: {stats['average_risk_score']:.2f}")
    print(f"  Unique Hosts: {stats['unique_hosts']}")
    print(f"  Unique Users: {stats['unique_users']}")
    
    # Identify critical findings
    critical_events = [d for d in data if d['risk_category'] == 'Critical']
    if critical_events:
        print("\n⚠ CRITICAL FINDINGS:")
        # Sort by risk score
        critical_events.sort(key=lambda x: float(x['risk_score']), reverse=True)
        for event in critical_events[:5]:
            print(f"  - {event['username']} on {event['hostname']}: {event['alert_description']}")
    
    # Save unified data
    save_unified_data(data, stats)
    
    print("\n" + "="*60)
    print("✓ Unified dashboard data preparation complete!")
    print("Dashboard should now display all consolidated findings.")
    print("="*60)

if __name__ == "__main__":
    main()