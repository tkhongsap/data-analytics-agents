#!/usr/bin/env python3
"""
Split CSV file based on username ending with '$' (computer accounts) or not (user accounts)
"""

import csv
import os

def split_csv_by_username():
    # File paths
    input_file = 'data/dfp_detections_azure7Days_samplepercentfiltered.csv'
    computer_accounts_file = 'data/dfp_detections_computer_accounts.csv'
    user_accounts_file = 'data/dfp_detections_user_accounts.csv'
    
    print(f"Reading {input_file}...")
    
    # Read the CSV file and split into two lists
    computer_accounts = []
    user_accounts = []
    headers = None
    total_rows = 0
    
    with open(input_file, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        headers = reader.fieldnames
        
        for row in reader:
            total_rows += 1
            username = row.get('username', '')
            
            # Check if username ends with '$' (computer account)
            if username and username.endswith('$'):
                computer_accounts.append(row)
            else:
                user_accounts.append(row)
    
    print(f"Total rows read: {total_rows}")
    print(f"Total columns: {len(headers)}")
    
    # Write computer accounts CSV
    print(f"\nSaving computer accounts (ending with $) to {computer_accounts_file}...")
    with open(computer_accounts_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(computer_accounts)
    print(f"  - Saved {len(computer_accounts)} rows")
    
    # Write user accounts CSV
    print(f"\nSaving user accounts (not ending with $) to {user_accounts_file}...")
    with open(user_accounts_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(user_accounts)
    print(f"  - Saved {len(user_accounts)} rows")
    
    # Print summary statistics
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Original file: {total_rows} rows")
    print(f"Computer accounts (ending with $): {len(computer_accounts)} rows")
    print(f"User accounts (not ending with $): {len(user_accounts)} rows")
    print(f"Total after split: {len(computer_accounts) + len(user_accounts)} rows")
    
    # Verify no data loss
    if total_rows == len(computer_accounts) + len(user_accounts):
        print("✓ Data integrity verified - no rows lost during split")
    else:
        print("⚠ Warning: Row count mismatch!")
    
    # Show sample usernames from each category
    print("\n" + "="*60)
    print("SAMPLE USERNAMES")
    print("="*60)
    
    # Get unique computer account usernames
    computer_usernames = list(set(row['username'] for row in computer_accounts if row.get('username')))
    print(f"\nComputer accounts (first 5 unique):")
    for username in computer_usernames[:5]:
        print(f"  - {username}")
    
    # Get unique user account usernames
    user_usernames = list(set(row['username'] for row in user_accounts if row.get('username')))
    print(f"\nUser accounts (first 5 unique):")
    for username in user_usernames[:5]:
        print(f"  - {username}")
    
    # Show distribution by event_id for each type
    print("\n" + "="*60)
    print("EVENT ID DISTRIBUTION")
    print("="*60)
    
    # Count event IDs for computer accounts
    computer_events = {}
    for row in computer_accounts:
        event_id = row.get('event_id', 'unknown')
        computer_events[event_id] = computer_events.get(event_id, 0) + 1
    
    print("\nComputer accounts - Event IDs:")
    for event_id, count in sorted(computer_events.items()):
        print(f"  - Event {event_id}: {count} occurrences")
    
    # Count event IDs for user accounts
    user_events = {}
    for row in user_accounts:
        event_id = row.get('event_id', 'unknown')
        user_events[event_id] = user_events.get(event_id, 0) + 1
    
    print("\nUser accounts - Event IDs:")
    for event_id, count in sorted(user_events.items()):
        print(f"  - Event {event_id}: {count} occurrences")

if __name__ == "__main__":
    split_csv_by_username()
    print("\n✓ CSV file successfully split into two files!")