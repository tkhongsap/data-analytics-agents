#!/usr/bin/env python3
"""
Enhanced Anomaly Description Generator for Cyber Data Analysis

This script analyzes anomaly detection results from a cyber security dataset,
generating detailed explanations and classifications for each detected anomaly
based on multiple z-score indicators and contextual information.

Author: Generated for cyber-data-analysis project
Date: 2025-09-03
"""

import csv
from datetime import datetime, time
import re
import sys
import os

class AnomalyDescriptionEnhancer:
    def __init__(self, input_file="data/dfp_detections_azure7Days_samplepercentfiltered.csv"):
        self.input_file = input_file
        self.data = []
        self.headers = []
        
        # Define anomaly type mappings
        self.anomaly_types = {
            'authentication': 'Authentication Anomaly',
            'privilege': 'Privilege Escalation',
            'process': 'Process Behavior Anomaly',
            'network': 'Network Behavior Anomaly',
            'temporal': 'Temporal Pattern Anomaly',
            'volume': 'Volume-based Anomaly'
        }
        
        # MITRE ATT&CK stage mappings
        self.attack_stages = {
            'initial_access': 'Initial Access',
            'execution': 'Execution',
            'persistence': 'Persistence',
            'privilege_escalation': 'Privilege Escalation',
            'defense_evasion': 'Defense Evasion',
            'credential_access': 'Credential Access',
            'discovery': 'Discovery',
            'lateral_movement': 'Lateral Movement',
            'collection': 'Collection',
            'exfiltration': 'Exfiltration',
            'impact': 'Impact'
        }
        
        # Event ID mappings for Windows security events
        self.event_id_meanings = {
            '4624': 'Successful Logon',
            '4634': 'Logoff',
            '4625': 'Failed Logon',
            '4648': 'Explicit Credential Use',
            '4672': 'Special Privileges Assigned',
            '4768': 'Kerberos Authentication Ticket Granted',
            '4769': 'Kerberos Service Ticket Requested'
        }
        
    def load_data(self):
        """Load the CSV data file"""
        try:
            with open(self.input_file, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                self.headers = reader.fieldnames
                self.data = list(reader)
            print(f"Loaded {len(self.data)} records from {self.input_file}")
            return True
        except FileNotFoundError:
            print(f"Error: File {self.input_file} not found")
            return False
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def is_service_account(self, username):
        """Check if username is a service account (ends with $)"""
        return str(username).endswith('$')
    
    def is_anonymous_logon(self, username):
        """Check if this is an anonymous logon"""
        return str(username).upper() in ['ANONYMOUS LOGON', 'ANONYMOUS', 'ANONYMOUS$']
    
    def is_night_time(self, timestamp):
        """Check if event occurred during suspicious hours (2-4 AM)"""
        try:
            # Parse ISO timestamp format: 2025-08-25T12:18:28.055000000Z
            if 'T' in str(timestamp):
                dt_str = str(timestamp).split('T')[1].split('.')[0]  # Get time part
                dt = datetime.strptime(dt_str, '%H:%M:%S')
                return 2 <= dt.hour <= 4
            return False
        except:
            return False
    
    def is_external_ip(self, ip):
        """Check if IP is external (not 10.x.x.x internal network)"""
        if not ip or str(ip) == '' or str(ip) == 'nan' or ip is None:
            return False
        ip_str = str(ip)
        return not (ip_str.startswith('10.') or ip_str == '127.0.0.1' or ip_str.startswith('192.168.'))
    
    def get_high_z_scores(self, row, threshold=5.0):
        """Identify which z-scores are significantly high"""
        high_scores = {}
        z_columns = {
            'logcount_z_loss': 'Volume',
            'hostincrement_z_loss': 'Host Behavior', 
            'ipincrement_z_loss': 'Network Pattern',
            'processincrement_z_loss': 'Process Behavior'
        }
        
        for col, name in z_columns.items():
            if col in row and row[col] and str(row[col]) != '' and str(row[col]) != 'nan':
                try:
                    z_val = float(row[col])
                    if z_val >= threshold:
                        high_scores[name] = z_val
                except (ValueError, TypeError):
                    continue
                    
        return high_scores
    
    def classify_anomaly_type(self, row):
        """Classify the primary anomaly type based on context and z-scores"""
        username = str(row['username'])
        event_action = str(row['event_action'])
        event_id = str(row['event_id'])
        
        # Check for anonymous logon - always authentication anomaly
        if self.is_anonymous_logon(username):
            return 'authentication'
        
        # Get high z-scores to determine primary anomaly
        high_z = self.get_high_z_scores(row)
        
        # Determine primary anomaly based on highest z-score and context
        if 'Volume' in high_z and high_z['Volume'] > 15:
            return 'volume'
        elif 'Network Pattern' in high_z and high_z['Network Pattern'] > 8:
            return 'network'
        elif 'Process Behavior' in high_z:
            return 'process'
        elif 'Host Behavior' in high_z:
            if event_action in ['logged-in', 'logged-out'] or event_id in ['4624', '4634']:
                return 'authentication'
            else:
                return 'privilege'
        elif self.is_night_time(row['timestamp']):
            return 'temporal'
        else:
            return 'authentication'  # Default for login/logout events
    
    def determine_attack_stage(self, row, anomaly_type):
        """Map anomaly to MITRE ATT&CK stage"""
        event_action = str(row['event_action'])
        event_id = str(row['event_id'])
        username = str(row['username'])
        
        # Anonymous logon or external access
        if self.is_anonymous_logon(username) or self.is_external_ip(row['source_ip']):
            return 'initial_access'
        
        # Service account doing user actions
        if self.is_service_account(username) and event_action == 'logged-in':
            return 'privilege_escalation'
        
        # Volume-based anomalies often indicate lateral movement or discovery
        if anomaly_type == 'volume':
            return 'lateral_movement'
        
        # Network anomalies suggest lateral movement or exfiltration
        if anomaly_type == 'network':
            return 'lateral_movement'
        
        # Process anomalies indicate execution
        if anomaly_type == 'process':
            return 'execution'
        
        # Authentication anomalies during off-hours
        if anomaly_type == 'temporal':
            return 'persistence'
        
        # Default authentication anomalies
        return 'credential_access'
    
    def calculate_priority(self, row, anomaly_type, high_z_scores):
        """Calculate investigation priority (1-5, 5 being highest)"""
        priority = 2  # Base priority
        
        # Critical indicators
        if self.is_anonymous_logon(row['username']):
            priority = 5
        elif len(high_z_scores) >= 3:  # Multiple high z-scores
            priority = 5
        elif max(high_z_scores.values()) if high_z_scores else 0 > 20:
            priority = 4
        
        # High priority modifiers
        if self.is_service_account(row['username']) and str(row['event_action']) == 'logged-in':
            priority = max(priority, 4)
        
        if self.is_night_time(row['timestamp']):
            priority = max(priority, 3)
            
        if self.is_external_ip(row['source_ip']) and 'Network Pattern' in high_z_scores:
            priority = max(priority, 4)
            
        if anomaly_type == 'volume' and high_z_scores.get('Volume', 0) > 25:
            priority = max(priority, 4)
        
        return min(priority, 5)  # Cap at 5
    
    def generate_threat_indicators(self, row, high_z_scores):
        """Generate list of threat indicators"""
        indicators = []
        
        # Z-score based indicators
        for indicator, value in high_z_scores.items():
            indicators.append(f"{indicator} Z-score: {value:.2f}")
        
        # Contextual indicators
        username = str(row['username'])
        if self.is_anonymous_logon(username):
            indicators.append("Anonymous logon detected")
        elif self.is_service_account(username):
            indicators.append("Service account authentication")
        
        if self.is_night_time(row['timestamp']):
            indicators.append("Off-hours activity (2-4 AM)")
        
        if self.is_external_ip(row['source_ip']):
            indicators.append(f"External source IP: {row['source_ip']}")
        
        if row.get('max_abs_z') and str(row['max_abs_z']) != 'nan' and str(row['max_abs_z']) != '':
            try:
                max_z = float(row['max_abs_z'])
                if max_z > 10:
                    indicators.append(f"Maximum Z-score: {max_z:.2f}")
            except (ValueError, TypeError):
                pass
        
        return "; ".join(indicators) if indicators else "Standard anomaly patterns detected"
    
    def generate_recommended_action(self, row, anomaly_type, priority):
        """Generate specific recommended actions"""
        actions = []
        username = str(row['username'])
        hostname = str(row['hostname'])
        
        # Priority-based initial actions
        if priority >= 4:
            actions.append("IMMEDIATE: Isolate affected systems")
            actions.append("IMMEDIATE: Disable user account if compromised")
        
        # Anomaly-specific actions
        if anomaly_type == 'authentication':
            actions.append("Review authentication logs for this user")
            actions.append("Check for concurrent sessions from different locations")
            actions.append("Verify user's recent password changes")
            
        elif anomaly_type == 'volume':
            actions.append("Analyze volume patterns over extended timeframe")
            actions.append("Check for automated processes or scripts")
            actions.append("Review system performance during anomaly period")
            
        elif anomaly_type == 'network':
            actions.append("Investigate network traffic patterns")
            actions.append("Check for data exfiltration indicators")
            actions.append("Review firewall and proxy logs")
            
        elif anomaly_type == 'process':
            actions.append("Examine process execution history")
            actions.append("Check for unauthorized software installation")
            actions.append("Review system integrity")
        
        # Context-specific actions
        if self.is_anonymous_logon(username):
            actions.append("CRITICAL: Investigate anonymous access vectors")
            actions.append("Review anonymous authentication policies")
        
        if self.is_service_account(username):
            actions.append("Verify service account permissions")
            actions.append("Check for service account credential theft")
        
        if self.is_external_ip(row['source_ip']):
            actions.append(f"Investigate external IP {row['source_ip']}")
            actions.append("Check IP reputation databases")
        
        # System-specific actions
        actions.append(f"Monitor {hostname} for continued anomalous behavior")
        actions.append("Document findings and create incident report")
        
        return " | ".join(actions[:6])  # Limit to 6 most important actions
    
    def generate_detailed_description(self, row):
        """Generate comprehensive anomaly description"""
        # Extract key information
        username = str(row['username'])
        hostname = str(row['hostname'])
        event_action = str(row['event_action'])
        event_id = str(row['event_id'])
        timestamp = row['timestamp']
        source_ip = str(row['source_ip']) if row.get('source_ip') and str(row['source_ip']) != 'nan' else "Internal"
        
        # Get high z-scores
        high_z_scores = self.get_high_z_scores(row)
        
        # Classify anomaly
        anomaly_type = self.classify_anomaly_type(row)
        
        # Build description components
        description_parts = []
        
        # PRIMARY: Anomaly type identification
        event_meaning = self.event_id_meanings.get(event_id, f"Event {event_id}")
        description_parts.append(f"PRIMARY: {self.anomaly_types.get(anomaly_type, 'Unknown')} detected during {event_meaning.lower()} event")
        
        # PATTERN: Specific deviation analysis
        if high_z_scores:
            pattern_desc = "PATTERN: Statistical deviations detected - "
            pattern_details = []
            
            for indicator, z_val in high_z_scores.items():
                if z_val > 20:
                    severity = "extreme"
                elif z_val > 10:
                    severity = "severe"
                elif z_val > 5:
                    severity = "moderate"
                else:
                    severity = "minor"
                pattern_details.append(f"{indicator.lower()} shows {severity} deviation ({z_val:.1f}σ)")
            
            description_parts.append(pattern_desc + ", ".join(pattern_details))
        
        # INDICATORS: Z-score triggers
        if high_z_scores:
            indicators_desc = f"INDICATORS: Triggered z-scores - "
            z_descriptions = [f"{name}: {val:.2f}" for name, val in high_z_scores.items()]
            description_parts.append(indicators_desc + ", ".join(z_descriptions))
        
        # CONTEXT: User and environmental context
        context_parts = []
        if self.is_anonymous_logon(username):
            context_parts.append("anonymous logon attempt")
        elif self.is_service_account(username):
            context_parts.append("service account authentication")
        else:
            context_parts.append(f"user {username}")
        
        if self.is_night_time(timestamp):
            context_parts.append("during off-hours (2-4 AM)")
        
        if source_ip != "Internal" and source_ip != "nan":
            if self.is_external_ip(source_ip):
                context_parts.append(f"from external IP {source_ip}")
            else:
                context_parts.append(f"from internal IP {source_ip}")
        
        context_parts.append(f"on host {hostname}")
        
        description_parts.append(f"CONTEXT: Event involves {', '.join(context_parts)}")
        
        # THREAT: Attack scenario mapping
        threat_scenarios = []
        
        if self.is_anonymous_logon(username):
            threat_scenarios.append("unauthorized access attempt")
        elif anomaly_type == 'volume' and high_z_scores.get('Volume', 0) > 15:
            threat_scenarios.append("potential automated attack or reconnaissance")
        elif anomaly_type == 'network' and self.is_external_ip(source_ip):
            threat_scenarios.append("possible lateral movement or data exfiltration")
        elif self.is_service_account(username) and event_action == 'logged-in':
            threat_scenarios.append("service account compromise or privilege escalation")
        elif anomaly_type == 'temporal':
            threat_scenarios.append("persistence mechanism or covert operations")
        else:
            threat_scenarios.append("anomalous behavior requiring investigation")
        
        if len(high_z_scores) >= 2:
            threat_scenarios.append("coordinated attack indicators")
        
        description_parts.append(f"THREAT: Suggests {' and '.join(threat_scenarios)}")
        
        # ACTION: Investigation guidance
        priority = self.calculate_priority(row, anomaly_type, high_z_scores)
        if priority >= 4:
            urgency = "immediate"
        elif priority >= 3:
            urgency = "high-priority"
        else:
            urgency = "standard"
        
        description_parts.append(f"ACTION: Requires {urgency} investigation focusing on authentication logs, system access patterns, and potential credential compromise")
        
        return " | ".join(description_parts)
    
    def enhance_dataset(self):
        """Process the entire dataset and add enhanced columns"""
        if not self.data:
            print("Error: No data loaded")
            return False
        
        print("Enhancing anomaly descriptions...")
        
        # Process each row and add enhanced fields
        for idx, row in enumerate(self.data):
            if idx % 100 == 0:
                print(f"Processing record {idx + 1}/{len(self.data)}")
            
            # Generate enhanced fields
            detailed_desc = self.generate_detailed_description(row)
            anomaly_type = self.classify_anomaly_type(row)
            attack_stage = self.determine_attack_stage(row, anomaly_type)
            high_z_scores = self.get_high_z_scores(row)
            priority = self.calculate_priority(row, anomaly_type, high_z_scores)
            threat_indicators = self.generate_threat_indicators(row, high_z_scores)
            recommended_action = self.generate_recommended_action(row, anomaly_type, priority)
            
            # Add enhanced fields to row
            row['detailed_description'] = detailed_desc
            row['anomaly_type'] = self.anomaly_types.get(anomaly_type, 'Unknown')
            row['attack_stage'] = attack_stage.replace('_', ' ').title()
            row['investigation_priority'] = str(priority)
            row['threat_indicators'] = threat_indicators
            row['recommended_action'] = recommended_action
        
        # Update headers to include new columns
        new_columns = ['detailed_description', 'anomaly_type', 'attack_stage', 'investigation_priority', 'threat_indicators', 'recommended_action']
        for col in new_columns:
            if col not in self.headers:
                self.headers.append(col)
        
        print(f"Enhancement complete! Added {len(new_columns)} new columns.")
        return True
    
    def save_enhanced_data(self, output_file="enhanced_data_v2.csv"):
        """Save the enhanced dataset"""
        if not self.data:
            print("Error: No enhanced data to save")
            return False
        
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.headers)
                writer.writeheader()
                writer.writerows(self.data)
            
            print(f"Enhanced data saved to {output_file}")
            print(f"Total records: {len(self.data)}")
            print(f"Total columns: {len(self.headers)}")
            
            # Print sample statistics
            print("\nPriority Distribution:")
            priority_counts = {}
            for row in self.data:
                priority = row.get('investigation_priority', 'Unknown')
                priority_counts[priority] = priority_counts.get(priority, 0) + 1
            for priority in sorted(priority_counts.keys()):
                print(f"  Priority {priority}: {priority_counts[priority]} records")
            
            print("\nAnomaly Type Distribution:")
            anomaly_counts = {}
            for row in self.data:
                anomaly_type = row.get('anomaly_type', 'Unknown')
                anomaly_counts[anomaly_type] = anomaly_counts.get(anomaly_type, 0) + 1
            for anomaly_type, count in anomaly_counts.items():
                print(f"  {anomaly_type}: {count} records")
            
            print("\nAttack Stage Distribution:")
            stage_counts = {}
            for row in self.data:
                stage = row.get('attack_stage', 'Unknown')
                stage_counts[stage] = stage_counts.get(stage, 0) + 1
            for stage, count in stage_counts.items():
                print(f"  {stage}: {count} records")
            
            return True
            
        except Exception as e:
            print(f"Error saving enhanced data: {e}")
            return False
    
    def print_sample_enhanced_records(self, num_samples=3):
        """Print sample enhanced records for verification"""
        if not self.data:
            print("No data available")
            return
        
        print(f"\n=== Sample Enhanced Records ===")
        
        # Show high-priority samples first
        high_priority_records = []
        for row in self.data:
            try:
                priority = int(row.get('investigation_priority', 2))
                if priority >= 4:
                    high_priority_records.append(row)
            except (ValueError, TypeError):
                continue
        
        if high_priority_records:
            sample_records = high_priority_records[:num_samples]
        else:
            sample_records = self.data[:num_samples]
        
        for idx, row in enumerate(sample_records):
            print(f"\n--- Record {idx + 1} ---")
            print(f"Username: {row.get('username', 'N/A')}")
            print(f"Event: {row.get('event_action', 'N/A')} ({row.get('event_id', 'N/A')})")
            print(f"Timestamp: {row.get('timestamp', 'N/A')}")
            max_z = row.get('max_abs_z', 'N/A')
            try:
                max_z_float = float(max_z)
                print(f"Max Z-Score: {max_z_float:.2f}")
            except (ValueError, TypeError):
                print(f"Max Z-Score: {max_z}")
            print(f"Priority: {row.get('investigation_priority', 'N/A')}")
            print(f"Anomaly Type: {row.get('anomaly_type', 'N/A')}")
            print(f"Attack Stage: {row.get('attack_stage', 'N/A')}")
            desc = row.get('detailed_description', '')
            print(f"Description: {desc[:200]}..." if len(desc) > 200 else f"Description: {desc}")
            print(f"Threat Indicators: {row.get('threat_indicators', 'N/A')}")
            action = row.get('recommended_action', '')
            print(f"Recommended Actions: {action[:150]}..." if len(action) > 150 else f"Recommended Actions: {action}")


def main():
    """Main execution function"""
    print("=== Cyber Data Analysis - Anomaly Description Enhancer ===")
    print("Starting anomaly description enhancement process...\n")
    
    # Initialize enhancer
    enhancer = AnomalyDescriptionEnhancer()
    
    # Load data
    if not enhancer.load_data():
        sys.exit(1)
    
    # Enhance dataset
    if not enhancer.enhance_dataset():
        sys.exit(1)
    
    # Save enhanced data
    if not enhancer.save_enhanced_data():
        sys.exit(1)
    
    # Print sample records
    enhancer.print_sample_enhanced_records()
    
    print("\n=== Enhancement Process Complete ===")
    print("Enhanced dataset saved as 'enhanced_data_v2.csv'")
    print("The dataset now includes detailed anomaly descriptions, classifications,")
    print("threat indicators, and specific investigation recommendations.")


if __name__ == "__main__":
    main()