#!/usr/bin/env python3
"""
Comprehensive Data Processor - Merges analysis from all agents
Generates enhanced unified dashboard data with complete threat context
"""

import csv
import json
import os
from datetime import datetime

class ComprehensiveDataProcessor:
    def __init__(self):
        self.base_path = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis"
        self.statistical_analysis = None
        self.event_interpretations = None
        self.anomaly_analysis = None
        
    def load_analyses(self):
        """Load all analysis outputs from the three agents"""
        print("Loading analysis from specialized agents...")
        
        # Load statistical analysis
        with open(f"{self.base_path}/outputs/statistical_analysis.json", 'r') as f:
            self.statistical_analysis = json.load(f)
        print("✓ Loaded statistical analysis")
        
        # Load event interpretations
        with open(f"{self.base_path}/outputs/event_interpretations.json", 'r') as f:
            self.event_interpretations = json.load(f)
        print("✓ Loaded event interpretations")
        
        # Load anomaly analysis
        with open(f"{self.base_path}/outputs/anomaly_analysis.json", 'r') as f:
            self.anomaly_analysis = json.load(f)
        print("✓ Loaded anomaly analysis")
    
    def determine_anomaly_type(self, event_id, cluster_desc, z_score):
        """Determine the anomaly type based on event and cluster"""
        event_id = str(event_id)
        
        # Event-based classification
        if event_id in ['4624', '4625', '4776', '4768', '4769']:
            return "Authentication Anomaly"
        elif event_id in ['4672', '4673', '4674']:
            return "Privilege Escalation"
        elif event_id in ['4688', '4689']:
            return "Process Anomaly"
        elif event_id in ['4648', '4904', '4905']:
            return "Lateral Movement"
        elif event_id == '4634':
            if z_score > 20:
                return "Session Anomaly"
            else:
                return "Authentication Anomaly"
        
        # Cluster-based classification
        if cluster_desc:
            if 'lateral' in cluster_desc.lower():
                return "Lateral Movement"
            elif 'authentication' in cluster_desc.lower() or 'suspicious_auth' in cluster_desc.lower():
                return "Authentication Anomaly"
            elif 'privilege' in cluster_desc.lower():
                return "Privilege Escalation"
            elif 'persistent' in cluster_desc.lower():
                return "Persistence Mechanism"
            elif 'reconnaissance' in cluster_desc.lower():
                return "Network Reconnaissance"
        
        # Z-score based fallback
        if z_score > 50:
            return "Extreme Behavioral Anomaly"
        elif z_score > 20:
            return "Critical Pattern Deviation"
        elif z_score > 10:
            return "Significant Anomaly"
        
        return "Behavioral Anomaly"
    
    def generate_detailed_description(self, row):
        """Generate detailed description explaining WHY the event is abnormal"""
        z_score = float(row.get('max_abs_z', 0))
        event_id = str(row.get('event_id', ''))
        username = row.get('username', '')
        hostname = row.get('hostname', '')
        timestamp = row.get('timestamp', '')
        cluster_desc = row.get('cluster_description', '')
        source_ip = row.get('source_ip', '')
        
        # Get event interpretation
        event_info = self.event_interpretations.get('event_mappings', {}).get(event_id, {})
        event_name = event_info.get('event_name', f'Event {event_id}')
        
        # Start with risk level
        if z_score >= 50:
            desc = f"EXTREME ANOMALY: {event_name} - "
            risk_context = f"Z-score of {z_score:.1f} represents unprecedented behavior never seen in normal operations. "
        elif z_score >= 20:
            desc = f"CRITICAL: {event_name} - "
            risk_context = f"Z-score of {z_score:.1f} means this event is {z_score:.0f} standard deviations from normal (probability < 0.00001%). "
        elif z_score >= 10:
            desc = f"HIGH RISK: {event_name} - "
            risk_context = f"Z-score of {z_score:.1f} indicates highly unusual activity ({z_score:.0f}x beyond normal variance). "
        else:
            desc = f"MEDIUM RISK: {event_name} - "
            risk_context = f"Z-score of {z_score:.1f} shows moderate deviation from baseline. "
        
        # Add account context
        if username.endswith('$'):
            desc += f"Computer account {username} "
        elif username == 'ANONYMOUS LOGON':
            desc += f"Anonymous access detected "
        else:
            desc += f"User {username} "
        
        # Add action context
        if event_id == '4624':
            desc += f"logged into {hostname}"
            if source_ip and source_ip != '-':
                desc += f" from {source_ip}"
        elif event_id == '4625':
            desc += f"failed login attempt to {hostname}"
        elif event_id == '4634':
            desc += f"logged off from {hostname}"
        elif event_id == '4672':
            desc += f"received special privileges on {hostname}"
        elif event_id == '4688':
            desc += f"created new process on {hostname}"
        else:
            desc += f"performed security event on {hostname}"
        
        desc += ". "
        
        # Add WHY it's abnormal
        desc += "\n\nWHY THIS IS ABNORMAL:\n"
        desc += f"• {risk_context}\n"
        
        # Add specific anomaly indicators
        if z_score > 20:
            if username == 'ANONYMOUS LOGON':
                desc += "• Anonymous logons should be extremely rare in a secure environment\n"
            elif username.endswith('$'):
                desc += "• Computer accounts showing this behavior indicates potential compromise or malware\n"
            
            if source_ip and '10.7.56' in source_ip:
                desc += f"• Source IP {source_ip} is showing concentrated attack patterns\n"
            
            if 'Suspicious_Authentication' in cluster_desc:
                desc += "• Part of suspicious authentication pattern cluster indicating coordinated attack\n"
            elif 'Lateral_Movement' in cluster_desc:
                desc += "• Behavior consistent with lateral movement techniques used by attackers\n"
            elif 'Persistent_Threat' in cluster_desc:
                desc += "• Indicates persistent threat activity with long-term compromise indicators\n"
        
        # Add threat context
        desc += "\nTHREAT CONTEXT:\n"
        threat_info = event_info.get('suspicious_indicators', [])
        if threat_info:
            for indicator in threat_info[:3]:
                desc += f"• {indicator}\n"
        else:
            if z_score > 50:
                desc += "• Behavior is so extreme it likely indicates active compromise\n"
            elif z_score > 20:
                desc += "• Statistical rarity suggests targeted attack or system compromise\n"
        
        # Add investigation priority
        if z_score > 50:
            desc += "\nINVESTIGATION: IMMEDIATE response required - isolate system and investigate"
        elif z_score > 20:
            desc += "\nINVESTIGATION: HIGH priority - review within 1 hour"
        elif z_score > 10:
            desc += "\nINVESTIGATION: Medium priority - investigate within 24 hours"
        else:
            desc += "\nINVESTIGATION: Review during normal security operations"
        
        return desc
    
    def process_clustered_data(self):
        """Process both clustered CSV files with enhanced analysis"""
        all_enhanced_data = []
        
        # Process computer accounts
        print("\nProcessing computer accounts...")
        with open(f"{self.base_path}/data/dfp_detections_computer_accounts_clustered.csv", 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                enhanced_row = self.enhance_row(row, 'System')
                all_enhanced_data.append(enhanced_row)
        
        print(f"✓ Processed {len(all_enhanced_data)} computer account events")
        
        # Process user accounts
        print("\nProcessing user accounts...")
        user_count_start = len(all_enhanced_data)
        with open(f"{self.base_path}/data/dfp_detections_user_accounts_clustered.csv", 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                enhanced_row = self.enhance_row(row, 'User')
                all_enhanced_data.append(enhanced_row)
        
        user_count = len(all_enhanced_data) - user_count_start
        print(f"✓ Processed {user_count} user account events")
        
        return all_enhanced_data
    
    def enhance_row(self, row, account_type):
        """Enhance a single row with all analysis data"""
        z_score = float(row.get('max_abs_z', 0))
        event_id = row.get('event_id', '')
        cluster_desc = row.get('cluster_description', '')
        
        # Determine anomaly type (NOT "Unknown")
        anomaly_type = self.determine_anomaly_type(event_id, cluster_desc, z_score)
        
        # Generate detailed description
        detailed_desc = self.generate_detailed_description(row)
        
        # Determine risk category
        if z_score >= 20:
            risk_category = 'Critical'
            investigation_priority = 1
        elif z_score >= 10:
            risk_category = 'High Risk'
            investigation_priority = 2
        elif z_score >= 5:
            risk_category = 'Medium'
            investigation_priority = 3
        else:
            risk_category = 'Normal/Moderate'
            investigation_priority = 4
        
        # Get MITRE ATT&CK mapping
        event_info = self.event_interpretations.get('event_mappings', {}).get(str(event_id), {})
        mitre_techniques = event_info.get('mitre_attack_mapping', [])
        attack_stage = self.determine_attack_stage(event_id, cluster_desc)
        
        # Build enhanced row
        enhanced_row = dict(row)
        enhanced_row.update({
            'account_type': account_type,
            'anomaly_type': anomaly_type,  # This fixes the "Unknown" issue
            'risk_category': risk_category,
            'risk_score': z_score,
            'detailed_description': detailed_desc,
            'threat_indicators': ', '.join(mitre_techniques[:3]) if mitre_techniques else '',
            'attack_stage': attack_stage,
            'investigation_priority': investigation_priority,
            'event_name': event_info.get('event_name', f'Event {event_id}'),
            'recommended_action': self.get_recommended_action(z_score)
        })
        
        return enhanced_row
    
    def determine_attack_stage(self, event_id, cluster_desc):
        """Determine MITRE ATT&CK stage"""
        event_id = str(event_id)
        
        if event_id in ['4624', '4625']:
            return 'Initial Access'
        elif event_id in ['4672', '4673']:
            return 'Privilege Escalation'
        elif event_id in ['4688', '4689']:
            return 'Execution'
        elif event_id in ['4648']:
            return 'Lateral Movement'
        
        if cluster_desc:
            if 'reconnaissance' in cluster_desc.lower():
                return 'Discovery'
            elif 'persistent' in cluster_desc.lower():
                return 'Persistence'
            elif 'lateral' in cluster_desc.lower():
                return 'Lateral Movement'
        
        return 'Detection'
    
    def get_recommended_action(self, z_score):
        """Get recommended action based on z-score"""
        if z_score >= 50:
            return "IMMEDIATE: Isolate system, activate incident response, forensic analysis required"
        elif z_score >= 20:
            return "URGENT: Investigate within 1 hour, check for related events, consider containment"
        elif z_score >= 10:
            return "HIGH: Review within 4 hours, correlate with other alerts, monitor closely"
        elif z_score >= 5:
            return "MEDIUM: Investigate within 24 hours, add to watch list"
        else:
            return "LOW: Review during normal operations, monitor for patterns"
    
    def save_enhanced_data(self, data):
        """Save the enhanced data to CSV for dashboard"""
        output_file = f"{self.base_path}/dashboard/public/unified_dashboard_data.csv"
        
        if not data:
            print("No data to save!")
            return
        
        # Get all unique keys
        all_keys = set()
        for row in data:
            all_keys.update(row.keys())
        
        # Write CSV
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
            writer.writeheader()
            writer.writerows(data)
        
        print(f"\n✓ Saved enhanced data to {output_file}")
        print(f"  Total events: {len(data)}")
        
        # Also save to outputs folder
        output_file2 = f"{self.base_path}/outputs/unified_dashboard_data.csv"
        with open(output_file2, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
            writer.writeheader()
            writer.writerows(data)
        print(f"✓ Backup saved to {output_file2}")
        
        # Print summary
        critical_count = sum(1 for r in data if float(r.get('max_abs_z', 0)) >= 20)
        high_count = sum(1 for r in data if 10 <= float(r.get('max_abs_z', 0)) < 20)
        print(f"\nRisk Summary:")
        print(f"  Critical events (z>=20): {critical_count}")
        print(f"  High risk events (10<=z<20): {high_count}")
        
        # Show anomaly type distribution
        anomaly_types = {}
        for row in data:
            atype = row.get('anomaly_type', 'Unknown')
            anomaly_types[atype] = anomaly_types.get(atype, 0) + 1
        
        print(f"\nAnomaly Type Distribution:")
        for atype, count in sorted(anomaly_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {atype}: {count}")

def main():
    print("="*60)
    print("COMPREHENSIVE DATA PROCESSOR")
    print("Merging analysis from all specialized agents")
    print("="*60)
    
    processor = ComprehensiveDataProcessor()
    
    # Load all analyses
    processor.load_analyses()
    
    # Process and enhance data
    enhanced_data = processor.process_clustered_data()
    
    # Save enhanced data
    processor.save_enhanced_data(enhanced_data)
    
    print("\n✓ Processing complete!")
    print("Dashboard data has been enhanced with:")
    print("  - Proper anomaly types (no more 'Unknown')")
    print("  - Detailed descriptions explaining WHY events are abnormal")
    print("  - Threat context and investigation recommendations")
    print("  - MITRE ATT&CK mappings")

if __name__ == "__main__":
    main()