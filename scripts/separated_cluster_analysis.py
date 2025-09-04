#!/usr/bin/env python3
"""
Separated Cluster Analysis for System vs User Accounts
======================================================
This script performs comprehensive security analysis on clustered data,
clearly separating system/computer accounts from user accounts.

Author: Claude Code
Date: 2025-09-04
"""

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
import statistics

class SeparatedSecurityAnalyzer:
    """Analyzes clustered security data with account type separation"""
    
    def __init__(self):
        self.computer_data = []
        self.user_data = []
        self.analysis_results = {
            'computer_accounts': {},
            'user_accounts': {},
            'combined': {},
            'correlations': {}
        }
        
    def load_data(self):
        """Load clustered CSV files"""
        print("="*60)
        print("LOADING CLUSTERED SECURITY DATA")
        print("="*60)
        
        # Load computer accounts
        with open('data/dfp_detections_computer_accounts_clustered.csv', 'r') as f:
            reader = csv.DictReader(f)
            self.computer_data = list(reader)
        print(f"✓ Loaded {len(self.computer_data)} computer account events")
        
        # Load user accounts
        with open('data/dfp_detections_user_accounts_clustered.csv', 'r') as f:
            reader = csv.DictReader(f)
            self.user_data = list(reader)
        print(f"✓ Loaded {len(self.user_data)} user account events")
        
    def analyze_risk_levels(self, data):
        """Categorize events by risk level based on z-scores"""
        risk_levels = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for row in data:
            try:
                z_score = float(row.get('max_abs_z', 0))
                if z_score >= 20:
                    risk_levels['CRITICAL'].append(row)
                elif z_score >= 10:
                    risk_levels['HIGH'].append(row)
                elif z_score >= 3:
                    risk_levels['MEDIUM'].append(row)
                else:
                    risk_levels['LOW'].append(row)
            except (ValueError, TypeError):
                risk_levels['LOW'].append(row)
                
        return risk_levels
    
    def analyze_clusters(self, data, account_type):
        """Analyze cluster distribution and characteristics"""
        cluster_analysis = {}
        
        # Group by cluster
        clusters = defaultdict(list)
        for row in data:
            cluster_desc = row.get('cluster_description', 'Unknown')
            clusters[cluster_desc].append(row)
        
        # Analyze each cluster
        for cluster_name, events in clusters.items():
            z_scores = []
            usernames = set()
            hostnames = set()
            event_ids = []
            timestamps = []
            
            for event in events:
                try:
                    z_scores.append(float(event.get('max_abs_z', 0)))
                    usernames.add(event.get('username', 'Unknown'))
                    hostnames.add(event.get('hostname', 'Unknown'))
                    event_ids.append(event.get('event_id', 'Unknown'))
                    timestamps.append(event.get('timestamp', ''))
                except (ValueError, TypeError):
                    continue
            
            # Calculate statistics
            avg_z = statistics.mean(z_scores) if z_scores else 0
            max_z = max(z_scores) if z_scores else 0
            min_z = min(z_scores) if z_scores else 0
            
            cluster_analysis[cluster_name] = {
                'event_count': len(events),
                'avg_anomaly_score': round(avg_z, 2),
                'max_anomaly_score': round(max_z, 2),
                'min_anomaly_score': round(min_z, 2),
                'unique_users': len(usernames),
                'unique_hosts': len(hostnames),
                'top_users': Counter([e.get('username') for e in events]).most_common(3),
                'top_hosts': Counter([e.get('hostname') for e in events]).most_common(3),
                'event_types': Counter(event_ids).most_common(3),
                'risk_level': self.get_cluster_risk_level(avg_z, cluster_name)
            }
            
        return cluster_analysis
    
    def get_cluster_risk_level(self, avg_z, cluster_name):
        """Determine cluster risk level"""
        critical_keywords = ['Critical', 'Extreme', 'Breach', 'Outlier']
        high_keywords = ['Suspicious', 'High_Risk', 'Escalation', 'Reconnaissance']
        
        # Check cluster name for risk indicators
        for keyword in critical_keywords:
            if keyword in cluster_name:
                return 'CRITICAL'
        
        for keyword in high_keywords:
            if keyword in cluster_name:
                return 'HIGH'
        
        # Use z-score if no keyword match
        if avg_z >= 20:
            return 'CRITICAL'
        elif avg_z >= 10:
            return 'HIGH'
        elif avg_z >= 3:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def identify_threat_actors(self, data, top_n=10):
        """Identify top threat actors by anomaly score and frequency"""
        actor_stats = defaultdict(lambda: {'events': 0, 'total_z': 0, 'max_z': 0, 'hosts': set(), 'clusters': set()})
        
        for row in data:
            username = row.get('username', 'Unknown')
            try:
                z_score = float(row.get('max_abs_z', 0))
                actor_stats[username]['events'] += 1
                actor_stats[username]['total_z'] += z_score
                actor_stats[username]['max_z'] = max(actor_stats[username]['max_z'], z_score)
                actor_stats[username]['hosts'].add(row.get('hostname', 'Unknown'))
                actor_stats[username]['clusters'].add(row.get('cluster_description', 'Unknown'))
            except (ValueError, TypeError):
                continue
        
        # Calculate threat score
        threat_actors = []
        for username, stats in actor_stats.items():
            threat_score = (stats['max_z'] * 0.5) + (stats['events'] * 0.3) + (len(stats['hosts']) * 0.2)
            threat_actors.append({
                'username': username,
                'threat_score': round(threat_score, 2),
                'event_count': stats['events'],
                'avg_anomaly': round(stats['total_z'] / stats['events'], 2) if stats['events'] > 0 else 0,
                'max_anomaly': round(stats['max_z'], 2),
                'unique_hosts': len(stats['hosts']),
                'cluster_types': list(stats['clusters'])
            })
        
        # Sort by threat score
        threat_actors.sort(key=lambda x: x['threat_score'], reverse=True)
        return threat_actors[:top_n]
    
    def analyze_host_vulnerability(self, data):
        """Analyze host vulnerability based on events and anomaly scores"""
        host_stats = defaultdict(lambda: {'events': 0, 'total_z': 0, 'max_z': 0, 'users': set(), 'critical_events': 0})
        
        for row in data:
            hostname = row.get('hostname', 'Unknown')
            try:
                z_score = float(row.get('max_abs_z', 0))
                host_stats[hostname]['events'] += 1
                host_stats[hostname]['total_z'] += z_score
                host_stats[hostname]['max_z'] = max(host_stats[hostname]['max_z'], z_score)
                host_stats[hostname]['users'].add(row.get('username', 'Unknown'))
                if z_score >= 20:
                    host_stats[hostname]['critical_events'] += 1
            except (ValueError, TypeError):
                continue
        
        # Calculate vulnerability score
        vulnerable_hosts = []
        for hostname, stats in host_stats.items():
            vuln_score = (stats['critical_events'] * 10) + (stats['max_z'] * 0.3) + (stats['events'] * 0.1)
            vulnerable_hosts.append({
                'hostname': hostname,
                'vulnerability_score': round(vuln_score, 2),
                'event_count': stats['events'],
                'critical_events': stats['critical_events'],
                'avg_anomaly': round(stats['total_z'] / stats['events'], 2) if stats['events'] > 0 else 0,
                'max_anomaly': round(stats['max_z'], 2),
                'unique_users': len(stats['users'])
            })
        
        vulnerable_hosts.sort(key=lambda x: x['vulnerability_score'], reverse=True)
        return vulnerable_hosts
    
    def analyze_temporal_patterns(self, data):
        """Analyze temporal patterns in the data"""
        daily_stats = defaultdict(lambda: {'events': 0, 'critical': 0, 'users': set()})
        
        for row in data:
            timestamp = row.get('timestamp', '')
            if timestamp:
                try:
                    # Extract date
                    date = timestamp.split('T')[0]
                    daily_stats[date]['events'] += 1
                    daily_stats[date]['users'].add(row.get('username'))
                    
                    z_score = float(row.get('max_abs_z', 0))
                    if z_score >= 20:
                        daily_stats[date]['critical'] += 1
                except:
                    continue
        
        # Convert to list
        temporal_analysis = []
        for date, stats in daily_stats.items():
            temporal_analysis.append({
                'date': date,
                'event_count': stats['events'],
                'critical_events': stats['critical'],
                'unique_users': len(stats['users']),
                'criticality_rate': round(stats['critical'] / stats['events'] * 100, 1) if stats['events'] > 0 else 0
            })
        
        temporal_analysis.sort(key=lambda x: x['date'])
        return temporal_analysis
    
    def find_correlations(self):
        """Find correlations between computer and user account threats"""
        correlations = {
            'shared_hosts': [],
            'temporal_overlap': [],
            'attack_progression': []
        }
        
        # Find shared hosts
        computer_hosts = set(row.get('hostname') for row in self.computer_data)
        user_hosts = set(row.get('hostname') for row in self.user_data)
        shared_hosts = computer_hosts.intersection(user_hosts)
        
        for host in shared_hosts:
            computer_events = [r for r in self.computer_data if r.get('hostname') == host]
            user_events = [r for r in self.user_data if r.get('hostname') == host]
            
            correlations['shared_hosts'].append({
                'hostname': host,
                'computer_events': len(computer_events),
                'user_events': len(user_events),
                'total_events': len(computer_events) + len(user_events)
            })
        
        # Analyze temporal overlap
        computer_dates = set(row.get('timestamp', '')[:10] for row in self.computer_data if row.get('timestamp'))
        user_dates = set(row.get('timestamp', '')[:10] for row in self.user_data if row.get('timestamp'))
        overlapping_dates = computer_dates.intersection(user_dates)
        
        for date in overlapping_dates:
            computer_critical = sum(1 for r in self.computer_data 
                                  if r.get('timestamp', '').startswith(date) 
                                  and float(r.get('max_abs_z', 0)) >= 20)
            user_critical = sum(1 for r in self.user_data 
                               if r.get('timestamp', '').startswith(date)
                               and float(r.get('max_abs_z', 0)) >= 20)
            
            if computer_critical > 0 or user_critical > 0:
                correlations['temporal_overlap'].append({
                    'date': date,
                    'computer_critical': computer_critical,
                    'user_critical': user_critical
                })
        
        # Identify attack progression patterns
        # Look for computer account compromise followed by user account activity
        for host in shared_hosts:
            computer_times = sorted([r.get('timestamp') for r in self.computer_data 
                                   if r.get('hostname') == host and r.get('timestamp')])
            user_times = sorted([r.get('timestamp') for r in self.user_data 
                               if r.get('hostname') == host and r.get('timestamp')])
            
            if computer_times and user_times:
                if computer_times[0] < user_times[0]:
                    correlations['attack_progression'].append({
                        'hostname': host,
                        'pattern': 'Computer → User',
                        'first_computer': computer_times[0],
                        'first_user': user_times[0]
                    })
        
        return correlations
    
    def generate_recommendations(self):
        """Generate security recommendations based on analysis"""
        recommendations = {
            'immediate_actions': [],
            'short_term': [],
            'long_term': []
        }
        
        # Analyze critical events
        computer_risk = self.analyze_risk_levels(self.computer_data)
        user_risk = self.analyze_risk_levels(self.user_data)
        
        # Immediate actions for critical events
        if len(computer_risk['CRITICAL']) > 0:
            recommendations['immediate_actions'].append({
                'priority': 1,
                'action': f"Investigate {len(computer_risk['CRITICAL'])} CRITICAL computer account anomalies",
                'details': f"Focus on Outlier_Extreme_Risk and Critical_Persistent_Threats clusters"
            })
        
        if len(user_risk['CRITICAL']) > 0:
            # Find the highest risk user
            critical_users = sorted(user_risk['CRITICAL'], 
                                  key=lambda x: float(x.get('max_abs_z', 0)), 
                                  reverse=True)
            if critical_users:
                top_user = critical_users[0]
                recommendations['immediate_actions'].append({
                    'priority': 1,
                    'action': f"Investigate user '{top_user.get('username')}' with z-score {top_user.get('max_abs_z')}",
                    'details': "Potential account compromise or insider threat"
                })
        
        # Short-term recommendations
        computer_clusters = self.analyze_clusters(self.computer_data, 'computer')
        for cluster_name, stats in computer_clusters.items():
            if stats['risk_level'] == 'HIGH' and stats['event_count'] > 50:
                recommendations['short_term'].append({
                    'priority': 2,
                    'action': f"Review {cluster_name} cluster with {stats['event_count']} events",
                    'details': f"Average anomaly score: {stats['avg_anomaly_score']}"
                })
        
        # Long-term recommendations
        vulnerable_hosts = self.analyze_host_vulnerability(self.computer_data + self.user_data)
        if vulnerable_hosts:
            top_host = vulnerable_hosts[0]
            recommendations['long_term'].append({
                'priority': 3,
                'action': f"Harden host '{top_host['hostname']}'",
                'details': f"Vulnerability score: {top_host['vulnerability_score']}, Critical events: {top_host['critical_events']}"
            })
        
        return recommendations
    
    def run_analysis(self):
        """Run complete separated analysis"""
        print("\n" + "="*60)
        print("PERFORMING SEPARATED SECURITY ANALYSIS")
        print("="*60)
        
        # Analyze computer accounts
        print("\n[1/6] Analyzing Computer/System Accounts...")
        self.analysis_results['computer_accounts'] = {
            'total_events': len(self.computer_data),
            'risk_levels': self.analyze_risk_levels(self.computer_data),
            'clusters': self.analyze_clusters(self.computer_data, 'computer'),
            'threat_actors': self.identify_threat_actors(self.computer_data),
            'vulnerable_hosts': self.analyze_host_vulnerability(self.computer_data),
            'temporal_patterns': self.analyze_temporal_patterns(self.computer_data)
        }
        
        # Count risk levels
        comp_risk = self.analysis_results['computer_accounts']['risk_levels']
        print(f"  ✓ Critical: {len(comp_risk['CRITICAL'])}, High: {len(comp_risk['HIGH'])}, "
              f"Medium: {len(comp_risk['MEDIUM'])}, Low: {len(comp_risk['LOW'])}")
        
        # Analyze user accounts
        print("\n[2/6] Analyzing User Accounts...")
        self.analysis_results['user_accounts'] = {
            'total_events': len(self.user_data),
            'risk_levels': self.analyze_risk_levels(self.user_data),
            'clusters': self.analyze_clusters(self.user_data, 'user'),
            'threat_actors': self.identify_threat_actors(self.user_data),
            'vulnerable_hosts': self.analyze_host_vulnerability(self.user_data),
            'temporal_patterns': self.analyze_temporal_patterns(self.user_data)
        }
        
        # Count risk levels
        user_risk = self.analysis_results['user_accounts']['risk_levels']
        print(f"  ✓ Critical: {len(user_risk['CRITICAL'])}, High: {len(user_risk['HIGH'])}, "
              f"Medium: {len(user_risk['MEDIUM'])}, Low: {len(user_risk['LOW'])}")
        
        # Find correlations
        print("\n[3/6] Finding Correlations...")
        self.analysis_results['correlations'] = self.find_correlations()
        print(f"  ✓ Shared hosts: {len(self.analysis_results['correlations']['shared_hosts'])}")
        
        # Generate recommendations
        print("\n[4/6] Generating Recommendations...")
        self.analysis_results['recommendations'] = self.generate_recommendations()
        print(f"  ✓ Immediate actions: {len(self.analysis_results['recommendations']['immediate_actions'])}")
        
        # Calculate combined statistics
        print("\n[5/6] Calculating Combined Statistics...")
        self.analysis_results['combined'] = {
            'total_events': len(self.computer_data) + len(self.user_data),
            'computer_percentage': round(len(self.computer_data) / (len(self.computer_data) + len(self.user_data)) * 100, 1),
            'user_percentage': round(len(self.user_data) / (len(self.computer_data) + len(self.user_data)) * 100, 1),
            'total_critical': len(comp_risk['CRITICAL']) + len(user_risk['CRITICAL']),
            'overall_risk': self.calculate_overall_risk()
        }
        
        print(f"  ✓ Total events: {self.analysis_results['combined']['total_events']}")
        print(f"  ✓ Critical events: {self.analysis_results['combined']['total_critical']}")
        print(f"  ✓ Overall risk: {self.analysis_results['combined']['overall_risk']}")
        
        print("\n[6/6] Analysis Complete!")
        
    def calculate_overall_risk(self):
        """Calculate overall security risk level"""
        comp_risk = self.analysis_results['computer_accounts']['risk_levels']
        user_risk = self.analysis_results['user_accounts']['risk_levels']
        
        total_critical = len(comp_risk['CRITICAL']) + len(user_risk['CRITICAL'])
        total_high = len(comp_risk['HIGH']) + len(user_risk['HIGH'])
        
        if total_critical > 50:
            return 'CRITICAL - Immediate action required'
        elif total_critical > 10:
            return 'HIGH - Significant threats detected'
        elif total_high > 100:
            return 'ELEVATED - Multiple anomalies detected'
        else:
            return 'MODERATE - Standard security posture'
    
    def save_results(self):
        """Save analysis results to file"""
        with open('separated_analysis_results.json', 'w') as f:
            # Convert sets to lists for JSON serialization
            def convert_sets(obj):
                if isinstance(obj, set):
                    return list(obj)
                elif isinstance(obj, dict):
                    return {k: convert_sets(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_sets(item) for item in obj]
                else:
                    return obj
            
            json.dump(convert_sets(self.analysis_results), f, indent=2)
        print(f"\n✓ Results saved to separated_analysis_results.json")

def main():
    """Main execution"""
    analyzer = SeparatedSecurityAnalyzer()
    analyzer.load_data()
    analyzer.run_analysis()
    analyzer.save_results()
    
    # Print summary
    print("\n" + "="*60)
    print("ANALYSIS SUMMARY")
    print("="*60)
    
    results = analyzer.analysis_results
    print(f"\nComputer Accounts:")
    print(f"  Total Events: {results['computer_accounts']['total_events']}")
    print(f"  Unique Clusters: {len(results['computer_accounts']['clusters'])}")
    print(f"  Top Threat: {results['computer_accounts']['threat_actors'][0]['username'] if results['computer_accounts']['threat_actors'] else 'N/A'}")
    
    print(f"\nUser Accounts:")
    print(f"  Total Events: {results['user_accounts']['total_events']}")
    print(f"  Unique Clusters: {len(results['user_accounts']['clusters'])}")
    print(f"  Top Threat: {results['user_accounts']['threat_actors'][0]['username'] if results['user_accounts']['threat_actors'] else 'N/A'}")
    
    print(f"\nOverall Security Posture: {results['combined']['overall_risk']}")
    
    # Print top recommendations
    print("\n" + "="*60)
    print("TOP SECURITY RECOMMENDATIONS")
    print("="*60)
    for rec in results['recommendations']['immediate_actions'][:3]:
        print(f"\n[PRIORITY {rec['priority']}] {rec['action']}")
        print(f"  → {rec['details']}")

if __name__ == "__main__":
    main()