#!/usr/bin/env python3
"""
Windows Security Event Log Interpreter (Standard Library Only)
Analyzes clustered CSV files and provides human-readable interpretations
"""

import csv
import json
from datetime import datetime
import os

class SimpleSecurityLogInterpreter:
    def __init__(self):
        self.event_definitions = {
            "4624": {
                "name": "Successful Account Logon",
                "normal_behavior": "Users logging in during business hours from known locations",
                "suspicious_indicators": [
                    "Logons from unusual IP addresses",
                    "Multiple logons from different locations simultaneously", 
                    "Service account logons from user workstations",
                    "Logons outside business hours",
                    "High frequency of logons (potential credential stuffing)"
                ],
                "attack_context": [
                    "Pass-the-hash attacks",
                    "Credential stuffing/spraying",
                    "Lateral movement", 
                    "Account takeover"
                ],
                "investigation_steps": [
                    "Verify logon location against user's normal pattern",
                    "Check for corresponding logoff events",
                    "Review source IP geolocation",
                    "Analyze logon type for appropriateness"
                ],
                "mitre_attack": ["T1078", "T1110", "T1021"]
            },
            "4625": {
                "name": "Failed Account Logon",
                "normal_behavior": "Occasional failed logons due to typos or forgotten passwords",
                "suspicious_indicators": [
                    "Multiple failures in short timeframe",
                    "Failed logons for disabled accounts", 
                    "Failures from unusual locations",
                    "Pattern suggesting password spraying"
                ],
                "attack_context": [
                    "Brute force attacks",
                    "Password spraying",
                    "Account enumeration",
                    "Credential stuffing"
                ],
                "investigation_steps": [
                    "Count failures per account and source IP",
                    "Check for subsequent successful logons",
                    "Review failure reasons",
                    "Correlate with threat intelligence"
                ],
                "mitre_attack": ["T1110.001", "T1110.003", "T1078"]
            },
            "4634": {
                "name": "Account Logoff",
                "normal_behavior": "Normal logoff events at end of work sessions",
                "suspicious_indicators": [
                    "Logoffs without corresponding logons",
                    "Unusual timing patterns",
                    "Service account logoffs from user systems"
                ],
                "attack_context": [
                    "Session cleanup after malicious activity",
                    "Evidence of unauthorized access", 
                    "Lateral movement cleanup"
                ],
                "investigation_steps": [
                    "Correlate with logon events",
                    "Check session duration",
                    "Review activity between logon and logoff"
                ],
                "mitre_attack": ["T1078", "T1021"]
            },
            "4688": {
                "name": "New Process Created",
                "normal_behavior": "Standard application and service process creation",
                "suspicious_indicators": [
                    "Unusual executable names or paths",
                    "Processes started by unexpected users",
                    "Command line arguments suggesting malicious intent",
                    "High frequency of process creation"
                ],
                "attack_context": [
                    "Malware execution",
                    "Living off the land techniques",
                    "Privilege escalation",
                    "Persistence mechanisms"
                ],
                "investigation_steps": [
                    "Analyze command line arguments",
                    "Check process hash against known malware",
                    "Review parent process relationship",
                    "Verify digital signatures"
                ],
                "mitre_attack": ["T1059", "T1055", "T1106"]
            },
            "4689": {
                "name": "Process Terminated",
                "normal_behavior": "Normal process termination during system operations",
                "suspicious_indicators": [
                    "Critical processes terminated unexpectedly",
                    "Security tools being killed",
                    "Unusual termination patterns"
                ],
                "attack_context": [
                    "Anti-forensics activities",
                    "Defense evasion",
                    "Service disruption",
                    "Covering tracks"
                ],
                "investigation_steps": [
                    "Identify what terminated the process",
                    "Check if process was critical for security",
                    "Look for subsequent suspicious activities",
                    "Review process lifetime"
                ],
                "mitre_attack": ["T1562", "T1489", "T1070"]
            },
            "4672": {
                "name": "Special Privileges Assigned",
                "normal_behavior": "Administrative accounts receiving expected privileges",
                "suspicious_indicators": [
                    "Regular users receiving admin privileges",
                    "Service accounts getting excessive privileges",
                    "Privilege assignment outside normal hours"
                ],
                "attack_context": [
                    "Privilege escalation",
                    "Account compromise", 
                    "Persistence mechanisms",
                    "Credential abuse"
                ],
                "investigation_steps": [
                    "Verify if privilege assignment was authorized",
                    "Check who granted the privileges",
                    "Review subsequent activities with elevated privileges",
                    "Correlate with change management records"
                ],
                "mitre_attack": ["T1078.003", "T1068", "T1134"]
            }
        }
        
        self.logon_types = {
            "2": "Interactive (Console/Keyboard)",
            "3": "Network (Remote Access)",
            "4": "Batch (Scheduled Task)",
            "5": "Service",
            "7": "Unlock",
            "8": "NetworkCleartext",
            "9": "NewCredentials",
            "10": "RemoteInteractive (RDP)",
            "11": "CachedInteractive"
        }
        
        self.cluster_descriptions = {
            "Normal_User_Activity": {
                "explanation": "Standard user behavior patterns within expected parameters",
                "risk_level": "Low",
                "details": "User activities that match historical baselines and expected patterns"
            },
            "Baseline_User_Behavior": {
                "explanation": "User activities that establish normal behavioral patterns",
                "risk_level": "Low",
                "details": "Events used to establish user behavior baselines, generally benign"
            },
            "Session_Management_Issues": {
                "explanation": "Potential problems with user session handling",
                "risk_level": "Medium",
                "details": "Sessions that may have unusual duration, timing, or characteristics"
            },
            "Suspicious_User_Behavior": {
                "explanation": "User activities that deviate from normal patterns",
                "risk_level": "Medium",
                "details": "Behavior that warrants investigation but may not be malicious"
            },
            "Critical_User_Breach": {
                "explanation": "High-confidence indicators of user account compromise",
                "risk_level": "Critical",
                "details": "Strong evidence of unauthorized access or malicious activity"
            },
            "Suspicious_Authentication_Pattern": {
                "explanation": "Login behaviors that suggest potential credential abuse",
                "risk_level": "High",
                "details": "Authentication events with unusual timing, frequency, or source patterns"
            },
            "Lateral_Movement_Indicators": {
                "explanation": "Activities suggesting movement between systems",
                "risk_level": "High", 
                "details": "Authentication or access patterns indicating potential lateral movement"
            },
            "Critical_Persistent_Threats": {
                "explanation": "Evidence of advanced persistent threat activity",
                "risk_level": "Critical",
                "details": "Sustained malicious activity suggesting sophisticated threat actor"
            },
            "High_Risk_Authentication": {
                "explanation": "Authentication events with elevated risk factors",
                "risk_level": "High",
                "details": "Logon activities with multiple risk indicators"
            },
            "System_Process_Anomalies": {
                "explanation": "Unusual system or service process behavior",
                "risk_level": "Medium",
                "details": "System processes acting outside normal parameters"
            },
            "Network_Reconnaissance": {
                "explanation": "Activities suggesting network discovery or scanning", 
                "risk_level": "High",
                "details": "Behavior patterns indicating network reconnaissance activities"
            },
            "Outlier_Extreme_Risk": {
                "explanation": "Extremely unusual activities requiring immediate attention",
                "risk_level": "Critical",
                "details": "Activities that are statistical outliers with very high risk scores"
            },
            "Moderate_Risk_Events": {
                "explanation": "Events with elevated risk but not immediately critical",
                "risk_level": "Medium",
                "details": "Activities that warrant monitoring and potential investigation"
            },
            "Baseline_Activity": {
                "explanation": "Standard system and user activities",
                "risk_level": "Low",
                "details": "Normal operational activities used for baseline establishment"
            }
        }

    def load_csv_data(self, filename):
        """Load CSV data using standard library"""
        data = []
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Convert numeric fields
                    for field in ['max_abs_z', 'event_id', 'winlog_logon_type', 'logon_type']:
                        if field in row and row[field]:
                            try:
                                if field == 'event_id':
                                    row[field] = int(float(row[field]))
                                else:
                                    row[field] = float(row[field])
                            except (ValueError, TypeError):
                                pass
                    data.append(row)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return []
        
        return data

    def analyze_high_zscore_events(self, data, account_type, threshold=20):
        """Find high z-score events"""
        high_risk = []
        for row in data:
            try:
                z_score = float(row.get('max_abs_z', 0))
                if z_score > threshold:
                    row['account_type'] = account_type
                    high_risk.append(row)
            except (ValueError, TypeError):
                continue
                
        # Sort by z-score descending
        high_risk.sort(key=lambda x: float(x.get('max_abs_z', 0)), reverse=True)
        return high_risk

    def generate_event_interpretation(self, row):
        """Generate human-readable interpretation for a specific event"""
        event_id = str(row.get('event_id', '0'))
        username = row.get('username', 'Unknown')
        hostname = row.get('hostname', 'Unknown')
        source_ip = row.get('source_ip', 'N/A')
        timestamp = row.get('timestamp', 'Unknown')
        z_score = float(row.get('max_abs_z', 0))
        cluster_desc = row.get('cluster_description', 'Unknown')
        account_type = row.get('account_type', 'Unknown')
        
        # Get base event information
        event_info = self.event_definitions.get(event_id, {
            "name": f"Event {event_id}",
            "normal_behavior": "Unknown event type",
            "suspicious_indicators": ["High z-score deviation"],
            "attack_context": ["Unknown"],
            "investigation_steps": ["Research event ID"],
            "mitre_attack": ["Unknown"]
        })
        
        # Account type context
        if account_type == 'Computer' and username.endswith('$'):
            account_context = f"Computer account {username} (service/machine account)"
        elif username == 'ANONYMOUS LOGON':
            account_context = "Anonymous logon (potentially suspicious)"
        elif username in ['LOCAL SERVICE', 'NETWORK SERVICE']:
            account_context = f"System service account ({username})"
        else:
            account_context = f"User account {username}"
            
        # Event context
        if event_id == '4624':
            logon_type = str(row.get('winlog_logon_type', row.get('logon_type', 'Unknown')))
            logon_desc = self.logon_types.get(logon_type, f"Type {logon_type}")
            event_context = f"successful logon ({logon_desc})"
            
            if source_ip and source_ip != 'N/A':
                if source_ip == '127.0.0.1' or source_ip.startswith('127.'):
                    ip_context = "from local system (localhost)"
                elif source_ip.startswith('10.'):
                    ip_context = f"from internal network ({source_ip})"
                else:
                    ip_context = f"from external IP ({source_ip})"
            else:
                ip_context = "with no source IP recorded"
                
        elif event_id == '4625':
            event_context = "failed logon attempt"
            ip_context = f"from {source_ip}" if source_ip != 'N/A' else ""
            
        elif event_id == '4634':
            event_context = "account logoff"
            ip_context = ""
            
        elif event_id == '4688':
            process_name = row.get('process_name', 'unknown process')
            event_context = f"process creation ({process_name})"
            ip_context = ""
            
        elif event_id == '4689':
            process_name = row.get('process_name', 'unknown process')
            event_context = f"process termination ({process_name})"
            ip_context = ""
            
        else:
            event_context = f"{event_info['name'].lower()}"
            ip_context = ""

        # Risk assessment based on z-score
        if z_score > 50:
            risk_level = "CRITICAL"
            risk_explanation = "This behavior has never been observed before and represents an extreme anomaly"
        elif z_score > 30:
            risk_level = "HIGH"
            risk_explanation = "This behavior is extremely rare and highly suspicious"
        elif z_score > 20:
            risk_level = "MEDIUM-HIGH" 
            risk_explanation = "This behavior significantly deviates from normal patterns"
        else:
            risk_level = "MEDIUM"
            risk_explanation = "This behavior shows some deviation from baseline"

        # Cluster context
        cluster_info = self.cluster_descriptions.get(cluster_desc, {
            "explanation": cluster_desc.replace('_', ' ').title(),
            "risk_level": "Unknown",
            "details": "Custom cluster requiring analysis"
        })

        # Build final description
        try:
            time_obj = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            time_str = time_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
        except:
            time_str = timestamp
        
        description = f"""
Event: {event_info['name']} - {account_context} {event_context} {ip_context}
Time: {time_str}
Host: {hostname}
Risk: {risk_level} (Z-Score: {z_score:.2f})
Reason: {risk_explanation}

Context: {cluster_info['explanation']} - {cluster_info['details']}

Why this is suspicious:
- Z-score of {z_score:.2f} indicates this behavior is {z_score:.1f} standard deviations from normal
- Classified as "{cluster_desc}" suggesting {cluster_info['explanation'].lower()}
- {event_info['name']} events normally involve {event_info['normal_behavior'].lower()}

Investigation priorities:
{chr(10).join('- ' + step for step in event_info['investigation_steps'])}

Associated MITRE ATT&CK techniques: {', '.join(event_info['mitre_attack'])}
        """.strip()
        
        return description

    def create_interpretation_mappings(self):
        """Create comprehensive JSON mappings for all event types"""
        mappings = {
            "event_interpretations": self.event_definitions,
            "logon_types": self.logon_types,
            "cluster_descriptions": self.cluster_descriptions,
            "risk_thresholds": {
                "low": {"min": 0, "max": 10, "description": "Normal baseline behavior"},
                "medium": {"min": 10, "max": 20, "description": "Some deviation warranting monitoring"},
                "medium_high": {"min": 20, "max": 30, "description": "Significant deviation requiring investigation"},
                "high": {"min": 30, "max": 50, "description": "Extreme deviation indicating potential threats"},
                "critical": {"min": 50, "max": 1000, "description": "Never-before-seen behavior requiring immediate response"}
            },
            "account_type_guidance": {
                "computer_accounts": {
                    "identification": "Username ending with $",
                    "normal_behavior": "Automated authentication for service-to-service communication",
                    "suspicious_patterns": [
                        "Interactive logons (should be network only)",
                        "Logons from unusual IPs",
                        "High frequency authentication",
                        "Authentication outside service windows"
                    ]
                },
                "user_accounts": {
                    "identification": "Standard username without $",
                    "normal_behavior": "Interactive and network logons during business hours",
                    "suspicious_patterns": [
                        "Logons from multiple locations simultaneously",
                        "Authentication outside normal hours",
                        "High frequency failed logons",
                        "Unusual source IP addresses"
                    ]
                },
                "service_accounts": {
                    "identification": "LOCAL SERVICE, NETWORK SERVICE, system accounts",
                    "normal_behavior": "Automated system operations",
                    "suspicious_patterns": [
                        "Interactive logons",
                        "Authentication from remote systems",
                        "Unusual process execution"
                    ]
                },
                "anonymous_logon": {
                    "identification": "ANONYMOUS LOGON",
                    "normal_behavior": "Limited system access for specific services",
                    "suspicious_patterns": [
                        "High frequency anonymous access",
                        "Access from external IPs",
                        "Unusual timing patterns"
                    ]
                }
            }
        }
        
        return mappings

    def run_full_analysis(self, computer_file, user_file, output_file):
        """Run complete analysis and generate outputs"""
        print("=== Windows Security Event Log Analysis ===\n")
        
        # Load data
        print("Loading computer accounts data...")
        computer_data = self.load_csv_data(computer_file)
        print(f"Loaded {len(computer_data)} computer account events")
        
        print("Loading user accounts data...")
        user_data = self.load_csv_data(user_file)
        print(f"Loaded {len(user_data)} user account events")
        
        # Analyze high z-score events
        print("\nAnalyzing high-risk events...")
        computer_high_risk = self.analyze_high_zscore_events(computer_data, 'Computer', threshold=20)
        user_high_risk = self.analyze_high_zscore_events(user_data, 'User', threshold=20)
        
        # Combine and sort all high-risk events
        all_high_risk = computer_high_risk + user_high_risk
        all_high_risk.sort(key=lambda x: float(x.get('max_abs_z', 0)), reverse=True)
        
        print(f"Found {len(all_high_risk)} high-risk events (z-score > 20)")
        
        # Create interpretation mappings
        mappings = self.create_interpretation_mappings()
        
        # Generate top critical event descriptions
        print("\nGenerating detailed descriptions for top 100 critical events...")
        critical_descriptions = []
        
        for i, row in enumerate(all_high_risk[:100]):
            description = self.generate_event_interpretation(row)
            
            critical_descriptions.append({
                "rank": i + 1,
                "timestamp": row.get('timestamp', 'Unknown'),
                "username": row.get('username', 'Unknown'),
                "hostname": row.get('hostname', 'Unknown'),
                "event_id": str(row.get('event_id', '0')),
                "z_score": float(row.get('max_abs_z', 0)),
                "cluster": row.get('cluster_description', 'Unknown'),
                "account_type": row.get('account_type', 'Unknown'),
                "source_ip": row.get('source_ip', 'N/A'),
                "detailed_description": description
            })
        
        # Calculate summary statistics
        total_events = len(computer_data) + len(user_data)
        high_risk_count = len(all_high_risk)
        
        # Event ID summaries
        computer_event_ids = {}
        user_event_ids = {}
        
        for row in computer_data:
            eid = str(row.get('event_id', '0'))
            computer_event_ids[eid] = computer_event_ids.get(eid, 0) + 1
            
        for row in user_data:
            eid = str(row.get('event_id', '0'))
            user_event_ids[eid] = user_event_ids.get(eid, 0) + 1
            
        # Cluster summaries
        cluster_summary = {}
        for row in all_high_risk:
            cluster = row.get('cluster_description', 'Unknown')
            cluster_summary[cluster] = cluster_summary.get(cluster, 0) + 1
            
        account_type_summary = {}
        for row in all_high_risk:
            acc_type = row.get('account_type', 'Unknown')
            account_type_summary[acc_type] = account_type_summary.get(acc_type, 0) + 1
            
        # Compile final output
        final_output = {
            "analysis_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_events_analyzed": total_events,
                "high_risk_events": high_risk_count,
                "risk_threshold_used": 20
            },
            "summary_statistics": {
                "event_id_breakdown": {
                    "Computer Accounts": dict(sorted(computer_event_ids.items(), key=lambda x: x[1], reverse=True)[:10]),
                    "User Accounts": dict(sorted(user_event_ids.items(), key=lambda x: x[1], reverse=True)[:10])
                },
                "high_risk_clusters": cluster_summary,
                "account_type_breakdown": account_type_summary
            },
            "interpretation_mappings": mappings,
            "critical_events_analysis": critical_descriptions
        }
        
        # Save to file
        print(f"\nSaving analysis to {output_file}...")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
            
        print(f"\n=== Analysis Complete ===")
        print(f"Total events analyzed: {total_events:,}")
        print(f"High-risk events identified: {high_risk_count}")
        if all_high_risk:
            print(f"Top critical event z-score: {float(all_high_risk[0].get('max_abs_z', 0)):.2f}")
        print(f"Analysis saved to: {output_file}")
        
        # Print sample critical events
        print(f"\n=== Top 5 Most Critical Events ===")
        for i, event in enumerate(critical_descriptions[:5], 1):
            event_info = self.event_definitions.get(event['event_id'], {})
            print(f"\n{i}. {event['username']} on {event['hostname']} (Z-Score: {event['z_score']:.2f})")
            print(f"   Event: {event_info.get('name', f'Event {event['event_id']}')}")
            print(f"   Cluster: {event['cluster']}")
            print(f"   Time: {event['timestamp']}")

if __name__ == "__main__":
    # Initialize interpreter
    interpreter = SimpleSecurityLogInterpreter()
    
    # Run full analysis
    computer_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_computer_accounts_clustered.csv"
    user_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_user_accounts_clustered.csv"
    output_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/outputs/event_interpretations.json"
    
    interpreter.run_full_analysis(computer_file, user_file, output_file)