#!/usr/bin/env python3
"""
Comprehensive Statistical Analysis of Cybersecurity Event Data
Using only built-in Python libraries for maximum compatibility
"""

import csv
import json
import math
from datetime import datetime
from collections import defaultdict, Counter

class CyberSecurityStatisticalAnalyzer:
    def __init__(self):
        self.computer_data = []
        self.user_data = []
        self.analysis_results = {}
        
    def load_csv_data(self, filename):
        """Load CSV data using built-in csv module"""
        data = []
        with open(filename, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                data.append(row)
        return data
    
    def safe_float(self, value):
        """Safely convert value to float"""
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    
    def calculate_statistics(self, values):
        """Calculate basic statistics for a list of values"""
        if not values:
            return {}
        
        values = [v for v in values if v is not None]
        n = len(values)
        if n == 0:
            return {}
        
        sorted_values = sorted(values)
        
        # Basic statistics
        mean_val = sum(values) / n
        
        # Median
        if n % 2 == 0:
            median_val = (sorted_values[n//2 - 1] + sorted_values[n//2]) / 2
        else:
            median_val = sorted_values[n//2]
        
        # Standard deviation
        variance = sum((x - mean_val) ** 2 for x in values) / n
        std_val = math.sqrt(variance)
        
        # Percentiles
        def percentile(data, p):
            k = (len(data) - 1) * p / 100
            f = math.floor(k)
            c = math.ceil(k)
            if f == c:
                return data[int(k)]
            return data[int(f)] * (c - k) + data[int(c)] * (k - f)
        
        return {
            'count': n,
            'mean': mean_val,
            'median': median_val,
            'std': std_val,
            'min': min(values),
            'max': max(values),
            'percentiles': {
                '25th': percentile(sorted_values, 25),
                '50th': percentile(sorted_values, 50),
                '75th': percentile(sorted_values, 75),
                '90th': percentile(sorted_values, 90),
                '95th': percentile(sorted_values, 95),
                '99th': percentile(sorted_values, 99),
                '99.9th': percentile(sorted_values, 99.9)
            }
        }
    
    def analyze_dataset(self, data, dataset_type):
        """Comprehensive analysis of a dataset"""
        print(f"Analyzing {dataset_type} dataset with {len(data)} events...")
        
        # Extract z-scores
        max_abs_z_values = [self.safe_float(row.get('max_abs_z', 0)) for row in data]
        logcount_z_values = [self.safe_float(row.get('logcount_z_loss', 0)) for row in data]
        hostincr_z_values = [self.safe_float(row.get('hostincrement_z_loss', 0)) for row in data]
        ipincr_z_values = [self.safe_float(row.get('ipincrement_z_loss', 0)) for row in data]
        procincr_z_values = [self.safe_float(row.get('processincrement_z_loss', 0)) for row in data]
        
        # Basic dataset info
        usernames = [row.get('username', '') for row in data]
        hostnames = [row.get('hostname', '') for row in data]
        timestamps = [row.get('timestamp', '') for row in data]
        
        # Statistical analysis
        analysis = {
            'dataset_info': {
                'total_events': len(data),
                'unique_users': len(set(usernames)),
                'unique_hosts': len(set(hostnames)),
                'time_range': {
                    'start': min(timestamps) if timestamps else 'Unknown',
                    'end': max(timestamps) if timestamps else 'Unknown'
                }
            },
            'z_score_statistics': {
                'max_abs_z': self.calculate_statistics(max_abs_z_values),
                'logcount_z_loss': self.calculate_statistics(logcount_z_values),
                'hostincrement_z_loss': self.calculate_statistics(hostincr_z_values),
                'ipincrement_z_loss': self.calculate_statistics(ipincr_z_values),
                'processincrement_z_loss': self.calculate_statistics(procincr_z_values)
            }
        }
        
        # Outlier analysis
        analysis['outlier_analysis'] = self.analyze_outliers(max_abs_z_values)
        
        # Risk distribution analysis
        analysis['risk_distribution'] = self.analyze_risk_distribution(max_abs_z_values)
        
        # Cluster analysis
        analysis['cluster_analysis'] = self.analyze_clusters(data)
        
        # Extreme anomalies
        analysis['extreme_anomalies'] = self.find_extreme_anomalies(data, max_abs_z_values)
        
        # Temporal patterns
        analysis['temporal_patterns'] = self.analyze_temporal_patterns(data, max_abs_z_values)
        
        return analysis
    
    def analyze_outliers(self, z_values):
        """Analyze statistical outliers"""
        total = len(z_values)
        outlier_thresholds = [3.0, 5.0, 10.0, 20.0]
        
        analysis = {
            'total_events': total,
            'outlier_analysis': {}
        }
        
        for threshold in outlier_thresholds:
            outliers = [z for z in z_values if z >= threshold]
            count = len(outliers)
            percentage = (count / total * 100) if total > 0 else 0
            
            # Statistical interpretation
            if threshold == 3.0:
                expected = 0.27  # ~0.27% in normal distribution
                interpretation = f"Expected in normal distribution: ~0.27%. Observed: {percentage:.2f}%"
            elif threshold == 5.0:
                expected = 0.000057
                interpretation = f"Expected in normal distribution: ~0.000057%. Observed: {percentage:.6f}%"
            else:
                interpretation = f"Extremely rare events: {percentage:.6f}% of total"
            
            analysis['outlier_analysis'][f'z_score_above_{threshold}'] = {
                'count': count,
                'percentage': percentage,
                'interpretation': interpretation
            }
        
        return analysis
    
    def analyze_risk_distribution(self, z_values):
        """Analyze risk score distribution and create thresholds"""
        if not z_values:
            return {}
        
        stats = self.calculate_statistics(z_values)
        
        # Define risk categories based on percentiles
        risk_thresholds = {
            'minimal': 0,
            'low': stats['percentiles']['75th'],
            'medium': stats['percentiles']['90th'],
            'high': stats['percentiles']['95th'],
            'critical': stats['percentiles']['99th'],
            'extreme': stats['percentiles']['99.9th']
        }
        
        # Count events in each category
        risk_distribution = {}
        thresholds_list = [
            ('minimal', 0, risk_thresholds['low']),
            ('low', risk_thresholds['low'], risk_thresholds['medium']),
            ('medium', risk_thresholds['medium'], risk_thresholds['high']),
            ('high', risk_thresholds['high'], risk_thresholds['critical']),
            ('critical', risk_thresholds['critical'], risk_thresholds['extreme']),
            ('extreme', risk_thresholds['extreme'], float('inf'))
        ]
        
        for category, min_val, max_val in thresholds_list:
            if max_val == float('inf'):
                count = len([z for z in z_values if z >= min_val])
            else:
                count = len([z for z in z_values if min_val <= z < max_val])
            
            percentage = (count / len(z_values) * 100) if z_values else 0
            
            risk_distribution[category] = {
                'count': count,
                'percentage': percentage,
                'threshold_range': f"{min_val:.3f} - {max_val:.3f}" if max_val != float('inf') else f">= {min_val:.3f}"
            }
        
        return {
            'risk_thresholds': risk_thresholds,
            'risk_distribution': risk_distribution
        }
    
    def analyze_clusters(self, data):
        """Analyze cluster patterns"""
        cluster_analysis = defaultdict(lambda: {'count': 0, 'z_scores': [], 'descriptions': set()})
        
        for row in data:
            cluster_id = row.get('cluster_id', 'unknown')
            z_score = self.safe_float(row.get('max_abs_z', 0))
            description = row.get('cluster_description', 'Unknown')
            
            cluster_analysis[cluster_id]['count'] += 1
            cluster_analysis[cluster_id]['z_scores'].append(z_score)
            cluster_analysis[cluster_id]['descriptions'].add(description)
        
        # Calculate statistics for each cluster
        result = {}
        for cluster_id, data_dict in cluster_analysis.items():
            z_scores = data_dict['z_scores']
            stats = self.calculate_statistics(z_scores)
            
            result[cluster_id] = {
                'count': data_dict['count'],
                'percentage': (data_dict['count'] / len(data) * 100) if data else 0,
                'descriptions': list(data_dict['descriptions']),
                'risk_statistics': stats
            }
        
        return result
    
    def find_extreme_anomalies(self, data, z_values):
        """Find and explain extreme anomalies"""
        extreme_threshold = 20.0
        extreme_anomalies = []
        
        for i, z_score in enumerate(z_values):
            if z_score >= extreme_threshold:
                row = data[i]
                
                # Calculate rarity
                probability = self.normal_tail_probability(z_score)
                odds = (1 / probability) if probability > 0 else float('inf')
                
                anomaly_info = {
                    'event_details': {
                        'username': row.get('username', 'Unknown'),
                        'hostname': row.get('hostname', 'Unknown'),
                        'timestamp': row.get('timestamp', 'Unknown'),
                        'event_action': row.get('event_action', 'Unknown'),
                        'cluster_description': row.get('cluster_description', 'Unknown')
                    },
                    'statistical_context': {
                        'z_score': z_score,
                        'probability': probability,
                        'rarity_description': self.describe_rarity(z_score),
                        'standard_deviations': f"{z_score:.1f} standard deviations from mean"
                    }
                }
                extreme_anomalies.append(anomaly_info)
        
        return extreme_anomalies
    
    def normal_tail_probability(self, z_score):
        """Approximate tail probability for normal distribution"""
        # Approximate using complementary error function
        # For large z, probability ≈ e^(-z²/2) / (z * sqrt(2π))
        if z_score > 8:
            return math.exp(-z_score**2 / 2) / (z_score * math.sqrt(2 * math.pi))
        else:
            # For smaller z, use more accurate approximation
            return 0.5 * (1 - math.erf(z_score / math.sqrt(2)))
    
    def describe_rarity(self, z_score):
        """Provide human-readable description of event rarity"""
        if z_score >= 30:
            return "Astronomically rare - essentially impossible under normal circumstances"
        elif z_score >= 20:
            return "Extremely rare - probability less than 1 in 10^10"
        elif z_score >= 10:
            return "Very rare - probability less than 1 in 10^6"
        elif z_score >= 5:
            return "Rare - probability less than 1 in 10^3"
        elif z_score >= 3:
            return "Unusual - probability less than 0.3%"
        else:
            return "Within normal variation"
    
    def analyze_temporal_patterns(self, data, z_values):
        """Analyze temporal patterns in the data"""
        hourly_data = defaultdict(list)
        daily_data = defaultdict(list)
        
        for i, row in enumerate(data):
            timestamp = row.get('timestamp', '')
            z_score = z_values[i]
            
            if timestamp:
                try:
                    # Extract hour and day from timestamp
                    # Format: 2025-08-27T01:22:02.078000000Z
                    date_part = timestamp.split('T')[0]
                    time_part = timestamp.split('T')[1].split('.')[0] if 'T' in timestamp else '00:00:00'
                    hour = int(time_part.split(':')[0])
                    
                    # Simple day extraction from date
                    day = date_part.split('-')[2] if '-' in date_part else 'unknown'
                    
                    hourly_data[hour].append(z_score)
                    daily_data[day].append(z_score)
                except:
                    continue
        
        # Calculate hourly statistics
        hourly_stats = {}
        for hour, scores in hourly_data.items():
            hourly_stats[hour] = {
                'count': len(scores),
                'avg_risk': sum(scores) / len(scores) if scores else 0,
                'max_risk': max(scores) if scores else 0
            }
        
        # Find peak activity hours
        peak_hours = sorted(hourly_data.keys(), key=lambda h: len(hourly_data[h]), reverse=True)[:3]
        
        return {
            'hourly_patterns': hourly_stats,
            'peak_activity_hours': peak_hours,
            'total_hours_analyzed': len(hourly_data)
        }
    
    def run_analysis(self, computer_file, user_file, output_file):
        """Run complete statistical analysis"""
        print("Loading cybersecurity event data...")
        
        # Load data
        try:
            self.computer_data = self.load_csv_data(computer_file)
            print(f"Loaded {len(self.computer_data)} computer account events")
        except Exception as e:
            print(f"Error loading computer data: {e}")
            self.computer_data = []
        
        try:
            self.user_data = self.load_csv_data(user_file)
            print(f"Loaded {len(self.user_data)} user account events")
        except Exception as e:
            print(f"Error loading user data: {e}")
            self.user_data = []
        
        # Initialize results
        self.analysis_results = {
            'analysis_metadata': {
                'generated_at': datetime.now().isoformat(),
                'analyzer_version': '1.0_builtin_only',
                'datasets_analyzed': ['computer_accounts', 'user_accounts']
            }
        }
        
        # Analyze datasets
        if self.computer_data:
            self.analysis_results['computer_accounts'] = self.analyze_dataset(self.computer_data, 'computer_accounts')
        
        if self.user_data:
            self.analysis_results['user_accounts'] = self.analyze_dataset(self.user_data, 'user_accounts')
        
        # Combined insights
        self.analysis_results['combined_insights'] = self.generate_combined_insights()
        
        # Save results
        print(f"Saving analysis results to {output_file}")
        with open(output_file, 'w') as f:
            json.dump(self.analysis_results, f, indent=2, default=str)
        
        # Print summary
        self.print_summary()
    
    def generate_combined_insights(self):
        """Generate comparative insights"""
        insights = {'key_findings': []}
        
        if self.computer_data and self.user_data:
            comp_z = [self.safe_float(row.get('max_abs_z', 0)) for row in self.computer_data]
            user_z = [self.safe_float(row.get('max_abs_z', 0)) for row in self.user_data]
            
            comp_avg = sum(comp_z) / len(comp_z) if comp_z else 0
            user_avg = sum(user_z) / len(user_z) if user_z else 0
            
            comp_extreme = len([z for z in comp_z if z >= 20])
            user_extreme = len([z for z in user_z if z >= 20])
            
            insights['comparative_statistics'] = {
                'computer_mean_risk': comp_avg,
                'user_mean_risk': user_avg,
                'computer_extreme_count': comp_extreme,
                'user_extreme_count': user_extreme
            }
            
            insights['key_findings'] = [
                f"Computer accounts: {len(self.computer_data)} events, avg risk: {comp_avg:.2f}",
                f"User accounts: {len(self.user_data)} events, avg risk: {user_avg:.2f}",
                f"Total extreme anomalies (z>20): {comp_extreme + user_extreme}",
                f"Risk differential: Computer accounts {'higher' if comp_avg > user_avg else 'lower'} average risk"
            ]
        
        return insights
    
    def print_summary(self):
        """Print comprehensive summary"""
        print("\n" + "="*80)
        print("CYBERSECURITY EVENT DATA - STATISTICAL ANALYSIS SUMMARY")
        print("="*80)
        
        # Computer accounts
        if 'computer_accounts' in self.analysis_results:
            comp_data = self.analysis_results['computer_accounts']
            comp_stats = comp_data['z_score_statistics']['max_abs_z']
            
            print(f"\nCOMPUTER ACCOUNTS DATASET")
            print(f"Events: {comp_data['dataset_info']['total_events']}")
            print(f"Unique Users: {comp_data['dataset_info']['unique_users']}")
            print(f"Unique Hosts: {comp_data['dataset_info']['unique_hosts']}")
            print(f"Mean Z-Score: {comp_stats.get('mean', 0):.3f}")
            print(f"95th Percentile: {comp_stats.get('percentiles', {}).get('95th', 0):.3f}")
            print(f"99th Percentile: {comp_stats.get('percentiles', {}).get('99th', 0):.3f}")
            print(f"Maximum Z-Score: {comp_stats.get('max', 0):.3f}")
            
            # Outliers
            outlier_data = comp_data.get('outlier_analysis', {}).get('outlier_analysis', {})
            if 'z_score_above_3.0' in outlier_data:
                print(f"Moderate Outliers (z>3): {outlier_data['z_score_above_3.0']['count']} ({outlier_data['z_score_above_3.0']['percentage']:.2f}%)")
            if 'z_score_above_20.0' in outlier_data:
                print(f"Extreme Outliers (z>20): {outlier_data['z_score_above_20.0']['count']} ({outlier_data['z_score_above_20.0']['percentage']:.6f}%)")
        
        # User accounts
        if 'user_accounts' in self.analysis_results:
            user_data = self.analysis_results['user_accounts']
            user_stats = user_data['z_score_statistics']['max_abs_z']
            
            print(f"\nUSER ACCOUNTS DATASET")
            print(f"Events: {user_data['dataset_info']['total_events']}")
            print(f"Unique Users: {user_data['dataset_info']['unique_users']}")
            print(f"Unique Hosts: {user_data['dataset_info']['unique_hosts']}")
            print(f"Mean Z-Score: {user_stats.get('mean', 0):.3f}")
            print(f"95th Percentile: {user_stats.get('percentiles', {}).get('95th', 0):.3f}")
            print(f"99th Percentile: {user_stats.get('percentiles', {}).get('99th', 0):.3f}")
            print(f"Maximum Z-Score: {user_stats.get('max', 0):.3f}")
            
            # Outliers
            outlier_data = user_data.get('outlier_analysis', {}).get('outlier_analysis', {})
            if 'z_score_above_3.0' in outlier_data:
                print(f"Moderate Outliers (z>3): {outlier_data['z_score_above_3.0']['count']} ({outlier_data['z_score_above_3.0']['percentage']:.2f}%)")
            if 'z_score_above_20.0' in outlier_data:
                print(f"Extreme Outliers (z>20): {outlier_data['z_score_above_20.0']['count']} ({outlier_data['z_score_above_20.0']['percentage']:.6f}%)")
        
        # Key findings
        if 'combined_insights' in self.analysis_results:
            insights = self.analysis_results['combined_insights']
            print(f"\nKEY INSIGHTS:")
            for finding in insights.get('key_findings', []):
                print(f"• {finding}")
        
        print("\nSTATISTICAL INTERPRETATION:")
        print("• Z-scores represent standard deviations from normal behavior")
        print("• Z-scores > 3: Unusual (less than 0.3% probability)")
        print("• Z-scores > 20: Extremely rare (less than 1 in 10^10 probability)")
        print("• Higher z-scores indicate more anomalous behavior requiring investigation")
        
        print("\n" + "="*80)

if __name__ == "__main__":
    # File paths
    computer_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_computer_accounts_clustered.csv"
    user_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_user_accounts_clustered.csv"
    output_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/outputs/statistical_analysis.json"
    
    # Create output directory
    import os
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Run analysis
    analyzer = CyberSecurityStatisticalAnalyzer()
    analyzer.run_analysis(computer_file, user_file, output_file)