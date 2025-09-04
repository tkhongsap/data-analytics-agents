#!/usr/bin/env python3
"""
Basic Statistical Analysis for Cybersecurity Data Clustering
===========================================================

This script performs statistical analysis on cybersecurity datasets using only 
built-in Python libraries to identify clustering characteristics.

Author: Data Statistician (Claude Code)
Date: 2025-09-03
"""

import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
import statistics
import math

class BasicCyberSecAnalyzer:
    """
    Basic statistical analyzer for cybersecurity event data
    """
    
    def __init__(self, computer_file, user_file):
        self.computer_file = computer_file
        self.user_file = user_file
        self.computer_data = []
        self.user_data = []
        
    def load_csv_data(self, filename):
        """Load CSV data with basic parsing"""
        data = []
        try:
            with open(filename, 'r', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                for row in reader:
                    # Convert numeric fields
                    for key, value in row.items():
                        if value and value.replace('.', '').replace('-', '').replace('E', '').replace('e', '').replace('+', '').isdigit():
                            try:
                                if '.' in value or 'E' in value or 'e' in value:
                                    row[key] = float(value)
                                else:
                                    row[key] = int(value)
                            except ValueError:
                                pass  # Keep as string
                    data.append(row)
        except FileNotFoundError:
            print(f"Error: File {filename} not found")
            return []
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return []
        
        return data
    
    def calculate_stats(self, values):
        """Calculate basic statistics for numeric values"""
        if not values:
            return {}
        
        values = [float(v) for v in values if v != '' and v is not None]
        if not values:
            return {}
        
        sorted_values = sorted(values)
        n = len(values)
        
        stats_dict = {
            'count': n,
            'mean': statistics.mean(values),
            'median': statistics.median(values),
            'min': min(values),
            'max': max(values),
            'range': max(values) - min(values),
            'std_dev': statistics.stdev(values) if n > 1 else 0
        }
        
        # Percentiles
        if n >= 4:
            stats_dict['q25'] = sorted_values[n//4]
            stats_dict['q75'] = sorted_values[3*n//4]
            stats_dict['iqr'] = stats_dict['q75'] - stats_dict['q25']
            
            # 95th and 99th percentiles
            stats_dict['p95'] = sorted_values[int(0.95 * n)]
            stats_dict['p99'] = sorted_values[int(0.99 * n)] if n >= 100 else stats_dict['max']
        
        # Outliers (3 standard deviations)
        if stats_dict['std_dev'] > 0:
            threshold = stats_dict['mean'] + 3 * stats_dict['std_dev']
            outliers = sum(1 for v in values if v > threshold)
            stats_dict['outliers_3sigma'] = outliers
            stats_dict['outlier_percentage'] = (outliers / n) * 100
            
            # Critical events (z > 20 for security context)
            critical_threshold = 20
            critical_events = sum(1 for v in values if v > critical_threshold)
            stats_dict['critical_events'] = critical_events
            stats_dict['critical_percentage'] = (critical_events / n) * 100
        
        return stats_dict
    
    def analyze_dataset(self, data, dataset_name):
        """Perform comprehensive analysis on dataset"""
        if not data:
            print(f"No data available for {dataset_name}")
            return {}
        
        print(f"\n{'='*60}")
        print(f"STATISTICAL ANALYSIS: {dataset_name.upper()}")
        print(f"{'='*60}")
        
        analysis = {
            'dataset_name': dataset_name,
            'total_events': len(data),
            'features': {},
            'clustering_recommendations': {}
        }
        
        # Basic dataset overview
        print(f"Dataset Overview:")
        print(f"- Total Events: {len(data):,}")
        
        # Count unique values for key categorical fields
        categorical_fields = ['username', 'hostname', 'event_id', 'event_action', 'source_ip']
        for field in categorical_fields:
            if field in data[0]:
                unique_values = len(set(row.get(field, '') for row in data))
                print(f"- Unique {field}: {unique_values:,}")
                analysis['features'][f'unique_{field}'] = unique_values
        
        # Identify numeric columns for statistical analysis
        numeric_cols = []
        sample_row = data[0]
        for key, value in sample_row.items():
            if isinstance(value, (int, float)) and key != 'Unnamed: 0':
                numeric_cols.append(key)
        
        # Focus on key security-relevant columns
        priority_cols = ['max_abs_z', 'mean_abs_z', 'logcount', 'hostincrement', 'ipincrement']
        available_priority = [col for col in priority_cols if col in numeric_cols]
        
        print(f"\nKey Numeric Features Found: {len(numeric_cols)}")
        print(f"Priority Security Features: {available_priority}")
        
        # Statistical analysis of priority columns
        if available_priority:
            print(f"\n{'='*40}")
            print("ANOMALY SCORE ANALYSIS")
            print(f"{'='*40}")
            
            for col in available_priority:
                values = [row.get(col) for row in data if row.get(col) is not None]
                if values:
                    stats = self.calculate_stats(values)
                    analysis['features'][col] = stats
                    
                    print(f"\n{col.upper()} Statistics:")
                    print(f"  Count: {stats.get('count', 0):,}")
                    print(f"  Mean: {stats.get('mean', 0):.4f}")
                    print(f"  Median: {stats.get('median', 0):.4f}")
                    print(f"  Std Dev: {stats.get('std_dev', 0):.4f}")
                    print(f"  Range: [{stats.get('min', 0):.4f}, {stats.get('max', 0):.4f}]")
                    
                    if 'p95' in stats:
                        print(f"  95th Percentile: {stats['p95']:.4f}")
                    if 'p99' in stats:
                        print(f"  99th Percentile: {stats['p99']:.4f}")
                    
                    if stats.get('outliers_3sigma', 0) > 0:
                        print(f"  Outliers (>3σ): {stats['outliers_3sigma']} ({stats.get('outlier_percentage', 0):.2f}%)")
                    
                    if stats.get('critical_events', 0) > 0:
                        print(f"  Critical Events (>20): {stats['critical_events']} ({stats.get('critical_percentage', 0):.2f}%)")
        
        # Event pattern analysis
        print(f"\n{'='*40}")
        print("EVENT PATTERN ANALYSIS")
        print(f"{'='*40}")
        
        if 'event_id' in data[0]:
            event_counts = Counter(str(row.get('event_id', '')) for row in data)
            print(f"Event ID Distribution (Top 10):")
            for event_id, count in event_counts.most_common(10):
                percentage = (count / len(data)) * 100
                print(f"  {event_id}: {count:,} ({percentage:.1f}%)")
            
            analysis['features']['event_distribution'] = dict(event_counts.most_common(20))
        
        if 'event_action' in data[0]:
            action_counts = Counter(str(row.get('event_action', '')) for row in data)
            print(f"\nEvent Action Distribution:")
            for action, count in action_counts.most_common():
                percentage = (count / len(data)) * 100
                print(f"  {action}: {count:,} ({percentage:.1f}%)")
            
            analysis['features']['action_distribution'] = dict(action_counts)
        
        # Host risk analysis
        if 'hostname' in data[0] and 'max_abs_z' in available_priority:
            print(f"\nHigh-Risk Host Analysis:")
            host_risks = defaultdict(list)
            for row in data:
                hostname = row.get('hostname', '')
                max_z = row.get('max_abs_z')
                if hostname and max_z is not None:
                    host_risks[hostname].append(float(max_z))
            
            # Calculate risk scores for hosts
            host_risk_scores = []
            for hostname, z_scores in host_risks.items():
                avg_z = statistics.mean(z_scores)
                max_z = max(z_scores)
                event_count = len(z_scores)
                risk_score = avg_z * math.log(event_count + 1)  # Weight by event frequency
                host_risk_scores.append((hostname, risk_score, avg_z, max_z, event_count))
            
            # Sort by risk score
            host_risk_scores.sort(key=lambda x: x[1], reverse=True)
            
            print(f"Top 10 Highest Risk Hosts:")
            for i, (hostname, risk_score, avg_z, max_z, count) in enumerate(host_risk_scores[:10], 1):
                print(f"  {i}. {hostname}: Risk={risk_score:.2f} (Avg_Z={avg_z:.2f}, Max_Z={max_z:.2f}, Events={count})")
            
            analysis['features']['host_risk_analysis'] = [
                {'hostname': h, 'risk_score': r, 'avg_z': a, 'max_z': m, 'event_count': c}
                for h, r, a, m, c in host_risk_scores[:20]
            ]
        
        # Clustering feature recommendations
        clustering_features = self._recommend_clustering_features(data, available_priority, numeric_cols)
        analysis['clustering_recommendations'] = clustering_features
        
        print(f"\n{'='*40}")
        print("CLUSTERING RECOMMENDATIONS")
        print(f"{'='*40}")
        print(f"Top Recommended Features:")
        for i, feature in enumerate(clustering_features.get('features', [])[:10], 1):
            print(f"  {i}. {feature}")
        
        print(f"\nClustering Insights:")
        insights = clustering_features.get('insights', [])
        for insight in insights:
            print(f"  • {insight}")
        
        return analysis
    
    def _recommend_clustering_features(self, data, priority_cols, all_numeric_cols):
        """Recommend best features for clustering"""
        recommendations = {
            'features': [],
            'insights': [],
            'optimal_k_estimate': 'Unknown'
        }
        
        # Priority order for security clustering
        feature_priority = [
            'max_abs_z',      # Maximum anomaly score - primary clustering feature
            'mean_abs_z',     # Average anomaly score - behavioral baseline
            'logcount',       # Event frequency - activity level
            'hostincrement',  # Host-based incremental patterns
            'ipincrement',    # IP-based patterns
            'processincrement' # Process-based patterns
        ]
        
        # Add available priority features
        for feature in feature_priority:
            if feature in priority_cols:
                recommendations['features'].append(feature)
        
        # Add z-loss features (prediction errors)
        z_loss_features = [col for col in all_numeric_cols if 'z_loss' in col]
        recommendations['features'].extend(z_loss_features[:3])  # Top 3 z-loss features
        
        # Add other relevant numeric features
        other_features = [col for col in all_numeric_cols if col not in recommendations['features'] and 'pred' not in col]
        recommendations['features'].extend(other_features[:2])  # Add 2 more features
        
        # Generate insights based on data characteristics
        if len(data) > 1000:
            recommendations['insights'].append("Large dataset - consider sampling or incremental clustering")
        
        if 'max_abs_z' in priority_cols:
            max_z_values = [row.get('max_abs_z') for row in data if row.get('max_abs_z') is not None]
            if max_z_values:
                max_val = max(max_z_values)
                if max_val > 20:
                    recommendations['insights'].append("Extreme outliers detected - consider robust scaling")
                if max_val > 100:
                    recommendations['insights'].append("Critical security events present - separate clustering for normal vs. anomalous behavior")
        
        # Estimate optimal number of clusters based on data size and diversity
        unique_users = len(set(row.get('username', '') for row in data))
        unique_hosts = len(set(row.get('hostname', '') for row in data))
        
        # Rough estimation based on user/host diversity
        if unique_users > 0 and unique_hosts > 0:
            estimated_k = min(int(math.sqrt(min(unique_users, unique_hosts))), 10)
            recommendations['optimal_k_estimate'] = f"{estimated_k}-{estimated_k+3}"
            recommendations['insights'].append(f"Estimated optimal K range: {estimated_k}-{estimated_k+3} based on user/host diversity")
        
        if len(data) < 100:
            recommendations['insights'].append("Small dataset - consider simple K-means with K=3-5")
        elif len(data) > 10000:
            recommendations['insights'].append("Large dataset - DBSCAN or Mini-batch K-means recommended")
        
        return recommendations
    
    def generate_comparative_analysis(self, computer_analysis, user_analysis):
        """Generate comparison between computer and user account analyses"""
        print(f"\n{'='*80}")
        print("COMPARATIVE ANALYSIS: COMPUTER vs USER ACCOUNTS")
        print(f"{'='*80}")
        
        print(f"Dataset Scale Comparison:")
        comp_events = computer_analysis.get('total_events', 0)
        user_events = user_analysis.get('total_events', 0)
        print(f"  Computer Accounts: {comp_events:,} events")
        print(f"  User Accounts: {user_events:,} events")
        print(f"  Scale Ratio: {comp_events/user_events:.1f}:1" if user_events > 0 else "  Scale Ratio: N/A")
        
        # Compare anomaly scores
        comp_max_z = computer_analysis.get('features', {}).get('max_abs_z', {})
        user_max_z = user_analysis.get('features', {}).get('max_abs_z', {})
        
        if comp_max_z and user_max_z:
            print(f"\nAnomaly Score Comparison:")
            print(f"  Computer Accounts Max Z-Score:")
            print(f"    Mean: {comp_max_z.get('mean', 0):.4f}, Max: {comp_max_z.get('max', 0):.4f}")
            print(f"    95th percentile: {comp_max_z.get('p95', 0):.4f}")
            print(f"    Critical events: {comp_max_z.get('critical_events', 0)} ({comp_max_z.get('critical_percentage', 0):.2f}%)")
            
            print(f"  User Accounts Max Z-Score:")
            print(f"    Mean: {user_max_z.get('mean', 0):.4f}, Max: {user_max_z.get('max', 0):.4f}")
            print(f"    95th percentile: {user_max_z.get('p95', 0):.4f}")
            print(f"    Critical events: {user_max_z.get('critical_events', 0)} ({user_max_z.get('critical_percentage', 0):.2f}%)")
            
            # Determine which has higher risk
            if comp_max_z.get('mean', 0) > user_max_z.get('mean', 0):
                print(f"  → Computer accounts show higher average anomaly scores")
            else:
                print(f"  → User accounts show higher average anomaly scores")
        
        # Compare event diversity
        comp_unique_events = computer_analysis.get('features', {}).get('unique_event_id', 0)
        user_unique_events = user_analysis.get('features', {}).get('unique_event_id', 0)
        
        print(f"\nEvent Diversity:")
        print(f"  Computer Accounts: {comp_unique_events} unique event types")
        print(f"  User Accounts: {user_unique_events} unique event types")
        
        # Clustering strategy recommendations
        print(f"\n{'='*50}")
        print("FINAL CLUSTERING STRATEGY RECOMMENDATIONS")
        print(f"{'='*50}")
        
        print(f"1. SEPARATE CLUSTERING APPROACH:")
        print(f"   • Cluster computer and user accounts separately")
        print(f"   • Different behavioral patterns require different clustering parameters")
        
        print(f"\n2. FEATURE SELECTION:")
        comp_features = computer_analysis.get('clustering_recommendations', {}).get('features', [])[:5]
        user_features = user_analysis.get('clustering_recommendations', {}).get('features', [])[:5]
        print(f"   • Computer accounts: {', '.join(comp_features)}")
        print(f"   • User accounts: {', '.join(user_features)}")
        
        print(f"\n3. SCALING CONSIDERATIONS:")
        print(f"   • Apply StandardScaler or RobustScaler due to extreme outliers")
        print(f"   • Consider log transformation for highly skewed features")
        
        print(f"\n4. ALGORITHM RECOMMENDATIONS:")
        if comp_events > 1000:
            print(f"   • Computer accounts: DBSCAN or Mini-batch K-means (large dataset)")
        else:
            print(f"   • Computer accounts: K-means with K=5-8")
        
        if user_events < 100:
            print(f"   • User accounts: K-means with K=3-5 (small dataset)")
        else:
            print(f"   • User accounts: K-means or Gaussian Mixture Model")
        
        print(f"\n5. VALIDATION STRATEGY:")
        print(f"   • Use silhouette score for cluster quality assessment")
        print(f"   • Manual inspection of high-risk clusters")
        print(f"   • Domain expert validation for security relevance")
        
        return {
            'computer_analysis': computer_analysis,
            'user_analysis': user_analysis,
            'comparison_insights': {
                'scale_ratio': comp_events/user_events if user_events > 0 else None,
                'higher_risk_dataset': 'computer' if comp_max_z.get('mean', 0) > user_max_z.get('mean', 0) else 'user',
                'recommended_approach': 'separate_clustering'
            }
        }
    
    def run_analysis(self):
        """Execute the complete statistical analysis"""
        print("CYBERSECURITY DATA STATISTICAL ANALYSIS FOR CLUSTERING")
        print("=" * 80)
        print("Analyzing datasets for optimal clustering characteristics...")
        
        # Load data
        print("\nLoading datasets...")
        self.computer_data = self.load_csv_data(self.computer_file)
        self.user_data = self.load_csv_data(self.user_file)
        
        if not self.computer_data and not self.user_data:
            print("Error: No data loaded. Please check file paths.")
            return None
        
        # Analyze both datasets
        computer_analysis = self.analyze_dataset(self.computer_data, "Computer Accounts") if self.computer_data else {}
        user_analysis = self.analyze_dataset(self.user_data, "User Accounts") if self.user_data else {}
        
        # Generate comparative analysis
        if computer_analysis and user_analysis:
            final_results = self.generate_comparative_analysis(computer_analysis, user_analysis)
        else:
            final_results = {
                'computer_analysis': computer_analysis,
                'user_analysis': user_analysis
            }
        
        print(f"\n{'='*80}")
        print("ANALYSIS COMPLETE")
        print(f"{'='*80}")
        
        return final_results

def main():
    """Main execution function"""
    # File paths
    computer_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_computer_accounts.csv"
    user_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_user_accounts.csv"
    
    # Create analyzer
    analyzer = BasicCyberSecAnalyzer(computer_file, user_file)
    
    # Run analysis
    results = analyzer.run_analysis()
    
    if results:
        print("\n" + "="*80)
        print("CLUSTERING IMPLEMENTATION READY")
        print("Results available for clustering algorithm implementation")
        print("="*80)
    
    return results

if __name__ == "__main__":
    results = main()