#!/usr/bin/env python3
"""
Cybersecurity Data Statistical Analysis for Clustering
====================================================

This script performs comprehensive statistical analysis on cybersecurity datasets
to identify optimal clustering characteristics and parameters.

Author: Data Statistician (Claude Code)
Date: 2025-09-03
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from scipy import stats
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.cluster import KMeans, DBSCAN
from sklearn.metrics import silhouette_score
from sklearn.decomposition import PCA
import warnings
warnings.filterwarnings('ignore')

class CybersecurityDataAnalyzer:
    """
    Statistical analyzer for cybersecurity event data with clustering recommendations
    """
    
    def __init__(self, computer_file, user_file):
        """Initialize analyzer with data files"""
        self.computer_file = computer_file
        self.user_file = user_file
        self.computer_data = None
        self.user_data = None
        self.stats_summary = {}
        
    def load_data(self):
        """Load and initial data preprocessing"""
        print("Loading cybersecurity datasets...")
        
        # Load computer accounts data
        self.computer_data = pd.read_csv(self.computer_file)
        print(f"Computer accounts dataset: {self.computer_data.shape[0]} events, {self.computer_data.shape[1]} features")
        
        # Load user accounts data
        self.user_data = pd.read_csv(self.user_file)
        print(f"User accounts dataset: {self.user_data.shape[0]} events, {self.user_data.shape[1]} features")
        
        # Convert timestamp columns
        for df in [self.computer_data, self.user_data]:
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            if 'event_time' in df.columns:
                df['event_time'] = pd.to_datetime(df['event_time'])
    
    def analyze_dataset(self, data, dataset_name):
        """Perform comprehensive statistical analysis on a dataset"""
        print(f"\n{'='*60}")
        print(f"STATISTICAL ANALYSIS: {dataset_name.upper()}")
        print(f"{'='*60}")
        
        analysis_results = {
            'dataset_name': dataset_name,
            'total_events': len(data),
            'time_range': None,
            'unique_users': None,
            'unique_hosts': None,
            'descriptive_stats': {},
            'clustering_features': {},
            'anomaly_distribution': {},
            'event_patterns': {},
            'outliers': {},
            'recommendations': {}
        }
        
        # Dataset Overview
        print(f"Dataset Overview:")
        print(f"- Total Events: {len(data):,}")
        
        if 'timestamp' in data.columns:
            time_range = f"{data['timestamp'].min()} to {data['timestamp'].max()}"
            analysis_results['time_range'] = time_range
            print(f"- Time Range: {time_range}")
        
        if 'username' in data.columns:
            unique_users = data['username'].nunique()
            analysis_results['unique_users'] = unique_users
            print(f"- Unique Users/Accounts: {unique_users:,}")
        
        if 'hostname' in data.columns:
            unique_hosts = data['hostname'].nunique()
            analysis_results['unique_hosts'] = unique_hosts
            print(f"- Unique Hosts: {unique_hosts:,}")
        
        # Identify numeric columns for statistical analysis
        numeric_cols = data.select_dtypes(include=[np.number]).columns.tolist()
        if 'Unnamed: 0' in numeric_cols:
            numeric_cols.remove('Unnamed: 0')
        
        # Focus on key anomaly and z-score columns
        anomaly_cols = [col for col in numeric_cols if 'z' in col.lower() or 'abs' in col.lower()]
        count_cols = [col for col in numeric_cols if 'count' in col.lower() or 'increment' in col.lower()]
        
        print(f"\nKey Analysis Columns:")
        print(f"- Anomaly/Z-score columns: {anomaly_cols}")
        print(f"- Count/increment columns: {count_cols[:5]}...")  # Show first 5
        
        # Statistical Analysis of Anomaly Scores
        if anomaly_cols:
            print(f"\n{'='*40}")
            print("ANOMALY SCORE ANALYSIS")
            print(f"{'='*40}")
            
            for col in ['max_abs_z', 'mean_abs_z'] if col in anomaly_cols else anomaly_cols[:2]:
                if col in data.columns:
                    values = data[col].dropna()
                    
                    # Descriptive statistics
                    stats_dict = {
                        'mean': values.mean(),
                        'median': values.median(),
                        'std': values.std(),
                        'min': values.min(),
                        'max': values.max(),
                        'q25': values.quantile(0.25),
                        'q75': values.quantile(0.75),
                        'q95': values.quantile(0.95),
                        'q99': values.quantile(0.99),
                        'iqr': values.quantile(0.75) - values.quantile(0.25),
                        'skewness': stats.skew(values),
                        'kurtosis': stats.kurtosis(values)
                    }
                    
                    analysis_results['descriptive_stats'][col] = stats_dict
                    
                    print(f"\n{col.upper()} Statistics:")
                    print(f"  Mean: {stats_dict['mean']:.4f}")
                    print(f"  Median: {stats_dict['median']:.4f}")
                    print(f"  Std Dev: {stats_dict['std']:.4f}")
                    print(f"  Range: [{stats_dict['min']:.4f}, {stats_dict['max']:.4f}]")
                    print(f"  95th Percentile: {stats_dict['q95']:.4f}")
                    print(f"  99th Percentile: {stats_dict['q99']:.4f}")
                    print(f"  Skewness: {stats_dict['skewness']:.4f}")
                    print(f"  Kurtosis: {stats_dict['kurtosis']:.4f}")
                    
                    # Identify outliers (>3 standard deviations)
                    threshold_3sigma = stats_dict['mean'] + 3 * stats_dict['std']
                    outliers_3sigma = (values > threshold_3sigma).sum()
                    
                    # Extreme outliers (z > 20 for security context)
                    extreme_outliers = (values > 20).sum() if values.max() > 20 else 0
                    
                    analysis_results['outliers'][col] = {
                        'outliers_3sigma': outliers_3sigma,
                        'extreme_outliers': extreme_outliers,
                        'outlier_percentage': (outliers_3sigma / len(values)) * 100
                    }
                    
                    print(f"  Outliers (>3σ): {outliers_3sigma} ({(outliers_3sigma/len(values)*100):.2f}%)")
                    if extreme_outliers > 0:
                        print(f"  Critical Events (z>20): {extreme_outliers} ({(extreme_outliers/len(values)*100):.2f}%)")
        
        # Event Pattern Analysis
        print(f"\n{'='*40}")
        print("EVENT PATTERN ANALYSIS")
        print(f"{'='*40}")
        
        if 'event_id' in data.columns:
            event_dist = data['event_id'].value_counts()
            print(f"Event ID Distribution (Top 10):")
            for i, (event_id, count) in enumerate(event_dist.head(10).items()):
                print(f"  {event_id}: {count:,} ({count/len(data)*100:.1f}%)")
            
            analysis_results['event_patterns']['event_id_distribution'] = event_dist.to_dict()
            analysis_results['event_patterns']['event_diversity'] = data['event_id'].nunique()
        
        if 'event_action' in data.columns:
            action_dist = data['event_action'].value_counts()
            print(f"\nEvent Action Distribution:")
            for action, count in action_dist.items():
                print(f"  {action}: {count:,} ({count/len(data)*100:.1f}%)")
            
            analysis_results['event_patterns']['action_distribution'] = action_dist.to_dict()
        
        # Host and User Risk Analysis
        if 'hostname' in data.columns and 'max_abs_z' in data.columns:
            host_risk = data.groupby('hostname')['max_abs_z'].agg(['mean', 'max', 'count']).reset_index()
            host_risk['risk_score'] = host_risk['mean'] * np.log(host_risk['count'])
            host_risk = host_risk.sort_values('risk_score', ascending=False)
            
            print(f"\nTop 5 Highest Risk Hosts:")
            for _, row in host_risk.head(5).iterrows():
                print(f"  {row['hostname']}: Risk={row['risk_score']:.2f} (Events={row['count']}, Max_Z={row['max']:.2f})")
            
            analysis_results['clustering_features']['host_risk_scores'] = host_risk.to_dict('records')[:10]
        
        # Temporal Pattern Analysis
        if 'timestamp' in data.columns:
            data['hour'] = data['timestamp'].dt.hour
            data['day_of_week'] = data['timestamp'].dt.dayofweek
            
            hourly_dist = data['hour'].value_counts().sort_index()
            daily_dist = data['day_of_week'].value_counts().sort_index()
            
            print(f"\nTemporal Patterns:")
            print(f"  Peak Activity Hour: {hourly_dist.idxmax()}:00 ({hourly_dist.max()} events)")
            print(f"  Peak Activity Day: {['Mon','Tue','Wed','Thu','Fri','Sat','Sun'][daily_dist.idxmax()]} ({daily_dist.max()} events)")
            
            analysis_results['event_patterns']['temporal'] = {
                'peak_hour': int(hourly_dist.idxmax()),
                'peak_day': int(daily_dist.idxmax()),
                'hourly_distribution': hourly_dist.to_dict(),
                'daily_distribution': daily_dist.to_dict()
            }
        
        # Clustering Feature Recommendations
        clustering_features = self._identify_clustering_features(data, numeric_cols)
        analysis_results['clustering_features']['recommended_features'] = clustering_features
        
        print(f"\n{'='*40}")
        print("CLUSTERING FEATURE ANALYSIS")
        print(f"{'='*40}")
        print(f"Recommended Features for Clustering:")
        for i, feature in enumerate(clustering_features[:10], 1):
            print(f"  {i}. {feature}")
        
        # Optimal Cluster Analysis
        if len(clustering_features) >= 2:
            cluster_recommendations = self._analyze_optimal_clusters(data, clustering_features[:5])
            analysis_results['recommendations']['clustering'] = cluster_recommendations
            
            print(f"\nClustering Recommendations:")
            print(f"  Optimal K (Elbow Method): {cluster_recommendations.get('optimal_k_elbow', 'N/A')}")
            print(f"  Optimal K (Silhouette): {cluster_recommendations.get('optimal_k_silhouette', 'N/A')}")
            print(f"  Recommended Algorithm: {cluster_recommendations.get('recommended_algorithm', 'K-Means')}")
        
        return analysis_results
    
    def _identify_clustering_features(self, data, numeric_cols):
        """Identify the most suitable features for clustering based on variance and correlation"""
        clustering_features = []
        
        # Priority features for security clustering
        priority_features = ['max_abs_z', 'mean_abs_z', 'logcount', 'hostincrement', 'ipincrement']
        
        # Add priority features that exist in data
        for feature in priority_features:
            if feature in data.columns:
                clustering_features.append(feature)
        
        # Add z-score loss features
        z_loss_features = [col for col in numeric_cols if 'z_loss' in col and col not in clustering_features]
        clustering_features.extend(z_loss_features[:3])  # Top 3 z-loss features
        
        # Add prediction error features
        pred_features = [col for col in numeric_cols if 'pred' in col and col not in clustering_features]
        clustering_features.extend(pred_features[:2])  # Top 2 prediction features
        
        # Calculate variance for remaining numeric features
        remaining_features = [col for col in numeric_cols if col not in clustering_features]
        if remaining_features:
            variances = data[remaining_features].var().sort_values(ascending=False)
            # Add top variance features
            clustering_features.extend(variances.head(3).index.tolist())
        
        return clustering_features[:10]  # Return top 10 features
    
    def _analyze_optimal_clusters(self, data, features):
        """Analyze optimal number of clusters using multiple methods"""
        # Prepare data for clustering
        cluster_data = data[features].dropna()
        if len(cluster_data) < 10:
            return {'error': 'Insufficient data for clustering analysis'}
        
        # Standardize features
        scaler = StandardScaler()
        scaled_data = scaler.fit_transform(cluster_data)
        
        # Limit sample size for performance if dataset is large
        if len(scaled_data) > 1000:
            sample_idx = np.random.choice(len(scaled_data), 1000, replace=False)
            scaled_data = scaled_data[sample_idx]
        
        results = {}
        
        try:
            # Elbow method for optimal K
            k_range = range(2, min(11, len(scaled_data)//10 + 1))
            inertias = []
            silhouette_scores = []
            
            for k in k_range:
                if k >= len(scaled_data):
                    break
                    
                kmeans = KMeans(n_clusters=k, random_state=42, n_init=10)
                kmeans.fit(scaled_data)
                inertias.append(kmeans.inertia_)
                
                # Calculate silhouette score
                if k < len(scaled_data):
                    sil_score = silhouette_score(scaled_data, kmeans.labels_)
                    silhouette_scores.append(sil_score)
                else:
                    silhouette_scores.append(0)
            
            # Find elbow point (simplified)
            if len(inertias) >= 3:
                # Calculate the rate of change
                deltas = np.diff(inertias)
                delta_deltas = np.diff(deltas)
                if len(delta_deltas) > 0:
                    elbow_k = np.argmax(delta_deltas) + 3  # +3 because we start from k=2
                    results['optimal_k_elbow'] = min(elbow_k, len(k_range) + 1)
            
            # Best silhouette score
            if silhouette_scores:
                best_sil_k = k_range[np.argmax(silhouette_scores)]
                results['optimal_k_silhouette'] = best_sil_k
                results['best_silhouette_score'] = max(silhouette_scores)
            
            # Try DBSCAN for density-based clustering
            dbscan = DBSCAN(eps=0.5, min_samples=5)
            dbscan_labels = dbscan.fit_predict(scaled_data)
            n_clusters_dbscan = len(set(dbscan_labels)) - (1 if -1 in dbscan_labels else 0)
            
            results['dbscan_clusters'] = n_clusters_dbscan
            results['dbscan_noise_points'] = list(dbscan_labels).count(-1)
            
            # Algorithm recommendation
            if results.get('best_silhouette_score', 0) > 0.5:
                results['recommended_algorithm'] = 'K-Means'
            elif n_clusters_dbscan > 0 and results.get('dbscan_noise_points', 0) / len(scaled_data) < 0.1:
                results['recommended_algorithm'] = 'DBSCAN'
            else:
                results['recommended_algorithm'] = 'K-Means (default)'
            
        except Exception as e:
            results['error'] = f"Clustering analysis failed: {str(e)}"
        
        return results
    
    def generate_summary_report(self, computer_analysis, user_analysis):
        """Generate comprehensive summary report"""
        print(f"\n{'='*80}")
        print("COMPREHENSIVE CYBERSECURITY CLUSTERING ANALYSIS SUMMARY")
        print(f"{'='*80}")
        
        print(f"\nDATASET COMPARISON:")
        print(f"{'='*50}")
        print(f"Computer Accounts: {computer_analysis['total_events']:,} events")
        print(f"User Accounts: {user_analysis['total_events']:,} events")
        
        # Compare anomaly distributions
        if 'max_abs_z' in computer_analysis['descriptive_stats'] and 'max_abs_z' in user_analysis['descriptive_stats']:
            comp_stats = computer_analysis['descriptive_stats']['max_abs_z']
            user_stats = user_analysis['descriptive_stats']['max_abs_z']
            
            print(f"\nANOMALY SCORE COMPARISON:")
            print(f"{'='*40}")
            print(f"Computer Accounts - Max Anomaly Z-Score:")
            print(f"  Mean: {comp_stats['mean']:.4f}, 95th percentile: {comp_stats['q95']:.4f}")
            print(f"User Accounts - Max Anomaly Z-Score:")
            print(f"  Mean: {user_stats['mean']:.4f}, 95th percentile: {user_stats['q95']:.4f}")
            
            if comp_stats['mean'] > user_stats['mean']:
                print(f"  → Computer accounts show higher average anomaly scores")
            else:
                print(f"  → User accounts show higher average anomaly scores")
        
        # Clustering recommendations
        print(f"\nCLUSTERING RECOMMENDATIONS:")
        print(f"{'='*40}")
        
        for dataset_name, analysis in [("Computer Accounts", computer_analysis), ("User Accounts", user_analysis)]:
            print(f"\n{dataset_name}:")
            clustering = analysis['recommendations'].get('clustering', {})
            features = analysis['clustering_features'].get('recommended_features', [])
            
            print(f"  Recommended Features: {', '.join(features[:5])}")
            print(f"  Optimal K-Means Clusters: {clustering.get('optimal_k_silhouette', 'N/A')}")
            print(f"  Best Silhouette Score: {clustering.get('best_silhouette_score', 'N/A'):.3f}" if 'best_silhouette_score' in clustering else "  Best Silhouette Score: N/A")
            print(f"  Recommended Algorithm: {clustering.get('recommended_algorithm', 'K-Means')}")
        
        # Security insights
        print(f"\nSECURITY INSIGHTS:")
        print(f"{'='*30}")
        
        # High-risk events analysis
        for dataset_name, analysis in [("Computer", computer_analysis), ("User", user_analysis)]:
            if 'max_abs_z' in analysis['outliers']:
                outlier_info = analysis['outliers']['max_abs_z']
                extreme_count = outlier_info.get('extreme_outliers', 0)
                if extreme_count > 0:
                    print(f"  {dataset_name} accounts: {extreme_count} critical security events (z>20)")
        
        # Event distribution insights
        comp_events = computer_analysis['event_patterns'].get('event_diversity', 0)
        user_events = user_analysis['event_patterns'].get('event_diversity', 0)
        print(f"  Event Type Diversity: Computer={comp_events}, User={user_events}")
        
        print(f"\nRECOMMENDED CLUSTERING STRATEGY:")
        print(f"{'='*45}")
        print(f"1. Use separate clustering for computer and user accounts due to different behavioral patterns")
        print(f"2. Focus on anomaly z-scores (max_abs_z, mean_abs_z) as primary clustering features")
        print(f"3. Include event count and increment features for behavioral profiling")
        print(f"4. Apply robust scaling due to presence of extreme outliers")
        print(f"5. Consider hybrid approach: K-Means for normal behavior, DBSCAN for outlier detection")
    
    def run_full_analysis(self):
        """Execute complete statistical analysis pipeline"""
        print("Starting Cybersecurity Data Statistical Analysis for Clustering")
        print(f"{'='*80}")
        
        # Load data
        self.load_data()
        
        # Analyze both datasets
        computer_analysis = self.analyze_dataset(self.computer_data, "Computer Accounts")
        user_analysis = self.analyze_dataset(self.user_data, "User Accounts")
        
        # Generate comprehensive summary
        self.generate_summary_report(computer_analysis, user_analysis)
        
        return {
            'computer_analysis': computer_analysis,
            'user_analysis': user_analysis
        }

def main():
    """Main execution function"""
    # File paths
    computer_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_computer_accounts.csv"
    user_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_user_accounts.csv"
    
    # Initialize analyzer
    analyzer = CybersecurityDataAnalyzer(computer_file, user_file)
    
    # Run comprehensive analysis
    results = analyzer.run_full_analysis()
    
    print(f"\n{'='*80}")
    print("ANALYSIS COMPLETE - Results available for clustering implementation")
    print(f"{'='*80}")
    
    return results

if __name__ == "__main__":
    results = main()