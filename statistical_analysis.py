#!/usr/bin/env python3
"""
Comprehensive Statistical Analysis of Cybersecurity Event Data
Analyzes z-score distributions, risk patterns, and statistical anomalies
"""

import pandas as pd
import numpy as np
import json
from datetime import datetime
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

class CyberSecurityStatisticalAnalyzer:
    def __init__(self):
        self.computer_data = None
        self.user_data = None
        self.analysis_results = {}
        
    def load_data(self, computer_file, user_file):
        """Load both datasets"""
        print("Loading cybersecurity event data...")
        self.computer_data = pd.read_csv(computer_file)
        self.user_data = pd.read_csv(user_file)
        
        print(f"Computer accounts: {len(self.computer_data)} events")
        print(f"User accounts: {len(self.user_data)} events")
        
    def basic_statistical_summary(self, df, data_type):
        """Calculate comprehensive statistical summary"""
        z_score_cols = ['max_abs_z', 'logcount_z_loss', 'hostincrement_z_loss', 
                       'ipincrement_z_loss', 'processincrement_z_loss']
        
        stats_summary = {
            'dataset_info': {
                'total_events': len(df),
                'unique_users': df['username'].nunique(),
                'unique_hosts': df['hostname'].nunique(),
                'time_range': {
                    'start': df['timestamp'].min(),
                    'end': df['timestamp'].max()
                }
            },
            'z_score_statistics': {}
        }
        
        # Analyze each z-score column
        for col in z_score_cols:
            if col in df.columns:
                data = df[col].dropna()
                stats_summary['z_score_statistics'][col] = {
                    'mean': float(data.mean()),
                    'median': float(data.median()),
                    'std': float(data.std()),
                    'min': float(data.min()),
                    'max': float(data.max()),
                    'skewness': float(stats.skew(data)),
                    'kurtosis': float(stats.kurtosis(data)),
                    'percentiles': {
                        '50th': float(np.percentile(data, 50)),
                        '90th': float(np.percentile(data, 90)),
                        '95th': float(np.percentile(data, 95)),
                        '99th': float(np.percentile(data, 99)),
                        '99.9th': float(np.percentile(data, 99.9))
                    }
                }
                
        return stats_summary
    
    def analyze_statistical_outliers(self, df, data_type):
        """Identify and analyze statistical outliers"""
        z_col = 'max_abs_z'
        data = df[z_col].dropna()
        
        # Define outlier thresholds
        outlier_analysis = {
            'total_events': len(data),
            'outlier_thresholds': {
                'moderate_outlier': 3.0,  # 3 sigma
                'extreme_outlier': 5.0,   # 5 sigma  
                'critical_outlier': 20.0  # 20 sigma (extremely rare)
            },
            'outlier_counts': {},
            'outlier_percentages': {},
            'statistical_interpretation': {}
        }
        
        # Count outliers at different thresholds
        for threshold_name, threshold_value in outlier_analysis['outlier_thresholds'].items():
            count = len(data[data >= threshold_value])
            percentage = (count / len(data)) * 100
            outlier_analysis['outlier_counts'][threshold_name] = int(count)
            outlier_analysis['outlier_percentages'][threshold_name] = float(percentage)
            
            # Statistical interpretation
            if threshold_value == 3.0:
                expected_normal = 0.27  # ~0.27% expected in normal distribution
                interpretation = f"Expected in normal distribution: 0.27%. Observed: {percentage:.2f}%"
            elif threshold_value == 5.0:
                expected_normal = 0.000057  # ~0.000057% expected
                interpretation = f"Expected in normal distribution: 0.000057%. Observed: {percentage:.6f}%"
            elif threshold_value == 20.0:
                probability = stats.norm.sf(threshold_value) * 2  # Two-tailed
                interpretation = f"Probability in normal distribution: {probability:.2e}. Observed: {percentage:.6f}%"
                
            outlier_analysis['statistical_interpretation'][threshold_name] = interpretation
        
        return outlier_analysis
    
    def analyze_risk_distributions(self, df, data_type):
        """Analyze risk score distributions and establish thresholds"""
        z_col = 'max_abs_z'
        data = df[z_col].dropna()
        
        # Calculate statistical risk thresholds
        risk_thresholds = {
            'low_risk': float(np.percentile(data, 75)),      # 75th percentile
            'medium_risk': float(np.percentile(data, 90)),   # 90th percentile
            'high_risk': float(np.percentile(data, 95)),     # 95th percentile
            'critical_risk': float(np.percentile(data, 99)), # 99th percentile
            'extreme_risk': float(np.percentile(data, 99.9)) # 99.9th percentile
        }
        
        # Count events in each risk category
        risk_distribution = {}
        total_events = len(data)
        
        # Define risk categories based on calculated thresholds
        conditions = [
            data < risk_thresholds['low_risk'],
            (data >= risk_thresholds['low_risk']) & (data < risk_thresholds['medium_risk']),
            (data >= risk_thresholds['medium_risk']) & (data < risk_thresholds['high_risk']),
            (data >= risk_thresholds['high_risk']) & (data < risk_thresholds['critical_risk']),
            (data >= risk_thresholds['critical_risk']) & (data < risk_thresholds['extreme_risk']),
            data >= risk_thresholds['extreme_risk']
        ]
        
        categories = ['minimal', 'low', 'medium', 'high', 'critical', 'extreme']
        
        for i, category in enumerate(categories):
            count = len(data[conditions[i]])
            percentage = (count / total_events) * 100
            risk_distribution[category] = {
                'count': int(count),
                'percentage': float(percentage),
                'threshold_min': float(risk_thresholds['low_risk'] if i > 0 else 0),
                'threshold_max': float(risk_thresholds[list(risk_thresholds.keys())[min(i, len(risk_thresholds)-1)]])
            }
        
        return {
            'risk_thresholds': risk_thresholds,
            'risk_distribution': risk_distribution,
            'statistical_explanation': {
                'threshold_methodology': "Risk thresholds calculated using percentiles of max_abs_z distribution",
                'interpretation': "Higher percentiles indicate increasingly rare and potentially dangerous events"
            }
        }
    
    def analyze_temporal_patterns(self, df, data_type):
        """Analyze temporal patterns in the data"""
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day_name()
        
        temporal_analysis = {
            'hourly_distribution': df.groupby('hour')['max_abs_z'].agg(['count', 'mean', 'std']).to_dict(),
            'daily_distribution': df.groupby('day')['max_abs_z'].agg(['count', 'mean', 'std']).to_dict(),
            'peak_activity_hours': [],
            'anomaly_time_patterns': {}
        }
        
        # Find peak activity hours (top 3)
        hourly_counts = df.groupby('hour').size()
        peak_hours = hourly_counts.nlargest(3).index.tolist()
        temporal_analysis['peak_activity_hours'] = [int(h) for h in peak_hours]
        
        # Analyze high-risk events by time
        high_risk_events = df[df['max_abs_z'] > df['max_abs_z'].quantile(0.95)]
        if len(high_risk_events) > 0:
            temporal_analysis['anomaly_time_patterns'] = {
                'high_risk_by_hour': high_risk_events.groupby('hour').size().to_dict(),
                'high_risk_peak_hours': high_risk_events.groupby('hour').size().nlargest(3).index.tolist()
            }
        
        return temporal_analysis
    
    def analyze_correlations(self, df, data_type):
        """Analyze correlations between different z-score metrics"""
        z_score_cols = [col for col in df.columns if 'z_loss' in col or col == 'max_abs_z']
        numeric_cols = df[z_score_cols].select_dtypes(include=[np.number])
        
        correlation_matrix = numeric_cols.corr()
        
        # Find strong correlations (absolute value > 0.7)
        strong_correlations = []
        for i in range(len(correlation_matrix.columns)):
            for j in range(i+1, len(correlation_matrix.columns)):
                corr_value = correlation_matrix.iloc[i, j]
                if abs(corr_value) > 0.7:
                    strong_correlations.append({
                        'metric1': correlation_matrix.columns[i],
                        'metric2': correlation_matrix.columns[j],
                        'correlation': float(corr_value),
                        'strength': 'strong positive' if corr_value > 0.7 else 'strong negative'
                    })
        
        return {
            'correlation_matrix': correlation_matrix.to_dict(),
            'strong_correlations': strong_correlations,
            'interpretation': "Strong correlations (>0.7) indicate metrics that tend to move together"
        }
    
    def analyze_cluster_patterns(self, df, data_type):
        """Analyze patterns by cluster_id"""
        if 'cluster_id' not in df.columns:
            return {}
            
        cluster_analysis = {}
        
        for cluster_id in df['cluster_id'].unique():
            cluster_data = df[df['cluster_id'] == cluster_id]
            cluster_analysis[int(cluster_id)] = {
                'count': len(cluster_data),
                'percentage': float((len(cluster_data) / len(df)) * 100),
                'description': cluster_data['cluster_description'].iloc[0] if 'cluster_description' in df.columns else 'Unknown',
                'avg_risk_score': float(cluster_data['max_abs_z'].mean()),
                'max_risk_score': float(cluster_data['max_abs_z'].max()),
                'risk_score_std': float(cluster_data['max_abs_z'].std())
            }
        
        return cluster_analysis
    
    def explain_extreme_anomalies(self, df, data_type):
        """Provide statistical context for extreme anomalies"""
        extreme_events = df[df['max_abs_z'] > 20]  # Very high z-scores
        
        explanations = []
        for _, event in extreme_events.iterrows():
            z_score = event['max_abs_z']
            probability = stats.norm.sf(z_score) * 2  # Two-tailed probability
            
            # Convert probability to odds
            if probability > 0:
                odds = 1 / probability
                explanation = {
                    'event_details': {
                        'username': event.get('username', 'Unknown'),
                        'hostname': event.get('hostname', 'Unknown'),
                        'timestamp': str(event.get('timestamp', 'Unknown')),
                        'cluster_description': event.get('cluster_description', 'Unknown')
                    },
                    'statistical_context': {
                        'z_score': float(z_score),
                        'probability': float(probability),
                        'odds_against': f"1 in {odds:.0f}" if odds < 1e10 else "Extremely rare",
                        'standard_deviations': f"{z_score:.1f} standard deviations from mean",
                        'rarity_explanation': f"This event is {z_score:.1f} standard deviations from normal behavior, making it extraordinarily rare"
                    }
                }
                explanations.append(explanation)
        
        return explanations
    
    def run_full_analysis(self, computer_file, user_file, output_file):
        """Run complete statistical analysis"""
        print("Starting comprehensive statistical analysis...")
        
        # Load data
        self.load_data(computer_file, user_file)
        
        # Initialize results structure
        self.analysis_results = {
            'analysis_metadata': {
                'generated_at': datetime.now().isoformat(),
                'analyzer_version': '1.0',
                'datasets_analyzed': ['computer_accounts', 'user_accounts']
            },
            'computer_accounts': {},
            'user_accounts': {},
            'combined_insights': {}
        }
        
        # Analyze computer accounts data
        print("Analyzing computer accounts data...")
        self.analysis_results['computer_accounts'] = {
            'basic_statistics': self.basic_statistical_summary(self.computer_data, 'computer'),
            'outlier_analysis': self.analyze_statistical_outliers(self.computer_data, 'computer'),
            'risk_distribution': self.analyze_risk_distributions(self.computer_data, 'computer'),
            'temporal_patterns': self.analyze_temporal_patterns(self.computer_data, 'computer'),
            'correlations': self.analyze_correlations(self.computer_data, 'computer'),
            'cluster_patterns': self.analyze_cluster_patterns(self.computer_data, 'computer'),
            'extreme_anomalies': self.explain_extreme_anomalies(self.computer_data, 'computer')
        }
        
        # Analyze user accounts data
        print("Analyzing user accounts data...")
        self.analysis_results['user_accounts'] = {
            'basic_statistics': self.basic_statistical_summary(self.user_data, 'user'),
            'outlier_analysis': self.analyze_statistical_outliers(self.user_data, 'user'),
            'risk_distribution': self.analyze_risk_distributions(self.user_data, 'user'),
            'temporal_patterns': self.analyze_temporal_patterns(self.user_data, 'user'),
            'correlations': self.analyze_correlations(self.user_data, 'user'),
            'cluster_patterns': self.analyze_cluster_patterns(self.user_data, 'user'),
            'extreme_anomalies': self.explain_extreme_anomalies(self.user_data, 'user')
        }
        
        # Combined insights
        print("Generating combined insights...")
        self.analysis_results['combined_insights'] = self.generate_combined_insights()
        
        # Save results
        print(f"Saving analysis results to {output_file}")
        with open(output_file, 'w') as f:
            json.dump(self.analysis_results, f, indent=2, default=str)
        
        # Print summary
        self.print_statistical_summary()
        
    def generate_combined_insights(self):
        """Generate insights comparing both datasets"""
        comp_max_z = self.computer_data['max_abs_z']
        user_max_z = self.user_data['max_abs_z']
        
        return {
            'comparative_statistics': {
                'computer_vs_user_mean_risk': {
                    'computer_mean': float(comp_max_z.mean()),
                    'user_mean': float(user_max_z.mean()),
                    'difference': float(comp_max_z.mean() - user_max_z.mean())
                },
                'computer_vs_user_extreme_events': {
                    'computer_extreme_count': int(len(comp_max_z[comp_max_z > 20])),
                    'user_extreme_count': int(len(user_max_z[user_max_z > 20])),
                    'computer_extreme_percentage': float((len(comp_max_z[comp_max_z > 20]) / len(comp_max_z)) * 100),
                    'user_extreme_percentage': float((len(user_max_z[user_max_z > 20]) / len(user_max_z)) * 100)
                }
            },
            'key_findings': [
                f"Computer accounts dataset contains {len(self.computer_data)} events vs {len(self.user_data)} user events",
                f"Average risk score for computer accounts: {comp_max_z.mean():.2f}",
                f"Average risk score for user accounts: {user_max_z.mean():.2f}",
                f"Total extreme anomalies (z>20): {len(comp_max_z[comp_max_z > 20]) + len(user_max_z[user_max_z > 20])}"
            ]
        }
    
    def print_statistical_summary(self):
        """Print comprehensive statistical summary to console"""
        print("\n" + "="*80)
        print("CYBERSECURITY EVENT DATA - STATISTICAL ANALYSIS SUMMARY")
        print("="*80)
        
        # Computer accounts summary
        comp_stats = self.analysis_results['computer_accounts']['basic_statistics']['z_score_statistics']['max_abs_z']
        comp_outliers = self.analysis_results['computer_accounts']['outlier_analysis']
        
        print(f"\nCOMPUTER ACCOUNTS DATASET (n={self.analysis_results['computer_accounts']['basic_statistics']['dataset_info']['total_events']})")
        print("-" * 40)
        print(f"Mean Z-Score: {comp_stats['mean']:.3f}")
        print(f"Median Z-Score: {comp_stats['median']:.3f}")
        print(f"Standard Deviation: {comp_stats['std']:.3f}")
        print(f"95th Percentile: {comp_stats['percentiles']['95th']:.3f}")
        print(f"99th Percentile: {comp_stats['percentiles']['99th']:.3f}")
        print(f"Maximum Z-Score: {comp_stats['max']:.3f}")
        
        print(f"\nStatistical Outliers (Computer Accounts):")
        print(f"  Moderate (z>3): {comp_outliers['outlier_counts']['moderate_outlier']} ({comp_outliers['outlier_percentages']['moderate_outlier']:.2f}%)")
        print(f"  Extreme (z>5): {comp_outliers['outlier_counts']['extreme_outlier']} ({comp_outliers['outlier_percentages']['extreme_outlier']:.4f}%)")
        print(f"  Critical (z>20): {comp_outliers['outlier_counts']['critical_outlier']} ({comp_outliers['outlier_percentages']['critical_outlier']:.6f}%)")
        
        # User accounts summary
        user_stats = self.analysis_results['user_accounts']['basic_statistics']['z_score_statistics']['max_abs_z']
        user_outliers = self.analysis_results['user_accounts']['outlier_analysis']
        
        print(f"\nUSER ACCOUNTS DATASET (n={self.analysis_results['user_accounts']['basic_statistics']['dataset_info']['total_events']})")
        print("-" * 40)
        print(f"Mean Z-Score: {user_stats['mean']:.3f}")
        print(f"Median Z-Score: {user_stats['median']:.3f}")
        print(f"Standard Deviation: {user_stats['std']:.3f}")
        print(f"95th Percentile: {user_stats['percentiles']['95th']:.3f}")
        print(f"99th Percentile: {user_stats['percentiles']['99th']:.3f}")
        print(f"Maximum Z-Score: {user_stats['max']:.3f}")
        
        print(f"\nStatistical Outliers (User Accounts):")
        print(f"  Moderate (z>3): {user_outliers['outlier_counts']['moderate_outlier']} ({user_outliers['outlier_percentages']['moderate_outlier']:.2f}%)")
        print(f"  Extreme (z>5): {user_outliers['outlier_counts']['extreme_outlier']} ({user_outliers['outlier_percentages']['extreme_outlier']:.4f}%)")
        print(f"  Critical (z>20): {user_outliers['outlier_counts']['critical_outlier']} ({user_outliers['outlier_percentages']['critical_outlier']:.6f}%)")
        
        # Key insights
        insights = self.analysis_results['combined_insights']
        print(f"\nKEY STATISTICAL INSIGHTS:")
        print("-" * 40)
        for finding in insights['key_findings']:
            print(f"• {finding}")
        
        # Extreme anomalies explanation
        comp_extreme = len(self.analysis_results['computer_accounts']['extreme_anomalies'])
        user_extreme = len(self.analysis_results['user_accounts']['extreme_anomalies'])
        
        if comp_extreme > 0 or user_extreme > 0:
            print(f"\nEXTREME ANOMALY ANALYSIS:")
            print("-" * 40)
            print(f"Found {comp_extreme} extreme computer account anomalies and {user_extreme} extreme user account anomalies")
            print("These events are statistically extraordinary - occurring with probabilities < 1 in 10^10")
            print("Such events warrant immediate investigation as they represent behavior far outside normal patterns")
        
        print("\n" + "="*80)

if __name__ == "__main__":
    # File paths
    computer_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_computer_accounts_clustered.csv"
    user_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_user_accounts_clustered.csv"
    output_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/outputs/statistical_analysis.json"
    
    # Create output directory if it doesn't exist
    import os
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Run analysis
    analyzer = CyberSecurityStatisticalAnalyzer()
    analyzer.run_full_analysis(computer_file, user_file, output_file)
    
    print(f"\nDetailed statistical analysis saved to: {output_file}")