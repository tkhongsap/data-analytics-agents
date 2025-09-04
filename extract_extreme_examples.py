#!/usr/bin/env python3
"""
Extract and explain specific examples of extreme anomalies
Provides concrete context for why certain z-scores are statistically abnormal
"""

import csv
import json
import math

def load_and_analyze_extremes(computer_file, user_file, output_file):
    """Load data and extract extreme examples with detailed explanations"""
    
    def safe_float(value):
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0
    
    def normal_tail_probability(z_score):
        """Calculate probability for extreme z-scores"""
        if z_score > 8:
            return math.exp(-z_score**2 / 2) / (z_score * math.sqrt(2 * math.pi))
        else:
            return 0.5 * (1 - math.erf(z_score / math.sqrt(2)))
    
    def explain_rarity(z_score):
        """Provide detailed explanation of statistical rarity"""
        probability = normal_tail_probability(z_score)
        
        if probability > 0:
            odds = 1 / probability
            
            if odds > 1e15:
                return f"Less than 1 in {odds:.0e} - more rare than winning the lottery 50 times in a row"
            elif odds > 1e12:
                return f"Less than 1 in {odds:.0e} - comparable to being struck by lightning multiple times"
            elif odds > 1e9:
                return f"Less than 1 in {odds:.0e} - rarer than being struck by lightning in a lifetime"
            elif odds > 1e6:
                return f"Less than 1 in {odds:.0e} - comparable to winning a major lottery"
            else:
                return f"Less than 1 in {odds:.0f} - very unlikely but possible"
        else:
            return "Probability too small to calculate - astronomically rare"
    
    extreme_examples = {
        'analysis_metadata': {
            'threshold_used': 20.0,
            'explanation': 'Examples of events with z-scores > 20 (probability < 1 in 10^10)'
        },
        'computer_accounts_extremes': [],
        'user_accounts_extremes': [],
        'statistical_context': {
            'normal_distribution_context': {
                'z_3_probability': '0.27% (about 1 in 370)',
                'z_5_probability': '0.000057% (about 1 in 1.75 million)',
                'z_10_probability': '1.5e-23 (essentially zero)',
                'z_20_probability': '5.4e-89 (beyond astronomical)',
                'z_30_probability': '4.9e-198 (incomprehensibly rare)'
            }
        }
    }
    
    # Process computer accounts
    print("Processing computer accounts for extreme examples...")
    try:
        with open(computer_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                z_score = safe_float(row.get('max_abs_z', 0))
                if z_score >= 20.0:
                    example = {
                        'event_details': {
                            'username': row.get('username', 'Unknown'),
                            'hostname': row.get('hostname', 'Unknown'), 
                            'timestamp': row.get('timestamp', 'Unknown'),
                            'event_action': row.get('event_action', 'Unknown'),
                            'event_id': row.get('event_id', 'Unknown'),
                            'process_name': row.get('process_name', 'Unknown'),
                            'cluster_description': row.get('cluster_description', 'Unknown')
                        },
                        'z_score_breakdown': {
                            'max_abs_z': z_score,
                            'logcount_z_loss': safe_float(row.get('logcount_z_loss', 0)),
                            'hostincrement_z_loss': safe_float(row.get('hostincrement_z_loss', 0)),
                            'ipincrement_z_loss': safe_float(row.get('ipincrement_z_loss', 0)),
                            'processincrement_z_loss': safe_float(row.get('processincrement_z_loss', 0))
                        },
                        'statistical_explanation': {
                            'z_score': z_score,
                            'standard_deviations_from_normal': f"{z_score:.1f} standard deviations",
                            'rarity_description': explain_rarity(z_score),
                            'why_abnormal': f"This event deviates {z_score:.1f} standard deviations from expected behavior. In a normal environment, such deviation would indicate a fundamental change in system behavior or a significant security incident."
                        },
                        'contributing_factors': []
                    }
                    
                    # Identify which metrics contribute most to the anomaly
                    metrics = [
                        ('Log Count Anomaly', safe_float(row.get('logcount_z_loss', 0))),
                        ('Host Activity Anomaly', safe_float(row.get('hostincrement_z_loss', 0))),
                        ('IP Activity Anomaly', safe_float(row.get('ipincrement_z_loss', 0))),
                        ('Process Activity Anomaly', safe_float(row.get('processincrement_z_loss', 0)))
                    ]
                    
                    for metric_name, value in metrics:
                        if value >= 5.0:  # Significant contributor
                            example['contributing_factors'].append({
                                'metric': metric_name,
                                'z_score': value,
                                'interpretation': f"This metric shows {value:.1f} standard deviations from normal - indicating {'extremely abnormal' if value > 10 else 'highly unusual'} {metric_name.lower()}"
                            })
                    
                    extreme_examples['computer_accounts_extremes'].append(example)
    
    except Exception as e:
        print(f"Error processing computer accounts: {e}")
    
    # Process user accounts
    print("Processing user accounts for extreme examples...")
    try:
        with open(user_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                z_score = safe_float(row.get('max_abs_z', 0))
                if z_score >= 20.0:
                    example = {
                        'event_details': {
                            'username': row.get('username', 'Unknown'),
                            'hostname': row.get('hostname', 'Unknown'),
                            'timestamp': row.get('timestamp', 'Unknown'),
                            'event_action': row.get('event_action', 'Unknown'),
                            'event_id': row.get('event_id', 'Unknown'),
                            'source_ip': row.get('source_ip', 'Unknown'),
                            'cluster_description': row.get('cluster_description', 'Unknown')
                        },
                        'z_score_breakdown': {
                            'max_abs_z': z_score,
                            'logcount_z_loss': safe_float(row.get('logcount_z_loss', 0)),
                            'hostincrement_z_loss': safe_float(row.get('hostincrement_z_loss', 0)),
                            'ipincrement_z_loss': safe_float(row.get('ipincrement_z_loss', 0)),
                            'processincrement_z_loss': safe_float(row.get('processincrement_z_loss', 0))
                        },
                        'statistical_explanation': {
                            'z_score': z_score,
                            'standard_deviations_from_normal': f"{z_score:.1f} standard deviations",
                            'rarity_description': explain_rarity(z_score),
                            'why_abnormal': f"This user account event deviates {z_score:.1f} standard deviations from expected behavior. Such extreme deviation suggests either a compromised account, insider threat, or significant change in user behavior patterns."
                        },
                        'contributing_factors': []
                    }
                    
                    # Identify contributing factors
                    metrics = [
                        ('Log Count Anomaly', safe_float(row.get('logcount_z_loss', 0))),
                        ('Host Activity Anomaly', safe_float(row.get('hostincrement_z_loss', 0))),
                        ('IP Activity Anomaly', safe_float(row.get('ipincrement_z_loss', 0))),
                        ('Process Activity Anomaly', safe_float(row.get('processincrement_z_loss', 0)))
                    ]
                    
                    for metric_name, value in metrics:
                        if value >= 5.0:
                            example['contributing_factors'].append({
                                'metric': metric_name,
                                'z_score': value,
                                'interpretation': f"This metric shows {value:.1f} standard deviations from normal - indicating {'extremely abnormal' if value > 10 else 'highly unusual'} {metric_name.lower()}"
                            })
                    
                    extreme_examples['user_accounts_extremes'].append(example)
    
    except Exception as e:
        print(f"Error processing user accounts: {e}")
    
    # Add summary statistics
    extreme_examples['summary'] = {
        'total_extreme_computer_events': len(extreme_examples['computer_accounts_extremes']),
        'total_extreme_user_events': len(extreme_examples['user_accounts_extremes']),
        'highest_computer_z_score': max([ex['z_score_breakdown']['max_abs_z'] for ex in extreme_examples['computer_accounts_extremes']], default=0),
        'highest_user_z_score': max([ex['z_score_breakdown']['max_abs_z'] for ex in extreme_examples['user_accounts_extremes']], default=0)
    }
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(extreme_examples, f, indent=2, default=str)
    
    # Print summary
    print(f"\nExtreme Anomaly Examples Summary:")
    print(f"Computer Account Extremes: {extreme_examples['summary']['total_extreme_computer_events']}")
    print(f"User Account Extremes: {extreme_examples['summary']['total_extreme_user_events']}")
    print(f"Highest Computer Z-Score: {extreme_examples['summary']['highest_computer_z_score']:.2f}")
    print(f"Highest User Z-Score: {extreme_examples['summary']['highest_user_z_score']:.2f}")
    
    # Print a few examples
    if extreme_examples['computer_accounts_extremes']:
        print(f"\nSample Computer Account Extreme (z={extreme_examples['computer_accounts_extremes'][0]['z_score_breakdown']['max_abs_z']:.1f}):")
        sample = extreme_examples['computer_accounts_extremes'][0]
        print(f"  User: {sample['event_details']['username']}")
        print(f"  Host: {sample['event_details']['hostname']}")
        print(f"  Action: {sample['event_details']['event_action']}")
        print(f"  Rarity: {sample['statistical_explanation']['rarity_description']}")
    
    if extreme_examples['user_accounts_extremes']:
        print(f"\nSample User Account Extreme (z={extreme_examples['user_accounts_extremes'][0]['z_score_breakdown']['max_abs_z']:.1f}):")
        sample = extreme_examples['user_accounts_extremes'][0]
        print(f"  User: {sample['event_details']['username']}")
        print(f"  Host: {sample['event_details']['hostname']}")
        print(f"  Action: {sample['event_details']['event_action']}")
        print(f"  Rarity: {sample['statistical_explanation']['rarity_description']}")
    
    print(f"\nDetailed examples saved to: {output_file}")

if __name__ == "__main__":
    computer_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_computer_accounts_clustered.csv"
    user_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/data/dfp_detections_user_accounts_clustered.csv"
    output_file = "/home/tb-tkhongsap/my-gitlab/cyber-data-analysis/outputs/extreme_anomaly_examples.json"
    
    load_and_analyze_extremes(computer_file, user_file, output_file)