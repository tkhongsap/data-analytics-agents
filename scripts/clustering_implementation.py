#!/usr/bin/env python3
"""
Cybersecurity Data Clustering Implementation
===========================================
This script performs clustering on computer and user account security events,
adding cluster IDs and meaningful descriptions to identify threat patterns.

Author: Claude Code
Date: 2025-09-04
"""

import csv
import json
from collections import Counter
from datetime import datetime
import math

def load_csv_data(filepath):
    """Load CSV file and return data as list of dictionaries"""
    with open(filepath, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

def save_csv_with_clusters(data, filepath, fieldnames):
    """Save data with cluster information to CSV"""
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)

def extract_features(row):
    """Extract key features for clustering"""
    features = {}
    try:
        features['max_abs_z'] = float(row.get('max_abs_z', 0))
        features['mean_abs_z'] = float(row.get('mean_abs_z', 0))
        features['logcount'] = float(row.get('logcount', 0))
        features['hostincrement'] = float(row.get('hostincrement', 0))
        features['ipincrement'] = float(row.get('ipincrement', 0))
        features['event_id'] = int(row.get('event_id', 0))
        # Add z-loss features
        features['logcount_z_loss'] = float(row.get('logcount_z_loss', 0))
        features['hostincrement_z_loss'] = float(row.get('hostincrement_z_loss', 0))
        features['ipincrement_z_loss'] = float(row.get('ipincrement_z_loss', 0))
    except (ValueError, TypeError):
        # Return zeros for any conversion errors
        for key in ['max_abs_z', 'mean_abs_z', 'logcount', 'hostincrement', 'ipincrement', 
                    'event_id', 'logcount_z_loss', 'hostincrement_z_loss', 'ipincrement_z_loss']:
            if key not in features:
                features[key] = 0
    return features

def normalize_features(features_list):
    """Simple normalization using min-max scaling"""
    if not features_list:
        return []
    
    # Get min and max for each feature
    feature_names = list(features_list[0].keys())
    min_vals = {key: float('inf') for key in feature_names}
    max_vals = {key: float('-inf') for key in feature_names}
    
    for features in features_list:
        for key, val in features.items():
            min_vals[key] = min(min_vals[key], val)
            max_vals[key] = max(max_vals[key], val)
    
    # Normalize
    normalized = []
    for features in features_list:
        norm_features = {}
        for key, val in features.items():
            if max_vals[key] - min_vals[key] > 0:
                norm_features[key] = (val - min_vals[key]) / (max_vals[key] - min_vals[key])
            else:
                norm_features[key] = 0
        normalized.append(norm_features)
    
    return normalized

def euclidean_distance(f1, f2, weights=None):
    """Calculate weighted Euclidean distance between two feature vectors"""
    if weights is None:
        # Default weights prioritizing anomaly scores
        weights = {
            'max_abs_z': 3.0,
            'mean_abs_z': 2.5,
            'logcount': 1.0,
            'event_id': 1.5,
            'hostincrement': 1.0,
            'ipincrement': 1.0,
            'logcount_z_loss': 1.5,
            'hostincrement_z_loss': 1.0,
            'ipincrement_z_loss': 1.0
        }
    
    distance = 0
    for key in f1.keys():
        w = weights.get(key, 1.0)
        distance += w * (f1[key] - f2[key]) ** 2
    return math.sqrt(distance)

def kmeans_clustering(data, k, max_iters=100):
    """Simple K-means clustering implementation"""
    if len(data) < k:
        # If we have fewer data points than clusters, assign each to its own cluster
        return list(range(len(data)))
    
    # Extract and normalize features
    features_list = [extract_features(row) for row in data]
    normalized_features = normalize_features(features_list)
    
    if not normalized_features:
        return [0] * len(data)
    
    # Initialize centroids using first k points
    centroids = normalized_features[:k]
    
    for iteration in range(max_iters):
        # Assign points to nearest centroid
        clusters = []
        for features in normalized_features:
            distances = [euclidean_distance(features, centroid) for centroid in centroids]
            clusters.append(distances.index(min(distances)))
        
        # Update centroids
        new_centroids = []
        for i in range(k):
            cluster_points = [normalized_features[j] for j in range(len(normalized_features)) if clusters[j] == i]
            if cluster_points:
                # Calculate mean of cluster points
                new_centroid = {}
                for key in cluster_points[0].keys():
                    new_centroid[key] = sum(p[key] for p in cluster_points) / len(cluster_points)
                new_centroids.append(new_centroid)
            else:
                # Keep old centroid if cluster is empty
                new_centroids.append(centroids[i])
        
        # Check for convergence
        if new_centroids == centroids:
            break
        centroids = new_centroids
    
    return clusters

def dbscan_outlier_detection(data, eps=0.5, min_samples=5):
    """Simplified DBSCAN for outlier detection"""
    features_list = [extract_features(row) for row in data]
    normalized_features = normalize_features(features_list)
    
    if not normalized_features:
        return [False] * len(data)
    
    n = len(normalized_features)
    is_outlier = [True] * n  # Start by assuming all are outliers
    
    # Find neighbors for each point
    for i in range(n):
        neighbors = []
        for j in range(n):
            if i != j and euclidean_distance(normalized_features[i], normalized_features[j]) <= eps:
                neighbors.append(j)
        
        # If point has enough neighbors, it's not an outlier
        if len(neighbors) >= min_samples:
            is_outlier[i] = False
            # Also mark its neighbors as non-outliers
            for neighbor in neighbors:
                is_outlier[neighbor] = False
    
    return is_outlier

def cluster_computer_accounts(data):
    """Cluster computer accounts using hybrid DBSCAN + K-means approach"""
    print("\nClustering Computer Accounts...")
    print(f"Total events: {len(data)}")
    
    # First, identify outliers using DBSCAN-like approach
    is_outlier = dbscan_outlier_detection(data, eps=0.3, min_samples=10)
    
    # Separate outliers and normal data
    outlier_indices = [i for i, outlier in enumerate(is_outlier) if outlier]
    normal_indices = [i for i, outlier in enumerate(is_outlier) if not outlier]
    
    print(f"Outliers detected: {len(outlier_indices)}")
    print(f"Normal events: {len(normal_indices)}")
    
    # Apply K-means to normal data
    normal_data = [data[i] for i in normal_indices]
    if normal_data:
        normal_clusters = kmeans_clustering(normal_data, k=5)
    else:
        normal_clusters = []
    
    # Combine results
    final_clusters = [0] * len(data)
    cluster_descriptions = [None] * len(data)
    
    # Assign outliers to cluster 5
    for idx in outlier_indices:
        final_clusters[idx] = 5
        cluster_descriptions[idx] = "Outlier_Extreme_Risk"
    
    # Assign normal clusters (0-4)
    for i, idx in enumerate(normal_indices):
        if i < len(normal_clusters):
            final_clusters[idx] = normal_clusters[i]
    
    # Determine cluster descriptions based on characteristics
    for i, row in enumerate(data):
        if cluster_descriptions[i] is None:  # Not an outlier
            features = extract_features(row)
            cluster_id = final_clusters[i]
            
            # Analyze characteristics for description
            max_z = features['max_abs_z']
            event_id = features['event_id']
            
            if cluster_id == 0:
                if max_z > 20:
                    cluster_descriptions[i] = "Critical_Persistent_Threats"
                else:
                    cluster_descriptions[i] = "High_Risk_Authentication"
            elif cluster_id == 1:
                if event_id in [4672, 4688]:
                    cluster_descriptions[i] = "Privilege_Escalation_Activity"
                else:
                    cluster_descriptions[i] = "Suspicious_Authentication_Pattern"
            elif cluster_id == 2:
                if max_z > 15:
                    cluster_descriptions[i] = "System_Process_Anomalies"
                else:
                    cluster_descriptions[i] = "Moderate_Risk_Events"
            elif cluster_id == 3:
                if features['ipincrement'] > features['hostincrement']:
                    cluster_descriptions[i] = "Network_Reconnaissance"
                else:
                    cluster_descriptions[i] = "Lateral_Movement_Indicators"
            elif cluster_id == 4:
                cluster_descriptions[i] = "Baseline_Activity"
            else:
                cluster_descriptions[i] = "Unknown_Pattern"
    
    return final_clusters, cluster_descriptions

def cluster_user_accounts(data):
    """Cluster user accounts using K-means"""
    print("\nClustering User Accounts...")
    print(f"Total events: {len(data)}")
    
    # Apply K-means directly due to small dataset
    clusters = kmeans_clustering(data, k=4)
    cluster_descriptions = []
    
    # Analyze each event for description
    for i, row in enumerate(data):
        features = extract_features(row)
        cluster_id = clusters[i]
        max_z = features['max_abs_z']
        event_id = features['event_id']
        
        # Assign descriptions based on cluster and features
        if max_z > 40:
            cluster_descriptions.append("Critical_User_Breach")
        elif max_z > 20:
            cluster_descriptions.append("High_Risk_User_Activity")
        elif max_z > 10:
            cluster_descriptions.append("Suspicious_User_Behavior")
        elif event_id == 4689:
            cluster_descriptions.append("Process_Termination_Events")
        elif cluster_id == 0:
            cluster_descriptions.append("Normal_User_Activity")
        elif cluster_id == 1:
            cluster_descriptions.append("Authentication_Anomalies")
        elif cluster_id == 2:
            cluster_descriptions.append("Session_Management_Issues")
        else:
            cluster_descriptions.append("Baseline_User_Behavior")
    
    return clusters, cluster_descriptions

def generate_cluster_summary(data, clusters, descriptions, dataset_name):
    """Generate summary statistics for clusters"""
    summary = {
        'dataset': dataset_name,
        'total_events': len(data),
        'unique_clusters': len(set(clusters)),
        'cluster_distribution': Counter(clusters),
        'description_distribution': Counter(descriptions),
        'cluster_details': {}
    }
    
    # Analyze each cluster
    unique_clusters = set(clusters)
    for cluster_id in unique_clusters:
        cluster_indices = [i for i, c in enumerate(clusters) if c == cluster_id]
        cluster_data = [data[i] for i in cluster_indices]
        
        # Get cluster statistics
        max_z_values = []
        event_ids = []
        usernames = set()
        hostnames = set()
        
        for row in cluster_data:
            try:
                max_z_values.append(float(row.get('max_abs_z', 0)))
                event_ids.append(row.get('event_id', 'unknown'))
                usernames.add(row.get('username', 'unknown'))
                hostnames.add(row.get('hostname', 'unknown'))
            except (ValueError, TypeError):
                continue
        
        avg_max_z = sum(max_z_values) / len(max_z_values) if max_z_values else 0
        
        summary['cluster_details'][cluster_id] = {
            'size': len(cluster_indices),
            'avg_anomaly_score': round(avg_max_z, 2),
            'unique_users': len(usernames),
            'unique_hosts': len(hostnames),
            'event_types': Counter(event_ids).most_common(3),
            'common_description': Counter([descriptions[i] for i in cluster_indices]).most_common(1)[0] if cluster_indices else ('Unknown', 0)
        }
    
    return summary

def main():
    """Main execution function"""
    print("="*60)
    print("CYBERSECURITY DATA CLUSTERING IMPLEMENTATION")
    print("="*60)
    
    # File paths
    computer_file = 'data/dfp_detections_computer_accounts.csv'
    user_file = 'data/dfp_detections_user_accounts.csv'
    
    # Output files
    computer_output = 'data/dfp_detections_computer_accounts_clustered.csv'
    user_output = 'data/dfp_detections_user_accounts_clustered.csv'
    report_file = 'cluster_analysis_report.txt'
    
    # Process computer accounts
    print(f"\nLoading {computer_file}...")
    computer_data = load_csv_data(computer_file)
    computer_clusters, computer_descriptions = cluster_computer_accounts(computer_data)
    
    # Add cluster information to data
    for i, row in enumerate(computer_data):
        row['cluster_id'] = computer_clusters[i]
        row['cluster_description'] = computer_descriptions[i]
    
    # Save clustered computer accounts
    fieldnames = list(computer_data[0].keys())
    save_csv_with_clusters(computer_data, computer_output, fieldnames)
    print(f"Saved clustered data to {computer_output}")
    
    # Process user accounts
    print(f"\nLoading {user_file}...")
    user_data = load_csv_data(user_file)
    user_clusters, user_descriptions = cluster_user_accounts(user_data)
    
    # Add cluster information to data
    for i, row in enumerate(user_data):
        row['cluster_id'] = user_clusters[i]
        row['cluster_description'] = user_descriptions[i]
    
    # Save clustered user accounts
    fieldnames = list(user_data[0].keys())
    save_csv_with_clusters(user_data, user_output, fieldnames)
    print(f"Saved clustered data to {user_output}")
    
    # Generate summaries
    computer_summary = generate_cluster_summary(computer_data, computer_clusters, computer_descriptions, "Computer Accounts")
    user_summary = generate_cluster_summary(user_data, user_clusters, user_descriptions, "User Accounts")
    
    # Write report
    with open(report_file, 'w') as f:
        f.write("="*60 + "\n")
        f.write("CLUSTER ANALYSIS REPORT\n")
        f.write("="*60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Computer accounts summary
        f.write("COMPUTER ACCOUNTS CLUSTERING\n")
        f.write("-"*40 + "\n")
        f.write(f"Total Events: {computer_summary['total_events']}\n")
        f.write(f"Unique Clusters: {computer_summary['unique_clusters']}\n")
        f.write(f"Cluster Distribution: {dict(computer_summary['cluster_distribution'])}\n\n")
        
        f.write("Cluster Descriptions Distribution:\n")
        for desc, count in computer_summary['description_distribution'].most_common():
            f.write(f"  - {desc}: {count} events\n")
        f.write("\n")
        
        f.write("Cluster Details:\n")
        for cluster_id, details in sorted(computer_summary['cluster_details'].items()):
            f.write(f"\nCluster {cluster_id}: {details['common_description'][0]}\n")
            f.write(f"  Size: {details['size']} events\n")
            f.write(f"  Avg Anomaly Score: {details['avg_anomaly_score']}\n")
            f.write(f"  Unique Users: {details['unique_users']}\n")
            f.write(f"  Unique Hosts: {details['unique_hosts']}\n")
            f.write(f"  Top Event Types: {details['event_types']}\n")
        
        f.write("\n" + "="*60 + "\n")
        
        # User accounts summary
        f.write("USER ACCOUNTS CLUSTERING\n")
        f.write("-"*40 + "\n")
        f.write(f"Total Events: {user_summary['total_events']}\n")
        f.write(f"Unique Clusters: {user_summary['unique_clusters']}\n")
        f.write(f"Cluster Distribution: {dict(user_summary['cluster_distribution'])}\n\n")
        
        f.write("Cluster Descriptions Distribution:\n")
        for desc, count in user_summary['description_distribution'].most_common():
            f.write(f"  - {desc}: {count} events\n")
        f.write("\n")
        
        f.write("Cluster Details:\n")
        for cluster_id, details in sorted(user_summary['cluster_details'].items()):
            f.write(f"\nCluster {cluster_id}: {details['common_description'][0]}\n")
            f.write(f"  Size: {details['size']} events\n")
            f.write(f"  Avg Anomaly Score: {details['avg_anomaly_score']}\n")
            f.write(f"  Unique Users: {details['unique_users']}\n")
            f.write(f"  Unique Hosts: {details['unique_hosts']}\n")
            f.write(f"  Top Event Types: {details['event_types']}\n")
        
        f.write("\n" + "="*60 + "\n")
        f.write("SECURITY RECOMMENDATIONS\n")
        f.write("-"*40 + "\n")
        f.write("1. Investigate all 'Outlier_Extreme_Risk' and 'Critical' clusters immediately\n")
        f.write("2. Review 'Privilege_Escalation_Activity' for potential insider threats\n")
        f.write("3. Monitor 'Network_Reconnaissance' for potential attack preparation\n")
        f.write("4. Baseline 'Normal' clusters for anomaly detection improvements\n")
        f.write("5. Correlate user and computer account clusters for comprehensive threat view\n")
    
    print(f"\nCluster analysis report saved to {report_file}")
    
    print("\n" + "="*60)
    print("CLUSTERING COMPLETE")
    print("="*60)
    print(f"✓ Computer accounts: {computer_output}")
    print(f"✓ User accounts: {user_output}")
    print(f"✓ Analysis report: {report_file}")
    print("\nBoth CSV files now contain:")
    print("  - cluster_id: Numeric cluster identifier")
    print("  - cluster_description: Human-readable security context")

if __name__ == "__main__":
    main()