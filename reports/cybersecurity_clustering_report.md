# Cybersecurity Data Statistical Analysis for Clustering

## Executive Summary

This comprehensive statistical analysis examines two cybersecurity datasets to identify optimal characteristics for clustering algorithms. The analysis reveals distinct behavioral patterns between computer accounts (1,371 events) and user accounts (58 events), requiring separate clustering approaches.

## Dataset Overview

### Computer Accounts Dataset
- **Total Events**: 1,371
- **Unique Users/Accounts**: 104
- **Unique Hosts**: 7
- **Event Types**: 5 (4634, 4624, 4672, 4689, 4688)
- **Time Range**: August 25-27, 2025
- **Source IPs**: 68 unique addresses

### User Accounts Dataset  
- **Total Events**: 58
- **Unique Users**: 49
- **Unique Hosts**: 7
- **Event Types**: 3 (4634, 4624, 4689)
- **Scale Ratio**: 23.6:1 (Computer:User events)

## Statistical Characteristics

### Anomaly Score Distribution

#### Computer Accounts (max_abs_z)
```
Mean: 16.58        Median: 15.21
Std Dev: 7.44      Range: [5.01, 50.65]
95th Percentile: 29.08
99th Percentile: 33.56
Critical Events (z>20): 439 (32.02%)
Outliers (>3σ): 13 (0.95%)
```

#### User Accounts (max_abs_z)
```
Mean: 10.81        Median: 7.70
Std Dev: 10.73     Range: [5.97, 75.86]
95th Percentile: 41.07
99th Percentile: 75.86
Critical Events (z>20): 3 (5.17%)
Outliers (>3σ): 1 (1.72%)
```

### Key Findings

1. **Computer accounts show higher average anomaly scores** but more consistent patterns
2. **User accounts have more extreme outliers** despite lower average scores
3. **Event distribution is similar** (48% logout, 48% login events) across both datasets
4. **High concentration of anomalous behavior** in computer accounts (32% critical events)

## Host Risk Analysis

### Top Risk Hosts (Computer Accounts)
1. **STBVDRADC01**: Risk=122.35 (1,149 events, Max_Z=32.17)
2. **STBVADC01**: Risk=78.21 (80 events, Max_Z=50.65)  
3. **STBVADC02**: Risk=46.54 (25 events, Max_Z=50.29)

### Top Risk Hosts (User Accounts)
1. **STBVADC04**: Risk=37.19 (9 events, Max_Z=75.86)
2. **STBVDRADC01**: Risk=27.51 (7 events, Max_Z=41.07)
3. **STBVADC05**: Risk=27.10 (10 events, Max_Z=41.18)

## Clustering Recommendations

### Primary Features for Clustering

Both datasets should use the following features (in priority order):

1. **max_abs_z** - Maximum anomaly score (primary clustering dimension)
2. **mean_abs_z** - Average anomaly score (behavioral baseline)
3. **logcount** - Event frequency (activity level indicator)
4. **hostincrement** - Host-based incremental patterns
5. **ipincrement** - IP-based connection patterns
6. **z_loss features** - Prediction error metrics (top 3)

### Optimal Clustering Parameters

#### Computer Accounts
- **Dataset Size**: Large (1,371 events)
- **Recommended Algorithm**: DBSCAN or Mini-batch K-means
- **Optimal K Range**: 5-8 clusters
- **Scaling**: RobustScaler (due to extreme outliers)
- **Special Considerations**: 
  - Separate cluster for critical events (z>20)
  - Consider hierarchical clustering for anomaly subgroups

#### User Accounts  
- **Dataset Size**: Small (58 events)
- **Recommended Algorithm**: K-means or Gaussian Mixture Model
- **Optimal K Range**: 3-5 clusters
- **Scaling**: StandardScaler or RobustScaler
- **Special Considerations**:
  - Manual inspection of all clusters due to small size
  - Validate clusters with domain experts

### Advanced Clustering Strategy

```python
# Recommended Implementation Approach

# 1. Data Preprocessing
from sklearn.preprocessing import RobustScaler
from sklearn.cluster import DBSCAN, KMeans
from sklearn.mixture import GaussianMixture

# Feature selection
primary_features = ['max_abs_z', 'mean_abs_z', 'logcount', 'hostincrement', 'ipincrement']

# 2. Computer Accounts Clustering
scaler_comp = RobustScaler()
X_comp_scaled = scaler_comp.fit_transform(computer_data[primary_features])

# DBSCAN for outlier detection
dbscan = DBSCAN(eps=0.5, min_samples=5)
computer_clusters = dbscan.fit_predict(X_comp_scaled)

# 3. User Accounts Clustering  
scaler_user = StandardScaler()
X_user_scaled = scaler_user.fit_transform(user_data[primary_features])

# K-means for small dataset
kmeans = KMeans(n_clusters=4, random_state=42)
user_clusters = kmeans.fit_predict(X_user_scaled)
```

### Cluster Validation Metrics

1. **Silhouette Score**: Target >0.5 for good separation
2. **Inertia/WCSS**: For elbow method optimization
3. **Security Relevance**: Manual validation of high-risk clusters
4. **Calinski-Harabasz Index**: For cluster compactness evaluation

## Security Insights

### Critical Security Events
- **Computer accounts**: 32% of events are critical (z>20)
- **User accounts**: 5% of events are critical, but more extreme (max z=75.86)
- **Domain controllers** (STBVDRADC01) show highest activity and risk

### Behavioral Patterns
- **Consistent event distribution**: 48% logout, 48% login events
- **Process events rare**: <6% of total events
- **Network-based logons dominate**: Type 3 (Network) most common
- **Time patterns**: Activity concentrated in specific time windows

### Risk Indicators
1. **High-frequency anomalous behavior** in computer accounts
2. **Extreme outlier events** in user accounts requiring investigation
3. **Host concentration**: 80% of events from single domain controller
4. **IP diversity**: 68 unique source IPs suggest distributed access

## Implementation Recommendations

### Phase 1: Baseline Clustering
1. Implement separate clustering for computer and user accounts
2. Use recommended features and algorithms
3. Apply robust scaling for outlier resilience
4. Validate clusters using silhouette analysis

### Phase 2: Advanced Analytics
1. **Temporal clustering**: Add time-based features for pattern detection
2. **Multi-level clustering**: Hierarchical approach for anomaly subgroups
3. **Hybrid approach**: Combine K-means for normal behavior, DBSCAN for outliers
4. **Dynamic clustering**: Real-time cluster updates for streaming data

### Phase 3: Integration
1. **Risk scoring**: Assign cluster-based risk scores
2. **Alert prioritization**: Use cluster membership for alert ranking  
3. **Behavioral baselines**: Establish normal behavior profiles per cluster
4. **Automated response**: Trigger actions based on cluster assignments

## Validation Strategy

1. **Statistical Validation**
   - Silhouette score >0.5
   - Within-cluster sum of squares minimization
   - Cross-validation stability

2. **Security Validation**
   - Domain expert review of high-risk clusters
   - Historical incident correlation
   - False positive/negative analysis

3. **Operational Validation**
   - SOC analyst feedback on cluster relevance
   - Integration with existing security tools
   - Performance impact assessment

## Conclusion

The analysis reveals two distinct datasets requiring tailored clustering approaches:

- **Computer accounts** need robust algorithms handling large-scale, consistently anomalous data
- **User accounts** require careful handling due to small size but extreme outliers
- **Separate clustering is essential** due to different behavioral patterns and scale
- **Feature engineering** focusing on anomaly scores and behavioral patterns is crucial
- **Validation through security domain expertise** is mandatory for operational success

The recommended clustering strategy provides a solid foundation for cybersecurity behavioral analysis, threat detection, and risk assessment capabilities.