/**
 * Security Incident Forecasting Engine
 * Provides predictive analytics for cybersecurity threats
 */

import { addDays, format, startOfDay } from 'date-fns';

/**
 * Calculate trend using simple linear regression
 */
const calculateTrend = (data) => {
  const n = data.length;
  if (n < 2) return { slope: 0, intercept: 0 };
  
  let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0;
  
  data.forEach((point, index) => {
    const x = index;
    const y = point.value || point.events || 0;
    sumX += x;
    sumY += y;
    sumXY += x * y;
    sumX2 += x * x;
  });
  
  const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
  const intercept = (sumY - slope * sumX) / n;
  
  return { slope, intercept };
};

/**
 * Forecast future incidents based on historical patterns
 */
export const forecastIncidents = (historicalData, daysToForecast = 7) => {
  // Group data by day
  const dailyData = {};
  
  historicalData.forEach(event => {
    const day = format(startOfDay(event.timestamp), 'yyyy-MM-dd');
    if (!dailyData[day]) {
      dailyData[day] = {
        date: day,
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        systemEvents: 0,
        userEvents: 0
      };
    }
    
    dailyData[day].total++;
    
    // Count by risk level
    const riskLevel = event.risk_category || event.risk_level || 'MEDIUM';
    if (riskLevel === 'CRITICAL' || event.risk_score >= 20) {
      dailyData[day].critical++;
    } else if (riskLevel === 'HIGH' || event.risk_score >= 10) {
      dailyData[day].high++;
    } else {
      dailyData[day].medium++;
    }
    
    // Count by account type
    if (event.account_type === 'System') {
      dailyData[day].systemEvents++;
    } else if (event.account_type === 'User') {
      dailyData[day].userEvents++;
    }
  });
  
  // Convert to array and sort
  const sortedDays = Object.values(dailyData).sort((a, b) => 
    new Date(a.date) - new Date(b.date)
  );
  
  // Calculate trends
  const totalTrend = calculateTrend(sortedDays.map(d => ({ value: d.total })));
  const criticalTrend = calculateTrend(sortedDays.map(d => ({ value: d.critical })));
  const systemTrend = calculateTrend(sortedDays.map(d => ({ value: d.systemEvents })));
  const userTrend = calculateTrend(sortedDays.map(d => ({ value: d.userEvents })));
  
  // Generate forecasts
  const forecasts = [];
  const lastDate = new Date(sortedDays[sortedDays.length - 1].date);
  const baseIndex = sortedDays.length;
  
  for (let i = 1; i <= daysToForecast; i++) {
    const forecastDate = addDays(lastDate, i);
    const dayIndex = baseIndex + i - 1;
    
    // Calculate forecasted values
    const totalForecast = Math.max(0, Math.round(totalTrend.slope * dayIndex + totalTrend.intercept));
    const criticalForecast = Math.max(0, Math.round(criticalTrend.slope * dayIndex + criticalTrend.intercept));
    const systemForecast = Math.max(0, Math.round(systemTrend.slope * dayIndex + systemTrend.intercept));
    const userForecast = Math.max(0, Math.round(userTrend.slope * dayIndex + userTrend.intercept));
    
    // Add confidence intervals (simplified)
    const confidence = Math.max(0.5, 1 - (i * 0.05)); // Decreases with distance
    
    forecasts.push({
      date: format(forecastDate, 'yyyy-MM-dd'),
      dateLabel: format(forecastDate, 'MMM dd'),
      predicted_total: totalForecast,
      predicted_critical: criticalForecast,
      predicted_system: systemForecast,
      predicted_user: userForecast,
      confidence_level: confidence,
      lower_bound: Math.round(totalForecast * (1 - (1 - confidence))),
      upper_bound: Math.round(totalForecast * (1 + (1 - confidence))),
      risk_trend: totalTrend.slope > 0 ? 'increasing' : totalTrend.slope < 0 ? 'decreasing' : 'stable'
    });
  }
  
  return {
    historical: sortedDays,
    forecasts: forecasts,
    trends: {
      total: totalTrend.slope > 0 ? 'increasing' : totalTrend.slope < 0 ? 'decreasing' : 'stable',
      critical: criticalTrend.slope > 0 ? 'increasing' : 'decreasing',
      system: systemTrend.slope > 0 ? 'increasing' : 'decreasing',
      user: userTrend.slope > 0 ? 'increasing' : 'decreasing',
      slope_values: {
        total: totalTrend.slope,
        critical: criticalTrend.slope,
        system: systemTrend.slope,
        user: userTrend.slope
      }
    }
  };
};

/**
 * Calculate risk score forecast
 */
export const forecastRiskScore = (historicalData) => {
  const riskScores = historicalData
    .map(event => event.risk_score || parseFloat(event.max_abs_z) || 0)
    .filter(score => score > 0);
  
  if (riskScores.length === 0) {
    return { current: 0, predicted: 0, trend: 'stable' };
  }
  
  // Calculate moving average
  const recentScores = riskScores.slice(-10); // Last 10 events
  const avgRecent = recentScores.reduce((a, b) => a + b, 0) / recentScores.length;
  
  const olderScores = riskScores.slice(-20, -10); // Previous 10 events
  const avgOlder = olderScores.length > 0 
    ? olderScores.reduce((a, b) => a + b, 0) / olderScores.length 
    : avgRecent;
  
  // Calculate trend
  const trendValue = avgRecent - avgOlder;
  const predictedNext = Math.max(0, avgRecent + trendValue);
  
  return {
    current: Math.round(avgRecent * 10) / 10,
    predicted: Math.round(predictedNext * 10) / 10,
    trend: trendValue > 1 ? 'increasing' : trendValue < -1 ? 'decreasing' : 'stable',
    change_rate: Math.round(trendValue * 10) / 10
  };
};

/**
 * Predict next likely attack vector
 */
export const predictAttackVector = (historicalData) => {
  // Count recent attack patterns
  const recentEvents = historicalData.slice(-100);
  const attackPatterns = {};
  
  recentEvents.forEach(event => {
    const pattern = event.cluster_description || event.attack_stage || 'Unknown';
    attackPatterns[pattern] = (attackPatterns[pattern] || 0) + 1;
  });
  
  // Sort by frequency
  const sortedPatterns = Object.entries(attackPatterns)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  
  // Predict based on patterns
  const predictions = sortedPatterns.map(([pattern, count]) => ({
    attack_type: pattern,
    probability: (count / recentEvents.length),
    likelihood: count > 20 ? 'High' : count > 10 ? 'Medium' : 'Low',
    recommended_action: getRecommendedAction(pattern)
  }));
  
  return predictions;
};

/**
 * Get recommended action based on attack pattern
 */
const getRecommendedAction = (pattern) => {
  const actions = {
    'Lateral_Movement_Indicators': 'Implement network segmentation and monitor service accounts',
    'Suspicious_Authentication_Pattern': 'Enable MFA and review authentication logs',
    'Critical_Persistent_Threats': 'Initiate incident response and isolate affected systems',
    'Outlier_Extreme_Risk': 'Immediate investigation required - potential breach',
    'Critical_User_Breach': 'Reset user credentials and audit access logs',
    'default': 'Enhanced monitoring and log analysis recommended'
  };
  
  return actions[pattern] || actions['default'];
};

/**
 * Calculate time to next critical incident
 */
export const predictTimeToNextCritical = (historicalData) => {
  const criticalEvents = historicalData
    .filter(event => event.risk_category === 'CRITICAL' || event.risk_score >= 20)
    .map(event => event.timestamp)
    .sort((a, b) => new Date(a) - new Date(b));
  
  if (criticalEvents.length < 2) {
    return { 
      hours: null, 
      confidence: 'low',
      message: 'Insufficient data for prediction'
    };
  }
  
  // Calculate intervals between critical events
  const intervals = [];
  for (let i = 1; i < criticalEvents.length; i++) {
    const interval = new Date(criticalEvents[i]) - new Date(criticalEvents[i - 1]);
    intervals.push(interval);
  }
  
  // Calculate average interval
  const avgInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;
  const hoursToNext = Math.round(avgInterval / (1000 * 60 * 60));
  
  // Calculate confidence based on variance
  const variance = intervals.map(i => Math.pow(i - avgInterval, 2))
    .reduce((a, b) => a + b, 0) / intervals.length;
  const stdDev = Math.sqrt(variance);
  const coefficientOfVariation = stdDev / avgInterval;
  
  const confidence = coefficientOfVariation < 0.3 ? 'high' : 
                    coefficientOfVariation < 0.6 ? 'medium' : 'low';
  
  return {
    hours: hoursToNext,
    confidence: confidence,
    message: `Next critical incident expected in approximately ${hoursToNext} hours`
  };
};

/**
 * Generate executive forecast summary
 */
export const generateForecastSummary = (historicalData) => {
  const incidentForecast = forecastIncidents(historicalData, 7);
  const riskForecast = forecastRiskScore(historicalData);
  const attackPredictions = predictAttackVector(historicalData);
  const timeToNextCritical = predictTimeToNextCritical(historicalData);
  
  // Calculate key metrics
  const next7DaysTotal = incidentForecast.forecasts
    .reduce((sum, f) => sum + f.predicted_total, 0);
  
  const next7DaysCritical = incidentForecast.forecasts
    .reduce((sum, f) => sum + f.predicted_critical, 0);
  
  return {
    executive_summary: {
      forecast_period: '7 days',
      predicted_total_incidents: next7DaysTotal,
      predicted_critical_incidents: next7DaysCritical,
      risk_trend: incidentForecast.trends.total,
      overall_risk_score: riskForecast.predicted,
      time_to_next_critical: timeToNextCritical.hours,
      confidence_level: timeToNextCritical.confidence
    },
    detailed_forecast: incidentForecast,
    risk_progression: riskForecast,
    likely_attack_vectors: attackPredictions,
    recommendations: generateRecommendations(incidentForecast, riskForecast, attackPredictions)
  };
};

/**
 * Generate proactive recommendations
 */
const generateRecommendations = (incidentForecast, riskForecast, attackPredictions) => {
  const recommendations = [];
  
  // Based on trend
  if (incidentForecast.trends.total === 'increasing') {
    recommendations.push({
      priority: 'HIGH',
      action: 'Increase SOC monitoring capacity',
      reason: 'Incident rate is trending upward'
    });
  }
  
  if (incidentForecast.trends.critical === 'increasing') {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Activate incident response team',
      reason: 'Critical incidents are increasing'
    });
  }
  
  // Based on risk score
  if (riskForecast.predicted > 20) {
    recommendations.push({
      priority: 'CRITICAL',
      action: 'Implement emergency security measures',
      reason: `Risk score predicted to reach ${riskForecast.predicted}`
    });
  }
  
  // Based on attack predictions
  const highProbAttacks = attackPredictions.filter(a => a.likelihood === 'High');
  if (highProbAttacks.length > 0) {
    recommendations.push({
      priority: 'HIGH',
      action: highProbAttacks[0].recommended_action,
      reason: `High probability of ${highProbAttacks[0].attack_type}`
    });
  }
  
  return recommendations;
};

export default {
  forecastIncidents,
  forecastRiskScore,
  predictAttackVector,
  predictTimeToNextCritical,
  generateForecastSummary
};