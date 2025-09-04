import React, { useMemo } from 'react';
import { TrendingUp, TrendingDown, Minus, AlertTriangle, Clock, Target, Shield } from 'lucide-react';
import { LineChart, Line, AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { generateForecastSummary } from '../utils/forecastingEngine';

const ForecastingPanel = ({ data }) => {
  const forecast = useMemo(() => {
    if (!data || data.length === 0) return null;
    return generateForecastSummary(data);
  }, [data]);

  if (!forecast) {
    return (
      <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6">
        <p className="text-gray-400">Loading forecast data...</p>
      </div>
    );
  }

  const { executive_summary, detailed_forecast, risk_progression, likely_attack_vectors, recommendations } = forecast;

  // Combine historical and forecast data for visualization
  const chartData = [
    ...detailed_forecast.historical.map(d => ({
      date: d.date.split('-').slice(1).join('/'),
      actual_total: d.total,
      actual_critical: d.critical,
      type: 'historical'
    })),
    ...detailed_forecast.forecasts.map(f => ({
      date: f.dateLabel,
      predicted_total: f.predicted_total,
      predicted_critical: f.predicted_critical,
      lower_bound: f.lower_bound,
      upper_bound: f.upper_bound,
      type: 'forecast'
    }))
  ];

  const getTrendIcon = (trend) => {
    if (trend === 'increasing') return <TrendingUp className="w-5 h-5 text-red-400" />;
    if (trend === 'decreasing') return <TrendingDown className="w-5 h-5 text-green-400" />;
    return <Minus className="w-5 h-5 text-yellow-400" />;
  };

  const getRiskColor = (score) => {
    if (score >= 20) return 'text-red-400';
    if (score >= 10) return 'text-orange-400';
    return 'text-yellow-400';
  };

  return (
    <div className="space-y-6">
      {/* Executive Summary */}
      <div className="bg-gradient-to-r from-purple-900/20 to-blue-900/20 backdrop-blur-sm rounded-lg p-6 border border-purple-500/20">
        <h2 className="text-2xl font-bold mb-4 flex items-center gap-2">
          <Target className="w-6 h-6 text-purple-400" />
          7-Day Security Forecast
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <div className="bg-gray-800/50 rounded-lg p-4">
            <p className="text-sm text-gray-400 mb-1">Predicted Incidents</p>
            <p className="text-2xl font-bold text-white">{executive_summary.predicted_total_incidents}</p>
            <div className="flex items-center gap-2 mt-2">
              {getTrendIcon(executive_summary.risk_trend)}
              <span className="text-sm capitalize">{executive_summary.risk_trend}</span>
            </div>
          </div>
          
          <div className="bg-gray-800/50 rounded-lg p-4">
            <p className="text-sm text-gray-400 mb-1">Critical Events Expected</p>
            <p className="text-2xl font-bold text-red-400">{executive_summary.predicted_critical_incidents}</p>
            <p className="text-xs text-gray-500 mt-1">High severity alerts</p>
          </div>
          
          <div className="bg-gray-800/50 rounded-lg p-4">
            <p className="text-sm text-gray-400 mb-1">Risk Score Forecast</p>
            <p className={`text-2xl font-bold ${getRiskColor(executive_summary.overall_risk_score)}`}>
              {executive_summary.overall_risk_score.toFixed(1)}
            </p>
            <p className="text-xs text-gray-500 mt-1">
              Current: {risk_progression.current.toFixed(1)}
            </p>
          </div>
          
          <div className="bg-gray-800/50 rounded-lg p-4">
            <p className="text-sm text-gray-400 mb-1">Time to Next Critical</p>
            <p className="text-2xl font-bold text-orange-400">
              {executive_summary.time_to_next_critical || 'N/A'} hrs
            </p>
            <p className="text-xs text-gray-500 mt-1">
              Confidence: {executive_summary.confidence_level}
            </p>
          </div>
        </div>

        {/* Trend Indicators */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">System:</span>
            {getTrendIcon(detailed_forecast.trends.system)}
            <span className="text-sm">{detailed_forecast.trends.system}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">User:</span>
            {getTrendIcon(detailed_forecast.trends.user)}
            <span className="text-sm">{detailed_forecast.trends.user}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">Critical:</span>
            {getTrendIcon(detailed_forecast.trends.critical)}
            <span className="text-sm">{detailed_forecast.trends.critical}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-sm text-gray-400">Overall:</span>
            {getTrendIcon(detailed_forecast.trends.total)}
            <span className="text-sm">{detailed_forecast.trends.total}</span>
          </div>
        </div>
      </div>

      {/* Forecast Chart */}
      <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <TrendingUp className="w-5 h-5 text-blue-400" />
          Incident Forecast Visualization
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.1}/>
              </linearGradient>
              <linearGradient id="colorCritical" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8}/>
                <stop offset="95%" stopColor="#ef4444" stopOpacity={0.1}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
            <XAxis dataKey="date" stroke="#9ca3af" fontSize={12} />
            <YAxis stroke="#9ca3af" fontSize={12} />
            <Tooltip 
              contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151' }}
              labelStyle={{ color: '#9ca3af' }}
            />
            <Legend />
            
            {/* Historical data */}
            <Area 
              type="monotone" 
              dataKey="actual_total" 
              stroke="#3b82f6" 
              fillOpacity={1} 
              fill="url(#colorTotal)" 
              name="Actual Total"
              strokeWidth={2}
            />
            <Area 
              type="monotone" 
              dataKey="actual_critical" 
              stroke="#ef4444" 
              fillOpacity={1} 
              fill="url(#colorCritical)" 
              name="Actual Critical"
              strokeWidth={2}
            />
            
            {/* Forecast data */}
            <Line 
              type="monotone" 
              dataKey="predicted_total" 
              stroke="#a78bfa" 
              strokeDasharray="5 5"
              name="Predicted Total"
              strokeWidth={2}
              dot={{ fill: '#a78bfa' }}
            />
            <Line 
              type="monotone" 
              dataKey="predicted_critical" 
              stroke="#fbbf24" 
              strokeDasharray="5 5"
              name="Predicted Critical"
              strokeWidth={2}
              dot={{ fill: '#fbbf24' }}
            />
            
            {/* Confidence bounds */}
            <Area
              type="monotone"
              dataKey="upper_bound"
              stroke="none"
              fill="#6366f1"
              fillOpacity={0.1}
              name="Upper Bound"
            />
            <Area
              type="monotone"
              dataKey="lower_bound"
              stroke="none"
              fill="#6366f1"
              fillOpacity={0.1}
              name="Lower Bound"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Likely Attack Vectors */}
      <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-orange-400" />
          Predicted Attack Vectors
        </h3>
        <div className="space-y-3">
          {likely_attack_vectors.slice(0, 5).map((vector, index) => (
            <div key={index} className="bg-gray-900/50 rounded-lg p-4 border border-gray-700">
              <div className="flex justify-between items-start mb-2">
                <div>
                  <h4 className="font-semibold text-white">{vector.attack_type}</h4>
                  <p className="text-sm text-gray-400 mt-1">Probability: {(vector.probability * 100).toFixed(1)}%</p>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium ${
                  vector.likelihood === 'High' ? 'bg-red-900/50 text-red-400' :
                  vector.likelihood === 'Medium' ? 'bg-orange-900/50 text-orange-400' :
                  'bg-yellow-900/50 text-yellow-400'
                }`}>
                  {vector.likelihood} Risk
                </span>
              </div>
              <p className="text-sm text-gray-300">{vector.recommended_action}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Proactive Recommendations */}
      <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-6">
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-green-400" />
          Proactive Security Recommendations
        </h3>
        <div className="space-y-3">
          {recommendations.map((rec, index) => (
            <div key={index} className={`rounded-lg p-4 border ${
              rec.priority === 'CRITICAL' ? 'bg-red-900/20 border-red-500/50' :
              rec.priority === 'HIGH' ? 'bg-orange-900/20 border-orange-500/50' :
              'bg-blue-900/20 border-blue-500/50'
            }`}>
              <div className="flex items-start gap-3">
                <div className={`px-2 py-1 rounded text-xs font-bold ${
                  rec.priority === 'CRITICAL' ? 'bg-red-600 text-white' :
                  rec.priority === 'HIGH' ? 'bg-orange-600 text-white' :
                  'bg-blue-600 text-white'
                }`}>
                  {rec.priority}
                </div>
                <div className="flex-1">
                  <p className="font-semibold text-white">{rec.action}</p>
                  <p className="text-sm text-gray-400 mt-1">{rec.reason}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Risk Progression Indicator */}
      <div className="bg-gradient-to-r from-red-900/20 to-orange-900/20 backdrop-blur-sm rounded-lg p-6 border border-red-500/20">
        <h3 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Clock className="w-5 h-5 text-red-400" />
          Risk Score Progression
        </h3>
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-gray-400 mb-1">Current Average Risk</p>
            <p className={`text-3xl font-bold ${getRiskColor(risk_progression.current)}`}>
              {risk_progression.current.toFixed(1)}
            </p>
          </div>
          <div className="text-center">
            <div className="flex items-center gap-2 text-2xl">
              {risk_progression.trend === 'increasing' ? (
                <TrendingUp className="w-8 h-8 text-red-400" />
              ) : risk_progression.trend === 'decreasing' ? (
                <TrendingDown className="w-8 h-8 text-green-400" />
              ) : (
                <Minus className="w-8 h-8 text-yellow-400" />
              )}
            </div>
            <p className="text-sm text-gray-400 mt-2">
              {risk_progression.change_rate > 0 ? '+' : ''}{risk_progression.change_rate.toFixed(1)} change
            </p>
          </div>
          <div>
            <p className="text-sm text-gray-400 mb-1">Predicted Risk Score</p>
            <p className={`text-3xl font-bold ${getRiskColor(risk_progression.predicted)}`}>
              {risk_progression.predicted.toFixed(1)}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ForecastingPanel;