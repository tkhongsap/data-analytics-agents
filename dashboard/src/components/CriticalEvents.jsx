import React from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, Clock, User, Monitor, Activity } from 'lucide-react';
import { format } from 'date-fns';

const SeverityBadge = ({ severity }) => {
  const colors = {
    Critical: 'bg-red-500/20 text-red-400 border-red-500/30 glow-red',
    High: 'bg-orange-500/20 text-orange-400 border-orange-500/30 glow-orange',
    Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    Low: 'bg-green-500/20 text-green-400 border-green-500/30'
  };

  return (
    <span className={`px-2 py-1 text-xs font-semibold rounded-full border ${colors[severity] || colors.Medium}`}>
      {severity}
    </span>
  );
};

const RiskScore = ({ score }) => {
  const getColor = (score) => {
    if (score >= 70) return 'text-red-400';
    if (score >= 50) return 'text-orange-400';
    if (score >= 30) return 'text-yellow-400';
    return 'text-green-400';
  };

  return (
    <div className="flex items-center space-x-1">
      <Activity className="w-3 h-3" />
      <span className={`font-bold ${getColor(score)}`}>
        {score.toFixed(1)}
      </span>
    </div>
  );
};

const CriticalEvents = ({ data, title = "Critical Security Events" }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.8 }}
      className="glass-card p-6 col-span-full"
    >
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-red-500/20 glow-red">
            <AlertTriangle className="w-5 h-5 text-red-400" />
          </div>
          <h2 className="text-xl font-bold text-white">{title}</h2>
        </div>
        <div className="text-sm text-gray-400">
          Real-time monitoring
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-white/10">
              <th className="text-left py-3 px-4 text-gray-400 font-medium">Time</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium">User</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium">Host</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium">Event</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium">Risk</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium">Severity</th>
              <th className="text-left py-3 px-4 text-gray-400 font-medium">Description</th>
            </tr>
          </thead>
          <tbody>
            {data.map((event, index) => (
              <motion.tr
                key={event.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: 1 + index * 0.1 }}
                className="border-b border-white/5 hover:bg-white/5 transition-all duration-200"
              >
                <td className="py-3 px-4">
                  <div className="flex items-center space-x-2 text-gray-300">
                    <Clock className="w-3 h-3" />
                    <span className="text-xs font-mono">
                      {format(event.timestamp, 'HH:mm:ss')}
                    </span>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center space-x-2">
                    <User className="w-3 h-3 text-blue-400" />
                    <span className="text-white font-medium text-sm">
                      {event.user}
                    </span>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <div className="flex items-center space-x-2">
                    <Monitor className="w-3 h-3 text-purple-400" />
                    <span className="text-gray-300 text-sm">
                      {event.host}
                    </span>
                  </div>
                </td>
                <td className="py-3 px-4">
                  <span className="text-cyan-400 text-sm font-medium">
                    {event.event}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <RiskScore score={event.risk_score} />
                </td>
                <td className="py-3 px-4">
                  <SeverityBadge severity={event.severity} />
                </td>
                <td className="py-3 px-4 max-w-xs">
                  <p className="text-gray-300 text-sm truncate">
                    {event.description}
                  </p>
                </td>
              </motion.tr>
            ))}
          </tbody>
        </table>
      </div>

      {data.length === 0 && (
        <div className="text-center py-8">
          <div className="text-gray-500 text-sm">No critical events detected</div>
        </div>
      )}
      
      {/* Pulsing border effect for critical events */}
      <div className="absolute inset-0 rounded-2xl border border-red-500/20 animate-pulse pointer-events-none"></div>
    </motion.div>
  );
};

export default CriticalEvents;