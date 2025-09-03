import React from 'react';
import { motion } from 'framer-motion';
import CountUp from 'react-countup';

const MetricsCard = ({ title, value, suffix = '', icon: Icon, color = 'red', trend, isPercentage = false }) => {
  const colorClasses = {
    red: 'glow-red pulse-red border-red-500/20',
    orange: 'glow-orange pulse-orange border-orange-500/20',
    green: 'glow-green pulse-green border-green-500/20',
    blue: 'border-blue-500/20'
  };

  const iconColors = {
    red: 'text-red-400',
    orange: 'text-orange-400',
    green: 'text-green-400',
    blue: 'text-blue-400'
  };

  const textColors = {
    red: 'text-red-400',
    orange: 'text-orange-400',
    green: 'text-green-400',
    blue: 'text-blue-400'
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className={`glass-card p-6 ${colorClasses[color]} transition-all duration-300 hover:scale-105`}
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-xl bg-gradient-to-r ${
          color === 'red' ? 'from-red-500/20 to-red-600/20' :
          color === 'orange' ? 'from-orange-500/20 to-orange-600/20' :
          color === 'green' ? 'from-green-500/20 to-green-600/20' :
          'from-blue-500/20 to-blue-600/20'
        }`}>
          <Icon className={`w-6 h-6 ${iconColors[color]}`} />
        </div>
        {trend && (
          <div className={`text-xs px-2 py-1 rounded-full ${
            trend > 0 ? 'bg-red-500/20 text-red-300' : 'bg-green-500/20 text-green-300'
          }`}>
            {trend > 0 ? '+' : ''}{trend}%
          </div>
        )}
      </div>
      
      <div className="space-y-1">
        <h3 className="text-gray-400 text-sm font-medium tracking-wide uppercase">
          {title}
        </h3>
        <div className={`text-3xl font-bold ${textColors[color]} tracking-tight`}>
          <CountUp
            end={value}
            duration={2}
            separator=","
            suffix={suffix}
            decimals={isPercentage ? 1 : 0}
          />
        </div>
      </div>
      
      {/* Animated background gradient */}
      <div className={`absolute inset-0 rounded-2xl opacity-5 bg-gradient-to-br ${
        color === 'red' ? 'from-red-500 to-red-600' :
        color === 'orange' ? 'from-orange-500 to-orange-600' :
        color === 'green' ? 'from-green-500 to-green-600' :
        'from-blue-500 to-blue-600'
      } animate-pulse`}></div>
    </motion.div>
  );
};

export default MetricsCard;