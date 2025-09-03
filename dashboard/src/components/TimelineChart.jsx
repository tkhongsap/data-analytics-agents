import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { motion } from 'framer-motion';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass-card p-4 border border-white/20 shadow-2xl">
        <p className="text-white font-medium mb-2">{label}</p>
        {payload.map((entry, index) => (
          <div key={index} className="flex items-center space-x-2 mb-1">
            <div 
              className="w-3 h-3 rounded-full" 
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-gray-300 text-sm">
              {entry.name}: <span className="text-white font-semibold">{entry.value}</span>
            </span>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

const TimelineChart = ({ data, title = "Security Event Timeline" }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.2 }}
      className="glass-card p-6 h-96"
    >
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-white">{title}</h2>
        <div className="flex items-center space-x-4 text-sm">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-red-400"></div>
            <span className="text-gray-300">Critical</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-orange-400"></div>
            <span className="text-gray-300">High</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-yellow-400"></div>
            <span className="text-gray-300">Medium</span>
          </div>
        </div>
      </div>
      
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis 
            dataKey="date" 
            stroke="rgba(255,255,255,0.6)"
            fontSize={12}
            tickLine={false}
          />
          <YAxis 
            stroke="rgba(255,255,255,0.6)"
            fontSize={12}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend 
            wrapperStyle={{ color: 'rgba(255,255,255,0.8)' }}
            iconType="circle"
          />
          <Line
            type="monotone"
            dataKey="critical"
            stroke="#ef4444"
            strokeWidth={3}
            dot={{ fill: '#ef4444', strokeWidth: 2, r: 5 }}
            activeDot={{ r: 8, stroke: '#ef4444', strokeWidth: 2, fill: '#fee2e2' }}
            name="Critical Events"
          />
          <Line
            type="monotone"
            dataKey="high"
            stroke="#fb923c"
            strokeWidth={2}
            dot={{ fill: '#fb923c', strokeWidth: 2, r: 4 }}
            activeDot={{ r: 6, stroke: '#fb923c', strokeWidth: 2, fill: '#fed7aa' }}
            name="High Risk Events"
          />
          <Line
            type="monotone"
            dataKey="medium"
            stroke="#fbbf24"
            strokeWidth={2}
            dot={{ fill: '#fbbf24', strokeWidth: 2, r: 3 }}
            activeDot={{ r: 5, stroke: '#fbbf24', strokeWidth: 2, fill: '#fef3c7' }}
            name="Medium Risk Events"
          />
        </LineChart>
      </ResponsiveContainer>
    </motion.div>
  );
};

export default TimelineChart;