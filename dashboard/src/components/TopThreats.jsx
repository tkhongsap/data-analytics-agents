import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip } from 'recharts';
import { motion } from 'framer-motion';

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass-card p-4 border border-white/20 shadow-2xl">
        <p className="text-white font-medium">{label}</p>
        <div className="flex items-center space-x-2 mt-2">
          <div className="w-3 h-3 rounded-full bg-gradient-to-r from-red-500 to-orange-500" />
          <span className="text-gray-300">
            Events: <span className="text-white font-semibold">{payload[0].value}</span>
          </span>
        </div>
      </div>
    );
  }
  return null;
};

const TopThreats = ({ data, title = "Top Security Threats" }) => {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.6 }}
      className="glass-card p-6 h-96"
    >
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-white">{title}</h2>
        <div className="text-sm text-gray-400">
          Last 24 hours
        </div>
      </div>
      
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          layout="horizontal"
          margin={{ top: 5, right: 30, left: 80, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
          <XAxis 
            type="number"
            stroke="rgba(255,255,255,0.6)"
            fontSize={12}
            tickLine={false}
          />
          <YAxis 
            type="category"
            dataKey="name"
            stroke="rgba(255,255,255,0.6)"
            fontSize={12}
            tickLine={false}
            width={75}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar
            dataKey="count"
            fill="url(#threatGradient)"
            radius={[0, 4, 4, 0]}
            animationDuration={1000}
            animationBegin={200}
          >
          </Bar>
          <defs>
            <linearGradient id="threatGradient" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#ef4444" stopOpacity={0.8} />
              <stop offset="50%" stopColor="#fb923c" stopOpacity={0.8} />
              <stop offset="100%" stopColor="#fbbf24" stopOpacity={0.8} />
            </linearGradient>
          </defs>
        </BarChart>
      </ResponsiveContainer>
      
      {/* Glow effect */}
      <div className="absolute inset-0 rounded-2xl opacity-10 bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 animate-pulse pointer-events-none"></div>
    </motion.div>
  );
};

export default TopThreats;