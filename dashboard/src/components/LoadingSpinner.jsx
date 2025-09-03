import React from 'react';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Activity, Lock } from 'lucide-react';

const LoadingSpinner = ({ message = "Loading Security Dashboard..." }) => {
  const icons = [Shield, AlertTriangle, Activity, Lock];
  
  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center">
      <div className="text-center">
        <div className="relative mb-8">
          {/* Outer rotating ring */}
          <div className="w-24 h-24 border-4 border-red-500/20 border-t-red-500 rounded-full animate-spin"></div>
          
          {/* Inner pulsing icons */}
          <div className="absolute inset-0 flex items-center justify-center">
            <motion.div
              animate={{ 
                scale: [1, 1.2, 1],
                rotate: [0, 180, 360],
              }}
              transition={{ 
                duration: 2, 
                repeat: Infinity,
                ease: "easeInOut"
              }}
              className="p-3 rounded-full bg-red-500/20 glow-red"
            >
              <Shield className="w-6 h-6 text-red-400" />
            </motion.div>
          </div>
          
          {/* Floating icons around the spinner */}
          {icons.map((Icon, index) => (
            <motion.div
              key={index}
              className="absolute w-8 h-8"
              animate={{
                x: [0, Math.cos(index * 90 * Math.PI / 180) * 40],
                y: [0, Math.sin(index * 90 * Math.PI / 180) * 40],
                rotate: [0, 360],
                opacity: [0.3, 0.8, 0.3],
              }}
              transition={{
                duration: 3,
                repeat: Infinity,
                delay: index * 0.5,
                ease: "easeInOut"
              }}
              style={{
                left: '50%',
                top: '50%',
                marginLeft: '-16px',
                marginTop: '-16px'
              }}
            >
              <Icon className="w-4 h-4 text-orange-400" />
            </motion.div>
          ))}
        </div>
        
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          <p className="text-white text-lg font-medium mb-2">{message}</p>
          <p className="text-gray-400 text-sm">Initializing threat analysis systems</p>
          
          <div className="mt-4 flex items-center justify-center space-x-1">
            {[...Array(3)].map((_, i) => (
              <motion.div
                key={i}
                className="w-2 h-2 bg-red-400 rounded-full"
                animate={{
                  scale: [1, 1.5, 1],
                  opacity: [0.5, 1, 0.5],
                }}
                transition={{
                  duration: 1,
                  repeat: Infinity,
                  delay: i * 0.2,
                }}
              />
            ))}
          </div>
        </motion.div>
        
        {/* Status messages */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
          className="mt-6 space-y-2 text-xs text-gray-500"
        >
          <div>Connecting to threat intelligence feeds...</div>
          <div>Processing security event data...</div>
          <div>Calibrating anomaly detection algorithms...</div>
        </motion.div>
      </div>
    </div>
  );
};

export default LoadingSpinner;