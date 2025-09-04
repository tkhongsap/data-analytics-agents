import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  AlertTriangle, 
  Users, 
  Server, 
  Activity, 
  Eye,
  Wifi,
  Clock,
  Home,
  FileText,
  BarChart3,
  TrendingUp
} from 'lucide-react';

// Components
import MetricsCard from './components/MetricsCard';
import TimelineChart from './components/TimelineChart';
import RiskDistribution from './components/RiskDistribution';
import TopThreats from './components/TopThreats';
import CriticalEvents from './components/CriticalEvents';
import LogsViewer from './components/LogsViewer';
import ForecastingPanel from './components/ForecastingPanel';

// Utils
import { loadCyberData } from './utils/dataLoader';

function App() {
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());
  const [connectionStatus, setConnectionStatus] = useState('Connected');
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const loadData = async () => {
      try {
        const data = await loadCyberData();
        setDashboardData(data);
      } catch (error) {
        console.error('Error loading dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();

    // Update time every second
    const timeInterval = setInterval(() => {
      setCurrentTime(new Date());
    }, 1000);

    // Simulate connection status updates
    const statusInterval = setInterval(() => {
      const statuses = ['Connected', 'Monitoring', 'Analyzing'];
      setConnectionStatus(statuses[Math.floor(Math.random() * statuses.length)]);
    }, 3000);

    return () => {
      clearInterval(timeInterval);
      clearInterval(statusInterval);
    };
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center"
        >
          <div className="relative">
            <div className="w-16 h-16 border-4 border-red-500/30 border-t-red-500 rounded-full animate-spin"></div>
            <Shield className="absolute inset-0 m-auto w-6 h-6 text-red-400" />
          </div>
          <p className="text-white mt-4 text-lg font-medium">Loading Security Dashboard...</p>
          <p className="text-gray-400 mt-2 text-sm">Initializing threat analysis systems</p>
        </motion.div>
      </div>
    );
  }

  const { metrics, timelineData, riskDistribution, topThreats, criticalEvents } = dashboardData;

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
      {/* Header */}
      <motion.header
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="border-b border-white/10 backdrop-blur-md bg-black/20 sticky top-0 z-50"
      >
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-3">
                <div className="p-2 rounded-xl bg-gradient-to-r from-red-500/20 to-red-600/20 glow-red">
                  <Shield className="w-6 h-6 text-red-400" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold bg-gradient-to-r from-white to-gray-300 bg-clip-text text-transparent">
                    Cybersecurity SOC Dashboard
                  </h1>
                  <p className="text-gray-400 text-sm">Real-time threat monitoring and analysis</p>
                </div>
              </div>
            </div>
            
            <div className="flex items-center space-x-6">
              <div className="flex items-center space-x-2">
                <Wifi className="w-4 h-4 text-green-400" />
                <span className="text-green-400 text-sm font-medium">{connectionStatus}</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-300">
                <Clock className="w-4 h-4" />
                <span className="text-sm font-mono">
                  {currentTime.toLocaleTimeString()}
                </span>
              </div>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-green-400 text-sm font-medium">Live</span>
              </div>
            </div>
          </div>
          
          {/* Navigation Tabs */}
          <div className="flex items-center space-x-1 mt-4">
            <button
              onClick={() => setActiveTab('overview')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                activeTab === 'overview'
                  ? 'bg-gradient-to-r from-blue-500/20 to-blue-600/20 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-slate-800/30'
              }`}
            >
              <Home className="w-4 h-4" />
              Overview
            </button>
            <button
              onClick={() => setActiveTab('forecast')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                activeTab === 'forecast'
                  ? 'bg-gradient-to-r from-purple-500/20 to-purple-600/20 text-purple-400 border border-purple-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-slate-800/30'
              }`}
            >
              <TrendingUp className="w-4 h-4" />
              Forecasting
            </button>
            <button
              onClick={() => setActiveTab('logs')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                activeTab === 'logs'
                  ? 'bg-gradient-to-r from-blue-500/20 to-blue-600/20 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-slate-800/30'
              }`}
            >
              <FileText className="w-4 h-4" />
              Logs Analysis
            </button>
            <button
              onClick={() => setActiveTab('analytics')}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                activeTab === 'analytics'
                  ? 'bg-gradient-to-r from-blue-500/20 to-blue-600/20 text-blue-400 border border-blue-500/30'
                  : 'text-gray-400 hover:text-white hover:bg-slate-800/30'
              }`}
            >
              <BarChart3 className="w-4 h-4" />
              Analytics
            </button>
          </div>
        </div>
      </motion.header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        <AnimatePresence mode="wait">
          {activeTab === 'overview' && (
            <motion.div
              key="overview"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.3 }}
              className="space-y-8"
            >
              {/* Key Metrics */}
              <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <MetricsCard
                  title="Critical Alerts"
                  value={metrics.criticalAlerts}
                  icon={AlertTriangle}
                  color="red"
                  trend={+12}
                />
                <MetricsCard
                  title="Anomaly Rate"
                  value={metrics.anomalyRate}
                  suffix="%"
                  icon={Activity}
                  color="orange"
                  trend={-3}
                  isPercentage={true}
                />
                <MetricsCard
                  title="Active Threats"
                  value={metrics.activeThreats}
                  suffix=" users"
                  icon={Users}
                  color="orange"
                  trend={+8}
                />
                <MetricsCard
                  title="Systems at Risk"
                  value={metrics.systemsAtRisk}
                  suffix=" hosts"
                  icon={Server}
                  color="red"
                  trend={+2}
                />
              </section>

              {/* Charts Section */}
              <section className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2">
                  <TimelineChart data={timelineData} />
                </div>
                <div>
                  <RiskDistribution data={riskDistribution} />
                </div>
              </section>

              {/* Threats and Analysis */}
              <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <TopThreats data={topThreats} />
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, delay: 1.0 }}
                  className="glass-card p-6 h-96"
                >
                  <div className="flex items-center space-x-3 mb-6">
                    <div className="p-2 rounded-lg bg-blue-500/20">
                      <Eye className="w-5 h-5 text-blue-400" />
                    </div>
                    <h2 className="text-xl font-bold text-white">Threat Intelligence</h2>
                  </div>
                  
                  <div className="space-y-4">
                    <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20">
                      <div className="flex items-center space-x-2 mb-2">
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        <span className="text-red-400 font-semibold text-sm">High Priority Alert</span>
                      </div>
                      <p className="text-gray-300 text-sm">
                        Unusual logon patterns detected from external IP addresses. 
                        Multiple failed authentication attempts followed by successful logins.
                      </p>
                    </div>
                    
                    <div className="p-4 rounded-lg bg-orange-500/10 border border-orange-500/20">
                      <div className="flex items-center space-x-2 mb-2">
                        <Activity className="w-4 h-4 text-orange-400" />
                        <span className="text-orange-400 font-semibold text-sm">Privilege Escalation</span>
                      </div>
                      <p className="text-gray-300 text-sm">
                        Service accounts gaining special privileges outside normal business hours.
                        Recommend immediate review of account permissions.
                      </p>
                    </div>
                    
                    <div className="p-4 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                      <div className="flex items-center space-x-2 mb-2">
                        <Server className="w-4 h-4 text-yellow-400" />
                        <span className="text-yellow-400 font-semibold text-sm">Process Anomaly</span>
                      </div>
                      <p className="text-gray-300 text-sm">
                        Unusual process execution patterns on domain controllers. 
                        Monitor for potential lateral movement attempts.
                      </p>
                    </div>
                  </div>
                </motion.div>
              </section>

              {/* Critical Events Table */}
              <section>
                <CriticalEvents data={criticalEvents} />
              </section>

              {/* Footer Stats */}
              <motion.footer
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.5, delay: 1.2 }}
                className="border-t border-white/10 pt-6 mt-8"
              >
                <div className="flex items-center justify-between text-sm text-gray-400">
                  <div className="flex items-center space-x-6">
                    <span>Total Events Processed: {dashboardData.totalEvents?.toLocaleString()}</span>
                    <span>Last Updated: {currentTime.toLocaleString()}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span>SOC Team Dashboard v2.1</span>
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                  </div>
                </div>
              </motion.footer>
            </motion.div>
          )}
          
          {activeTab === 'forecast' && (
            <motion.div
              key="forecast"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.3 }}
            >
              <ForecastingPanel data={dashboardData.allLogs || []} />
            </motion.div>
          )}
          
          {activeTab === 'logs' && (
            <motion.div
              key="logs"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.3 }}
            >
              <LogsViewer logs={dashboardData.allLogs || []} />
            </motion.div>
          )}
          
          {activeTab === 'analytics' && (
            <motion.div
              key="analytics"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.3 }}
              className="space-y-8"
            >
              <div className="glass-card p-6">
                <h2 className="text-2xl font-bold text-white mb-4">Advanced Analytics</h2>
                <p className="text-gray-400">Advanced analytics features coming soon...</p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
                  <div className="p-6 bg-slate-800/50 rounded-lg">
                    <h3 className="text-lg font-semibold text-blue-400 mb-2">Threat Prediction Model</h3>
                    <p className="text-gray-300 text-sm">ML-based threat prediction and anomaly forecasting</p>
                  </div>
                  <div className="p-6 bg-slate-800/50 rounded-lg">
                    <h3 className="text-lg font-semibold text-green-400 mb-2">Attack Pattern Analysis</h3>
                    <p className="text-gray-300 text-sm">MITRE ATT&CK framework mapping and analysis</p>
                  </div>
                  <div className="p-6 bg-slate-800/50 rounded-lg">
                    <h3 className="text-lg font-semibold text-yellow-400 mb-2">User Behavior Analytics</h3>
                    <p className="text-gray-300 text-sm">UEBA insights and baseline deviation tracking</p>
                  </div>
                  <div className="p-6 bg-slate-800/50 rounded-lg">
                    <h3 className="text-lg font-semibold text-purple-400 mb-2">Network Flow Analysis</h3>
                    <p className="text-gray-300 text-sm">East-west traffic patterns and lateral movement detection</p>
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Background Effects */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden">
        <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-red-500/5 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-1/4 right-1/4 w-64 h-64 bg-orange-500/5 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-1/2 left-1/2 w-32 h-32 bg-blue-500/5 rounded-full blur-2xl animate-pulse" style={{ animationDelay: '2s' }}></div>
      </div>
    </div>
  );
}

export default App;