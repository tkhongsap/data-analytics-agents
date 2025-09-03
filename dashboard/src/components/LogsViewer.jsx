import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Search, 
  Filter, 
  ChevronDown, 
  ChevronUp,
  AlertTriangle,
  Shield,
  Activity,
  Eye,
  Download,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

const LogsViewer = ({ logs }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('all');
  const [selectedPriority, setSelectedPriority] = useState('all');
  const [expandedRow, setExpandedRow] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 15;

  // Filter logs based on search and filters
  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      const matchesSearch = 
        searchTerm === '' ||
        log.username?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.detailed_description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        log.event_description?.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesType = 
        selectedType === 'all' || 
        log.anomaly_type === selectedType;

      const matchesPriority = 
        selectedPriority === 'all' || 
        log.investigation_priority?.toString() === selectedPriority;

      return matchesSearch && matchesType && matchesPriority;
    });
  }, [logs, searchTerm, selectedType, selectedPriority]);

  // Pagination
  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage);
  const startIndex = (currentPage - 1) * itemsPerPage;
  const paginatedLogs = filteredLogs.slice(startIndex, startIndex + itemsPerPage);

  const getPriorityColor = (priority) => {
    const colors = {
      5: 'text-red-400 bg-red-500/20',
      4: 'text-orange-400 bg-orange-500/20',
      3: 'text-yellow-400 bg-yellow-500/20',
      2: 'text-blue-400 bg-blue-500/20',
      1: 'text-green-400 bg-green-500/20'
    };
    return colors[priority] || 'text-gray-400 bg-gray-500/20';
  };

  const getTypeIcon = (type) => {
    const icons = {
      'Authentication': Shield,
      'Process': Activity,
      'Network': Eye,
      'Privilege': AlertTriangle
    };
    const Icon = icons[type] || Shield;
    return <Icon className="w-4 h-4" />;
  };

  const handleExport = () => {
    const csvContent = [
      ['Timestamp', 'User', 'Host', 'Event', 'Anomaly Type', 'Priority', 'Description'],
      ...filteredLogs.map(log => [
        log.timestamp,
        log.username,
        log.hostname,
        log.event_description,
        log.anomaly_type,
        log.investigation_priority,
        log.detailed_description
      ])
    ].map(row => row.join(',')).join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security_logs_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      className="space-y-6"
    >
      {/* Header and Filters */}
      <div className="glass-card p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-bold text-white">Security Logs Analysis</h2>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-4 py-2 bg-blue-500/20 hover:bg-blue-500/30 
                     text-blue-400 rounded-lg transition-colors"
          >
            <Download className="w-4 h-4" />
            Export CSV
          </button>
        </div>

        <div className="flex flex-wrap gap-4">
          {/* Search */}
          <div className="flex-1 min-w-[300px] relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search users, hosts, or descriptions..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-slate-800/50 border border-white/10 
                       rounded-lg text-white placeholder-gray-400 focus:outline-none 
                       focus:border-blue-400/50 focus:bg-slate-800"
            />
          </div>

          {/* Type Filter */}
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="px-4 py-2 bg-slate-800/50 border border-white/10 rounded-lg 
                     text-white focus:outline-none focus:border-blue-400/50"
          >
            <option value="all">All Types</option>
            <option value="Authentication">Authentication</option>
            <option value="Process">Process</option>
            <option value="Network">Network</option>
            <option value="Privilege">Privilege</option>
            <option value="Volume">Volume</option>
            <option value="Temporal">Temporal</option>
          </select>

          {/* Priority Filter */}
          <select
            value={selectedPriority}
            onChange={(e) => setSelectedPriority(e.target.value)}
            className="px-4 py-2 bg-slate-800/50 border border-white/10 rounded-lg 
                     text-white focus:outline-none focus:border-blue-400/50"
          >
            <option value="all">All Priorities</option>
            <option value="5">Critical (5)</option>
            <option value="4">High (4)</option>
            <option value="3">Medium (3)</option>
            <option value="2">Low (2)</option>
            <option value="1">Info (1)</option>
          </select>
        </div>

        <div className="text-sm text-gray-400">
          Showing {paginatedLogs.length} of {filteredLogs.length} logs
        </div>
      </div>

      {/* Logs Table */}
      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-800/50 border-b border-white/10">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Time
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  User
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Host
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Priority
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Event
                </th>
                <th className="px-6 py-3 text-center text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              <AnimatePresence mode="wait">
                {paginatedLogs.map((log, index) => (
                  <React.Fragment key={log.id || index}>
                    <motion.tr
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      exit={{ opacity: 0, x: 20 }}
                      transition={{ delay: index * 0.02 }}
                      className="hover:bg-slate-800/30 transition-colors cursor-pointer"
                      onClick={() => setExpandedRow(expandedRow === index ? null : index)}
                    >
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`text-sm ${log.username?.endsWith('$') ? 'text-blue-400' : 'text-white'}`}>
                          {log.username}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                        {log.hostname}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="flex items-center gap-2 text-sm text-gray-300">
                          {getTypeIcon(log.anomaly_type)}
                          {log.anomaly_type}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getPriorityColor(log.investigation_priority)}`}>
                          Priority {log.investigation_priority}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-gray-300">
                        <div className="max-w-xs truncate">
                          {log.event_description}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-center">
                        {expandedRow === index ? 
                          <ChevronUp className="w-4 h-4 text-gray-400 mx-auto" /> : 
                          <ChevronDown className="w-4 h-4 text-gray-400 mx-auto" />
                        }
                      </td>
                    </motion.tr>

                    {/* Expanded Row */}
                    <AnimatePresence>
                      {expandedRow === index && (
                        <motion.tr
                          initial={{ opacity: 0, height: 0 }}
                          animate={{ opacity: 1, height: 'auto' }}
                          exit={{ opacity: 0, height: 0 }}
                          transition={{ duration: 0.2 }}
                        >
                          <td colSpan="7" className="px-6 py-4 bg-slate-900/50">
                            <div className="space-y-4">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div>
                                  <h4 className="text-sm font-medium text-gray-400 mb-2">Detailed Description</h4>
                                  <p className="text-sm text-white whitespace-pre-wrap">
                                    {log.detailed_description}
                                  </p>
                                </div>
                                <div className="space-y-3">
                                  <div>
                                    <h4 className="text-sm font-medium text-gray-400 mb-2">Threat Indicators</h4>
                                    <p className="text-sm text-orange-400">
                                      {log.threat_indicators}
                                    </p>
                                  </div>
                                  <div>
                                    <h4 className="text-sm font-medium text-gray-400 mb-2">Attack Stage</h4>
                                    <p className="text-sm text-yellow-400">
                                      {log.attack_stage}
                                    </p>
                                  </div>
                                  <div>
                                    <h4 className="text-sm font-medium text-gray-400 mb-2">Recommended Action</h4>
                                    <p className="text-sm text-green-400">
                                      {log.recommended_action}
                                    </p>
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-center gap-4 text-xs text-gray-500">
                                <span>Event ID: {log.event_id}</span>
                                <span>Z-Score: {log.max_abs_z?.toFixed(2)}</span>
                                <span>Source IP: {log.source_ip || 'N/A'}</span>
                              </div>
                            </div>
                          </td>
                        </motion.tr>
                      )}
                    </AnimatePresence>
                  </React.Fragment>
                ))}
              </AnimatePresence>
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-6 py-3 bg-slate-800/30 border-t border-white/10">
            <button
              onClick={() => setCurrentPage(Math.max(1, currentPage - 1))}
              disabled={currentPage === 1}
              className="flex items-center gap-2 px-3 py-1 bg-slate-700/50 hover:bg-slate-700 
                       disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
              Previous
            </button>
            
            <span className="text-sm text-gray-400">
              Page {currentPage} of {totalPages}
            </span>
            
            <button
              onClick={() => setCurrentPage(Math.min(totalPages, currentPage + 1))}
              disabled={currentPage === totalPages}
              className="flex items-center gap-2 px-3 py-1 bg-slate-700/50 hover:bg-slate-700 
                       disabled:opacity-50 disabled:cursor-not-allowed rounded transition-colors"
            >
              Next
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>
    </motion.div>
  );
};

export default LogsViewer;