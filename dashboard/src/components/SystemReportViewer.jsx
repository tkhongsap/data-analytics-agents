import React, { useState, useEffect } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { motion } from 'framer-motion';
import { Shield, AlertTriangle, Loader } from 'lucide-react';

const SystemReportViewer = () => {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const loadReport = async () => {
      try {
        const response = await fetch('/SYSTEM_ACCOUNTS_SECURITY_REPORT.md');
        if (!response.ok) {
          throw new Error('Failed to load report');
        }
        const text = await response.text();
        setContent(text);
      } catch (err) {
        setError(err.message);
        console.error('Error loading system report:', err);
      } finally {
        setLoading(false);
      }
    };

    loadReport();
  }, []);

  if (loading) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="flex items-center justify-center min-h-[600px]"
      >
        <div className="flex items-center space-x-3">
          <Loader className="w-6 h-6 text-blue-400 animate-spin" />
          <span className="text-gray-300">Loading System Security Report...</span>
        </div>
      </motion.div>
    );
  }

  if (error) {
    return (
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="glass-card p-8 text-center"
      >
        <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
        <h3 className="text-xl font-semibold text-red-400 mb-2">Error Loading Report</h3>
        <p className="text-gray-400">{error}</p>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="space-y-6"
    >
      {/* Header */}
      <div className="glass-card p-6">
        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2 rounded-lg bg-gradient-to-r from-red-500/20 to-red-600/20">
            <Shield className="w-6 h-6 text-red-400" />
          </div>
          <h2 className="text-2xl font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent">
            System Accounts Security Report
          </h2>
        </div>
        <p className="text-gray-400">
          Comprehensive analysis of system and service account anomalies, threats, and security incidents
        </p>
      </div>

      {/* Report Content */}
      <div className="glass-card p-8 prose prose-invert max-w-none">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            // Custom styling for markdown elements
            h1: ({children}) => (
              <h1 className="text-3xl font-bold text-white mb-6 pb-3 border-b border-gray-700">{children}</h1>
            ),
            h2: ({children}) => (
              <h2 className="text-2xl font-bold text-blue-400 mt-8 mb-4">{children}</h2>
            ),
            h3: ({children}) => (
              <h3 className="text-xl font-semibold text-blue-300 mt-6 mb-3">{children}</h3>
            ),
            p: ({children}) => (
              <p className="text-gray-300 mb-4 leading-relaxed">{children}</p>
            ),
            ul: ({children}) => (
              <ul className="list-disc list-inside text-gray-300 mb-4 space-y-2">{children}</ul>
            ),
            ol: ({children}) => (
              <ol className="list-decimal list-inside text-gray-300 mb-4 space-y-2">{children}</ol>
            ),
            li: ({children}) => (
              <li className="text-gray-300">{children}</li>
            ),
            strong: ({children}) => (
              <strong className="text-white font-semibold">{children}</strong>
            ),
            em: ({children}) => (
              <em className="text-gray-200 italic">{children}</em>
            ),
            blockquote: ({children}) => (
              <blockquote className="border-l-4 border-blue-500 pl-4 my-4 text-gray-300 italic">{children}</blockquote>
            ),
            code: ({inline, children}) => 
              inline ? (
                <code className="bg-slate-800 text-blue-300 px-2 py-1 rounded text-sm">{children}</code>
              ) : (
                <code className="block bg-slate-900 text-green-300 p-4 rounded-lg overflow-x-auto my-4">{children}</code>
              ),
            pre: ({children}) => (
              <pre className="bg-slate-900 rounded-lg overflow-x-auto my-4">{children}</pre>
            ),
            table: ({children}) => (
              <div className="overflow-x-auto my-6">
                <table className="w-full border-collapse border border-gray-600">{children}</table>
              </div>
            ),
            thead: ({children}) => (
              <thead className="bg-slate-800">{children}</thead>
            ),
            tbody: ({children}) => (
              <tbody className="divide-y divide-gray-700">{children}</tbody>
            ),
            tr: ({children}) => (
              <tr className="hover:bg-slate-800/50 transition-colors">{children}</tr>
            ),
            th: ({children}) => (
              <th className="border border-gray-600 px-4 py-3 text-left font-semibold text-blue-400">{children}</th>
            ),
            td: ({children}) => (
              <td className="border border-gray-600 px-4 py-3 text-gray-300">{children}</td>
            ),
            hr: () => (
              <hr className="border-gray-700 my-8" />
            ),
            a: ({children, href}) => (
              <a href={href} className="text-blue-400 hover:text-blue-300 underline" target="_blank" rel="noopener noreferrer">
                {children}
              </a>
            ),
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    </motion.div>
  );
};

export default SystemReportViewer;