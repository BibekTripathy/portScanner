import os

content = """import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import SystemMetrics from '../components/SystemMetrics';
import ProcessList from '../components/ProcessList';
import DockerStatus from '../components/DockerStatus';
import { ArrowLeft } from 'lucide-react';
import '../index.css';
import SplitPane from '../components/SplitPane';
import { useTheme } from '../hooks/useTheme';

function Stats() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');
  const [pollingInterval, setPollingInterval] = useState(3000);
  const { darkMode, toggleTheme } = useTheme();

  // Auth check
  const backendUrl = localStorage.getItem('backendUrl');
  const token = localStorage.getItem('authToken');

  useEffect(() => {
    if (!backendUrl) navigate('/setup');
    if (!token) navigate('/login');
  }, [backendUrl, token, navigate]);

  return (
    <div className="min-h-screen p-4 md:p-8 transition-colors duration-300 bg-[#87CEEB] dark:bg-[#040d1a] text-black dark:text-white">
      {/* Header */}
      <header className="mb-4 flex justify-between items-start text-white">
        <div className="flex flex-col gap-2">
          <button onClick={() => navigate('/')} className="flex items-center gap-2 text-sm text-white/80 hover:text-white transition-colors w-fit mb-2">
            <ArrowLeft size={16} /> Back to Home
          </button>
          
          <div className="flex items-center gap-3 mb-1">
            <h1 className="text-4xl font-bold tracking-tight text-white">
              System Monitor
            </h1>
          </div>
        </div>
        
        {/* Controls */}
        <div className="flex items-center gap-4 mt-8">
          <button
            onClick={toggleTheme}
            className="p-2 rounded-full shadow-sm transition-colors text-slate-800 dark:text-slate-200 bg-white dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700"
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle theme"
          >
            {!darkMode ? (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
              </svg>
            ) : (
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="5"></circle>
                <line x1="12" y1="1" x2="12" y2="3"></line>
                <line x1="12" y1="21" x2="12" y2="23"></line>
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
                <line x1="1" y1="12" x2="3" y2="12"></line>
                <line x1="21" y1="12" x2="23" y2="12"></line>
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
              </svg>
            )}
          </button>

          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-white/90">REFRESH:</span>
            <select
              value={pollingInterval === null ? 'paused' : pollingInterval.toString()}
              onChange={(e) => setPollingInterval(e.target.value === 'paused' ? null : parseInt(e.target.value))}
              className="text-xs rounded px-2 py-1 border cursor-pointer outline-none transition-colors bg-white/20 dark:bg-black/20 text-white border-white/30 hover:bg-white/30 dark:hover:bg-black/40"
            >
              <option value="1000">1s</option>
              <option value="3000">3s</option>
              <option value="5000">5s</option>
              <option value="10000">10s</option>
              <option value="paused">Paused</option>
            </select>
          </div>
        </div>
      </header>

      {/* Dashboard Content */}
      <SplitPane>
        <div className="h-full pr-2">
          <SystemMetrics pollingInterval={pollingInterval} />
        </div>
        <div className="h-full flex flex-col pl-2">
          {/* Tabs */}
          <div className="flex gap-2 mb-4">
            <button 
              onClick={() => setActiveTab('overview')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'overview' ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 shadow-sm border border-slate-200 dark:border-slate-700' : 'text-slate-600 dark:text-slate-400 hover:bg-white/50 dark:hover:bg-slate-800/50 border border-transparent'}`}
            >
              Processes
            </button>
            <button 
              onClick={() => setActiveTab('docker')}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'docker' ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 shadow-sm border border-slate-200 dark:border-slate-700' : 'text-slate-600 dark:text-slate-400 hover:bg-white/50 dark:hover:bg-slate-800/50 border border-transparent'}`}
            >
              Docker
            </button>
          </div>
          
          <div className="flex-1 min-h-0">
            {activeTab === 'overview' ? <ProcessList pollingInterval={pollingInterval} /> : <DockerStatus pollingInterval={pollingInterval} />}
          </div>
        </div>
      </SplitPane>
    </div>
  );
}

export default Stats;
"""

with open('frontend/src/pages/Stats.jsx', 'w') as f:
    f.write(content)

