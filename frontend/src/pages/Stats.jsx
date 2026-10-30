import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import SystemMetrics from '../components/SystemMetrics';
import ProcessList from '../components/ProcessList';
import DockerStatus from '../components/DockerStatus';
import { ArrowLeft } from 'lucide-react';
import '../index.css';
import { useTheme } from '../hooks/useTheme'; // ensure styles are applied if needed
import TargetSwitcher from '../components/TargetSwitcher';
import { useConnections } from '../hooks/useConnections';

function Stats() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');
  const [pollingInterval, setPollingInterval] = useState(3000);
  const { darkMode, toggleTheme } = useTheme();
  // `signature` changes when a different machine is selected; using it as a key below
  // discards the previous machine's readings instead of blending them.
  const { active, signature } = useConnections();

  return (
    <div className="min-h-screen p-4 md:p-8 transition-colors duration-300 bg-[#87CEEB] dark:bg-[#040d1a] text-black dark:text-white">
      {/* Header */}
            <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-8 bg-slate-100 dark:bg-slate-800 p-4 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 gap-4">
        <div className="flex items-center gap-4">
          <button 
            onClick={() => navigate('/')} 
            className="p-2 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-full transition-colors hidden sm:block text-slate-500 dark:text-slate-400"
            title="Back to Home"
          >
            <ArrowLeft size={20} />
          </button>
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-800 dark:text-slate-200">
              System Monitor
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">{active?.label}</p>
          </div>
        </div>
        
        {/* Controls */}
        <div className="flex items-center gap-3">
          <TargetSwitcher />
          <div className="flex items-center gap-2 bg-white dark:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600">
            <span className="text-sm font-medium text-slate-600 dark:text-slate-300">Auto-refresh:</span>
            <select
              value={pollingInterval === null ? 'paused' : pollingInterval.toString()}
              onChange={(e) => setPollingInterval(e.target.value === 'paused' ? null : parseInt(e.target.value))}
              className="text-sm bg-transparent outline-none cursor-pointer text-slate-700 dark:text-slate-200 font-medium"
            >
              <option value="1000">1s</option>
              <option value="3000">3s</option>
              <option value="5000">5s</option>
              <option value="10000">10s</option>
              <option value="paused">Off</option>
            </select>
          </div>

          <button
            onClick={toggleTheme}
            className="p-2 rounded-full bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors text-slate-500 dark:text-slate-400"
            title={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
            aria-label="Toggle theme"
          >
            {!darkMode ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>
              </svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
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
        </div>
      </header>

      {/* Tab Navigation */}
      <nav className="flex gap-2 mb-6 w-fit">
        {['overview', 'processes', 'docker'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-lg text-sm font-medium capitalize transition-all ${
              activeTab === tab
                ? 'bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 shadow-sm border border-slate-200 dark:border-slate-700'
                : 'text-slate-600 dark:text-slate-400 hover:bg-white/50 dark:hover:bg-slate-800/50 border border-transparent'
            }`}
          >
            {tab}
          </button>
        ))}
      </nav>

      {/* Content */}
      <main key={signature}>
        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-1">
              <SystemMetrics pollingInterval={pollingInterval} />
            </div>
            <div className="lg:col-span-2">
              <ProcessList compact pollingInterval={pollingInterval} />
            </div>
          </div>
        )}
        {activeTab === 'processes' && <ProcessList pollingInterval={pollingInterval} />}
        {activeTab === 'docker' && <DockerStatus pollingInterval={pollingInterval} />}
      </main>

      
    </div>
  );
}

export default Stats;
