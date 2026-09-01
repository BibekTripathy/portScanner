import { useState, useEffect } from 'react';
import { RefreshCw, Sun, Moon, ShieldAlert, Monitor } from 'lucide-react';

function App() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    // Check system preference
    if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setDarkMode(true);
    }
  }, []);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
  }, [darkMode]);

  const fetchScanData = async () => {
    setLoading(true);
    setError('');
    try {
      const response = await fetch('http://localhost:8000/api/scan');
      if (!response.ok) {
        throw new Error('Failed to fetch scan data');
      }
      const result = await response.json();
      setData(result.data || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScanData();
  }, []);

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 dark:bg-slate-900 dark:text-slate-300 transition-colors duration-200">
      <div className="max-w-6xl mx-auto p-6">
        <header className="flex justify-between items-center mb-8 bg-slate-100 dark:bg-slate-800 p-4 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700">
          <div className="flex items-center gap-3">
            <Monitor className="text-indigo-500 dark:text-indigo-400" size={28} />
            <h1 className="text-2xl font-medium tracking-tight">Port Scanner</h1>
          </div>
          
          <div className="flex items-center gap-4">
            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-full hover:bg-slate-200 dark:hover:bg-slate-700 transition-colors text-slate-500 dark:text-slate-400"
              title="Toggle Light/Dark Mode"
            >
              {darkMode ? <Sun size={20} /> : <Moon size={20} />}
            </button>
            <button 
              onClick={fetchScanData}
              disabled={loading}
              className="flex items-center gap-2 bg-indigo-500 hover:bg-indigo-600 dark:bg-indigo-600 dark:hover:bg-indigo-700 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-70 font-medium"
            >
              <RefreshCw size={18} className={loading ? 'animate-spin' : ''} />
              {loading ? 'Scanning...' : 'Scan Now'}
            </button>
          </div>
        </header>

        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 p-4 rounded-xl mb-6 flex items-center gap-3 border border-red-100 dark:border-red-900/50">
            <ShieldAlert size={20} />
            <p>{error}</p>
          </div>
        )}

        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-100 dark:bg-slate-700/50 text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700 text-sm">
                  <th className="p-4 font-medium">Protocol</th>
                  <th className="p-4 font-medium">Port</th>
                  <th className="p-4 font-medium">Service</th>
                  <th className="p-4 font-medium">IP</th>
                  <th className="p-4 font-medium">Scope</th>
                  <th className="p-4 font-medium">Process</th>
                  <th className="p-4 font-medium">User</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50 text-sm">
                {data.length === 0 && !loading ? (
                  <tr>
                    <td colSpan="7" className="p-8 text-center text-slate-500 dark:text-slate-400">
                      No listening ports found
                    </td>
                  </tr>
                ) : (
                  data.map((port, idx) => (
                    <tr key={`${port.port}-${idx}`} className="hover:bg-slate-50 dark:hover:bg-slate-700/25 transition-colors">
                      <td className="p-4 text-cyan-600 dark:text-cyan-400">{port.protocol}</td>
                      <td className="p-4 font-medium text-slate-700 dark:text-slate-200">{port.port}</td>
                      <td className="p-4 text-emerald-600 dark:text-emerald-400">{port.service_guess}</td>
                      <td className="p-4 font-mono text-xs text-slate-500 dark:text-slate-400">{port.ip}</td>
                      <td className="p-4">
                        <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                          port.scope === 'localhost' 
                            ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' 
                            : 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400'
                        }`}>
                          {port.scope}
                        </span>
                      </td>
                      <td className="p-4 text-fuchsia-600 dark:text-fuchsia-400">{port.process_name || 'Unknown'}</td>
                      <td className="p-4 text-amber-600 dark:text-amber-400">{port.process_user || port.username || 'Unknown'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {data.length > 0 && (
            <div className="p-4 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700 text-xs text-slate-500 dark:text-slate-400 flex justify-between">
              <span>Found {data.length} listening ports</span>
              <span>Last scanned: {new Date().toLocaleTimeString()}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
