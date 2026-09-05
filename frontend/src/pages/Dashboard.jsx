import { useState, useEffect, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { RefreshCw, Sun, Moon, ShieldAlert, Monitor, ArrowUpDown, ArrowUp, ArrowDown, LogOut, ArrowLeft } from 'lucide-react';

function Dashboard() {
  const navigate = useNavigate();
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [error, setError] = useState('');
  const [lastScanned, setLastScanned] = useState(null);
  
  const [refreshInterval, setRefreshInterval] = useState(0);
  const [sortConfig, setSortConfig] = useState({ key: null, direction: 'asc' });

  const backendUrl = localStorage.getItem('backendUrl');
  const token = localStorage.getItem('authToken');

  useEffect(() => {
    if (!backendUrl) navigate('/setup');
    if (!token) navigate('/login');
  }, [backendUrl, token, navigate]);

  useEffect(() => {
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
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      const response = await fetch(`${backendUrl}/api/scan`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.status === 401) {
        // Token expired or invalid
        localStorage.removeItem('authToken');
        navigate('/login');
        return;
      }
      if (!response.ok) {
        throw new Error('Failed to fetch scan data');
      }
      const result = await response.json();
      setData(result.data || []);
      setLastScanned(new Date());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  // Initial fetch
  useEffect(() => {
    fetchScanData();
  }, []);

  // Auto-refresh logic
  useEffect(() => {
    let intervalId;
    if (refreshInterval > 0) {
      intervalId = setInterval(() => {
        fetchScanData();
      }, refreshInterval * 1000);
    }
    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [refreshInterval]);

  // Sorting logic
  const handleSort = (key) => {
    if (sortConfig.key === key) {
      if (sortConfig.direction === 'asc') {
        setSortConfig({ key, direction: 'desc' });
      } else if (sortConfig.direction === 'desc') {
        setSortConfig({ key: null, direction: 'asc' }); // Default state
      }
    } else {
      setSortConfig({ key, direction: 'asc' });
    }
  };

  const sortedData = useMemo(() => {
    let sortableItems = [...data];
    if (sortConfig.key) {
      sortableItems.sort((a, b) => {
        let aValue = a[sortConfig.key];
        let bValue = b[sortConfig.key];

        // Normalization for specific keys
        if (sortConfig.key === 'process_user') {
          aValue = aValue || a.username || 'Unknown';
          bValue = bValue || b.username || 'Unknown';
        }
        if (sortConfig.key === 'process_name') {
          aValue = aValue || 'Unknown';
          bValue = bValue || 'Unknown';
        }

        if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1;
        if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1;
        return 0;
      });
    }
    return sortableItems;
  }, [data, sortConfig]);

  const SortIcon = ({ columnKey }) => {
    if (sortConfig.key !== columnKey) return <ArrowUpDown size={14} className="text-slate-400" />;
    return sortConfig.direction === 'asc' ? <ArrowUp size={14} className="text-indigo-500" /> : <ArrowDown size={14} className="text-indigo-500" />;
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 dark:bg-slate-900 dark:text-slate-300 transition-colors duration-200">
      <div className="max-w-6xl mx-auto p-6">
        <header className="flex flex-col sm:flex-row sm:justify-between sm:items-center mb-8 bg-slate-100 dark:bg-slate-800 p-4 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 gap-4">
          <div className="flex items-center gap-4">
            <Link to="/" className="p-2 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-full transition-colors hidden sm:block">
              <ArrowLeft size={20} className="text-slate-500 dark:text-slate-400" />
            </Link>
            <div className="flex items-center gap-3">
              <Monitor className="text-indigo-500 dark:text-indigo-400" size={28} />
              <h1 className="text-2xl font-medium tracking-tight">Port Scanner</h1>
            </div>
          </div>
          
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400 bg-white dark:bg-slate-700 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 shadow-sm">
              <label htmlFor="autoRefresh" className="font-medium">Auto-refresh:</label>
              <select
                id="autoRefresh"
                value={refreshInterval}
                onChange={(e) => setRefreshInterval(Number(e.target.value))}
                className="bg-transparent border-none focus:outline-none focus:ring-0 cursor-pointer"
              >
                <option value={0}>Off</option>
                <option value={5}>Every 5s</option>
                <option value={10}>Every 10s</option>
                <option value={30}>Every 30s</option>
              </select>
            </div>

            <button 
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-full bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors text-slate-500 dark:text-slate-400"
              title="Toggle Light/Dark Mode"
            >
              {darkMode ? <Sun size={20} /> : <Moon size={20} />}
            </button>
            <button 
              onClick={() => {
                localStorage.removeItem('authToken');
                navigate('/login');
              }}
              className="p-2 rounded-full bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors text-slate-500 dark:text-slate-400"
              title="Logout"
            >
              <LogOut size={20} />
            </button>
            <button 
              onClick={fetchScanData}
              disabled={loading}
              className="flex items-center gap-2 bg-indigo-500 hover:bg-indigo-600 dark:bg-indigo-600 dark:hover:bg-indigo-700 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-70 shadow-sm font-medium"
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
            <table className="w-full text-left border-collapse min-w-[700px]">
              <thead>
                <tr className="bg-slate-100 dark:bg-slate-700/50 text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-700 text-sm select-none">
                  <th className="p-4 font-medium cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors group" onClick={() => handleSort('protocol')}>
                    <div className="flex items-center justify-between">Protocol <SortIcon columnKey="protocol" /></div>
                  </th>
                  <th className="p-4 font-medium cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors group" onClick={() => handleSort('port')}>
                    <div className="flex items-center justify-between">Port <SortIcon columnKey="port" /></div>
                  </th>
                  <th className="p-4 font-medium cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors group" onClick={() => handleSort('service_guess')}>
                    <div className="flex items-center justify-between">Service <SortIcon columnKey="service_guess" /></div>
                  </th>
                  <th className="p-4 font-medium cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors group" onClick={() => handleSort('scope')}>
                    <div className="flex items-center justify-between">Scope <SortIcon columnKey="scope" /></div>
                  </th>
                  <th className="p-4 font-medium cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors group" onClick={() => handleSort('process_name')}>
                    <div className="flex items-center justify-between">Process <SortIcon columnKey="process_name" /></div>
                  </th>
                  <th className="p-4 font-medium cursor-pointer hover:bg-slate-200 dark:hover:bg-slate-600 transition-colors group" onClick={() => handleSort('process_user')}>
                    <div className="flex items-center justify-between">User <SortIcon columnKey="process_user" /></div>
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 dark:divide-slate-700/50 text-sm">
                {sortedData.length === 0 && !loading ? (
                  <tr>
                    <td colSpan="6" className="p-8 text-center text-slate-500 dark:text-slate-400">
                      No listening ports found
                    </td>
                  </tr>
                ) : (
                  sortedData.map((port, idx) => (
                    <tr key={`${port.port}-${port.protocol}-${idx}`} className="hover:bg-slate-50 dark:hover:bg-slate-700/25 transition-colors">
                      <td className="p-4">{port.protocol}</td>
                      <td className="p-4 font-medium">{port.port}</td>
                      <td className="p-4">{port.service_guess}</td>
                      <td className="p-4">
                        <span className="px-2 py-1 rounded-full text-xs font-medium border border-slate-300 dark:border-slate-600">
                          {port.scope}
                        </span>
                      </td>
                      <td className="p-4">{port.process_name || 'Unknown'}</td>
                      <td className="p-4">{port.process_user || port.username || 'Unknown'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          {sortedData.length > 0 && (
            <div className="p-4 bg-slate-50 dark:bg-slate-800/50 border-t border-slate-200 dark:border-slate-700 text-xs text-slate-500 dark:text-slate-400 flex justify-between">
              <span>Found {sortedData.length} listening ports</span>
              <span>Last scanned: {lastScanned ? lastScanned.toLocaleTimeString() : '...'}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
