import { useEffect, useState } from 'react';
import { processAPI } from '../services/api';
import { RefreshCw, Search, List, Grid } from 'lucide-react';

export default function ProcessList({ compact = false, pollingInterval = 3000 }) {
  const [processes, setProcesses] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [viewMode, setViewMode] = useState('list'); // list or grid
  
  // Sorting state: column name, and direction ('desc', 'asc', null)
  const [sortConfig, setSortConfig] = useState({ key: null, direction: null });

  const fetchProcesses = async () => {
    try {
      const data = await processAPI.getProcesses(compact ? 10 : 50);
      setProcesses(data);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProcesses();
    let id;
    if (pollingInterval) {
      id = setInterval(fetchProcesses, pollingInterval);
    }
    return () => {
      if (id) clearInterval(id);
    };
  }, [pollingInterval, compact]);

  const handleKill = async (pid) => {
    if (!window.confirm(`Are you sure you want to kill process ${pid}?`)) return;
    try {
      await processAPI.killProcess(pid);
      fetchProcesses();
    } catch (e) {
      alert(`Failed to kill process: ${e.message}`);
    }
  };

  const handleSort = (key) => {
    let direction = 'desc';
    if (sortConfig.key === key && sortConfig.direction === 'desc') {
      direction = 'asc';
    } else if (sortConfig.key === key && sortConfig.direction === 'asc') {
      direction = null;
    }
    setSortConfig({ key: direction ? key : null, direction });
  };

  const getSortIcon = (columnKey) => {
    if (sortConfig.key !== columnKey) return <span className="ml-1 opacity-20">↕</span>;
    if (sortConfig.direction === 'asc') return <span className="ml-1 text-[var(--accent-neon)]">↑</span>;
    if (sortConfig.direction === 'desc') return <span className="ml-1 text-[var(--accent-neon)]">↓</span>;
    return null;
  };

  let filtered = processes.filter(p => 
    p.name.toLowerCase().includes(search.toLowerCase()) || 
    p.username.toLowerCase().includes(search.toLowerCase()) ||
    p.pid.toString().includes(search)
  );

  if (sortConfig.key) {
    filtered.sort((a, b) => {
      let aValue = a[sortConfig.key];
      let bValue = b[sortConfig.key];
      
      if (typeof aValue === 'string') {
        aValue = aValue.toLowerCase();
        bValue = bValue.toLowerCase();
      }
      
      if (aValue < bValue) return sortConfig.direction === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortConfig.direction === 'asc' ? 1 : -1;
      return 0;
    });
  }

  if (error && !processes.length) {
    return (
      <div className="rounded-xl bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700 p-6 border border-red-500/20 text-red-400">
        Failed to load processes: {error}
      </div>
    );
  }

  if (loading && !processes.length) {
    return <div className="rounded-xl bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700 p-6 animate-pulse h-64 bg-[var(--bg-tertiary)]" />;
  }

  return (
    <div className={`rounded-xl bg-white dark:bg-slate-800 shadow-sm border border-slate-200 dark:border-slate-700 flex flex-col ${compact ? 'h-full' : 'h-[80vh]'}`}>
      <div className="p-4 border-b border-slate-200 dark:border-slate-700 flex flex-wrap gap-4 items-center justify-between">
        <h2 className="font-semibold text-slate-800 dark:text-slate-200">
          {compact ? 'Top Processes' : 'Process Explorer'}
        </h2>
        
        <div className="flex gap-2 items-center flex-1 justify-end">
          {!compact && (
            <div className="relative max-w-xs w-full">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 dark:text-slate-400" />
              <input
                type="text"
                placeholder="Search PID, name, user..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full text-sm pl-9 pr-3 py-1.5 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 outline-none focus:border-cyan-500 transition-colors text-slate-800 dark:text-slate-200"
              />
            </div>
          )}
          
          <button 
            onClick={() => setViewMode(v => v === 'list' ? 'grid' : 'list')}
            className="p-1.5 rounded hover:bg-slate-500/20 text-slate-600 dark:text-slate-400"
            title="Toggle View"
          >
            {viewMode === 'list' ? <Grid size={16} /> : <List size={16} />}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-4">
        {viewMode === 'list' ? (
          <div className="w-full overflow-x-auto">
            <table className="w-full table-fixed text-left text-sm whitespace-nowrap">
              <thead className="text-slate-500 dark:text-slate-400 sticky top-0 bg-white dark:bg-slate-800 shadow-sm">
                <tr>
                  <th className="w-16 sm:w-20 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort('pid')}>PID {getSortIcon('pid')}</th>
                  <th className="pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort('name')}>Name {getSortIcon('name')}</th>
                  <th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort('username')}>User {getSortIcon('username')}</th>
                  <th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort('cpu_percent')}>CPU % {getSortIcon('cpu_percent')}</th>
                  <th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort('memory_percent')}>RAM % {getSortIcon('memory_percent')}</th>
                  <th className="w-20 sm:w-24 pb-3 px-2 font-medium cursor-pointer select-none hover:text-slate-800 dark:text-slate-200" onClick={() => handleSort('status')}>Status {getSortIcon('status')}</th>
                  {!compact && <th className="w-16 pb-3 px-2 font-medium text-right">Actions</th>}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                {filtered.map(p => (
                  <tr key={p.pid} className="hover:bg-slate-500/5 transition-colors">
                    <td className="py-3 px-2 font-mono text-xs text-slate-800 dark:text-slate-200">{p.pid}</td>
                    <td className="py-3 px-2 font-medium text-slate-800 dark:text-slate-200 truncate" title={p.name}>{p.name}</td>
                    <td className="py-3 px-2 text-slate-600 dark:text-slate-400">{p.username}</td>
                    <td className="py-3 px-2">
                      {p.cpu_percent.toFixed(1)}%
                    </td>
                    <td className="py-3 px-2">
                      {p.memory_percent.toFixed(1)}%
                    </td>
                    <td className="py-3 px-2">
                      <span className={`px-2 py-0.5 rounded text-xs ${
                        p.status === 'running' ? 'bg-emerald-500/10 text-emerald-400' :
                        p.status === 'sleeping' ? 'bg-blue-500/10 text-blue-400' :
                        'bg-slate-500/10 text-slate-400'
                      }`}>
                        {p.status}
                      </span>
                    </td>
                    {!compact && (
                      <td className="py-3 px-2 text-right">
                        <button 
                          onClick={() => handleKill(p.pid)}
                          className="text-xs px-2 py-1 rounded bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white transition-colors"
                        >
                          Kill
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filtered.map(p => (
              <div key={p.pid} className="border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 rounded-lg p-4 hover:border-cyan-500/50 transition-colors flex flex-col">
                <div className="flex justify-between items-start mb-3">
                  <div className="font-medium truncate pr-2 text-slate-800 dark:text-slate-200" title={p.name}>{p.name}</div>
                  <span className={`shrink-0 px-2 py-0.5 rounded text-[10px] uppercase ${
                        p.status === 'running' ? 'bg-emerald-500/10 text-emerald-400' :
                        p.status === 'sleeping' ? 'bg-blue-500/10 text-blue-400' :
                        'bg-slate-500/10 text-slate-400'
                      }`}>
                    {p.status}
                  </span>
                </div>
                
                <div className="text-xs font-mono mb-4 flex justify-between text-slate-600 dark:text-slate-400">
                  <span>PID: <span className="text-slate-800 dark:text-slate-200">{p.pid}</span></span>
                  <span>{p.username}</span>
                </div>
                
                <div className="space-y-3 mt-auto">
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-500 dark:text-slate-400">CPU</span>
                      <span>{p.cpu_percent.toFixed(1)}%</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-white dark:bg-slate-800 overflow-hidden">
                      <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${Math.min(p.cpu_percent, 100)}%` }} />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-slate-500 dark:text-slate-400">RAM</span>
                      <span>{p.memory_percent.toFixed(1)}%</span>
                    </div>
                    <div className="h-1.5 rounded-full bg-white dark:bg-slate-800 overflow-hidden">
                      <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${Math.min(p.memory_percent, 100)}%` }} />
                    </div>
                  </div>
                </div>
                
                {!compact && (
                  <div className="mt-4 pt-3 border-t border-slate-200 dark:border-slate-700 flex justify-end">
                    <button 
                      onClick={() => handleKill(p.pid)}
                      className="text-xs px-3 py-1 rounded bg-red-500/10 text-red-500 hover:bg-red-500 hover:text-white transition-colors"
                    >
                      Kill
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        
        {filtered.length === 0 && !loading && (
          <div className="text-center py-12 text-slate-500 dark:text-slate-400 text-sm">
            No processes found matching your criteria.
          </div>
        )}
      </div>
    </div>
  );
}
