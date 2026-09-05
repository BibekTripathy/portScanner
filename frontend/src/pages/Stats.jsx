import { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Activity, ArrowLeft, Cpu, HardDrive, Database, Network } from 'lucide-react';

function Stats() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const backendUrl = localStorage.getItem('backendUrl');
  const token = localStorage.getItem('authToken');

  useEffect(() => {
    if (!backendUrl) navigate('/setup');
    if (!token) navigate('/login');
  }, [backendUrl, token, navigate]);

  const fetchStats = async () => {
    if (!token) return;
    try {
      const response = await fetch(`${backendUrl}/api/metrics`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.status === 401) {
        localStorage.removeItem('authToken');
        navigate('/login');
        return;
      }
      if (!response.ok) throw new Error('Failed to fetch stats');
      
      const result = await response.json();
      setData(result.data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  const formatBytes = (bytes) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-300">
      <header className="p-6 bg-white dark:bg-slate-800 shadow-sm border-b border-slate-200 dark:border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/" className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-full transition-colors">
            <ArrowLeft size={20} />
          </Link>
          <div className="flex items-center gap-2">
            <Activity className="text-emerald-500" size={24} />
            <h1 className="text-xl font-medium">System Monitor</h1>
          </div>
        </div>
        {loading && !data && <div className="animate-pulse text-sm text-slate-500">Connecting...</div>}
      </header>

      <main className="max-w-6xl mx-auto p-6 mt-4">
        {error && (
          <div className="bg-red-50 text-red-600 p-4 rounded-xl mb-6 border border-red-200">
            {error}
          </div>
        )}

        {data && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            
            {/* CPU Card */}
            <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 bg-blue-50 dark:bg-blue-900/30 rounded-xl text-blue-500">
                  <Cpu size={24} />
                </div>
                <h2 className="text-lg font-semibold">CPU Usage</h2>
              </div>
              <div className="mb-4">
                <div className="flex justify-between mb-2 text-sm">
                  <span>Total Load</span>
                  <span className="font-medium">{data.cpu.total}%</span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-700 rounded-full h-2.5">
                  <div className="bg-blue-500 h-2.5 rounded-full transition-all duration-500" style={{ width: `${data.cpu.total}%` }}></div>
                </div>
              </div>
              <div className="grid grid-cols-4 gap-2 mt-6">
                {data.cpu.per_core.map((core, i) => (
                  <div key={i} className="text-center">
                    <div className="text-xs text-slate-500 mb-1">Core {i}</div>
                    <div className="text-sm font-medium">{core}%</div>
                  </div>
                ))}
              </div>
            </div>

            {/* RAM Card */}
            <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 bg-fuchsia-50 dark:bg-fuchsia-900/30 rounded-xl text-fuchsia-500">
                  <Database size={24} />
                </div>
                <h2 className="text-lg font-semibold">Memory (RAM)</h2>
              </div>
              <div className="mb-6">
                <div className="flex justify-between mb-2 text-sm">
                  <span>Usage</span>
                  <span className="font-medium">{data.memory.percent}%</span>
                </div>
                <div className="w-full bg-slate-100 dark:bg-slate-700 rounded-full h-2.5">
                  <div className="bg-fuchsia-500 h-2.5 rounded-full transition-all duration-500" style={{ width: `${data.memory.percent}%` }}></div>
                </div>
              </div>
              <div className="flex justify-between text-sm">
                <div>
                  <div className="text-slate-500 mb-1">Used</div>
                  <div className="font-medium text-lg">{formatBytes(data.memory.used)}</div>
                </div>
                <div className="text-right">
                  <div className="text-slate-500 mb-1">Total</div>
                  <div className="font-medium text-lg">{formatBytes(data.memory.total)}</div>
                </div>
              </div>
            </div>

            {/* Disk Card */}
            <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 bg-amber-50 dark:bg-amber-900/30 rounded-xl text-amber-500">
                  <HardDrive size={24} />
                </div>
                <h2 className="text-lg font-semibold">Disk Storage</h2>
              </div>
              <div className="space-y-6">
                {data.disk.map((disk, i) => (
                  <div key={i}>
                    <div className="flex justify-between mb-2 text-sm">
                      <span>{disk.mountpoint} <span className="text-slate-400 text-xs ml-2">({disk.device})</span></span>
                      <span className="font-medium">{disk.percent}%</span>
                    </div>
                    <div className="w-full bg-slate-100 dark:bg-slate-700 rounded-full h-2.5 mb-2">
                      <div className={`h-2.5 rounded-full transition-all duration-500 ${disk.percent > 90 ? 'bg-red-500' : 'bg-amber-500'}`} style={{ width: `${disk.percent}%` }}></div>
                    </div>
                    <div className="flex justify-between text-xs text-slate-500">
                      <span>{formatBytes(disk.used)} used</span>
                      <span>{formatBytes(disk.total)} total</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Network Card */}
            <div className="bg-white dark:bg-slate-800 p-6 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700">
              <div className="flex items-center gap-3 mb-6">
                <div className="p-3 bg-cyan-50 dark:bg-cyan-900/30 rounded-xl text-cyan-500">
                  <Network size={24} />
                </div>
                <h2 className="text-lg font-semibold">Network I/O (Total)</h2>
              </div>
              <div className="flex justify-around mt-8">
                <div className="text-center">
                  <div className="text-slate-500 mb-2">Data Sent</div>
                  <div className="text-2xl font-medium text-cyan-600 dark:text-cyan-400">{formatBytes(data.network.bytes_sent)}</div>
                </div>
                <div className="text-center">
                  <div className="text-slate-500 mb-2">Data Received</div>
                  <div className="text-2xl font-medium text-cyan-600 dark:text-cyan-400">{formatBytes(data.network.bytes_recv)}</div>
                </div>
              </div>
            </div>

          </div>
        )}
      </main>
    </div>
  );
}

export default Stats;
