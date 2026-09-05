import { useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Activity, Network, LogOut, LayoutDashboard } from 'lucide-react';

function Home() {
  const navigate = useNavigate();
  const token = localStorage.getItem('authToken');
  const backendUrl = localStorage.getItem('backendUrl');

  useEffect(() => {
    if (!backendUrl) navigate('/setup');
    if (!token) navigate('/login');
  }, [backendUrl, token, navigate]);

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-300">
      <header className="flex justify-between items-center p-6 bg-white dark:bg-slate-800 shadow-sm border-b border-slate-200 dark:border-slate-700">
        <div className="flex items-center gap-3">
          <LayoutDashboard className="text-indigo-500" size={28} />
          <h1 className="text-2xl font-medium tracking-tight">Unified Dashboard</h1>
        </div>
        <button 
          onClick={() => {
            localStorage.removeItem('authToken');
            navigate('/login');
          }}
          className="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
          title="Logout"
        >
          <LogOut size={20} className="text-slate-500 dark:text-slate-400" />
        </button>
      </header>

      <main className="max-w-6xl mx-auto p-6 mt-8">
        <h2 className="text-xl font-semibold mb-6">Select a Module</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Link to="/ports" className="block group">
            <div className="bg-white dark:bg-slate-800 p-8 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700 hover:border-indigo-500 dark:hover:border-indigo-400 transition-all hover:shadow-md h-full">
              <div className="w-14 h-14 bg-indigo-50 dark:bg-indigo-900/30 rounded-2xl flex items-center justify-center text-indigo-500 dark:text-indigo-400 mb-6 group-hover:scale-110 transition-transform">
                <Network size={32} />
              </div>
              <h3 className="text-2xl font-semibold mb-2">Port Scanner</h3>
              <p className="text-slate-500 dark:text-slate-400">
                Scan the host machine for listening TCP/UDP ports, mapped to their underlying processes and users.
              </p>
            </div>
          </Link>

          <Link to="/stats" className="block group">
            <div className="bg-white dark:bg-slate-800 p-8 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700 hover:border-emerald-500 dark:hover:border-emerald-400 transition-all hover:shadow-md h-full">
              <div className="w-14 h-14 bg-emerald-50 dark:bg-emerald-900/30 rounded-2xl flex items-center justify-center text-emerald-500 dark:text-emerald-400 mb-6 group-hover:scale-110 transition-transform">
                <Activity size={32} />
              </div>
              <h3 className="text-2xl font-semibold mb-2">System Monitor</h3>
              <p className="text-slate-500 dark:text-slate-400">
                View real-time hardware telemetry including CPU load, RAM utilization, Disk space, and Network I/O.
              </p>
            </div>
          </Link>
        </div>
      </main>
    </div>
  );
}

export default Home;
