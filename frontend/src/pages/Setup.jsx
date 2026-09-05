import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Server, ArrowRight } from 'lucide-react';

function Setup() {
  const [ip, setIp] = useState('');
  const navigate = useNavigate();

  const handleSave = (e) => {
    e.preventDefault();
    // Default to localhost if left blank
    const backendUrl = ip.trim() ? ip.trim() : 'http://localhost:8000';
    
    // Ensure it has http:// or https://
    let finalUrl = backendUrl;
    if (!finalUrl.startsWith('http')) {
      finalUrl = 'http://' + finalUrl;
    }

    localStorage.setItem('backendUrl', finalUrl);
    // After setting the IP, go to login
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center p-6 text-slate-800 dark:text-slate-300">
      <div className="max-w-md w-full bg-white dark:bg-slate-800 p-8 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700">
        <div className="flex justify-center mb-6">
          <div className="p-4 bg-indigo-50 dark:bg-indigo-900/30 rounded-full text-indigo-500 dark:text-indigo-400">
            <Server size={32} />
          </div>
        </div>
        <h2 className="text-2xl font-semibold text-center mb-2">Connect to Backend</h2>
        <p className="text-slate-500 dark:text-slate-400 text-center text-sm mb-8">
          Enter the IP address or URL of your monitoring server. Leave blank for localhost.
        </p>

        <form onSubmit={handleSave} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Server URL</label>
            <input 
              type="text" 
              placeholder="e.g. 192.168.1.50:8000" 
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              className="w-full p-3 rounded-lg border border-slate-300 dark:border-slate-600 bg-transparent focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:focus:ring-indigo-400"
            />
          </div>
          <button 
            type="submit"
            className="w-full flex items-center justify-center gap-2 bg-indigo-500 hover:bg-indigo-600 text-white p-3 rounded-lg font-medium transition-colors"
          >
            Connect <ArrowRight size={18} />
          </button>
        </form>
      </div>
    </div>
  );
}

export default Setup;
