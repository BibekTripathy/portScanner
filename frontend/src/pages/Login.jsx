import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, User as UserIcon, ShieldAlert, LogIn, UserPlus, Server, ArrowLeft } from 'lucide-react';
import { useConnections } from '../hooks/useConnections';
import { setToken } from '../services/connections';
import { authAPI } from '../services/api';

/**
 * Login for the *active* target. Each server has its own user database, so the token
 * we get back is stored against that target only.
 */
function Login() {
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const { active } = useConnections();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setNotice('');
    setLoading(true);

    try {
      const data = await authAPI.login(active.url, username, password, { register: isRegistering });

      if (isRegistering) {
        setIsRegistering(false);
        setNotice('Account created. You can log in now.');
      } else {
        setToken(active.id, data.access_token);
        navigate('/home');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-slate-900 flex items-center justify-center p-6 text-slate-800 dark:text-slate-300">
      <div className="max-w-md w-full bg-white dark:bg-slate-800 p-8 rounded-2xl shadow-sm border border-slate-200 dark:border-slate-700">
        <div className="flex justify-center mb-6">
          <div className="p-4 bg-indigo-50 dark:bg-indigo-900/30 rounded-full text-indigo-500 dark:text-indigo-400">
            <Lock size={32} />
          </div>
        </div>

        <h2 className="text-2xl font-semibold text-center mb-2">
          {isRegistering ? 'Create Account' : 'Welcome Back'}
        </h2>

        {/* Which machine these credentials are for. */}
        <div className="flex items-center justify-center gap-2 text-sm text-slate-500 dark:text-slate-400 mb-8">
          <Server size={14} />
          <span className="truncate">{active?.label}</span>
          {active?.url && <span className="text-slate-400 dark:text-slate-600 truncate">· {active.url}</span>}
        </div>

        {(error || notice) && (
          <div
            className={`p-3 rounded-lg mb-6 flex items-center gap-2 text-sm border ${
              notice
                ? 'bg-emerald-50 text-emerald-600 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-900/50'
                : 'bg-red-50 text-red-600 border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-900/50'
            }`}
          >
            {error && <ShieldAlert size={16} />}
            <span>{notice || error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1">Username</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                <UserIcon size={18} />
              </div>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full pl-10 p-3 rounded-lg border border-slate-300 dark:border-slate-600 bg-transparent focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:focus:ring-indigo-400"
                placeholder="admin"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1">Password</label>
            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-400">
                <Lock size={18} />
              </div>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 p-3 rounded-lg border border-slate-300 dark:border-slate-600 bg-transparent focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:focus:ring-indigo-400"
                placeholder="••••••••"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full flex items-center justify-center gap-2 bg-indigo-500 hover:bg-indigo-600 text-white p-3 rounded-lg font-medium transition-colors disabled:opacity-70 mt-6"
          >
            {isRegistering ? <UserPlus size={18} /> : <LogIn size={18} />}
            {loading ? 'Processing...' : isRegistering ? 'Register' : 'Login'}
          </button>
        </form>

        <div className="mt-6 flex flex-col items-center gap-3">
          <button
            type="button"
            onClick={() => {
              setIsRegistering(!isRegistering);
              setError('');
              setNotice('');
            }}
            className="text-sm text-indigo-500 dark:text-indigo-400 hover:underline"
          >
            {isRegistering ? 'Already have an account? Log in' : 'Need an account? Register'}
          </button>

          <button
            type="button"
            onClick={() => navigate('/servers')}
            className="text-sm text-slate-400 dark:text-slate-500 hover:underline flex items-center gap-1"
          >
            <ArrowLeft size={14} /> Choose a different machine
          </button>
        </div>
      </div>
    </div>
  );
}

export default Login;
