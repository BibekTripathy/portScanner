import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, User as UserIcon, ShieldAlert, LogIn, UserPlus } from 'lucide-react';

function Login() {
  const [isRegistering, setIsRegistering] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const backendUrl = localStorage.getItem('backendUrl') || 'http://localhost:8000';

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Both register and login in FastAPI's OAuth2PasswordRequestForm expect form data, not JSON
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);

      const endpoint = isRegistering ? '/api/register' : '/api/login';
      
      const response = await fetch(`${backendUrl}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: formData.toString()
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Authentication failed');
      }

      if (isRegistering) {
        // Automatically switch to login after successful registration
        setIsRegistering(false);
        setError('Registration successful! Please log in.');
        // Don't set error class for success message, we'll keep it simple
      } else {
        // Save the JWT token
        localStorage.setItem('authToken', data.access_token);
        navigate('/'); // Go to dashboard
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
        
        <h2 className="text-2xl font-semibold text-center mb-8">
          {isRegistering ? 'Create Account' : 'Welcome Back'}
        </h2>

        {error && (
          <div className={`p-3 rounded-lg mb-6 flex items-center gap-2 text-sm border ${
            error.includes('successful') 
              ? 'bg-emerald-50 text-emerald-600 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-900/50'
              : 'bg-red-50 text-red-600 border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-900/50'
          }`}>
            {!error.includes('successful') && <ShieldAlert size={16} />}
            <span>{error}</span>
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
            {loading ? 'Processing...' : (isRegistering ? 'Register' : 'Login')}
          </button>
        </form>

        <div className="mt-6 text-center">
          <button 
            type="button" 
            onClick={() => {
              setIsRegistering(!isRegistering);
              setError('');
            }}
            className="text-sm text-indigo-500 dark:text-indigo-400 hover:underline"
          >
            {isRegistering ? 'Already have an account? Log in' : 'Need an account? Register'}
          </button>
        </div>
      </div>
    </div>
  );
}

export default Login;
