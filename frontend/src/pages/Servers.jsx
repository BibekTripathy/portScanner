import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  ArrowLeft, CheckCircle2, Laptop, Loader2, LogIn, LogOut, Plus,
  Server, ShieldAlert, Trash2,
} from 'lucide-react';
import { useConnections } from '../hooks/useConnections';
import {
  addRemote, removeRemote, setActive, clearToken, isAuthenticated,
} from '../services/connections';
import { infoAPI } from '../services/api';

/**
 * Manage the machines this app monitors. "This machine" is always present (it is the
 * local backend in the desktop app, or the server hosting the page in the browser);
 * everything else is a server the user adds by address.
 */
function Servers() {
  const { targets, active } = useConnections();
  const navigate = useNavigate();
  const [params] = useSearchParams();

  const [adding, setAdding] = useState(params.get('add') === '1');
  const [url, setUrl] = useState('');
  const [label, setLabel] = useState('');
  const [probe, setProbe] = useState(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState('');

  const handleCheck = async () => {
    setChecking(true);
    setError('');
    setProbe(null);
    try {
      const info = await infoAPI.probe(url);
      setProbe(info);
      if (!label.trim()) setLabel(info.hostname || '');
    } catch (err) {
      setError(err.message);
    } finally {
      setChecking(false);
    }
  };

  const handleAdd = async (e) => {
    e.preventDefault();
    setError('');
    try {
      // Verify before saving, so a typo doesn't become a dead entry in the list.
      const info = probe || (await infoAPI.probe(url));
      const target = addRemote({ label: label || info.hostname, url });
      setAdding(false);
      setUrl('');
      setLabel('');
      setProbe(null);
      if (!isAuthenticated(target.id)) navigate('/login');
      else navigate('/home');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleUse = (target) => {
    setActive(target.id);
    if (!isAuthenticated(target.id)) navigate('/login');
    else navigate('/home');
  };

  return (
    <div className="min-h-screen bg-[#87CEEB] dark:bg-[#040d1a] text-slate-800 dark:text-slate-200 p-4 md:p-8 transition-colors duration-300">
      <div className="max-w-3xl mx-auto">
        <header className="flex items-center gap-3 mb-8">
          <button
            onClick={() => navigate('/home')}
            className="p-2 rounded-full hover:bg-white/50 dark:hover:bg-slate-700/50 transition-colors text-slate-600 dark:text-slate-400"
            title="Back"
          >
            <ArrowLeft size={20} />
          </button>
          <h1 className="text-2xl font-semibold tracking-tight">Servers</h1>
        </header>

        <div className="space-y-3">
          {targets.map((target) => {
            const isActive = target.id === active?.id;
            const authed = isAuthenticated(target.id);
            return (
              <div
                key={target.id}
                className={`bg-white dark:bg-slate-800 rounded-2xl border p-5 flex items-center gap-4 transition-colors ${
                  isActive
                    ? 'border-indigo-500 dark:border-indigo-400'
                    : 'border-slate-200 dark:border-slate-700'
                }`}
              >
                <div className="w-11 h-11 rounded-xl bg-slate-50 dark:bg-slate-700/60 flex items-center justify-center text-slate-500 dark:text-slate-400 shrink-0">
                  {target.kind === 'remote' ? <Server size={20} /> : <Laptop size={20} />}
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium truncate">{target.label}</span>
                    {isActive && (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-50 text-indigo-600 dark:bg-indigo-900/40 dark:text-indigo-300">
                        active
                      </span>
                    )}
                  </div>
                  <div className="text-sm text-slate-400 dark:text-slate-500 truncate">
                    {target.url || 'served from this page'}
                  </div>
                  <div className="text-xs mt-1">
                    {target.available === false ? (
                      <span className="text-red-500">local backend not running</span>
                    ) : authed ? (
                      <span className="text-emerald-500">connected</span>
                    ) : (
                      <span className="text-amber-500">login required</span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {!isActive && (
                    <button
                      onClick={() => handleUse(target)}
                      className="px-3 py-1.5 text-sm rounded-lg bg-indigo-500 hover:bg-indigo-600 text-white transition-colors"
                    >
                      Use
                    </button>
                  )}
                  {target.kind === 'remote' && authed && (
                    <button
                      onClick={() => clearToken(target.id)}
                      className="p-2 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
                      title="Sign out of this server"
                    >
                      <LogOut size={16} />
                    </button>
                  )}
                  {target.kind === 'remote' && !authed && (
                    <button
                      onClick={() => handleUse(target)}
                      className="p-2 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
                      title="Log in to this server"
                    >
                      <LogIn size={16} />
                    </button>
                  )}
                  {target.kind === 'remote' && (
                    <button
                      onClick={() => removeRemote(target.id)}
                      className="p-2 rounded-lg text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                      title="Remove this server"
                    >
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {!adding ? (
          <button
            onClick={() => setAdding(true)}
            className="mt-4 w-full flex items-center justify-center gap-2 p-4 rounded-2xl border-2 border-dashed border-slate-300 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:border-indigo-400 hover:text-indigo-500 transition-colors"
          >
            <Plus size={18} /> Add a server
          </button>
        ) : (
          <form
            onSubmit={handleAdd}
            className="mt-4 bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 p-6 space-y-4"
          >
            <h2 className="font-semibold">Add a server</h2>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              The address of a machine running this app as a container or service. Port 8000
              is assumed if you don’t give one.
            </p>

            <div>
              <label className="block text-sm font-medium mb-1">Address</label>
              <input
                autoFocus
                required
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  setProbe(null);
                }}
                placeholder="192.168.1.50:8000"
                className="w-full p-3 rounded-lg border border-slate-300 dark:border-slate-600 bg-transparent focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">
                Name <span className="text-slate-400 font-normal">(optional)</span>
              </label>
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="home-server"
                className="w-full p-3 rounded-lg border border-slate-300 dark:border-slate-600 bg-transparent focus:outline-none focus:ring-2 focus:ring-indigo-500"
              />
            </div>

            {error && (
              <div className="p-3 rounded-lg text-sm flex items-start gap-2 bg-red-50 text-red-600 border border-red-200 dark:bg-red-900/20 dark:text-red-400 dark:border-red-900/50">
                <ShieldAlert size={16} className="mt-0.5 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {probe && (
              <div className="p-3 rounded-lg text-sm flex items-start gap-2 bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-900/50">
                <CheckCircle2 size={16} className="mt-0.5 shrink-0" />
                <span>
                  Found <strong>{probe.hostname}</strong> — {probe.system} {probe.release},
                  portScanner {probe.version}
                  {probe.docker_available ? ', Docker available' : ''}.
                </span>
              </div>
            )}

            <div className="flex items-center gap-3 pt-1">
              <button
                type="submit"
                className="px-4 py-2.5 rounded-lg bg-indigo-500 hover:bg-indigo-600 text-white font-medium transition-colors"
              >
                Add server
              </button>
              <button
                type="button"
                onClick={handleCheck}
                disabled={!url || checking}
                className="px-4 py-2.5 rounded-lg border border-slate-300 dark:border-slate-600 font-medium hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {checking && <Loader2 size={16} className="animate-spin" />}
                Test connection
              </button>
              <button
                type="button"
                onClick={() => {
                  setAdding(false);
                  setError('');
                  setProbe(null);
                }}
                className="px-4 py-2.5 text-slate-500 dark:text-slate-400 hover:underline"
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

export default Servers;
