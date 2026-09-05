import { useEffect, useState } from 'react';
import { dockerAPI } from '../services/api';
import { Minus, Maximize2, Minimize2 } from 'lucide-react';

export default function DockerStatus({ pollingInterval = 5000 }) {
  const [containers, setContainers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [logs, setLogs] = useState({ id: null, text: '' });
  const [isMinimized, setIsMinimized] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);

  const fetchContainers = async () => {
    try {
      const data = await dockerAPI.getContainers();
      setContainers(data);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchContainers();
    let id;
    if (pollingInterval) {
      id = setInterval(fetchContainers, pollingInterval);
    }
    return () => {
      if (id) clearInterval(id);
    };
  }, [pollingInterval]);

  const handleAction = async (id, action) => {
    try {
      await dockerAPI.controlContainer(id, action);
      fetchContainers();
    } catch (e) {
      alert(`Failed to ${action}: ${e.message}`);
    }
  };

  const toggleLogs = async (id) => {
    if (logs.id === id) {
      setLogs({ id: null, text: '' });
      return;
    }
    try {
      const text = await dockerAPI.getLogs(id, 50);
      setLogs({ id, text });
    } catch (e) {
      setLogs({ id, text: `Error: ${e.message}` });
    }
  };

  if (error) {
    return (
      <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-6 text-red-400 text-sm">
        Failed to connect to Docker: {error}
      </div>
    );
  }

  const containerClass = isMaximized 
    ? "fixed inset-4 z-[100] rounded-xl theme-card p-6 flex flex-col backdrop-blur-3xl shadow-2xl transition-all"
    : `rounded-xl theme-card p-6 flex flex-col relative transition-all ${isMinimized ? 'h-fit' : 'h-full'}`;

  return (
    <div className={containerClass} style={!isMaximized && !isMinimized ? { resize: 'both', overflow: 'hidden', minHeight: '200px' } : undefined}>
      {/* Window Controls */}
      <div className="absolute top-4 right-4 flex gap-1 z-50">
        <button onClick={() => { setIsMinimized(!isMinimized); setIsMaximized(false); }} className="p-1 hover:bg-slate-500/20 rounded text-[var(--text-secondary)] transition-colors hover:text-[var(--text-primary)]" title={isMinimized ? "Restore" : "Minimize"}>
          <Minus size={14} />
        </button>
        {!isMinimized && (
          <button onClick={() => setIsMaximized(!isMaximized)} className="p-1 hover:bg-slate-500/20 rounded text-[var(--text-secondary)] transition-colors hover:text-[var(--text-primary)]" title={isMaximized ? "Restore down" : "Maximize"}>
            {isMaximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
        )}
      </div>

      <div className={`flex justify-between items-center mb-5 pr-16 w-full ${isMinimized ? '!mb-0' : ''}`}>
        <h2 className="text-sm font-semibold theme-muted uppercase tracking-wider">
          Docker Containers
        </h2>
        <span className="text-xs theme-muted px-2 py-1 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }}>
          {containers.length} containers
        </span>
      </div>

      {!isMinimized && (
        <div className="flex-1 overflow-auto min-h-0 w-full">
          {loading ? (
            <div className="theme-muted animate-pulse p-4 text-center">Loading…</div>
          ) : containers.length === 0 ? (
            <div className="theme-muted text-sm text-center py-8">
              No Docker containers found. Is Docker running?
            </div>
          ) : (
            <div className="space-y-3 pb-2">
          {containers.map((c) => {
            const running = c.state?.Running;
            return (
              <div
                key={c.id}
                className="rounded-lg bg-slate-900/50 border border-slate-700/40 p-4 hover:border-slate-600 transition-colors"
              >
                {/* Container info row */}
                <div className="flex items-center justify-between mb-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div
                        className={`w-2 h-2 rounded-full ${
                          running ? 'bg-emerald-400 shadow-[0_0_6px_rgba(52,211,153,0.5)]' : 'bg-slate-500'
                        }`}
                      />
                      <span className="text-sm font-medium text-slate-200 truncate">
                        {c.name}
                      </span>
                    </div>
                    <div className="text-xs text-slate-500 mt-1 ml-4 font-mono">{c.image}</div>
                  </div>
                  <span
                    className={`text-xs px-2 py-0.5 rounded font-medium ${
                      running
                        ? 'bg-emerald-500/15 text-emerald-400'
                        : 'bg-slate-700/50 text-slate-400'
                    }`}
                  >
                    {c.status}
                  </span>
                </div>

                {/* Action buttons */}
                <div className="flex gap-2 flex-wrap">
                  <ActionBtn label="Start" onClick={() => handleAction(c.id, 'start')} disabled={running} />
                  <ActionBtn label="Stop" onClick={() => handleAction(c.id, 'stop')} disabled={!running} />
                  <ActionBtn label="Restart" onClick={() => handleAction(c.id, 'restart')} />
                  <button
                    onClick={() => toggleLogs(c.id)}
                    className={`text-xs px-3 py-1.5 rounded border transition-colors ${
                      logs.id === c.id
                        ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                        : 'bg-slate-700/50 text-slate-400 border-slate-600 hover:text-white hover:bg-slate-600'
                    }`}
                  >
                    Logs
                  </button>
                  <ActionBtn
                    label="Remove"
                    onClick={() => handleAction(c.id, 'remove')}
                    className="ml-auto text-red-400 border-red-500/20 hover:bg-red-500 hover:text-white"
                  />
                </div>

                {/* Logs panel */}
                {logs.id === c.id && (
                  <pre className="mt-3 p-3 rounded bg-black/40 text-xs text-slate-300 max-h-48 overflow-auto font-mono border border-slate-700/30 whitespace-pre-wrap">
                    {logs.text || 'No logs available.'}
                  </pre>
                )}
              </div>
            );
          })}
        </div>
        )}
        </div>
      )}
    </div>
  );
}

function ActionBtn({ label, onClick, disabled, className = '' }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`text-xs px-3 py-1.5 rounded border transition-colors ${
        disabled
          ? 'bg-slate-800/30 border-slate-700/30 text-slate-600 cursor-not-allowed'
          : `bg-slate-700/50 border-slate-600 text-slate-300 hover:bg-slate-600 hover:text-white ${className}`
      }`}
    >
      {label}
    </button>
  );
}
