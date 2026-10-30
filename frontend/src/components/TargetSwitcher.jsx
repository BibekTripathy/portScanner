import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Check, ChevronDown, Laptop, Lock, Plus, Server, Settings } from 'lucide-react';
import { useConnections } from '../hooks/useConnections';
import { setActive, isAuthenticated } from '../services/connections';

/**
 * The machine picker that sits in every page header: your own machine plus any saved
 * servers. Selecting one re-points every API call at it; if we have no token for it
 * yet, the login screen is shown for that server.
 */
function TargetSwitcher() {
  const { targets, active } = useConnections();
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => e.key === 'Escape' && setOpen(false);
    document.addEventListener('mousedown', onClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onClick);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const choose = (target) => {
    setActive(target.id);
    setOpen(false);
    if (!isAuthenticated(target.id)) navigate('/login');
  };

  const iconFor = (target) =>
    target.kind === 'remote' ? <Server size={15} /> : <Laptop size={15} />;

  const statusFor = (target) => {
    if (target.available === false) return { color: 'bg-red-500', title: 'Backend not running' };
    if (!isAuthenticated(target.id)) return { color: 'bg-amber-500', title: 'Login required' };
    return { color: 'bg-emerald-500', title: 'Connected' };
  };

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white dark:bg-slate-700 border border-slate-200 dark:border-slate-600 text-sm font-medium text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-600 transition-colors"
        title="Choose which machine to monitor"
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span className={`w-2 h-2 rounded-full ${statusFor(active || {}).color}`} />
        {iconFor(active || {})}
        <span className="max-w-[12rem] truncate">{active?.label || 'No target'}</span>
        <ChevronDown size={15} className="text-slate-400" />
      </button>

      {open && (
        <div
          role="listbox"
          className="absolute right-0 mt-2 w-72 z-50 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl shadow-lg overflow-hidden"
        >
          <div className="px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
            Monitoring target
          </div>

          {targets.map((target) => {
            const status = statusFor(target);
            return (
              <button
                key={target.id}
                type="button"
                role="option"
                aria-selected={target.id === active?.id}
                onClick={() => choose(target)}
                className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-700/60 transition-colors"
              >
                <span className={`w-2 h-2 rounded-full shrink-0 ${status.color}`} title={status.title} />
                <span className="text-slate-400 dark:text-slate-500 shrink-0">{iconFor(target)}</span>
                <span className="min-w-0 flex-1">
                  <span className="block text-sm font-medium text-slate-700 dark:text-slate-200 truncate">
                    {target.label}
                  </span>
                  <span className="block text-xs text-slate-400 dark:text-slate-500 truncate">
                    {target.url || 'this page’s origin'}
                  </span>
                </span>
                {target.id === active?.id ? (
                  <Check size={16} className="text-indigo-500 shrink-0" />
                ) : !isAuthenticated(target.id) ? (
                  <Lock size={14} className="text-amber-500 shrink-0" />
                ) : null}
              </button>
            );
          })}

          <div className="border-t border-slate-200 dark:border-slate-700">
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                navigate('/servers?add=1');
              }}
              className="w-full flex items-center gap-2 px-3 py-2.5 text-sm text-indigo-500 dark:text-indigo-400 hover:bg-slate-50 dark:hover:bg-slate-700/60 transition-colors"
            >
              <Plus size={16} /> Add a server
            </button>
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                navigate('/servers');
              }}
              className="w-full flex items-center gap-2 px-3 py-2.5 text-sm text-slate-500 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-700/60 transition-colors"
            >
              <Settings size={16} /> Manage servers
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default TargetSwitcher;
