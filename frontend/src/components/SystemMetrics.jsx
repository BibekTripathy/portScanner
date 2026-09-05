import { useEffect, useState } from 'react';
import { systemAPI } from '../services/api';
import { Minus, Maximize2, Minimize2 } from 'lucide-react';

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let val = bytes;
  while (val >= 1024 && i < units.length - 1) {
    val /= 1024;
    i++;
  }
  return `${val.toFixed(1)} ${units[i]}`;
}

function formatUptime(seconds) {
  if (!seconds) return '0s';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return `${h}h ${m}m ${s}s`;
}

function formatPercent(value) {
  return `${(value ?? 0).toFixed(1)}%`;
}

/* ── Line Chart ──────────────────────────────────────── */
function LineChart({ history, isMaximized, showCores, pollingInterval }) {
  if (!history || history.length < 2) {
    return <div className="text-center text-xs theme-muted my-16">Collecting historical data...</div>;
  }
  
  const width = 300;
  const height = 150;
  const maxHistory = 20;
  const stepX = width / (maxHistory - 1);

  // Extract points
  const pointsCpu = history.map(h => typeof h.cpu === 'object' ? h.cpu.total : h.cpu);
  const pointsMem = history.map(h => h.memory.percent);
  const pointsDisk = history.map(h => Array.isArray(h.disk) ? h.disk[0].percent : h.disk.percent);

  const effectiveInterval = (pollingInterval || 3000) / 1000;
  const LINK_BPS = 125_000_000; // 1 Gbps link in B/s

  const pointsNetwork = history.map((h, idx) => {
    if (idx === 0) return 0;
    const prev = history[idx - 1].network || { bytes_sent: 0, bytes_recv: 0 };
    const curr = h.network || { bytes_sent: 0, bytes_recv: 0 };
    const deltaBytes = Math.max(0, (curr.bytes_sent - prev.bytes_sent) + (curr.bytes_recv - prev.bytes_recv));
    const bps = deltaBytes / effectiveInterval;
    return Math.min(100, (bps / LINK_BPS) * 100);
  });

  const coreHistoryAvailable = showCores && history[0]?.cpu?.per_core && Array.isArray(history[0].cpu.per_core);
  const coreColors = ['#34d399', '#60a5fa', '#f97316', '#f43f5e', '#a855f7', '#facc15', '#06b6d4', '#f472b6'];

  const coreSeries = coreHistoryAvailable
    ? history[0].cpu.per_core.map((_, coreIndex) => history.map(h => (h.cpu?.per_core?.[coreIndex]) ?? 0))
    : [];
  
  const generatePath = (points) => {
    return points.map((p, i) => {
      // align to the right if history is less than max
      const offsetIdx = maxHistory - history.length + i;
      const x = offsetIdx * stepX;
      const y = height - (Math.min(p ?? 0, 100) / 100) * height;
      return `${i === 0 ? 'M' : 'L'} ${x} ${y}`;
    }).join(' ');
  };

  return (
    <div className={`flex flex-col w-full mt-4 transition-all duration-300 ${isMaximized ? 'h-full flex-1 justify-center' : 'items-center'}`}>
      <div className="relative w-full transition-all duration-300" style={{ height: isMaximized ? 'min(60vh, 600px)' : height, minHeight: height }}>
        {/* Y-axis Labels */}
        {[0, 25, 50, 75, 100].map(val => (
          <div key={val} className="absolute left-0 w-8 text-right text-[10px] text-[var(--text-secondary)] pr-2" 
               style={{ top: `${100 - val}%`, transform: 'translateY(-50%)' }}>
            {val}
          </div>
        ))}
        
        {/* Chart SVG wrapper with left margin for labels */}
        <div className="absolute left-8 right-0 top-0 bottom-0">
          <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} className="overflow-visible" preserveAspectRatio="none">
            {/* Grid lines */}
            <line x1="0" y1={0} x2={width} y2={0} stroke="var(--border-card)" strokeDasharray="4 4" opacity="0.5" />
            <line x1="0" y1={height * 0.25} x2={width} y2={height * 0.25} stroke="var(--border-card)" strokeDasharray="4 4" opacity="0.5" />
            <line x1="0" y1={height * 0.5} x2={width} y2={height * 0.5} stroke="var(--border-card)" strokeDasharray="4 4" opacity="0.5" />
            <line x1="0" y1={height * 0.75} x2={width} y2={height * 0.75} stroke="var(--border-card)" strokeDasharray="4 4" opacity="0.5" />
            <line x1="0" y1={height} x2={width} y2={height} stroke="var(--border-card)" />
            
            {/* Lines */}
            <path d={generatePath(pointsCpu)} fill="none" stroke="var(--chart-cpu)" strokeWidth="2.5" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" className="transition-all duration-700 ease-linear" />
            <path d={generatePath(pointsMem)} fill="none" stroke="var(--chart-mem)" strokeWidth="2.5" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" className="transition-all duration-700 ease-linear" />
            <path d={generatePath(pointsDisk)} fill="none" stroke="var(--chart-disk)" strokeWidth="2.5" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" className="transition-all duration-700 ease-linear" />
            <path d={generatePath(pointsNetwork)} fill="none" stroke="var(--chart-network)" strokeWidth="2.5" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" className="transition-all duration-700 ease-linear" />
            {coreSeries.map((series, idx) => (
              <path
                key={`core-${idx}`}
                d={generatePath(series)}
                fill="none"
                stroke={coreColors[idx % coreColors.length]}
                strokeWidth="1.2"
                opacity="0.5"
                vectorEffect="non-scaling-stroke"
                strokeLinecap="round"
                className="transition-all duration-700 ease-linear"
              />
            ))}
          </svg>
        </div>
      </div>
      
      {/* Legend */}
      <div className={`flex gap-4 text-xs drop-shadow-md transition-all duration-300 ${isMaximized ? 'mt-12 justify-center text-sm' : 'mt-8'}`}>
         <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full shadow-[0_0_5px_currentColor]" style={{ backgroundColor: 'var(--chart-cpu)', color: 'var(--chart-cpu)' }} /> <span style={{ color: 'var(--text-secondary)' }}>CPU</span></div>
         <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full shadow-[0_0_5px_currentColor]" style={{ backgroundColor: 'var(--chart-mem)', color: 'var(--chart-mem)' }} /> <span style={{ color: 'var(--text-secondary)' }}>Memory</span></div>
         <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full shadow-[0_0_5px_currentColor]" style={{ backgroundColor: 'var(--chart-disk)', color: 'var(--chart-disk)' }} /> <span style={{ color: 'var(--text-secondary)' }}>Disk</span></div>
         <div className="flex items-center gap-1"><span className="w-2 h-2 rounded-full shadow-[0_0_5px_currentColor]" style={{ backgroundColor: 'var(--chart-network)', color: 'var(--chart-network)' }} /> <span style={{ color: 'var(--text-secondary)' }}>Network</span></div>
         {coreHistoryAvailable && <div className="flex items-center gap-1"><span className="text-xs" style={{ color: 'var(--text-secondary)' }}>Core details shown</span></div>}
      </div>
    </div>
  );
}

/* ── SVG Gauge Chart (Radar-style) ────────────────────────────────────────────── */
function GaugeChart({ metrics, isMaximized }) {
  const sizeClass = isMaximized ? "w-80 h-80 sm:w-96 sm:h-96" : "w-48 h-48";
  
  return (
    <div className={`flex flex-col items-center justify-center relative mt-4 transition-all duration-300 ${isMaximized ? 'h-full flex-1' : ''}`}>
      {/* Radar screen container */}
      <div className={`relative rounded-full overflow-hidden transition-all duration-300 ${sizeClass}`} 
           style={{ backgroundColor: 'var(--bg-tertiary)', border: '2px solid var(--border-card)', boxShadow: '0 0 25px color-mix(in srgb, var(--accent-neon) 20%, transparent)' }}>
        
        {/* Radar grid markings */}
        <div className="absolute inset-0 rounded-full border opacity-30 m-6" style={{ borderColor: 'var(--accent-neon)' }} />
        <div className="absolute inset-0 rounded-full border opacity-20 m-12" style={{ borderColor: 'var(--accent-neon)' }} />
        <div className="absolute top-1/2 left-0 w-full h-px opacity-30" style={{ backgroundColor: 'var(--accent-neon)' }} />
        <div className="absolute left-1/2 top-0 w-px h-full opacity-30" style={{ backgroundColor: 'var(--accent-neon)' }} />

        {/* Concentric Data Rings */}
        <svg viewBox="0 0 100 100" className="absolute inset-0 w-full h-full -rotate-90">
          {metrics.map((m, i) => {
            const r = 40 - i * 12; // Radius decreases for each metric: 40, 28, 16
            const c = 2 * Math.PI * r;
            const val = Math.min(m.value ?? 0, 100);
            const offset = c - (val / 100) * c;
            return (
              <circle
                key={m.label}
                cx="50"
                cy="50"
                r={r}
                fill="none"
                stroke={m.color}
                strokeWidth="6"
                strokeLinecap="round"
                strokeDasharray={c}
                strokeDashoffset={offset}
                className="transition-all duration-700 ease-out"
                opacity="0.85"
                style={{ filter: `drop-shadow(0 0 4px ${m.color})` }}
              />
            );
          })}
        </svg>
      </div>
      
      {/* Legend */}
      <div className="flex gap-4 mt-6 text-xs drop-shadow-md">
         {metrics.map((m) => (
           <div key={m.label} className="flex items-center gap-1">
             <span className="w-2 h-2 rounded-full shadow-[0_0_5px_currentColor]" style={{ backgroundColor: m.color, color: m.color }} />
             <span style={{ color: 'var(--text-secondary)' }}>{m.label}: </span>
             <span className="font-bold" style={{ color: 'var(--text-primary)' }}>{(m.value ?? 0).toFixed(0)}%</span>
           </div>
         ))}
      </div>
    </div>
  );
}

/* ── Bar Chart (original styled) ───────────────────────────────────────── */
function BarChart({ metrics, isMaximized, showCores, coreUsage }) {
  return (
    <div className={`space-y-6 mt-4 transition-all duration-300 ${isMaximized ? 'flex flex-col justify-around h-full flex-1 py-10' : ''}`}>
      {metrics.map((m, idx) => (
        <div key={m.label}>
          <div className={`flex justify-between items-end mb-2 ${isMaximized ? 'mb-4' : ''}`}>
            <div>
              <span className="text-sm font-bold uppercase tracking-wider" style={{ color: m.color || 'var(--text-primary)' }}>{m.label}</span>
              {m.label === 'Network' && (
                <span
                  className="ml-1 text-xs font-medium cursor-help" 
                  title="Network % = (bytes sent+recv per second) / 1Gbps × 100"
                  style={{ color: 'var(--text-muted)' }}
                >
                  ⓘ
                </span>
              )}
              {m.sub && <span className="text-xs ml-2 opacity-80" style={{ color: 'var(--text-muted)' }}>{m.sub}</span>}
            </div>
            <span className={`tabular-nums transition-all ${isMaximized ? 'text-2xl font-medium' : 'text-lg font-bold'}`} style={{ color: 'var(--text-primary)' }}>
              {(m.value ?? 0).toFixed(1)}%
            </span>
          </div>
          <div className={`${isMaximized ? 'h-6' : 'h-2.5'} transition-all duration-300 w-full rounded-full overflow-hidden shadow-[inset_0_2px_4px_rgba(0,0,0,0.5)] border`} style={{ backgroundColor: 'var(--bg-tertiary)', borderColor: 'var(--border-card)' }}>
            <div
              className="h-full rounded-full transition-all duration-700 ease-out"
              style={{ 
                width: `${Math.min(m.value ?? 0, 100)}%`, 
                backgroundColor: m.color || 'var(--accent-neon)',
                boxShadow: `0 0 10px color-mix(in srgb, ${m.color || 'var(--accent-neon)'} 50%, transparent)`
              }}
            />
          </div>

          {showCores && m.label === 'CPU' && Array.isArray(coreUsage) && (
            <div className="mt-3 p-3 rounded-lg border border-[var(--border-card)] bg-[var(--bg-secondary)]">
              <div className="text-xs text-[var(--text-muted)] mb-2">Per-core CPU Usage</div>
              <div className="grid grid-cols-2 gap-2">
                {coreUsage.map((value, coreIdx) => (
                  <div key={`bar-core-${coreIdx}`} className="text-xs">
                    <div className="flex justify-between mb-1">
                      <span>Core {coreIdx}</span>
                      <span className="font-semibold">{formatPercent(value)}</span>
                    </div>
                    <div className="h-2 rounded bg-[var(--bg-primary)] overflow-hidden">
                      <div className="h-full rounded" style={{ width: `${Math.min(value, 100)}%`, backgroundColor: 'var(--chart-cpu)' }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/* ── Main Component ─────────────────────────────────────────────── */
export default function SystemMetrics({ pollingInterval = 3000 }) {
  const [data, setData] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState(null);
  const [chartType, setChartType] = useState('bar');
  const [showCores, setShowCores] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);

  useEffect(() => {
    let active = true;
    const poll = async () => {
      try {
        const metrics = await systemAPI.getMetrics();
        if (active) { 
          setData(metrics);
          setHistory(prev => {
            const next = [...prev, metrics];
            // keep last 20 samples
            return next.length > 20 ? next.slice(next.length - 20) : next;
          });
          setError(null); 
        }
      } catch (e) {
        if (active) setError(e.message);
      }
    };
    poll();
    
    let id;
    if (pollingInterval) {
      id = setInterval(poll, pollingInterval);
    }
    
    return () => { 
      active = false; 
      if (id) clearInterval(id); 
    };
  }, [pollingInterval]);

  if (error) {
    return (
      <div className="rounded-xl bg-red-500/10 border border-red-500/20 p-6 text-red-400 text-sm">
        Failed to load metrics: {error}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="rounded-xl theme-card p-6 animate-pulse">
        <div className="h-4 rounded w-1/3 mb-6" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        <div className="space-y-5">
          <div className="h-12 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-12 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
          <div className="h-12 rounded" style={{ backgroundColor: 'var(--bg-tertiary)' }} />
        </div>
      </div>
    );
  }

  // Handle new backend data shape
  const cpuVal = typeof data.cpu === 'object' ? data.cpu.total : data.cpu;
  const mainDisk = Array.isArray(data.disk) ? data.disk[0] : data.disk;
  const mainNetwork = data.network || { bytes_sent: 0, bytes_recv: 0, packets_sent: 0, packets_recv: 0 };
  const hasCoreData = Array.isArray(data.cpu?.per_core);
  const coreUsage = hasCoreData ? data.cpu.per_core : [];

  const calculateNetworkRate = () => {
    if (history.length < 2) return 0;
    const prev = history[history.length - 2].network || { bytes_sent: 0, bytes_recv: 0 };
    const curr = history[history.length - 1].network || { bytes_sent: 0, bytes_recv: 0 };
    const deltaBytes = Math.max(0, (curr.bytes_sent - prev.bytes_sent) + (curr.bytes_recv - prev.bytes_recv));
    const seconds = (pollingInterval || 3000) / 1000;
    return deltaBytes / seconds;
  };

  const networkRateBps = calculateNetworkRate();
  const networkPercent = Math.min(100, (networkRateBps / 125_000_000) * 100);

  const metrics = [
    {
      label: 'CPU',
      value: cpuVal,
      color: 'var(--chart-cpu)',
      gradient: 'from-cyan-500 to-blue-500',
    },
    {
      label: 'Memory',
      value: data.memory.percent,
      sub: `${formatBytes(data.memory.used)} / ${formatBytes(data.memory.total)}`,
      color: 'var(--chart-mem)',
      gradient: 'from-emerald-500 to-teal-500',
    },
    {
      label: 'Disk' + (Array.isArray(data.disk) && data.disk.length > 1 ? ` (${mainDisk.mountpoint})` : ''),
      value: mainDisk.percent,
      sub: `${formatBytes(mainDisk.used)} / ${formatBytes(mainDisk.total)}`,
      color: 'var(--chart-disk)',
      gradient: 'from-violet-500 to-purple-500',
    },
  ];

  const containerClass = isMaximized 
    ? "fixed inset-4 z-[100] rounded-xl theme-card p-6 flex flex-col backdrop-blur-3xl shadow-2xl transition-all"
    : `rounded-xl theme-card p-6 flex flex-col relative transition-all ${isMinimized ? 'h-fit' : 'min-h-[320px]'}`;

  return (
    <div className={containerClass} style={!isMaximized && !isMinimized ? { resize: 'both', overflow: 'hidden', minHeight: '320px' } : undefined}>
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

      <div className={`flex flex-col gap-3 mb-5 w-full pr-16 ${isMinimized ? '!mb-0' : ''}`}>
        <h2 className="text-sm font-semibold uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
          System Resources
        </h2>
        <div className="flex items-center gap-3 w-full justify-between sm:justify-start">
          {data.uptime && (
            <div className="text-[10px] font-mono rounded border flex flex-col items-start justify-center w-28 h-10 px-3"
                  style={{ color: 'var(--text-muted)', backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-card)' }}>
              <span className="opacity-70 text-[8px] leading-none mb-1 tracking-widest font-sans">UPTIME</span>
              <span className="leading-none text-xs">{formatUptime(data.uptime)}</span>
            </div>
          )}
          {/* Chart Type Dropdown with custom arrow */}
          <div className="relative w-28 h-10">
            <select
              value={chartType}
              onChange={(e) => setChartType(e.target.value)}
              className="appearance-none text-xs rounded border cursor-pointer outline-none transition-colors w-full h-full px-3 pr-8"
              style={{
                backgroundColor: 'var(--bg-primary)',
                color: 'var(--text-secondary)',
                borderColor: 'var(--border-card)',
              }}
            >
              <option value="bar">Bar</option>
              <option value="line">Line</option>
              <option value="gauge">Gauge</option>
            </select>
            <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none opacity-50" style={{ color: 'var(--text-secondary)' }}>
              <svg width="10" height="6" viewBox="0 0 10 6" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M1 1L5 5L9 1" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
          </div>
          <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-secondary)' }}>
            <label className="flex items-center gap-1">
              <input
                type="checkbox"
                checked={showCores}
                onChange={(e) => setShowCores(e.target.checked)}
                className="h-4 w-4"
              />
              Show per-core
            </label>
          </div>
        </div>
      </div>

      <div className={isMinimized ? 'hidden' : 'flex-1 overflow-auto flex flex-col min-h-0 w-full'}>
        {/* Render chosen chart */}
        {chartType === 'bar' && <BarChart metrics={metrics} isMaximized={isMaximized} showCores={showCores} coreUsage={coreUsage} />}
        {chartType === 'line' && <LineChart history={history} isMaximized={isMaximized} showCores={showCores} pollingInterval={pollingInterval} />}
        {chartType === 'gauge' && <GaugeChart metrics={metrics} isMaximized={isMaximized} />}

        <div className="mt-8 mb-4 p-3 shrink-0 rounded-lg border border-[var(--border-card)] bg-[var(--bg-secondary)]">
          <div className="text-xs text-[var(--text-muted)] mb-2">Network Traffic</div>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <div>
              <div className="text-[var(--text-secondary)]">Sent</div>
              <div className="font-semibold">{formatBytes(mainNetwork.bytes_sent)}</div>
            </div>
            <div>
              <div className="text-[var(--text-secondary)]">Received</div>
              <div className="font-semibold">{formatBytes(mainNetwork.bytes_recv)}</div>
            </div>
            <div>
              <div className="text-[var(--text-secondary)]">Packets Sent</div>
              <div className="font-semibold">{mainNetwork.packets_sent}</div>
            </div>
            <div>
              <div className="text-[var(--text-secondary)]">Packets Recv</div>
              <div className="font-semibold">{mainNetwork.packets_recv}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
