import { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import Servers from './pages/Servers';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Home from './pages/Home';
import Stats from './pages/Stats';
import { initConnections } from './services/connections';
import { useConnections } from './hooks/useConnections';

/** Only render a monitoring page once we hold a token for the selected machine. */
function RequireTarget({ children }) {
  const { active, authenticated } = useConnections();
  if (!active) return <Navigate to="/servers" replace />;
  // A local backend that never came up has no login to offer, so send the user to
  // the server list (which explains the state) rather than to a form that cannot work.
  if (active.available === false) return <Navigate to="/servers" replace />;
  if (!authenticated) return <Navigate to="/login" replace />;
  return children;
}

function App() {
  // The connection store has to resolve the built-in target first: in the desktop app
  // that means asking the Tauri shell which port its backend came up on.
  const [booted, setBooted] = useState(false);

  useEffect(() => {
    initConnections().finally(() => setBooted(true));
  }, []);

  if (!booted) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center gap-3 bg-[#87CEEB] dark:bg-[#040d1a] text-slate-600 dark:text-slate-400">
        <Loader2 size={28} className="animate-spin" />
        <p className="text-sm">Starting monitor…</p>
      </div>
    );
  }

  return (
    <Router>
      <Routes>
        <Route path="/servers" element={<Servers />} />
        {/* /setup was the old single-server screen */}
        <Route path="/setup" element={<Navigate to="/servers" replace />} />
        <Route path="/login" element={<Login />} />
        <Route path="/ports" element={<RequireTarget><Dashboard /></RequireTarget>} />
        <Route path="/stats" element={<RequireTarget><Stats /></RequireTarget>} />
        <Route path="/home" element={<RequireTarget><Home /></RequireTarget>} />
        <Route path="*" element={<Navigate to="/home" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
