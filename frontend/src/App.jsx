import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Setup from './pages/Setup';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/setup" element={<Setup />} />
        <Route path="/login" element={<Login />} />
        <Route path="/ports" element={<Dashboard />} />
        <Route path="/" element={<Navigate to="/ports" replace />} />
      </Routes>
    </Router>
  );
}

export default App;
