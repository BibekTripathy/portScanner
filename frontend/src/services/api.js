const getBaseUrl = () => {
  const stored = localStorage.getItem('backendUrl');
  if (stored) return stored;
  if (import.meta.env.PROD) {
    return ''; // Relative to the origin in production
  }
  return 'http://localhost:8000';
};

const getHeaders = () => {
  const token = localStorage.getItem('authToken');
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {})
  };
};

async function request(path, options = {}) {
  const res = await fetch(`${getBaseUrl()}${path}`, {
    ...options,
    headers: { ...getHeaders(), ...(options.headers || {}) }
  });
  
  if (res.status === 401) {
    localStorage.removeItem('authToken');
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  const json = await res.json();
  if (json.status !== 'success' && !json.success) throw new Error(json.error || json.detail || 'Request failed');
  return json;
}

export const systemAPI = {
  getMetrics: () => request('/api/metrics').then(r => r.data),
};

export const processAPI = {
  getProcesses: (limit = 50) =>
    request(`/api/processes?limit=${limit}`).then(r => r.data),
  killProcess: (pid) =>
    request(`/api/processes/${pid}/kill`, { method: 'POST' }),
};

export const dockerAPI = {
  getContainers: () => request('/api/docker/containers').then(r => r.data),
  controlContainer: (id, action) =>
    request(`/api/docker/containers/${id}/control`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    }),
  getLogs: (id, tail = 100) =>
    request(`/api/docker/containers/${id}/logs?tail=${tail}`).then(r => r.logs),
};
