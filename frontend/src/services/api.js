/**
 * api.js
 *
 * Every request goes to whichever target is currently selected in the switcher, with
 * that target's own token. Switching machines therefore needs no change here: the
 * components just re-fetch.
 */

import {
  getActiveTarget,
  getToken,
  clearToken,
  getActiveId,
  normalizeUrl,
} from './connections';
import { httpJson, NetworkError } from './transport';

/** Raised on a 401 so callers can send the user to the login screen for that target. */
export class AuthError extends Error {
  constructor(message = 'Not authorised for this target') {
    super(message);
    this.name = 'AuthError';
  }
}

async function request(path, options = {}) {
  const target = getActiveTarget();
  if (!target || target.available === false) {
    throw new Error('The local monitoring service is not running.');
  }

  const token = getToken();
  const { status, ok, json } = await httpJson(`${target.url}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  }).catch((err) => {
    if (err instanceof NetworkError) {
      throw new Error(`Could not reach ${target.label}${target.url ? ` at ${target.url}` : ''}.`);
    }
    throw err;
  });

  if (status === 401) {
    clearToken(getActiveId());
    throw new AuthError();
  }

  if (!json) throw new Error(`Unexpected response from ${target.label} (HTTP ${status}).`);
  if (!ok || (json.status !== 'success' && !json.success)) {
    throw new Error(json.error || json.detail || `Request failed (HTTP ${status}).`);
  }
  return json;
}

export const infoAPI = {
  /** Identity of the active target. Unauthenticated, so it works before logging in. */
  getInfo: () => request('/api/info').then((r) => r.data),

  /**
   * Probe an address the user has just typed, without saving it, so the dialog can
   * confirm what it found (or explain what is wrong).
   */
  probe: async (url) => {
    const origin = normalizeUrl(url);
    if (!origin) throw new Error('That does not look like a valid address.');

    const { status, ok, json } = await httpJson(`${origin}/api/info`).catch((err) => {
      if (err instanceof NetworkError) throw new Error(`Nothing answered at ${origin}.`);
      throw err;
    });

    if (!ok) throw new Error(`${origin} answered with HTTP ${status}.`);
    if (json?.data?.app !== 'portScanner') {
      throw new Error(`${origin} is reachable but does not look like a portScanner server.`);
    }
    return json.data;
  },
};

export const authAPI = {
  /** Log in to (or register on) a specific target, which may not be the active one. */
  login: async (targetUrl, username, password, { register = false } = {}) => {
    const { ok, status, json } = await httpJson(`${targetUrl}${register ? '/api/register' : '/api/login'}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password }).toString(),
    }).catch((err) => {
      if (err instanceof NetworkError) throw new Error('Could not reach that server.');
      throw err;
    });

    if (!ok) throw new Error(json?.detail || `Authentication failed (HTTP ${status}).`);
    return json;
  },
};

export const scanAPI = {
  getPorts: () => request('/api/scan').then((r) => r.data),
};

export const systemAPI = {
  getMetrics: () => request('/api/metrics').then((r) => r.data),
};

export const processAPI = {
  getProcesses: (limit = 50) => request(`/api/processes?limit=${limit}`).then((r) => r.data),
  killProcess: (pid) => request(`/api/processes/${pid}/kill`, { method: 'POST' }),
};

export const dockerAPI = {
  getContainers: () => request('/api/docker/containers').then((r) => r.data),
  controlContainer: (id, action) =>
    request(`/api/docker/containers/${id}/control`, {
      method: 'POST',
      body: JSON.stringify({ action }),
    }),
  getLogs: (id, tail = 100) => request(`/api/docker/containers/${id}/logs?tail=${tail}`).then((r) => r.logs),
};
