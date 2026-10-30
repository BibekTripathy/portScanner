/**
 * connections.js
 *
 * The list of machines this app can talk to, and which one is currently selected.
 *
 * There is always exactly one built-in target:
 *   - in the desktop app it is "This machine", backed by the sidecar the Tauri shell
 *     started, and it is pre-authenticated with the sidecar's loopback token;
 *   - in the browser it is the server that served the page, which needs a login.
 *
 * On top of that the user can save any number of remote servers (an IP or URL plus
 * their own JWT for it). Remotes and their tokens are persisted; the built-in target
 * is not, because its address and token change on every launch.
 *
 * This is a plain store with a subscribe() so that both React components and the API
 * client can read the same state without prop-drilling.
 */

import { getLocalBackend, runtime } from './runtime';

const TARGETS_KEY = 'ps.targets.v1';
const ACTIVE_KEY = 'ps.activeTarget.v1';
const TOKENS_KEY = 'ps.tokens.v1';

export const LOCAL_ID = 'local';

let remotes = [];
let tokens = {};
let activeId = LOCAL_ID;
let localTarget = null;
let ready = false;

const listeners = new Set();
const emit = () => listeners.forEach((fn) => fn());

export function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

const read = (key, fallback) => {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
};

const persist = () => {
  try {
    localStorage.setItem(TARGETS_KEY, JSON.stringify(remotes));
    localStorage.setItem(TOKENS_KEY, JSON.stringify(tokens));
    localStorage.setItem(ACTIVE_KEY, activeId);
  } catch {
    /* private browsing / storage disabled - the session still works, it just won't be remembered */
  }
};

/** Unique even when two servers are added in the same millisecond. */
let idCounter = 0;
const newId = () => `remote-${Date.now().toString(36)}-${(idCounter += 1)}`;

/** Normalise whatever the user typed into a usable origin: `192.168.1.5` -> `http://192.168.1.5:8000` */
export function normalizeUrl(input, { defaultPort = 8000 } = {}) {
  // The scheme is added before parsing and the path is dropped by `.origin`, so the
  // input is never rewritten by hand -- doing so turns `http://` into `http://http`.
  let value = (input || '').trim();
  if (!value) return '';
  if (!/^https?:\/\//i.test(value)) value = `http://${value}`;

  try {
    const url = new URL(value);
    if (!url.hostname) return '';
    if (!url.port && url.protocol === 'http:' && defaultPort) url.port = String(defaultPort);
    return url.origin;
  } catch {
    return '';
  }
}

/**
 * Pull across the single-server settings used before multi-server support, so an
 * existing install keeps its server and stays logged in.
 */
function migrateLegacy() {
  const legacyUrl = localStorage.getItem('backendUrl');
  const legacyToken = localStorage.getItem('authToken');
  if (!legacyUrl && !legacyToken) return;

  const origin = normalizeUrl(legacyUrl || '');
  const isLocalhost = !origin || /^https?:\/\/(127\.0\.0\.1|localhost)/i.test(origin);

  if (isLocalhost) {
    // It was pointing at this machine, which is now the built-in target.
    if (legacyToken) tokens[LOCAL_ID] = legacyToken;
  } else {
    const id = newId();
    remotes.push({ id, kind: 'remote', label: new URL(origin).hostname, url: origin });
    if (legacyToken) tokens[id] = legacyToken;
    activeId = id;
  }

  localStorage.removeItem('backendUrl');
  localStorage.removeItem('authToken');
  persist();
}

/** Build the built-in target for whichever shell we are in. */
async function resolveLocalTarget() {
  const mode = runtime();

  if (mode === 'desktop') {
    const local = await getLocalBackend();
    return {
      id: LOCAL_ID,
      kind: 'local',
      label: 'This machine',
      url: local?.url || '',
      // Handed over by the Tauri shell: no login screen for your own machine.
      token: local?.token || null,
      available: !!local?.url,
    };
  }

  return {
    id: LOCAL_ID,
    kind: mode === 'web' ? 'origin' : 'dev',
    label: mode === 'web' ? 'This server' : 'Local dev (:8000)',
    // Empty string means "same origin as this page".
    url: mode === 'web' ? '' : 'http://localhost:8000',
    token: null,
    available: true,
  };
}

/** Must be awaited once before the app renders. */
export async function initConnections() {
  remotes = read(TARGETS_KEY, []);
  tokens = read(TOKENS_KEY, {});
  activeId = localStorage.getItem(ACTIVE_KEY) || LOCAL_ID;

  migrateLegacy();
  localTarget = await resolveLocalTarget();

  if (activeId !== LOCAL_ID && !remotes.some((r) => r.id === activeId)) activeId = LOCAL_ID;

  ready = true;
  emit();
  return getActiveTarget();
}

export const isReady = () => ready;

export function getTargets() {
  return localTarget ? [localTarget, ...remotes] : [...remotes];
}

export function getActiveTarget() {
  return getTargets().find((t) => t.id === activeId) || localTarget;
}

export const getActiveId = () => activeId;

export function setActive(id) {
  if (!getTargets().some((t) => t.id === id)) return;
  activeId = id;
  persist();
  emit();
}

export function addRemote({ label, url }) {
  const origin = normalizeUrl(url);
  if (!origin) throw new Error('That does not look like a valid address.');

  const existing = remotes.find((r) => r.url === origin);
  if (existing) {
    setActive(existing.id);
    return existing;
  }

  const target = {
    id: newId(),
    kind: 'remote',
    label: (label || '').trim() || new URL(origin).hostname,
    url: origin,
  };
  remotes.push(target);
  activeId = target.id;
  persist();
  emit();
  return target;
}

export function updateRemote(id, patch) {
  const target = remotes.find((r) => r.id === id);
  if (!target) return;
  if (patch.url !== undefined) {
    const origin = normalizeUrl(patch.url);
    if (!origin) throw new Error('That does not look like a valid address.');
    patch = { ...patch, url: origin };
  }
  Object.assign(target, patch);
  persist();
  emit();
}

export function removeRemote(id) {
  remotes = remotes.filter((r) => r.id !== id);
  delete tokens[id];
  if (activeId === id) activeId = LOCAL_ID;
  persist();
  emit();
}

/** Token for a target: the desktop sidecar's is injected, the rest come from logging in. */
export function getToken(id = activeId) {
  const target = getTargets().find((t) => t.id === id);
  if (target?.token) return target.token;
  return tokens[id] || null;
}

export function setToken(id, token) {
  tokens[id] = token;
  persist();
  emit();
}

export function clearToken(id) {
  delete tokens[id];
  persist();
  emit();
}

/** True when the active target can be queried right now (desktop local, or we hold a token). */
export function isAuthenticated(id = activeId) {
  return !!getToken(id);
}

/** Label for the target, preferring the hostname the server reported about itself. */
export function describeTarget(target) {
  if (!target) return 'No target';
  if (target.hostname && target.kind === 'remote') return `${target.label} (${target.hostname})`;
  return target.label;
}
