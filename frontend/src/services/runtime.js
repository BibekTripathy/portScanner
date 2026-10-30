/**
 * runtime.js
 *
 * Tells the UI which shell it is running inside, since the same React build is used
 * three ways:
 *
 *   desktop - inside the Tauri window, which has already started a private backend
 *             on loopback and will hand us its URL and one-shot token.
 *   web     - served by the backend itself (the Docker image), so the machine being
 *             monitored is whatever served this page.
 *   dev     - `npm run dev`, where the backend is assumed to be on :8000.
 */

export const isDesktop = () => typeof window !== 'undefined' && !!window.__TAURI__;

export const runtime = () => {
  if (isDesktop()) return 'desktop';
  return import.meta.env.PROD ? 'web' : 'dev';
};

/**
 * Ask the Tauri shell where it put the local backend.
 * Returns `{ url, token }`, or null when we are not in the desktop app.
 */
export async function getLocalBackend() {
  if (!isDesktop()) return null;
  try {
    return await window.__TAURI__.core.invoke('local_backend');
  } catch (err) {
    console.error('Could not reach the local backend sidecar:', err);
    return null;
  }
}
