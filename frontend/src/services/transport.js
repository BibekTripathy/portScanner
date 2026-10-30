/**
 * transport.js
 *
 * One HTTP call, performed the right way for the shell we are in.
 *
 * In the browser this is just `fetch`. In the desktop app the request is handed to
 * the Tauri shell and made from Rust instead, because the webview runs in a secure
 * context and would refuse a plain-HTTP call to a server on your LAN as mixed
 * content -- which is exactly what monitoring a remote machine needs.
 */

import { isDesktop } from './runtime';

/** A connection-level failure (unreachable host, refused, timed out). */
export class NetworkError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NetworkError';
  }
}

/**
 * @returns {Promise<{ status: number, ok: boolean, text: string }>}
 * @throws {NetworkError} when the server could not be reached at all
 */
export async function httpRequest(url, { method = 'GET', headers = {}, body = null } = {}) {
  if (isDesktop()) {
    try {
      const res = await window.__TAURI__.core.invoke('http_request', {
        req: { url, method, headers, body },
      });
      return {
        status: res.status,
        ok: res.status >= 200 && res.status < 300,
        text: res.body,
      };
    } catch (err) {
      throw new NetworkError(typeof err === 'string' ? err : err?.message || 'Request failed');
    }
  }

  let res;
  try {
    // `fetch` rejects a body on GET/HEAD, so only pass one when there is one.
    res = await fetch(url, { method, headers, ...(body === null ? {} : { body }) });
  } catch {
    throw new NetworkError('Could not reach that address.');
  }
  return { status: res.status, ok: res.ok, text: await res.text() };
}

/** As above, but parses a JSON body. Returns `null` when the body is not JSON. */
export async function httpJson(url, options) {
  const res = await httpRequest(url, options);
  let json = null;
  try {
    json = JSON.parse(res.text);
  } catch {
    /* left as null; callers report it against the status code */
  }
  return { ...res, json };
}
