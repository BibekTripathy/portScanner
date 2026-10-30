import { useSyncExternalStore } from 'react';
import { subscribe, getTargets, getActiveTarget, getActiveId, isAuthenticated } from '../services/connections';

/**
 * React view of the connection store. Re-renders whenever the target list, the
 * selection or a stored token changes.
 */
export function useConnections() {
  // The snapshot has to be a stable primitive, so subscribe to a cheap signature of
  // the store and read the real values after it changes.
  const signature = useSyncExternalStore(subscribe, () =>
    `${getActiveId()}|${getTargets().map((t) => `${t.id}:${t.url}`).join(',')}|${isAuthenticated() ? 1 : 0}`
  );

  return {
    signature,
    targets: getTargets(),
    active: getActiveTarget(),
    activeId: getActiveId(),
    authenticated: isAuthenticated(),
  };
}
