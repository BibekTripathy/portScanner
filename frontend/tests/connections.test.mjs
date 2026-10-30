/**
 * Exercises the connection store (this machine + saved servers) against a
 * localStorage stub. No test framework: run it with `npm test`.
 */

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
globalThis.window = globalThis;

const c = await import('../src/services/connections.js');

let failures = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : `\n        got ${JSON.stringify(got)}\n       want ${JSON.stringify(want)}`}`);
};

check('bare ip gets scheme + default port', c.normalizeUrl('192.168.1.50'), 'http://192.168.1.50:8000');
check('ip:port kept', c.normalizeUrl('192.168.1.50:9000'), 'http://192.168.1.50:9000');
check('explicit http kept', c.normalizeUrl('http://nas.local:8000'), 'http://nas.local:8000');
check('https keeps implicit 443', c.normalizeUrl('https://mon.example.com'), 'https://mon.example.com');
check('trailing slash and path dropped', c.normalizeUrl('http://10.0.0.2:8000/'), 'http://10.0.0.2:8000');
check('whitespace tolerated', c.normalizeUrl('  10.0.0.3:8000  '), 'http://10.0.0.3:8000');
check('empty input rejected', c.normalizeUrl(''), '');
check('garbage rejected', c.normalizeUrl('http://'), '');

// Adding, selecting, tokens, removal.
const a = c.addRemote({ label: 'prod', url: '10.0.0.5:8000' });
const b = c.addRemote({ url: '10.0.0.6' });
check('label defaults to hostname', b.label, '10.0.0.6');
check('newest add becomes active', c.getActiveId(), b.id);
check('two remotes saved', c.getTargets().length, 2); // no local target until initConnections()
check('duplicate url reuses entry', c.addRemote({ url: 'http://10.0.0.5:8000' }).id, a.id);
check('…and makes it active', c.getActiveId(), a.id);

check('no token before login', c.isAuthenticated(a.id), false);
c.setToken(a.id, 'jwt-a');
check('token stored per target', c.getToken(a.id), 'jwt-a');
check('other target unaffected', c.getToken(b.id), null);
check('tokens persist', JSON.parse(store.get('ps.tokens.v1')), { [a.id]: 'jwt-a' });

c.clearToken(a.id);
check('logout drops only that token', c.isAuthenticated(a.id), false);

c.setToken(b.id, 'jwt-b');
c.removeRemote(b.id);
check('removal drops the target', c.getTargets().some((t) => t.id === b.id), false);
check('removal drops its token', JSON.parse(store.get('ps.tokens.v1'))[b.id], undefined);
check('removing an inactive server keeps the selection', c.getActiveId(), a.id);

c.updateRemote(a.id, { label: 'renamed', url: '10.0.0.9:8001' });
const renamed = c.getTargets().find((t) => t.id === a.id);
check('rename + re-address applied', [renamed.label, renamed.url], ['renamed', 'http://10.0.0.9:8001']);

// Removing the *active* server has to leave us somewhere valid.
c.removeRemote(a.id);
check('removing the active server falls back to local', c.getActiveId(), 'local');
check('all remotes gone', c.getTargets().length, 0);

const d = c.addRemote({ label: 'again', url: '10.0.0.7:8000' });
c.setActive('nope-not-a-target');
check('selecting an unknown target is ignored', c.getActiveId(), d.id);

let threw = false;
try { c.addRemote({ url: 'not a url at all ://' }); } catch { threw = true; }
check('invalid address refused', threw, true);

console.log(failures ? `\n${failures} FAILED` : '\nall passed');
process.exit(failures ? 1 : 0);
