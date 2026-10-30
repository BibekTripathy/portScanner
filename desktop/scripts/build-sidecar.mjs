/**
 * Builds the Python backend into a single executable and drops it into
 * src-tauri/binaries/ under the name Tauri expects for a sidecar:
 *
 *     portscanner-backend-<rust target triple>[.exe]
 *
 * Run it before `npm run build` (the release workflow does exactly this).
 * Requires `pyinstaller` and the backend requirements on the current PATH/venv.
 */

import { execFileSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, copyFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const desktop = resolve(here, '..');
const repo = resolve(desktop, '..');
const outDir = join(desktop, 'src-tauri', 'binaries');

/** The triple Tauri appends to a sidecar's name, taken from rustc itself. */
function targetTriple() {
  const out = execFileSync('rustc', ['-vV'], { encoding: 'utf8' });
  const match = out.match(/^host:\s*(\S+)$/m);
  if (!match) throw new Error('Could not read the host target triple from `rustc -vV`.');
  return match[1];
}

const triple = targetTriple();
const isWindows = process.platform === 'win32';
const exeSuffix = isWindows ? '.exe' : '';
const sep = isWindows ? ';' : ':';

const buildRoot = join(desktop, '.sidecar-build');
rmSync(buildRoot, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

const args = [
  '--onefile',
  '--noconfirm',
  '--clean',
  '--name', 'portscanner-backend',
  '--distpath', join(buildRoot, 'dist'),
  '--workpath', join(buildRoot, 'work'),
  '--specpath', buildRoot,
  // The backend serves the built UI too, so the headless binary works on its own.
  '--add-data', `${join(repo, 'frontend', 'dist')}${sep}frontend/dist`,
  '--add-data', `${join(repo, 'backend', 'config', 'criticalPorts.yaml')}${sep}backend/config`,
  // Imported by name through uvicorn/sqlalchemy, so PyInstaller cannot see them.
  '--hidden-import', 'uvicorn.logging',
  '--hidden-import', 'uvicorn.loops.auto',
  '--hidden-import', 'uvicorn.protocols.http.auto',
  '--hidden-import', 'uvicorn.protocols.websockets.auto',
  '--hidden-import', 'uvicorn.lifespan.on',
  '--paths', join(repo, 'backend'),
  join(repo, 'backend', 'server.py'),
];

console.log(`Building the backend sidecar for ${triple} ...`);
execSync(`pyinstaller ${args.map((a) => JSON.stringify(a)).join(' ')}`, {
  stdio: 'inherit',
  cwd: repo,
});

const built = join(buildRoot, 'dist', `portscanner-backend${exeSuffix}`);
if (!existsSync(built)) throw new Error(`PyInstaller did not produce ${built}`);

const target = join(outDir, `portscanner-backend-${triple}${exeSuffix}`);
copyFileSync(built, target);
console.log(`\nSidecar ready: ${target}`);
