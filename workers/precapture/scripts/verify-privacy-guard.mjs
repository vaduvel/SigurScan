import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

const workerDir = path.resolve(import.meta.dirname, '..');
const outDir = await fs.mkdtemp(path.join(os.tmpdir(), 'sigurscan-privacy-guard-'));
const fixture = path.join(workerDir, 'samples', 'privacy_guard_test.json');

try {
  await new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        'src/index.js',
        '--email-source', fixture,
        '--out-dir', outDir,
        '--concurrency', '1',
        '--chromium-sandbox', 'false',
      ],
      {
        cwd: workerDir,
        env: { ...process.env, SUPABASE_URL: '', SUPABASE_SERVICE_KEY: '' },
        stdio: 'inherit',
      },
    );
    child.once('error', reject);
    child.once('exit', code => code === 0 ? resolve() : reject(new Error(`worker exited with ${code}`)));
  });

  const reportText = await fs.readFile(path.join(outDir, 'final_report.json'), 'utf8');
  const report = JSON.parse(reportText);
  const files = await fs.readdir(outDir);

  if (files.includes('manifest.json')) throw new Error('privacy-skipped URL was persisted to manifest');
  if (report.skippedSensitive !== 1) throw new Error('privacy skip metric was not recorded');
  if (report.failedDeadUrls !== 0) throw new Error('privacy skip must not be counted as a failed/dead URL');
  if (/fake-private-token|test@example\.com|\/reset\?/i.test(reportText)) {
    throw new Error('sensitive URL data leaked into final_report.json');
  }

  console.log('Privacy guard verified: no sensitive URL persistence.');
} finally {
  await fs.rm(outDir, { recursive: true, force: true });
}
