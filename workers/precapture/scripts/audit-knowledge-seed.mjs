import path from 'node:path';
import { auditRepositoryKnowledgeSeed } from '../src/knowledge-seed-audit.js';

const repoRoot = path.resolve(import.meta.dirname, '../../..');
const audit = await auditRepositoryKnowledgeSeed({ repoRoot });

console.log('=== SigurScan Knowledge -> Pre-Capture Seed Audit ===');
console.log(`required URLs:               ${audit.required.requiredCount}`);
console.log(`worker seed coverage keys:    ${audit.required.seedCount}`);
console.log(`missing required URLs:        ${audit.required.missingRequired.length}`);
console.log(`knowledge candidates:         ${audit.candidates.totalCandidates}`);
console.log(`non-strict missing candidates:${audit.candidates.missingCandidates.length}`);

if (audit.required.missingRequired.length) {
  console.log('\nMissing required URLs:');
  for (const item of audit.required.missingRequired) {
    console.log(`- ${item.url} (${item.source}${item.brand ? `, ${item.brand}` : ''})`);
  }
  process.exitCode = 1;
}

if (audit.candidates.missingCandidates.length) {
  console.log('\nNon-strict knowledge candidates not in worker seed (first 50):');
  for (const item of audit.candidates.missingCandidates.slice(0, 50)) {
    console.log(`- ${item.url} (${item.source}${item.brand ? `, ${item.brand}` : ''})`);
  }
  if (audit.candidates.missingCandidates.length > 50) {
    console.log(`... +${audit.candidates.missingCandidates.length - 50} more`);
  }
}
