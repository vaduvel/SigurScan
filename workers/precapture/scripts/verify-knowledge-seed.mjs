import assert from 'node:assert/strict';
import path from 'node:path';
import {
  auditSeedCoverage,
  auditRepositoryKnowledgeSeed,
  collectStrictRequiredUrls,
  normalizePreviewUrl,
} from '../src/knowledge-seed-audit.js';

const fixtureKnowledge = {
  claim_verifier_targets: [
    {
      claim_type: 'service status',
      surse_oficiale_folosim: [
        { source_id: 'idroid_home', url: 'https://idroid.ro/' },
        { source_id: 'ignored_test', url: 'https://idroid-status-service.test/card' },
      ],
    },
  ],
};

const fixturePreviewSeed = {
  urls: [
    { label: 'OLX', brand: 'OLX', url: 'https://www.olx.ro/' },
    { label: 'BT root blocked by origin', brand: 'BT', url: 'https://www.bancatransilvania.ro/' },
  ],
};

const required = collectStrictRequiredUrls({
  previewSeed: fixturePreviewSeed,
  brandKnowledgePack: fixtureKnowledge,
});

assert.deepEqual(
  required.map(item => item.url).sort(),
  ['https://idroid.ro/', 'https://www.bancatransilvania.ro/', 'https://www.olx.ro/'],
);

const audit = auditSeedCoverage({
  seedTargets: [
    { id: 'official_olx_home', url: 'https://www.olx.ro/' },
    { id: 'official_idroid_home', url: 'https://idroid.ro/' },
  ],
  requiredUrls: required,
  allowedMissingHosts: ['bancatransilvania.ro'],
});

assert.deepEqual(audit.missingRequired, []);
assert.equal(normalizePreviewUrl('revolut.com/ro-ro'), 'https://revolut.com/ro-ro');
assert.equal(normalizePreviewUrl('https://example.invalid/path'), null);

const repoRoot = path.resolve(import.meta.dirname, '../../..');
const repoAudit = await auditRepositoryKnowledgeSeed({ repoRoot });
assert.deepEqual(repoAudit.required.missingRequired, []);
assert.ok(repoAudit.required.requiredCount >= 10);
assert.ok(repoAudit.candidates.totalCandidates >= repoAudit.required.requiredCount);

console.log(
  `Knowledge seed coverage policy verified: ${repoAudit.required.requiredCount} required URLs covered, ` +
  `${repoAudit.candidates.missingCandidates.length} non-strict knowledge candidates not seeded.`,
);
