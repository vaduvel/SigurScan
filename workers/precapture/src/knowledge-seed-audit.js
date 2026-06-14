import fs from 'node:fs/promises';
import path from 'node:path';

const RESERVED_SUFFIXES = ['.test', '.invalid', '.example', '.localhost'];
const DEFAULT_ALLOWED_MISSING_HOSTS = [
  'bancatransilvania.ro',
  'dnsc.ro',
  'help.revolut.com',
];

function isReservedHost(hostname) {
  const host = String(hostname || '').toLowerCase();
  return RESERVED_SUFFIXES.some(suffix => host === suffix.slice(1) || host.endsWith(suffix));
}

function hasLikelyHost(value) {
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+(\/.*)?$/i.test(value);
}

export function normalizePreviewUrl(value) {
  const raw = String(value || '').trim().replace(/[)>}\]",'`]+$/g, '');
  if (!raw) return null;
  const withScheme = /^https?:\/\//i.test(raw)
    ? raw
    : (hasLikelyHost(raw) ? `https://${raw}` : null);
  if (!withScheme) return null;

  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return null;
  if (isReservedHost(parsed.hostname)) return null;

  parsed.protocol = 'https:';
  parsed.hostname = parsed.hostname.toLowerCase();
  parsed.hash = '';
  parsed.search = '';
  if (parsed.pathname !== '/') parsed.pathname = parsed.pathname.replace(/\/+$/, '');
  return parsed.toString();
}

function hostCoverageKey(url) {
  const normalized = normalizePreviewUrl(url);
  if (!normalized) return null;
  const parsed = new URL(normalized);
  const host = parsed.hostname.replace(/^www\./, '');
  const pathKey = parsed.pathname === '/' ? '/' : parsed.pathname.replace(/\/+$/, '');
  return `${host}${pathKey}`;
}

function hostFromUrl(url) {
  const normalized = normalizePreviewUrl(url);
  if (!normalized) return null;
  return new URL(normalized).hostname.replace(/^www\./, '');
}

function addUniqueUrl(items, seen, url, source, brand = null, required = false, match = 'exact') {
  const normalized = normalizePreviewUrl(url);
  if (!normalized) return;
  const host = hostFromUrl(normalized);
  const key = match === 'host' ? `${host}/` : hostCoverageKey(normalized);
  if (!key || seen.has(key)) return;
  seen.add(key);
  items.push({ url: normalized, key, source, brand, required, match });
}

export function collectStrictRequiredUrls({ previewSeed = {}, brandKnowledgePack = {} } = {}) {
  const items = [];
  const seen = new Set();

  for (const entry of previewSeed.urls || []) {
    addUniqueUrl(items, seen, entry?.url, 'backend_preview_seed', entry?.brand || entry?.label, true, 'exact');
  }

  for (const target of brandKnowledgePack.claim_verifier_targets || []) {
    for (const source of target.surse_oficiale_folosim || []) {
      addUniqueUrl(items, seen, source?.url, 'claim_verifier_target', target.claim_type, true, 'host');
    }
  }

  return items.sort((a, b) => a.key.localeCompare(b.key));
}

export function collectKnowledgeCandidateUrls({
  brandKnowledgePack = {},
  officialRegistry = {},
  officialUrlPatch = {},
} = {}) {
  const items = [];
  const seen = new Set();

  for (const item of collectStrictRequiredUrls({ brandKnowledgePack })) {
    addUniqueUrl(items, seen, item.url, item.source, item.brand, true, item.match);
  }

  for (const [brand, domains] of Object.entries(brandKnowledgePack.brand_registry || {})) {
    for (const domain of domains || []) {
      addUniqueUrl(items, seen, domain, 'brand_registry', brand, false);
    }
  }

  for (const [brand, domains] of Object.entries(brandKnowledgePack.brand_domain_exceptions || {})) {
    for (const domain of domains || []) {
      addUniqueUrl(items, seen, domain, 'brand_domain_exception', brand, false);
    }
  }

  const registryRows = officialRegistry.official_registry_updates || [];
  for (const row of registryRows) {
    for (const domain of row.official_domains || []) {
      addUniqueUrl(items, seen, domain, 'official_registry_domain', row.display_name || row.brand_id, false);
    }
    for (const domain of row.approved_tracking_or_partner_domains || []) {
      addUniqueUrl(items, seen, domain, 'official_registry_partner', row.display_name || row.brand_id, false);
    }
    for (const source of row.source_urls || []) {
      addUniqueUrl(items, seen, source?.url, 'official_registry_source', row.display_name || row.brand_id, false);
    }
  }

  const officialPatchRows = officialUrlPatch.entries || [];
  for (const row of officialPatchRows) {
    addUniqueUrl(items, seen, row?.url, 'official_url_patch', row?.display_name || row?.brand_id, false);
    const evidenceUrl = row?.official_evidence_url;
    if (evidenceUrl && evidenceUrl !== row?.url) {
      addUniqueUrl(items, seen, evidenceUrl, 'official_url_patch_evidence', row?.display_name || row?.brand_id, false);
    }
  }

  return items.sort((a, b) => a.key.localeCompare(b.key));
}

export function auditSeedCoverage({
  seedTargets = [],
  requiredUrls = [],
  allowedMissingHosts = DEFAULT_ALLOWED_MISSING_HOSTS,
} = {}) {
  const seedKeys = new Set();
  const seedHosts = new Set();
  for (const target of seedTargets) {
    const key = hostCoverageKey(target?.url);
    if (key) seedKeys.add(key);
    const host = hostFromUrl(target?.url);
    if (host) seedHosts.add(host);
  }

  const allowedHosts = new Set(allowedMissingHosts.map(host => String(host).replace(/^www\./, '').toLowerCase()));
  const missingRequired = [];
  for (const item of requiredUrls) {
    const host = hostFromUrl(item.url);
    if (item.match === 'host' && host && seedHosts.has(host)) continue;
    if (item.match !== 'host' && seedKeys.has(item.key)) continue;
    if (host && allowedHosts.has(host)) continue;
    missingRequired.push(item);
  }

  return {
    seedCount: seedKeys.size,
    requiredCount: requiredUrls.length,
    missingRequired,
  };
}

async function loadJson(filePath) {
  return JSON.parse(await fs.readFile(filePath, 'utf8'));
}

export async function auditRepositoryKnowledgeSeed({
  repoRoot,
  allowedMissingHosts = DEFAULT_ALLOWED_MISSING_HOSTS,
} = {}) {
  if (!repoRoot) throw new Error('repoRoot is required');
  const workerSeed = await loadJson(path.join(repoRoot, 'workers/precapture/samples/official_preview_targets.ro.json'));
  const previewSeed = await loadJson(path.join(repoRoot, 'backend/data/preview_seed_urls_ro.json'));
  const brandKnowledgePack = await loadJson(path.join(repoRoot, 'backend/data/brand_knowledge_pack.json'));
  const officialRegistry = await loadJson(path.join(repoRoot, 'backend/data/knowledge/official_registry_v2026_06_08.json'));
  const officialUrlPatch = await loadJson(path.join(repoRoot, 'backend/data/knowledge/official_url_patch_2026_06_14.json'));

  const seedTargets = workerSeed.targets || [];
  const requiredUrls = collectStrictRequiredUrls({ previewSeed, brandKnowledgePack });
  const candidateUrls = collectKnowledgeCandidateUrls({ brandKnowledgePack, officialRegistry, officialUrlPatch });
  const required = auditSeedCoverage({ seedTargets, requiredUrls, allowedMissingHosts });
  const candidateAudit = auditSeedCoverage({
    seedTargets,
    requiredUrls: candidateUrls,
    allowedMissingHosts,
  });

  return {
    required,
    candidates: {
      totalCandidates: candidateUrls.length,
      missingCandidates: candidateAudit.missingRequired,
    },
  };
}
