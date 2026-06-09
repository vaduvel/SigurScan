#!/usr/bin/env node
import 'dotenv/config';
import fs from 'node:fs/promises';
import fssync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import dns from 'node:dns/promises';
import net from 'node:net';
import { Command } from 'commander';
import * as cheerio from 'cheerio';
import LinkifyIt from 'linkify-it';
import { simpleParser } from 'mailparser';
import { chromium } from 'playwright';
import { createClient } from '@supabase/supabase-js';
import ipaddr from 'ipaddr.js';
import pLimit from 'p-limit';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const linkify = new LinkifyIt();

const program = new Command();
program
  .requiredOption('--email-source <path>', 'Folder/file containing .eml/.html/.txt/.json URL inputs')
  .option('--out-dir <path>', 'Local output dir when Supabase is not configured', 'output')
  .option('--bucket <name>', 'Supabase storage bucket', process.env.STORAGE_BUCKET || 'previews')
  .option('--cache-table <name>', 'Supabase cache table', process.env.CACHE_TABLE || 'fast_preview_cache')
  .option('--alias-table <name>', 'Optional Supabase alias table from original URL hash to final URL hash', process.env.ALIAS_TABLE || 'fast_preview_alias_cache')
  .option('--cache-ttl-days <days>', 'Cache TTL days', process.env.CACHE_TTL_DAYS || '7')
  .option('--max-redirect-hops <n>', 'Maximum redirect hops', process.env.MAX_REDIRECT_HOPS || '10')
  .option('--nav-timeout-seconds <seconds>', 'Hard navigation timeout', process.env.NAV_TIMEOUT_SECONDS || '20')
  .option('--max-screenshot-height <px>', 'Maximum screenshot height in pixels', process.env.MAX_SCREENSHOT_HEIGHT || '5000')
  .option('--max-urls <n>', 'Maximum URLs to process in one run', process.env.MAX_URLS || '50')
  .option('--concurrency <n>', 'Concurrent browser captures', process.env.CONCURRENCY || '2')
  .option('--user-agent <ua>', 'Browser user-agent', process.env.USER_AGENT || 'SigurScanPreviewBot/1.0 (+https://sigurscan.ro/bot)')
  .option('--chromium-sandbox <bool>', 'Enable Chromium sandbox when the host supports it', process.env.CHROMIUM_SANDBOX || 'true')
  .option('--cleanup-expired <bool>', 'Delete expired cache rows and screenshots before capture', process.env.CLEANUP_EXPIRED || 'true')
  .option('--cleanup-limit <n>', 'Maximum expired cache rows to delete in one run', process.env.CLEANUP_LIMIT || '200')
  .option('--skip-reserved <bool>', 'Skip .test/.example/.invalid/.localhost', 'true')
  .option('--dry-run', 'Only parse/extract URLs; no browser, no upload')
  .parse(process.argv);

const opts = program.opts();
const CACHE_TTL_DAYS = Number(opts.cacheTtlDays);
const MAX_REDIRECT_HOPS = Number(opts.maxRedirectHops);
const NAV_TIMEOUT_MS = Number(opts.navTimeoutSeconds) * 1000;
const MAX_SCREENSHOT_HEIGHT = Math.max(600, Number(opts.maxScreenshotHeight) || 5000);
const MAX_URLS = Math.max(1, Number(opts.maxUrls) || 50);
const CONCURRENCY = Number(opts.concurrency);
const SKIP_RESERVED = String(opts.skipReserved).toLowerCase() !== 'false';
const CHROMIUM_SANDBOX = String(opts.chromiumSandbox).toLowerCase() !== 'false';
const CLEANUP_EXPIRED = String(opts.cleanupExpired).toLowerCase() !== 'false';
const CLEANUP_LIMIT = Math.max(1, Number(opts.cleanupLimit) || 200);

const supabaseEnabled = Boolean(process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY);
const supabase = supabaseEnabled
  ? createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY, {
      auth: { persistSession: false },
      global: { headers: { 'x-sigurscan-worker': 'precapture-v1' } }
    })
  : null;

const stats = {
  totalEmailsParsed: 0,
  totalRawUrlsFound: 0,
  uniqueUrlsAfterDedup: 0,
  screenshotsCapturedNew: 0,
  skippedAlreadyCachedFresh: 0,
  skippedReserved: 0,
  expiredRowsDeleted: 0,
  expiredScreenshotsDeleted: 0,
  cleanupErrors: [],
  failedDeadUrls: 0,
  failed: []
};

function nowIso() {
  return new Date().toISOString();
}

function expiresAtIso(ttlDays = CACHE_TTL_DAYS) {
  const ttlMs = Number(ttlDays) * 24 * 60 * 60 * 1000;
  return new Date(Date.now() + ttlMs).toISOString();
}

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function sha256Buffer(buffer) {
  return crypto.createHash('sha256').update(buffer).digest('hex');
}

function normalizeUrl(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let cleaned = raw.trim()
    .replace(/^['"<({\[]+/, '')
    .replace(/[>'")},\]]+$/, '');

  if (!cleaned) return null;
  if (/^www\./i.test(cleaned)) cleaned = `https://${cleaned}`;

  let url;
  try {
    url = new URL(cleaned);
  } catch {
    return null;
  }

  if (!['http:', 'https:'].includes(url.protocol)) return null;
  url.hash = '';
  url.hostname = url.hostname.toLowerCase();

  // Normalize default ports.
  if ((url.protocol === 'https:' && url.port === '443') || (url.protocol === 'http:' && url.port === '80')) {
    url.port = '';
  }

  return url.toString();
}

function isReservedHost(hostname) {
  const h = hostname.toLowerCase().replace(/\.$/, '');
  return h === 'example.com' || h === 'example.org' || h === 'example.net'
    ? false
    : h.endsWith('.test') || h === 'test' ||
      h.endsWith('.example') || h === 'example' ||
      h.endsWith('.invalid') || h === 'invalid' ||
      h.endsWith('.localhost') || h === 'localhost';
}

function hostnameFromUrl(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

function parsedHttpUrl(url) {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function disallowedPortReason(parsed) {
  if (!parsed) return 'invalid_url';
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  return ['80', '443'].includes(port) ? null : `blocked_port:${port}`;
}

function privacySkipReason(url) {
  const parsed = parsedHttpUrl(url);
  if (!parsed) return 'invalid_url';
  const pathAndQuery = `${parsed.pathname}?${parsed.searchParams.toString()}`.toLowerCase();
  if (/(reset|magic[-_]?link|password|session|auth|token|otp|invoice|factura|payment|plata)/i.test(pathAndQuery)) {
    return 'privacy_skipped:sensitive_path_or_query';
  }
  for (const [key, value] of parsed.searchParams.entries()) {
    const k = key.toLowerCase();
    const v = String(value || "");
    if (/(token|session|auth|otp|code|email|phone|cnp|iban|card|cvv|customer|client|user|uid)/i.test(k)) {
      return `privacy_skipped:sensitive_param:${k}`;
    }
    if (/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(v)) {
      return `privacy_skipped:email_value:${k}`;
    }
    if (/(\+?4?0)?7\d{8}\b/.test(v.replace(/[\s.-]/g, ""))) {
      return `privacy_skipped:phone_value:${k}`;
    }
    if (v.length >= 48 && /[A-Za-z0-9_-]{32,}/.test(v)) {
      return `privacy_skipped:opaque_token:${k}`;
    }
  }
  return null;
}

function finalDomainFromUrl(url) {
  return hostnameFromUrl(url) || 'unknown';
}

function seedCategoryFromInput(input) {
  const ids = Array.isArray(input?.sourceEmailIds) ? input.sourceEmailIds : [];
  const joined = ids.join(' ').toLowerCase();
  if (joined.includes('bank') || joined.includes('banca') || joined.includes('bt_') || joined.includes('bcr') || joined.includes('ing')) return 'official_bank';
  if (joined.includes('fan') || joined.includes('sameday') || joined.includes('posta') || joined.includes('curier') || joined.includes('courier') || joined.includes('cargus')) return 'courier';
  if (joined.includes('orange') || joined.includes('yoxo') || joined.includes('vodafone') || joined.includes('digi') || joined.includes('telekom')) return 'telecom';
  if (joined.includes('emag') || joined.includes('olx') || joined.includes('altex') || joined.includes('flanco')) return 'marketplace';
  if (joined.includes('anaf') || joined.includes('dnsc') || joined.includes('bnr') || joined.includes('gov') || joined.includes('ghiseul')) return 'public';
  if (joined.includes('onelink') || joined.includes('app_link') || joined.includes('aka_ms') || joined.includes('deeplink')) return 'deeplink';
  return 'official_seed';
}

function statusFromError(error) {
  const text = String(error || '').toLowerCase();
  if (text.includes('blocked') || text.includes('reserved') || text.includes('private_ip')) return 'blocked';
  if (text.includes('dns_no_records') || text.includes('http_status:404') || text.includes('http_status:410')) return 'dead';
  return 'error';
}

function makeBaseRow({ input, finalUrl, redirectChain, status, reachable, error }) {
  const normalizedFinal = normalizeUrl(finalUrl) || finalUrl;
  const capturedAt = nowIso();
  return {
    url_hash: sha256(normalizedFinal),
    original_url: input.originalUrl,
    final_url: normalizedFinal,
    final_domain: finalDomainFromUrl(normalizedFinal),
    redirect_chain: redirectChain,
    http_status: null,
    page_title: null,
    screenshot_path: null,
    screenshot_w: null,
    screenshot_h: null,
    content_hash: null,
    captured_at: capturedAt,
    expires_at: expiresAtIso(),
    source_email_id: input.sourceEmailIds,
    reachable,
    status,
    source: 'precapture_worker',
    seed_category: seedCategoryFromInput(input),
    error
  };
}

function isPrivateIp(ip) {
  try {
    const addr = ipaddr.parse(ip);
    const range = addr.range();
    return [
      'unspecified', 'broadcast', 'multicast', 'linkLocal', 'loopback',
      'private', 'uniqueLocal', 'ipv4Mapped', 'carrierGradeNat', 'reserved'
    ].includes(range);
  } catch {
    return true;
  }
}

async function resolveHostSafe(hostname, dnsCache) {
  if (!hostname) return { ok: false, reason: 'missing_hostname', ips: [] };
  if (hostname.toLowerCase().replace(/\.$/, '') === 'metadata.google.internal') {
    return { ok: false, reason: 'blocked_metadata_host', ips: [] };
  }

  if (net.isIP(hostname)) {
    return isPrivateIp(hostname)
      ? { ok: false, reason: `blocked_private_ip:${hostname}`, ips: [hostname] }
      : { ok: true, reason: null, ips: [hostname] };
  }

  const cached = dnsCache.get(hostname);
  if (cached) return cached;

  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: false });
    const ips = records.map(r => r.address);
    if (!ips.length) {
      const out = { ok: false, reason: 'dns_no_records', ips: [] };
      dnsCache.set(hostname, out);
      return out;
    }
    const privateIps = ips.filter(isPrivateIp);
    const out = privateIps.length
      ? { ok: false, reason: `blocked_private_ip:${privateIps.join(',')}`, ips }
      : { ok: true, reason: null, ips };
    dnsCache.set(hostname, out);
    return out;
  } catch (err) {
    const out = { ok: false, reason: `dns_error:${err.code || err.message}`, ips: [] };
    dnsCache.set(hostname, out);
    return out;
  }
}

function extractUrlsFromText(text) {
  if (!text) return [];
  const matches = linkify.match(text) || [];
  return matches.map(m => m.url);
}

function extractUrlsFromHtml(html) {
  if (!html) return [];
  const urls = [];
  const $ = cheerio.load(html, { decodeEntities: true });
  const attrs = ['href', 'src', 'action', 'data-href', 'data-url'];
  for (const attr of attrs) {
    $(`[${attr}]`).each((_, el) => {
      const val = $(el).attr(attr);
      if (val) urls.push(val);
    });
  }
  urls.push(...extractUrlsFromText($.text()));
  return urls;
}

async function listFilesRecursive(sourcePath) {
  const st = await fs.stat(sourcePath);
  if (st.isFile()) return [sourcePath];
  const out = [];
  const entries = await fs.readdir(sourcePath, { withFileTypes: true });
  for (const e of entries) {
    const p = path.join(sourcePath, e.name);
    if (e.isDirectory()) out.push(...await listFilesRecursive(p));
    else out.push(p);
  }
  return out;
}

function sourceIdFor(filePath) {
  return path.basename(filePath);
}

async function parseJsonInput(filePath, content) {
  const sourceId = sourceIdFor(filePath);
  let json;
  try { json = JSON.parse(content); } catch { return []; }
  const rows = [];

  function addUrl(u, id = sourceId) {
    if (typeof u === 'string') rows.push({ url: u, sourceEmailId: id });
  }

  if (Array.isArray(json)) {
    for (const item of json) {
      if (typeof item === 'string') addUrl(item);
      else if (item && typeof item === 'object') {
        const id = item.source_email_id || item.source_id || item.id || sourceId;
        if (item.url) addUrl(item.url, String(id));
        if (item.input) addUrl(item.input, String(id));
        if (Array.isArray(item.urls)) item.urls.forEach(u => addUrl(u, String(id)));
      }
    }
  } else if (json && typeof json === 'object') {
    if (Array.isArray(json.urls)) json.urls.forEach(u => addUrl(typeof u === 'string' ? u : u.url, String(u.id || u.brand_id || sourceId)));
    if (Array.isArray(json.targets)) json.targets.forEach(u => addUrl(typeof u === 'string' ? u : u.url, String(u.id || u.brand_id || sourceId)));
    if (Array.isArray(json.test_cases)) json.test_cases.forEach(tc => {
      const id = tc.id || sourceId;
      if (tc.input) addUrl(tc.input, String(id));
      if (Array.isArray(tc.urls)) tc.urls.forEach(u => addUrl(u, String(id)));
    });
  }
  return rows;
}

async function parseFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const buf = await fs.readFile(filePath);
  const content = buf.toString('utf8');
  const sourceEmailId = sourceIdFor(filePath);

  if (ext === '.eml') {
    const parsed = await simpleParser(buf);
    const urls = [];
    urls.push(...extractUrlsFromText(parsed.text || ''));
    urls.push(...extractUrlsFromHtml(parsed.html || ''));
    const id = parsed.messageId || sourceEmailId;
    return urls.map(url => ({ url, sourceEmailId: id }));
  }

  if (ext === '.html' || ext === '.htm') {
    return extractUrlsFromHtml(content).map(url => ({ url, sourceEmailId }));
  }

  if (ext === '.json') {
    return parseJsonInput(filePath, content);
  }

  if (['.txt', '.md', '.csv'].includes(ext)) {
    return extractUrlsFromText(content).map(url => ({ url, sourceEmailId }));
  }

  return [];
}

async function extractAllUrls(sourcePath) {
  const files = await listFilesRecursive(sourcePath);
  const rawRows = [];
  for (const file of files) {
    try {
      const rows = await parseFile(file);
      if (rows.length) stats.totalEmailsParsed += 1;
      rawRows.push(...rows);
    } catch (err) {
      stats.failed.push({ original_url: null, error: `parse_failed:${path.basename(file)}:${err.message}` });
    }
  }
  stats.totalRawUrlsFound = rawRows.length;

  const byUrl = new Map();
  for (const row of rawRows) {
    const norm = normalizeUrl(row.url);
    if (!norm) continue;
    const existing = byUrl.get(norm) || { originalUrl: norm, sourceEmailIds: new Set() };
    existing.sourceEmailIds.add(String(row.sourceEmailId || 'unknown'));
    byUrl.set(norm, existing);
  }
  stats.uniqueUrlsAfterDedup = byUrl.size;
  return [...byUrl.values()]
    .slice(0, MAX_URLS)
    .map(x => ({ originalUrl: x.originalUrl, sourceEmailIds: [...x.sourceEmailIds] }));
}

async function ensureOutDirs(outDir) {
  await fs.mkdir(path.join(outDir, 'screenshots'), { recursive: true });
}

async function loadLocalManifest(outDir) {
  const manifestPath = path.join(outDir, 'manifest.json');
  if (!fssync.existsSync(manifestPath)) return [];
  try {
    const rows = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
    return Array.isArray(rows) ? rows : [];
  } catch {
    return [];
  }
}

function isFresh(rowOrCapturedAt, ttlDays) {
  const expiresAt = typeof rowOrCapturedAt === 'object' && rowOrCapturedAt
    ? rowOrCapturedAt.expires_at
    : null;
  if (expiresAt) {
    const expiresTs = new Date(expiresAt).getTime();
    return Number.isFinite(expiresTs) && expiresTs > Date.now();
  }
  const capturedAt = typeof rowOrCapturedAt === 'object' && rowOrCapturedAt
    ? rowOrCapturedAt.captured_at
    : rowOrCapturedAt;
  if (!capturedAt) return false;
  const t = new Date(capturedAt).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t < ttlDays * 24 * 60 * 60 * 1000;
}

async function isCachedFresh(urlHash, outDir, table, ttlDays) {
  if (supabaseEnabled) {
    const { data, error } = await supabase
      .from(table)
      .select('url_hash,captured_at,expires_at,screenshot_path,reachable,status')
      .eq('url_hash', urlHash)
      .maybeSingle();
    if (error) return false;
    return Boolean(data && isFresh(data, ttlDays) && data.status === 'ready' && data.screenshot_path);
  }
  const rows = await loadLocalManifest(outDir);
  const found = rows.find(r => r.url_hash === urlHash);
  return Boolean(found && isFresh(found, ttlDays) && found.status === 'ready' && found.screenshot_path);
}

async function uploadOrWrite(row, screenshotBuffer, outDir, bucket, table) {
  if (supabaseEnabled) {
    if (screenshotBuffer && row.screenshot_path) {
      const { error: uploadError } = await supabase.storage
        .from(bucket)
        .upload(row.screenshot_path, screenshotBuffer, {
          contentType: 'image/png',
          upsert: true
        });
      if (uploadError) throw new Error(`supabase_storage_upload_failed:${uploadError.message}`);
    }
    const { error } = await supabase
      .from(table)
      .upsert(row, { onConflict: 'url_hash' });
    if (error) throw new Error(`supabase_upsert_failed:${error.message}`);

    // Optional but highly recommended: map the original URL to the final-url cache key.
    // This lets the API serve cached preview instantly when the same tracking/original URL appears again.
    if (row.original_url && row.final_url && opts.aliasTable) {
      const originalNorm = normalizeUrl(row.original_url) || row.original_url;
      const { error: aliasError } = await supabase
        .from(opts.aliasTable)
        .upsert({
          alias_hash: sha256(originalNorm),
          final_url_hash: row.url_hash,
          original_url: row.original_url,
          captured_at: row.captured_at,
          expires_at: row.expires_at
        }, { onConflict: 'alias_hash' });
      if (aliasError) throw new Error(`supabase_alias_upsert_failed:${aliasError.message}`);
    }
    return;
  }

  await ensureOutDirs(outDir);
  if (screenshotBuffer && row.screenshot_path) {
    await fs.writeFile(path.join(outDir, row.screenshot_path), screenshotBuffer);
  }
  const manifestPath = path.join(outDir, 'manifest.json');
  const existing = await loadLocalManifest(outDir);
  const idx = existing.findIndex(r => r.url_hash === row.url_hash);
  if (idx >= 0) existing[idx] = row;
  else existing.push(row);
  await fs.writeFile(manifestPath, JSON.stringify(existing, null, 2));
}

async function cleanupExpiredSupabaseCache(bucket, table) {
  if (!supabaseEnabled || !CLEANUP_EXPIRED) return;

  const { data, error } = await supabase
    .from(table)
    .select('url_hash,screenshot_path')
    .lt('expires_at', nowIso())
    .limit(CLEANUP_LIMIT);
  if (error) {
    stats.cleanupErrors.push(`expired_cache_select_failed:${error.message}`);
    return;
  }

  const rows = Array.isArray(data) ? data : [];
  if (!rows.length) return;

  const screenshotPaths = [...new Set(
    rows
      .map(row => String(row?.screenshot_path || '').trim().replace(/^\/+/, ''))
      .filter(Boolean)
  )];
  if (screenshotPaths.length) {
    const { error: storageError } = await supabase.storage.from(bucket).remove(screenshotPaths);
    if (storageError) {
      stats.cleanupErrors.push(`expired_screenshot_delete_failed:${storageError.message}`);
    } else {
      stats.expiredScreenshotsDeleted += screenshotPaths.length;
    }
  }

  const hashes = rows.map(row => row?.url_hash).filter(Boolean);
  if (!hashes.length) return;
  const { error: deleteError } = await supabase.from(table).delete().in('url_hash', hashes);
  if (deleteError) {
    stats.cleanupErrors.push(`expired_cache_delete_failed:${deleteError.message}`);
    return;
  }
  stats.expiredRowsDeleted += hashes.length;
}

async function createBrowser() {
  return chromium.launch({
    headless: true,
    chromiumSandbox: CHROMIUM_SANDBOX
  });
}

async function getScreenshotClip(page) {
  const size = await page.evaluate((maxHeight) => {
    const doc = document.documentElement;
    const body = document.body;
    const width = Math.max(
      window.innerWidth || 0,
      doc?.clientWidth || 0,
      doc?.scrollWidth || 0,
      body?.scrollWidth || 0
    );
    const height = Math.max(
      window.innerHeight || 0,
      doc?.clientHeight || 0,
      doc?.scrollHeight || 0,
      body?.scrollHeight || 0
    );
    return {
      width: Math.max(1, Math.min(Math.ceil(width || 1365), 1600)),
      height: Math.max(1, Math.min(Math.ceil(height || 900), maxHeight))
    };
  }, MAX_SCREENSHOT_HEIGHT).catch(() => ({ width: 1365, height: 900 }));
  return { x: 0, y: 0, width: size.width, height: size.height };
}

async function captureOne(browser, input, outDir, bucket, table) {
  const originalUrl = input.originalUrl;
  const originalHost = hostnameFromUrl(originalUrl);
  const originalParsed = parsedHttpUrl(originalUrl);
  const blockedPort = disallowedPortReason(originalParsed);
  const privacyReason = privacySkipReason(originalUrl);

  if (blockedPort || privacyReason) {
    const finalNorm = normalizeUrl(originalUrl) || originalUrl;
    const reason = blockedPort || privacyReason;
    const row = makeBaseRow({
      input,
      finalUrl: finalNorm,
      redirectChain: [originalUrl],
      status: 'skipped',
      reachable: false,
      error: reason
    });
    await uploadOrWrite(row, null, outDir, bucket, table);
    stats.failedDeadUrls += 1;
    stats.failed.push({ original_url: originalUrl, error: reason });
    return row;
  }

  if (SKIP_RESERVED && originalHost && isReservedHost(originalHost)) {
    const finalNorm = normalizeUrl(originalUrl) || originalUrl;
    const row = makeBaseRow({
      input,
      finalUrl: finalNorm,
      redirectChain: [originalUrl],
      status: 'skipped',
      reachable: false,
      error: 'reserved_domain_skipped'
    });
    await uploadOrWrite(row, null, outDir, bucket, table);
    stats.skippedReserved += 1;
    return row;
  }

  const dnsCache = new Map();
  const preflight = await resolveHostSafe(originalHost, dnsCache);
  if (!preflight.ok) {
    const finalNorm = normalizeUrl(originalUrl) || originalUrl;
    const row = makeBaseRow({
      input,
      finalUrl: finalNorm,
      redirectChain: [originalUrl],
      status: statusFromError(preflight.reason),
      reachable: false,
      error: preflight.reason
    });
    await uploadOrWrite(row, null, outDir, bucket, table);
    stats.failedDeadUrls += 1;
    stats.failed.push({ original_url: originalUrl, error: preflight.reason });
    return row;
  }

  const context = await browser.newContext({
    userAgent: opts.userAgent,
    javaScriptEnabled: true,
    acceptDownloads: false,
    serviceWorkers: 'block',
    permissions: [],
    viewport: { width: 1365, height: 900 },
    deviceScaleFactor: 1,
    ignoreHTTPSErrors: false
  });
  const page = await context.newPage();
  page.setDefaultTimeout(NAV_TIMEOUT_MS);
  page.setDefaultNavigationTimeout(NAV_TIMEOUT_MS);

  page.on('dialog', async d => { try { await d.dismiss(); } catch {} });
  page.on('download', async d => { try { await d.cancel(); } catch {} });

  await page.route('**/*', async route => {
    const req = route.request();
    const url = req.url();
    let parsed;
    try { parsed = new URL(url); } catch { return route.abort('blockedbyclient'); }
    if (!['http:', 'https:'].includes(parsed.protocol)) return route.abort('blockedbyclient');
    if (disallowedPortReason(parsed) || privacySkipReason(url)) return route.abort('blockedbyclient');
    if (SKIP_RESERVED && isReservedHost(parsed.hostname)) return route.abort('blockedbyclient');

    const check = await resolveHostSafe(parsed.hostname, dnsCache);
    if (!check.ok) return route.abort('blockedbyclient');

    // Avoid accidental file downloads/navigation to binary formats. We still allow images/css/fonts needed for render.
    const lowerPath = parsed.pathname.toLowerCase();
    if (req.isNavigationRequest() && /\.(apk|exe|msi|dmg|pkg|zip|rar|7z|tar|gz|iso|jar|scr|bat|cmd|ps1)$/i.test(lowerPath)) {
      return route.abort('blockedbyclient');
    }
    return route.continue();
  });

  let row;
  let screenshotBuffer = null;
  try {
    const response = await page.goto(originalUrl, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS });
    await page.waitForTimeout(1000);

    const finalUrlRaw = page.url();
    const finalNorm = normalizeUrl(finalUrlRaw) || finalUrlRaw;
    const finalHost = hostnameFromUrl(finalNorm);

    if (SKIP_RESERVED && finalHost && isReservedHost(finalHost)) {
      throw new Error('final_reserved_domain_skipped');
    }

    const finalHash = sha256(finalNorm);
    const redirectChain = response ? buildRedirectChain(response) : [originalUrl, finalNorm];

    if (redirectChain.length > MAX_REDIRECT_HOPS + 1) {
      throw new Error(`redirect_hops_exceeded:${redirectChain.length}`);
    }

    if (await isCachedFresh(finalHash, outDir, table, CACHE_TTL_DAYS)) {
      stats.skippedAlreadyCachedFresh += 1;
      row = makeBaseRow({
        input,
        finalUrl: finalNorm,
        redirectChain,
        status: 'ready',
        reachable: true,
        error: 'skipped_cached_fresh'
      });
      row.http_status = response ? response.status() : null;
      row.page_title = await safeTitle(page);
      row.screenshot_path = supabaseEnabled ? `${finalHash}.png` : `screenshots/${finalHash}.png`;
      return row;
    }

    const clip = await getScreenshotClip(page);
    screenshotBuffer = await page.screenshot({ type: 'png', fullPage: false, clip, timeout: NAV_TIMEOUT_MS });
    const reachable = Boolean(response && response.ok());
    const error = response && !response.ok() ? `http_status:${response.status()}` : null;
    row = makeBaseRow({
      input,
      finalUrl: finalNorm,
      redirectChain,
      status: reachable ? 'ready' : statusFromError(error),
      reachable,
      error
    });
    row.http_status = response ? response.status() : null;
    row.page_title = await safeTitle(page);
    row.screenshot_path = supabaseEnabled ? `${finalHash}.png` : `screenshots/${finalHash}.png`;
    row.screenshot_w = clip.width;
    row.screenshot_h = clip.height;
    row.content_hash = sha256Buffer(screenshotBuffer);
    await uploadOrWrite(row, screenshotBuffer, outDir, bucket, table);
    stats.screenshotsCapturedNew += 1;
    if (!row.reachable) {
      stats.failedDeadUrls += 1;
      stats.failed.push({ original_url: originalUrl, error: row.error });
    }
    return row;
  } catch (err) {
    const fallbackFinal = normalizeUrl(page.url()) || normalizeUrl(originalUrl) || originalUrl;
    const error = `capture_failed:${err.message}`;
    row = makeBaseRow({
      input,
      finalUrl: fallbackFinal,
      redirectChain: [originalUrl, fallbackFinal].filter(Boolean),
      status: statusFromError(error),
      reachable: false,
      error
    });
    await uploadOrWrite(row, null, outDir, bucket, table);
    stats.failedDeadUrls += 1;
    stats.failed.push({ original_url: originalUrl, error: row.error });
    return row;
  } finally {
    await context.close().catch(() => {});
  }
}

function buildRedirectChain(response) {
  const chain = [];
  let req = response.request();
  while (req) {
    chain.unshift(req.url());
    req = req.redirectedFrom();
  }
  const finalUrl = response.url();
  if (chain[chain.length - 1] !== finalUrl) chain.push(finalUrl);
  return chain.map(u => normalizeUrl(u) || u);
}

async function safeTitle(page) {
  try {
    const title = await page.title();
    return title ? title.slice(0, 300) : null;
  } catch {
    return null;
  }
}

async function main() {
  const sourcePath = path.resolve(opts.emailSource);
  const outDir = path.resolve(opts.outDir);
  await ensureOutDirs(outDir);

  const uniqueInputs = await extractAllUrls(sourcePath);

  if (opts.dryRun) {
    const dry = uniqueInputs.map(x => ({ original_url: x.originalUrl, source_email_id: x.sourceEmailIds }));
    await fs.writeFile(path.join(outDir, 'dry_run_urls.json'), JSON.stringify(dry, null, 2));
    printReport();
    console.log(`\nDry run URL list: ${path.join(outDir, 'dry_run_urls.json')}`);
    return;
  }

  await cleanupExpiredSupabaseCache(opts.bucket, opts.cacheTable);

  const browser = await createBrowser();
  const limit = pLimit(CONCURRENCY);
  const tasks = uniqueInputs.map(input => limit(() => captureOne(browser, input, outDir, opts.bucket, opts.cacheTable)));
  await Promise.all(tasks);
  await browser.close();

  await fs.writeFile(path.join(outDir, 'final_report.json'), JSON.stringify(stats, null, 2));
  printReport();
  if (!supabaseEnabled) {
    console.log(`\nLocal manifest: ${path.join(outDir, 'manifest.json')}`);
    console.log(`Local screenshots: ${path.join(outDir, 'screenshots')}`);
  }
}

function printReport() {
  console.log('\n=== SigurScan Preview Pre-Capture Final Report ===');
  console.log(`total emails/files parsed:       ${stats.totalEmailsParsed}`);
  console.log(`total raw URLs found:           ${stats.totalRawUrlsFound}`);
  console.log(`unique URLs after dedup:        ${stats.uniqueUrlsAfterDedup}`);
  console.log(`screenshots captured (new):     ${stats.screenshotsCapturedNew}`);
  console.log(`skipped cached & fresh:         ${stats.skippedAlreadyCachedFresh}`);
  console.log(`skipped reserved/test domains:  ${stats.skippedReserved}`);
  console.log(`expired cache rows deleted:     ${stats.expiredRowsDeleted}`);
  console.log(`expired screenshots deleted:    ${stats.expiredScreenshotsDeleted}`);
  console.log(`cleanup errors:                 ${stats.cleanupErrors.length}`);
  console.log(`failed / dead URLs:             ${stats.failedDeadUrls}`);
  if (stats.cleanupErrors.length) {
    console.log('\nCleanup errors:');
    for (const error of stats.cleanupErrors.slice(0, 20)) {
      console.log(`- ${error}`);
    }
  }
  if (stats.failed.length) {
    console.log('\nFailures:');
    for (const f of stats.failed.slice(0, 50)) {
      console.log(`- ${f.original_url || 'n/a'} :: ${f.error}`);
    }
    if (stats.failed.length > 50) console.log(`... +${stats.failed.length - 50} more`);
  }
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
