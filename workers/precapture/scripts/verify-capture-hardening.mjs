import { captureFailurePolicy, shouldRetryCapture } from '../src/capture-policy.js';

const forbidden = captureFailurePolicy('http_status:403');
if (forbidden.status !== 'error' || forbidden.reason !== 'blocked_by_origin' || forbidden.retryable) {
  throw new Error(`403 policy invalid: ${JSON.stringify(forbidden)}`);
}

const timeout = captureFailurePolicy('capture_failed:page.goto: Timeout 20000ms exceeded');
if (!timeout.retryable || timeout.reason !== 'transient_capture_failure') {
  throw new Error(`timeout policy invalid: ${JSON.stringify(timeout)}`);
}

const http2 = captureFailurePolicy('capture_failed:net::ERR_HTTP2_PROTOCOL_ERROR');
if (!http2.retryable) throw new Error('HTTP/2 protocol failures must be retried once');

if (!shouldRetryCapture('timeout', 0, 1)) throw new Error('first transient failure must retry');
if (shouldRetryCapture('timeout', 1, 1)) throw new Error('retry must be bounded');
if (shouldRetryCapture('http_status:403', 0, 1)) throw new Error('origin blocks must not be retried');

const missing = captureFailurePolicy('http_status:404');
if (missing.status !== 'dead' || missing.retryable) {
  throw new Error(`404 policy invalid: ${JSON.stringify(missing)}`);
}

console.log('Capture hardening policy verified.');

