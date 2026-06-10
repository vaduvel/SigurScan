export function captureFailurePolicy(error) {
  const text = String(error || '').toLowerCase();
  if (text.includes('http_status:404') || text.includes('http_status:410') || text.includes('dns_no_records')) {
    return { status: 'dead', reason: 'dead_destination', retryable: false };
  }
  if (text.includes('http_status:401') || text.includes('http_status:403')) {
    return { status: 'error', reason: 'blocked_by_origin', retryable: false };
  }
  if (
    text.includes('timeout')
    || text.includes('err_http2_protocol_error')
    || text.includes('http_status:408')
    || text.includes('http_status:425')
    || text.includes('http_status:429')
    || text.includes('http_status:500')
    || text.includes('http_status:502')
    || text.includes('http_status:503')
    || text.includes('http_status:504')
  ) {
    return { status: 'error', reason: 'transient_capture_failure', retryable: true };
  }
  if (text.includes('blocked') || text.includes('reserved') || text.includes('private_ip')) {
    return { status: 'blocked', reason: 'security_block', retryable: false };
  }
  return { status: 'error', reason: 'capture_error', retryable: false };
}

export function shouldRetryCapture(error, attempt, maxRetries = 1) {
  return attempt < maxRetries && captureFailurePolicy(error).retryable;
}

