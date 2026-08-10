const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/**
 * Strip trailing slashes from a configured origin so path concatenation cannot double the
 * separator. This matters beyond cosmetics: `io('https://host//events')` parses the namespace as
 * `//events`, which never matches the gateway's `/events` namespace — a trailing slash in
 * VITE_WS_URL silently broke every realtime feature while REST kept working.
 */
export function stripTrailingSlashes(url: string): string {
  return url.replace(/\/+$/, '');
}

/** Whether a hostname is a loopback/local address where plaintext http is acceptable. */
export function isLocalhostHost(hostname: string): boolean {
  return LOCALHOST_HOSTS.has(hostname.toLowerCase().replace(/^\[|\]$/g, ''));
}

/**
 * Warn (NOT throw) when a URL is `http://` and the host is not localhost. Sending API keys over
 * plaintext http to a non-local host exposes credentials on the wire; warning instead of refusing
 * keeps local dev and TLS-terminating-proxy setups working. Returns the original URL unchanged so
 * the caller can chain.
 */
export function warnIfInsecureHttpUrl(url: string, label: string): string {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'http:' && !isLocalhostHost(parsed.hostname)) {
      console.warn(
        `[OpenWA] ${label} uses an insecure http:// URL (host: ${parsed.hostname}). ` +
          'API keys are sent in cleartext over http. Use https:// in production.',
      );
    }
  } catch {
    // Unparseable — the downstream fetch will produce a clear error; not our job to validate here.
  }
  return url;
}
