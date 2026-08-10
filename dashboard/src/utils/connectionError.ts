// Statuses that mean the backend (or the reverse proxy in front of it) did not serve the request.
// 504 is deliberately absent: the gateway itself answers 504 for domain timeouts (e.g. a WhatsApp
// auth timeout), and folding those into "connection lost" would hide their actual message.
const CONNECTION_LOSS_STATUSES = new Set([502, 503]);

/**
 * Whether an error toast describes losing the backend connection — the case the toast layer
 * de-dupes into a single "connection lost" toast instead of stacking one per failed call.
 *
 * The structured signal wins: api.ts attaches the HTTP `status` (and the gateway's machine `code`,
 * when one exists) to every thrown request error precisely so callers do not have to guess from
 * rendered text. A 502/503 carrying a `code` DID reach the application, so it is a domain failure,
 * not a lost connection; a fetch()-level TypeError never reached anything. The substring match on
 * title/message survives only as a last-resort fallback for call sites that forward plain text
 * with no error object — matching on user-facing strings misclassifies any backend message that
 * happens to contain one of these phrases.
 */
export function isConnectionLossError(err: unknown, title?: string, message?: string): boolean {
  if (err && typeof err === 'object') {
    const { status, code } = err as { status?: number; code?: string };
    if (typeof status === 'number') {
      return CONNECTION_LOSS_STATUSES.has(status) && typeof code !== 'string';
    }
    if (err instanceof TypeError) return true; // fetch() itself failed — nothing was reached
  }
  const haystack = `${title ?? ''} ${message ?? ''}`.toLowerCase();
  return (
    haystack.includes('failed to fetch') ||
    haystack.includes('networkerror') ||
    haystack.includes('http 502') ||
    haystack.includes('http 503')
  );
}
