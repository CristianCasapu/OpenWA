import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isConnectionLossError } from './connectionError.ts';

const apiError = (status: number, code?: string): Error => {
  const err = new Error(`HTTP ${status}`) as Error & { status?: number; code?: string };
  err.status = status;
  if (code) err.code = code;
  return err;
};

test('classifies a bare reverse-proxy 502/503 as connection loss', () => {
  assert.ok(isConnectionLossError(apiError(502)));
  assert.ok(isConnectionLossError(apiError(503)));
});

test('a 502/503 carrying a gateway machine code reached the app — NOT connection loss', () => {
  assert.ok(!isConnectionLossError(apiError(502, 'SESSION_LOGOUT_INCOMPLETE')));
  assert.ok(!isConnectionLossError(apiError(503, 'SOME_DOMAIN_CODE')));
});

test('domain statuses are never connection loss, whatever their message says', () => {
  assert.ok(!isConnectionLossError(apiError(400)));
  assert.ok(!isConnectionLossError(apiError(403)));
  assert.ok(!isConnectionLossError(apiError(500)));
  // The gateway answers 504 itself for domain timeouts (e.g. a WhatsApp auth timeout) — folding
  // it into "connection lost" would hide the actual message.
  assert.ok(!isConnectionLossError(apiError(504)));
});

test('a backend message that merely CONTAINS a trigger phrase is not misclassified when status is present', () => {
  const err = apiError(400);
  err.message = 'validation: webhook url must not be "failed to fetch"';
  assert.ok(!isConnectionLossError(err, 'Save failed', err.message));
});

test('a fetch()-level TypeError (server unreachable) is connection loss', () => {
  assert.ok(isConnectionLossError(new TypeError('Failed to fetch')));
});

test('text-only fallback still matches the classic phrases', () => {
  assert.ok(isConnectionLossError(undefined, 'Error', 'Failed to fetch'));
  assert.ok(isConnectionLossError(undefined, 'NetworkError when attempting to fetch resource.'));
  assert.ok(isConnectionLossError(undefined, 'Error', 'HTTP 503'));
  assert.ok(!isConnectionLossError(undefined, 'Save failed', 'name already exists'));
});
