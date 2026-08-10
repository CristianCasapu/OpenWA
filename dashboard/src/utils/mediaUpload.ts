// Client-side cap for media staged for upload, kept safely under the server's default
// BODY_SIZE_LIMIT of 25mb once base64 inflates the bytes by 4/3 (18 MiB × 4/3 ≈ 24 MiB encoded).
// Rejecting BEFORE encoding surfaces a clear error instead of OOMing the tab on the encode or
// earning a 413 only after the whole body has uploaded. Shared by every picker that stages a file
// as base64 (message tester, chat composer) so the limit cannot drift between them. The backend's
// MEDIA_DOWNLOAD_MAX_BYTES (default 50 MiB) stays authoritative for URL sends (fetched server-side).
export const MEDIA_UPLOAD_MAX_BYTES = 18 * 1024 * 1024;
