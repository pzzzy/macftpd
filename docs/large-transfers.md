# Large Transfer Operations

## Overnight MKV result

The overnight large-file validation completed for a 10,824,083,788-byte MKV (about 10.08 GiB). The final range response reached the exact end of the file, so the client obtained the complete object.

macftpd did not perform a media-processing job. Public, share, and admin downloads open the stored file and stream its bytes through Go's HTTP range-serving path. There is no transcoding, remuxing, indexing, or MKV-specific transformation. Any codec probing or playback initialization happens in the client.

The request history contained several failures at roughly 60 seconds followed by range retries. That pattern is consistent with the former whole-response write deadline interrupting a large stream. The defaults now leave `http.read_timeout` and `http.write_timeout` at `0s`; header parsing remains bounded by `http.read_header_timeout` (10 seconds by default), and idle keep-alive connections remain bounded by `http.idle_timeout` (60 seconds by default).

Media clients commonly request a small tail range to inspect container metadata. macftpd records a partial response as a completed download only when it reaches EOF and transfers a meaningful amount: one percent of the object, capped at 8 MiB. A tiny tail probe therefore does not inflate download counts, while a substantial resume that completes the object does.

If a browser, media player, or tunnel closes a response before it finishes, macftpd records the transfer as `canceled`. The byte count and range remain in the event for diagnosis, but the weekly report keeps these client-side interruptions separate from server failures.

## Integrity checks

For an end-to-end transfer test, compare the byte count and SHA-256 digest at the source and destination:

```bash
stat -f '%z' large-file.mkv
shasum -a 256 large-file.mkv
curl --fail --location --output downloaded.mkv 'https://ftp.example.com/public/large-file.mkv'
stat -f '%z' downloaded.mkv
shasum -a 256 downloaded.mkv
```

On Linux, use `stat -c '%s'` instead of `stat -f '%z'`. An optional `ffprobe -v error downloaded.mkv` checks container readability, but that is a client-side validation step rather than macftpd processing.

To validate resume behavior without downloading the first portion again:

```bash
curl --fail --location --range '8388608-' --output resumed.bin \
  'https://ftp.example.com/public/large-file.mkv'
```

Expect `206 Partial Content`, `Accept-Ranges: bytes`, and a `Content-Range` whose total matches the stored byte count.

## Upload and overwrite behavior

FTP STOR/APPE/REST, admin multipart uploads, chunked uploads, public drops, and admin remote FTP pulls write to `._macftpd_uploads` first. The destination is unchanged until the staged file is closed and any existing destination has been copied into `._macftpd_versions`. A retention failure aborts the commit and leaves the original file intact. Non-overwrite drop links use an atomic no-replace install so concurrent uploads cannot bypass the overwrite policy.

Stale chunk parts older than 24 hours are cleaned opportunistically. The upload, trash, and versions directories are always hidden and cannot be addressed through FTP or the HTTP file API.

## Operational checklist

- Keep whole-body read/write timeouts at `0s` unless a deliberate maximum transfer duration is required.
- Keep the header timeout enabled to bound slow-header attacks.
- Confirm sufficient free space for the incoming staged file and, on overwrite, one retained copy of the previous destination.
- Compare the final byte count and digest for release or incident validation.
- Treat tiny EOF range requests as media probes; use the activity detail, status, bytes, and range fields to distinguish them from completed transfers.
- Review `Client Cancellations` separately from `Failures` in the weekly report. Repeated cancellations at a consistent duration can still reveal a proxy or timeout problem, but isolated broken pipes and resets normally mean the client stopped reading.
- The loopback FTP monitor identifies itself with `CLNT macftpd-monitor`. Intermediate successful probe actions are suppressed, one completed cycle is retained per hour, and every failed action is retained.
- When Cloudflare caching is enabled, configure a cache tag and public base URL. Public mutations purge the tag; HTTP mutations fall back to exact object and parent-listing URLs.
