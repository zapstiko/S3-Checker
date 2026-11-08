# Changelog

All notable releases of S3 Checker. The source of truth is the
[GitHub Releases page](https://github.com/zapstiko/S3-Checker/releases).

## v2.0.0 — 2026-11-08

Current release.

### Added

- Correct S3 classification: `200` public listing, `403` private, `404` unclaimed, `301/307` region redirects
- Automatic region detection through `x-amz-bucket-region`
- Read-only permission and exposure enumeration (`-p`):
  - ListBucket and object listing
  - ACL, bucket policy, website, CORS, logging, versioning, tagging
  - encryption, lifecycle, replication, public access block, object lock
  - notifications, multipart uploads, and safe object `HEAD` probes
- Public write detection from ACL grants and bucket policies
- S3 takeover detection (`-d`) with CNAME parsing and `NoSuchBucket` fallback
- AWS and S3-compatible providers: DigitalOcean, Wasabi, B2, Linode, Scaleway, GCS, custom
- Exact, deep, and remote wordlist modes
- Generated 87,484-entry master wordlist and 645 mutation keywords
- JSON, JSONL, and CSV output
- Global rate limiter, retries with backoff, proxy support, graceful interruption
- Target lists (`-tL`) and bucket lists (`-bL`)

### Fixed

- The old per-worker rate limiter multiplied the effective request rate
- Dotted bucket names now use path-style URLs to avoid TLS wildcard failures
- Output and progress are separated so structured output stays machine-readable

## v1.3.1 — 2026-03-01

Final legacy release before v2.

### Added

- GrayHatWarfare enrichment via `GHW_API_KEY`
- `osint.sh` bucket search
- `-v` version flag

### Changed

- Updated banner and help output
- Improved exclude-status parsing

## v1.3.0 — 2026-02-27

### Added

- Help menu with usage examples
- Multi-code exclusion (`-e 403,404`)
- Colorized output and status filtering
- Explicit version constant

## v1.2.0 — 2026-02-27

Earliest tagged version in the repository history.

### Included

- Target-aware bucket permutations
- Bucket existence checks
- Custom wordlists
- Concurrency and rate limiting
- Status filters and file output
