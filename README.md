# S3 Checker

[![CI](https://github.com/zapstiko/S3-Checker/actions/workflows/ci.yml/badge.svg)](https://github.com/zapstiko/S3-Checker/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/zapstiko/S3-Checker)](https://github.com/zapstiko/S3-Checker/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Fast, focused AWS S3 bucket discovery, exposure auditing, and subdomain-takeover detection written in Go.

S3 Checker generates high-probability bucket names for a target, validates them, detects the bucket's region, classifies anonymous access, and can enumerate readable bucket configuration. It also finds dangling S3 CNAMEs and ships a large, shareable wordlist built for community use.

```
s3-checker -t example -p
```

## Features

- Target-aware permutation engine (brand, domain, and URL inputs)
- Deep mode with services, environments, years, numbers, and regions
- Exact-mode scanning for external wordlists
- Remote wordlists over HTTPS (`-w https://...`)
- Correct S3 status handling (`200` public, `403` private, `404` unclaimed)
- Automatic region detection via `x-amz-bucket-region`
- Path-style addressing for dotted bucket names (avoids TLS wildcard failures)
- Read-only permission and exposure enumeration
- Public policy analysis (principal, action, condition)
- Public object discovery through listing or safe `HEAD` probes
- Dangling S3 CNAME and `NoSuchBucket` takeover detection
- AWS and S3-compatible providers (DigitalOcean, Wasabi, Backblaze B2, Linode, Scaleway, GCS, custom)
- Global rate limiting, retries with backoff, proxy support
- Console, JSON, JSONL, and CSV output
- Graceful interruption and scan statistics
- Zero external Go dependencies

## What's new in v2

- Real exposure classification instead of treating every non-404 as "found"
- Region detection and region-redirect handling
- `-p/--perms` read-only permission enumeration
- S3 takeover detection (`-d`)
- Direct bucket checks (`-b`), target lists (`-tL`), and bucket lists (`-bL`)
- Exact and deep wordlist modes
- Remote wordlist support
- JSON/JSONL/CSV reporting
- Shareable generated wordlists under [`wordlists/`](wordlists/)
- S3-compatible provider support
- Free OSINT sources are now opt-in (`--osint`); GrayHatWarfare remains automatic with `GHW_API_KEY`
- Fixed the old per-worker rate limiter (which multiplied the effective rate)
- Output and progress separation for clean piping

## Installation

Requires Go 1.25 or newer.

### Prebuilt binaries

Download macOS, Linux, and Windows binaries from the
[latest release](https://github.com/zapstiko/S3-Checker/releases/latest)
(checksums are attached to every release).

### Using Go

```bash
go install github.com/zapstiko/s3-checker@latest
```

Build from source:

```bash
git clone https://github.com/zapstiko/S3-Checker.git
cd S3-Checker
go build -trimpath -o s3-checker .
```

Optionally:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

## Releases

| Version | Status | Highlights |
|---|---|---|
| [v2.0.0](https://github.com/zapstiko/S3-Checker/releases/tag/v2.0.0) | Latest | Permissions, takeover detection, providers, structured output, 87k wordlist |
| [v1.3.1](https://github.com/zapstiko/S3-Checker/releases/tag/v1.3.1) | Legacy | GrayHatWarfare, osint.sh, `-v` |
| [v1.3.0](https://github.com/zapstiko/S3-Checker/releases/tag/v1.3.0) | Legacy | Help menu, multi-code exclusion |
| [v1.2.0](https://github.com/zapstiko/S3-Checker/releases/tag/v1.2.0) | Legacy | Earliest tagged release |

See [CHANGELOG.md](CHANGELOG.md) for details.

## Quick start

```bash
# Standard target scan
s3-checker -t example

# Deep target scan with permission enumeration
s3-checker -t example --deep -p -r 25

# Check known buckets directly
s3-checker -b my-bucket,backup-bucket -p

# Scan a target using the shareable keyword list
s3-checker -t example -w wordlists/s3-keywords.txt --deep

# Scan an exact remote wordlist
s3-checker -w \
  https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-buckets-master.txt \
  --exact -c 100

# Find dangling S3 CNAMEs
s3-checker -d domains.txt --takeover-all

# Structured output
s3-checker -b my-bucket -p -f json -o findings.json
```

## Wordlists

The repository ships curated and generated wordlists that can be downloaded and shared independently:

| File | Entries | Purpose |
|---|---:|---|
| [`wordlists/s3-buckets-master.txt`](wordlists/s3-buckets-master.txt) | 87,484 | Exact bucket-name list for broad discovery |
| [`wordlists/s3-keywords.txt`](wordlists/s3-keywords.txt) | 645 | Keywords for target-aware mutation (`-w` without `--exact`) |
| [`wordlists/services.txt`](wordlists/services.txt) | 200+ | Service and technology names |
| [`wordlists/environments.txt`](wordlists/environments.txt) | 22 | Environment tokens |
| [`wordlists/objects.txt`](wordlists/objects.txt) | 50 | Object keys used for safe `HEAD` exposure probes |
| [`common_bucket_prefixes.txt`](common_bucket_prefixes.txt) | 502 | Default base prefixes used by the permutation engine |

Raw download URLs:

```text
https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-buckets-master.txt
https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-keywords.txt
```

A public gist mirror of the master list is also available:

```text
https://gist.github.com/zapstiko/f6df988598003a08a24e22dd14533246
```

The gist is a snapshot; the repository file is the canonical version. Both generated lists are also attached to the
[v2.0.0 release](https://github.com/zapstiko/S3-Checker/releases/tag/v2.0.0).

Use the master list as exact candidates. `--exact` ignores target-derived permutations and scans each wordlist entry as-is:

```bash
s3-checker -w wordlists/s3-buckets-master.txt --exact -c 100
# or
s3-checker -w https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-buckets-master.txt --exact
```

Use the keyword list for target-aware mutation:

```bash
s3-checker -t acme -w wordlists/s3-keywords.txt --deep
```

Regenerate the generated lists after changing components:

```bash
./scripts/build-wordlists.sh
./scripts/build-wordlists.sh --check   # CI verification
```

See [`wordlists/README.md`](wordlists/README.md) for details and licensing.

## How detection works

| Response | Interpretation | Result |
|---|---|---|
| `200` on bucket root | Anonymous `ListBucket` is allowed | `PUBLIC` |
| `403` | Bucket exists but anonymous access is denied | `PRIVATE` |
| `301`, `307`, `308` | Bucket exists in another region | `EXISTS` (region extracted) |
| `404` with S3 headers | Bucket name is unclaimed | `NOT_FOUND` |
| `400` | Invalid name or endpoint | `ERROR` |
| `429`, `5xx` | Transient failure | Retried, then `ERROR` |

Region detection uses the `x-amz-bucket-region` response header. If a legacy endpoint returns a region redirect, the checker can re-check the regional endpoint (`--follow-region`, enabled by default).

Dotted bucket names use path-style URLs (`https://s3.amazonaws.com/name.with.dots`) because `*.s3.amazonaws.com` certificates do not cover multi-label names.

### Permission enumeration (`-p`)

For every existing bucket, `-p` performs read-only requests:

- `ListBucket` via `?list-type=2&max-keys=N`
- Bucket ACL, policy, website, CORS, logging, versioning, tagging
- Encryption, lifecycle, replication, public access block, object lock, notification
- Multipart uploads
- Safe `HEAD` probes for common object keys when listing is denied

Public policy statements are parsed for `Principal: "*"` and public `s3:GetObject`, `s3:ListBucket`, `s3:PutObject`, or `s3:DeleteObject` actions. ACL grants to `AllUsers` are classified as public read, public write, or full control. Conditional statements are marked separately.

The tool never performs `PUT`, `POST`, or `DELETE` operations. Write-access validation is intentionally excluded because it can modify or destroy data.

### Takeover detection (`-d`)

`-d` accepts a domain or a file of domains and:

1. Resolves the CNAME chain.
2. Recognizes AWS S3 virtual-host, website, dualstack, and accelerate endpoints.
3. Recognizes DigitalOcean Spaces, Wasabi, Backblaze B2, Linode, Scaleway, and GCS endpoints.
4. Checks whether the referenced bucket is unclaimed.
5. Falls back to HTTP inspection for ALIAS/flattened records, looking for S3's `NoSuchBucket` signature.

A domain pointing at an unclaimed bucket is reported as `VULNERABLE`. Use `--takeover-all` to show existing and non-S3 results too.

## Usage

```text
s3-checker -t <target> [options]
s3-checker -b <bucket[,bucket...]> [options]
s3-checker -w <file|url> --exact [options]
s3-checker -d <domain|file> [options]
```

### Target input

| Flag | Description |
|---|---|
| `-t, --target` | Target brand, domain, URL, or comma-separated list |
| `-tL, --target-list` | File containing targets |
| `-b, --buckets` | Comma-separated exact bucket names |
| `-bL, --bucket-list` | File containing exact bucket names |
| `-d, --domains` | Domain or file for takeover checks |

### Wordlists and permutations

| Flag | Description |
|---|---|
| `-w, --wordlist` | Wordlist file, HTTPS URL, or `-` for stdin |
| `--exact` | Treat wordlist entries as exact bucket names |
| `--deep` | Deep permutations (services, years, numbers, regions) |
| `--max-candidates` | Cap generated candidates (`0` = unlimited) |

### Scanning

| Flag | Description | Default |
|---|---|---|
| `-c, --concurrency` | Worker count | `50` |
| `-r, --rate` | Global requests per second | unlimited |
| `--timeout` | Per-request timeout | `8s` |
| `--retries` | Retries for transient failures | `2` |
| `--proxy` | Proxy URL (or `HTTP(S)_PROXY`) | environment |
| `--provider` | `aws`, `do`, `wasabi`, `linode`, `b2`, `scaleway`, `gcs`, `custom` | `aws` |
| `--region` | Provider region | provider default |
| `--endpoint` | Custom endpoint; supports `{bucket}` and `{region}` | |
| `-p, --perms` | Enumerate permissions and exposure | off |
| `--objects` | Objects to list/probe in perms mode (`0` disables) | `10` |
| `--osint` | Enable free OSINT enrichment | off |
| `--follow-region` | Follow region redirects | on |
| `--user-agent` | Custom User-Agent | built in |

### Output

| Flag | Description | Default |
|---|---|---|
| `-o, --output` | Output file | stdout |
| `-f, --format` | `console`, `json`, `jsonl`, `csv` | `console` |
| `--json` | Shorthand for `-f jsonl` | |
| `-s, --status` | Only show a specific HTTP status | |
| `-e, --exclude` | Exclude HTTP status codes (comma-separated) | |
| `--quiet` | Suppress banner, progress, and summary | |
| `--no-progress` | Disable progress line | |
| `--no-color` | Disable ANSI colors | |
| `--takeover-all` | Show non-vulnerable takeover results | |
| `-v, --version` | Print version | |

### Output examples

Console:

```text
https://noaa-goes16.s3.amazonaws.com [200] [PUBLIC] [region=us-east-1] list acl=read cors=* listed=10
https://aws.s3.amazonaws.com [403] [PRIVATE] [region=us-east-1]
[TAKEOVER] assets.example.com -> example-assets (aws) [VULNERABLE]
```

JSON (single record, from the `json` format):

```json
{
  "type": "bucket",
  "bucket": "noaa-goes16",
  "url": "https://noaa-goes16.s3.amazonaws.com",
  "provider": "aws",
  "status": "PUBLIC",
  "exists": true,
  "http_status": 200,
  "region": "us-east-1",
  "permissions": {
    "list_bucket": true,
    "cors_readable": true,
    "cors_wildcard": true
  }
}
```

CSV columns are stable and include both bucket and takeover findings.

## OSINT enrichment

Free sources are opt-in because they disclose the target to a third party:

```bash
s3-checker -t example --osint
```

- `crt.sh` certificate-transparency search for S3 hostnames
- `osint.sh` public-bucket search (best effort; the site may change)

GrayHatWarfare is used automatically when `GHW_API_KEY` is set:

```bash
export GHW_API_KEY=your_api_key
s3-checker -t example
```

OSINT results are merged into the candidate set and validated before scanning.

## S3-compatible providers

```bash
# DigitalOcean Spaces (default region nyc3)
s3-checker -t example --provider do --region nyc3

# Wasabi
s3-checker -t example --provider wasabi --region eu-central-1

# Custom endpoint (MinIO, Ceph, LocalStack, etc.)
s3-checker -t example --endpoint https://s3.internal.example.com

# Custom endpoint with placeholders
s3-checker -t example --endpoint 'https://{region}.s3.example.com/{bucket}' --region us-east-1
```

Provider support is best effort because 403/404 semantics differ between implementations. AWS behavior is the reference.

## Project structure

```text
S3-Checker/
├── main.go                    CLI, input handling, orchestration
├── checker.go                 S3 requests, classification, permission enumeration
├── takeover.go                CNAME parsing and takeover detection
├── providers.go               Provider endpoint templates
├── wordlist.go                Wordlist loading, validation, permutations
├── osint.go                   crt.sh, osint.sh, GrayHatWarfare
├── output.go                  Console/JSON/JSONL/CSV reporting and stats
├── common_bucket_prefixes.txt Embedded base prefixes
├── wordlists/
│   ├── services.txt
│   ├── environments.txt
│   ├── objects.txt
│   ├── s3-keywords.txt        Generated
│   └── s3-buckets-master.txt  Generated, ~87k exact names
├── scripts/build-wordlists.sh Wordlist generator and CI check
├── Makefile                   build/test/check helpers
├── CHANGELOG.md               release history
└── main_test.go
```

## Limitations

- Anonymous checks only; no AWS credentials or signed requests.
- `-p` is a heuristic audit. A policy may be public but restricted by conditions; review `policy_conditional` manually.
- Some S3-compatible providers return `403` for nonexistent buckets or mask bucket existence.
- The master wordlist is generic. It is most useful for broad discovery; target-aware scans should use `-t` with keywords.
- OSINT sources can rate-limit, change format, or be unavailable.
- Takeover detection reports the bucket state at scan time. Always verify before reporting.

## Security and ethics

This tool is intended strictly for authorized security testing, bug bounty programs, and education.

- Obtain written permission before testing.
- Respect scope, rate limits, and applicable law.
- Do not use the permission checks against buckets you do not own or have permission to assess.
- Follow responsible disclosure.
- The author assumes no liability for misuse.

## Contributing

Pull requests and improvements are welcome. For major changes, open an issue first.

When changing wordlist components, run:

```bash
./scripts/build-wordlists.sh
make check
```

`make check` runs gofmt verification, `go vet`, race-enabled tests, and the wordlist drift check.

## License

MIT License. See [LICENSE](LICENSE).

## Acknowledgements

- [Nahamsec](https://twitter.com/nahamsec)
- [Jobert Abma](https://twitter.com/JobertAbma)
- The cloud security community and public bucket researchers
