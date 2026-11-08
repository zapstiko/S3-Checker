# S3 Checker Wordlists

Curated and generated wordlists for S3 bucket discovery, shared for reuse with S3 Checker and other bucket-auditing tools.

## Files

| File | Entries | Description |
|---|---:|---|
| `s3-buckets-master.txt` | 87,484 | Generated exact bucket names (base + suffix/env/year/number/region permutations) |
| `s3-keywords.txt` | 645 | Keywords for target-aware mutation |
| `services.txt` | 200+ | Service, platform, and technology names |
| `environments.txt` | 22 | Environment tokens |
| `objects.txt` | 50 | Common object keys for safe `HEAD` exposure probes |

The base prefixes live in [`../common_bucket_prefixes.txt`](../common_bucket_prefixes.txt).

## Download

Raw GitHub URLs:

```text
https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-buckets-master.txt
https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-keywords.txt
https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/services.txt
https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/environments.txt
https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/objects.txt
```

Public gist mirror of the master list (snapshot):

```text
https://gist.github.com/zapstiko/f6df988598003a08a24e22dd14533246
```

## Usage

Exact list (each line is a complete bucket name):

```bash
s3-checker -w s3-buckets-master.txt --exact -c 100
```

Remote exact list:

```bash
s3-checker -w \
  https://raw.githubusercontent.com/zapstiko/S3-Checker/main/wordlists/s3-buckets-master.txt \
  --exact
```

Bounded scan:

```bash
s3-checker -w s3-buckets-master.txt --exact --max-candidates 10000 -r 50
```

Mutation mode (combine keywords with a target):

```bash
s3-checker -t acme -w s3-keywords.txt --deep
```

Other tools can consume the master list directly because it is a plain newline-separated list with no comments.

## Generation

`s3-buckets-master.txt` and `s3-keywords.txt` are generated. Do not edit them by hand.

```bash
./scripts/build-wordlists.sh
```

The script normalizes entries, enforces S3 bucket-name rules, removes duplicates, and sorts deterministically with `LC_ALL=C`. CI verifies that committed files are current:

```bash
./scripts/build-wordlists.sh --check
```

Generation inputs:

- Base names from `common_bucket_prefixes.txt` and `services.txt`
- Suffixes such as `backup`, `data`, `static`, `uploads`, `logs`, `prod`
- Environments from `environments.txt`
- Years `2018`–`2026`
- Numbers `1`–`10`
- Common AWS regions
- Dot-separated variants for selected suffixes

The generator skips names that violate S3 rules: length outside 3–63, uppercase, underscores, leading/trailing hyphens or dots, adjacent dots, reserved suffixes, and IP-address forms.

## Quality notes

- The master list is intentionally generic. It does not know your target. Use `-t` plus keywords for target-specific coverage.
- A bucket-name match is not proof of ownership. Use `-p` and manual verification before reporting.
- Some very common names (`backup`, `test`, `dev`, `assets`) are almost always registered. They remain in the list because they are useful as suffix components and for completeness.
- Dotted names are valid but are usually served with path-style URLs. S3 Checker handles this automatically.

## License

These wordlists are released under the MIT License, the same license as the project. See [`../LICENSE`](../LICENSE).

Only use them for authorized security testing and research.
