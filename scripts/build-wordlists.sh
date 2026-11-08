#!/usr/bin/env bash
# Builds shareable S3 wordlists from the curated components.
# Usage: scripts/build-wordlists.sh [--check]
set -euo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK=0
if [[ "${1:-}" == "--check" ]]; then
  CHECK=1
fi

SUFFIXES="backup backups bak data db dumps files file assets asset static media images img uploads downloads docs documents logs archive archives export exports temp tmp old new dev test stage staging prod production qa uat preprod private public internal external config configs secrets keys certs users customers customer billing invoices payroll hr finance legal contracts reports research analytics data-lake warehouse ml models training snapshots releases artifacts builds cache"
ENVS="$(cat "$ROOT/wordlists/environments.txt")"
YEARS="2018 2019 2020 2021 2022 2023 2024 2025 2026"
NUMBERS="1 2 3 4 5 6 7 8 9 10"
REGIONS="us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-west-2 eu-central-1 ap-south-1 ap-southeast-1 ap-southeast-2"
DOT_SUFFIXES="backup data files assets static prod dev logs media"

normalize() {
  tr '[:upper:]' '[:lower:]' \
    | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
    | grep -E '^[a-z0-9][a-z0-9.-]*[a-z0-9]$' \
    | awk '
      function is_ip(s, a, n, i) {
        n = split(s, a, ".")
        if (n != 4) return 0
        for (i = 1; i <= 4; i++) {
          if (a[i] !~ /^[0-9]+$/ || a[i] + 0 > 255) return 0
        }
        return 1
      }
      length($0) >= 3 && length($0) <= 63 &&
      $0 !~ /\.\./ && $0 !~ /--/ &&
      $0 !~ /^xn--/ && $0 !~ /-s3alias$/ &&
      !is_ip($0)
    ' \
    || true
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat "$ROOT/common_bucket_prefixes.txt" "$ROOT/wordlists/services.txt" | normalize | grep -vE '^[0-9]+$' | sort -u > "$tmp/bases.txt"
if [[ ! -s "$tmp/bases.txt" ]]; then
  echo "error: no base keywords found" >&2
  exit 1
fi

# Keyword list for mutation mode (-w without --exact).
{
  cat "$tmp/bases.txt"
  printf '%s\n' $SUFFIXES
  printf '%s\n' $ENVS
} | normalize | sort -u > "$tmp/keywords.txt"

# Master list of exact bucket names.
{
  cat "$tmp/bases.txt"
  printf '%s\n' $ENVS
  while IFS= read -r base; do
    printf '%s\n' "$base"
    for suffix in $SUFFIXES; do
      printf '%s-%s\n' "$base" "$suffix"
    done
    for env in $ENVS; do
      printf '%s-%s\n%s-%s\n' "$base" "$env" "$env" "$base"
    done
    for year in $YEARS; do
      printf '%s-%s\n' "$base" "$year"
    done
    for number in $NUMBERS; do
      printf '%s-%s\n' "$base" "$number"
    done
    for region in $REGIONS; do
      printf '%s-%s\n' "$base" "$region"
    done
    for suffix in $DOT_SUFFIXES; do
      printf '%s.%s\n' "$base" "$suffix"
    done
  done < "$tmp/bases.txt"
} | normalize | sort -u > "$tmp/master.txt"

if [[ "$CHECK" -eq 1 ]]; then
  status=0
  if ! diff -q "$tmp/keywords.txt" "$ROOT/wordlists/s3-keywords.txt" >/dev/null; then
    echo "wordlists/s3-keywords.txt is out of date" >&2
    status=1
  fi
  if ! diff -q "$tmp/master.txt" "$ROOT/wordlists/s3-buckets-master.txt" >/dev/null; then
    echo "wordlists/s3-buckets-master.txt is out of date" >&2
    status=1
  fi
  if [[ "$status" -eq 0 ]]; then
    echo "wordlists are up to date"
  fi
  exit "$status"
fi

cp "$tmp/keywords.txt" "$ROOT/wordlists/s3-keywords.txt"
cp "$tmp/master.txt" "$ROOT/wordlists/s3-buckets-master.txt"
echo "wrote wordlists/s3-keywords.txt ($(wc -l < "$ROOT/wordlists/s3-keywords.txt" | tr -d ' ') entries)"
echo "wrote wordlists/s3-buckets-master.txt ($(wc -l < "$ROOT/wordlists/s3-buckets-master.txt" | tr -d ' ') entries)"
