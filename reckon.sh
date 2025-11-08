#!/usr/bin/env bash
# reckon.sh — v3 fixed and final
set -euo pipefail
IFS=$'\n\t'

DOMAIN="${1:-}"
MODE="${2:-medium}"
VERBOSE=false

for a in "$@"; do
  case "$a" in
    -v|--verbose) VERBOSE=true ;;
    -h|--help)
      cat <<'HELP'
Usage: reckon.sh <domain> [mode] [-v|--verbose]

Modes:
  fast   - Subdomains + live hosts only
  medium - Adds URL collection, nuclei, screenshots
  full   - Deep (adds fuzzing, secrets, ports, etc.)

Options:
  -v, --verbose   Show live command output
  -h, --help      Show this help
HELP
      exit 0 ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [mode] [-v]"
  exit 1
fi

OUTPUT_DIR="${DOMAIN}-recon"
WORDLIST_DIR="${HOME}/Recon-Wordlists"
START_TS=$(date +%s)

# ===== Colors =====
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"

# ===== Helpers =====
info(){ echo -e "${BLUE}[*]${NC} $*"; }
ok(){ echo -e "${GREEN}[✓]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
die(){ echo -e "${RED}[✗]${NC} $*"; exit 1; }

section() {
  echo -e "\n${BLUE}══════════════════════════════════════════════════════════════${NC}"
  echo -e "${YELLOW}▶ $1${NC}"
  echo -e "${BLUE}══════════════════════════════════════════════════════════════${NC}"
}

run_cmd() {
  if $VERBOSE; then
    echo -e "${BLUE}→${NC} $*"
    eval "$@"
  else
    eval "$@" >/dev/null 2>&1 || true
  fi
}

# ===== Tool Lists =====
ESSENTIAL=(git curl wget jq awk sed sort unzip python3)
OPTIONAL=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner katana)
ALL_TOOLS=("${ESSENTIAL[@]}" "${OPTIONAL[@]}")

present=(); missing=(); essential_missing=(); optional_missing=()

for t in "${ALL_TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    present+=("$t")
  else
    missing+=("$t")
    if printf '%s\n' "${ESSENTIAL[@]}" | grep -Fxq "$t"; then
      essential_missing+=("$t")
    else
      optional_missing+=("$t")
    fi
  fi
done

# ===== Dependency Summary =====
section "🧰 Dependency Check"

echo -e "${GREEN}Present tools (${#present[@]}):${NC}"
for t in "${present[@]}"; do echo "  ✓ $t"; done
echo
if ((${#missing[@]})); then
  echo -e "${RED}Missing tools (${#missing[@]}):${NC}"
  for t in "${missing[@]}"; do echo "  ✗ $t"; done
  echo
fi

if ((${#essential_missing[@]})); then
  warn "Essential tools missing — cannot continue."
  for t in "${essential_missing[@]}"; do echo "   • $t"; done
  echo
  die "Install essentials manually and re-run."
fi

if ((${#optional_missing[@]})); then
  warn "Optional tools missing (some features limited):"
  for t in "${optional_missing[@]}"; do echo "   • $t"; done
  echo
fi
ok "All essential tools available. Proceeding..."

mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp,s3,scans}
mkdir -p "$WORDLIST_DIR"

# ===== Wordlists =====
section "📜 Wordlist Setup"
declare -A WL=(
  [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
  [dir_medium]="https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt"
  [raft_small]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
  [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
  [s3]="https://raw.githubusercontent.com/Den1al/PyLazyS3/refs/heads/master/lists/common_bucket_prefixes.txt"
)
for k in "${!WL[@]}"; do
  tgt="$WORDLIST_DIR/$k.txt"
  if [ ! -s "$tgt" ]; then
    info "Downloading wordlist: $k"
    run_cmd "curl -sSfL '${WL[$k]}' -o '$tgt'"
  fi
done
ok "Wordlists ready in $WORDLIST_DIR"

# ===== Subdomain Enumeration =====
section "🔍 Subdomain Enumeration"
# Run subdomain finders in parallel
subfinder -silent -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/subfinder.txt" &
assetfinder --subs-only "$DOMAIN" > "$OUTPUT_DIR/subdomains/assetfinder.txt" &
amass enum -passive -d "$DOMAIN" -o "$OUTPUT_DIR/subdomains/amass.txt" &
wait

# ===== Merge & Clean safely =====
ALL_SUBS="$OUTPUT_DIR/subdomains/all_subs.txt"
TMP_MERGED="$OUTPUT_DIR/subdomains/merged_tmp.txt"

# Create temp file and ensure cleanup
: > "$TMP_MERGED"
: > "$ALL_SUBS"

# Collect available result files
shopt -s nullglob
sub_files=( "$OUTPUT_DIR/subdomains"/*.txt )
shopt -u nullglob

if [ ${#sub_files[@]} -eq 0 ]; then
  warn "No subdomain files found in $OUTPUT_DIR/subdomains. Creating placeholder."
  echo "$DOMAIN" > "$TMP_MERGED"
else
  for f in "${sub_files[@]}"; do
    if [ -s "$f" ]; then
      echo "  → merging: $(basename "$f")"
      cat "$f" >> "$TMP_MERGED"
      echo >> "$TMP_MERGED"
    fi
  done
fi

# Clean: remove leading dots, uppercase, invalid lines, duplicates
cat "$TMP_MERGED" \
  | sed -e 's/^\.*//' -e 's/\r$//' \
  | tr '[:upper:]' '[:lower:]' \
  | sed 's#https\?://##g' \
  | sed 's#/.*$##' \
  | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
  | sort -u > "$ALL_SUBS"

total_subs=$(wc -l < "$ALL_SUBS" 2>/dev/null || echo 0)
ok "Merged and cleaned → $total_subs unique subdomains saved to: $ALL_SUBS"

# ===== Live Host Detection =====
section "🌐 Live Host Detection"

info "Resolving valid subdomains..."
dnsx -silent -l "$OUTPUT_DIR/subdomains/all_subs.txt" -o "$OUTPUT_DIR/subdomains/resolved.txt" || true

info "Probing live hosts..."
httpx -silent -l "$OUTPUT_DIR/subdomains/resolved.txt" \
  -threads 100 -follow-redirects -status-code -title -probe \
  -o "$OUTPUT_DIR/subdomains/live_subs.txt" || true

resolved_count=$(wc -l < "$OUTPUT_DIR/subdomains/resolved.txt" || echo 0)
live_count=$(wc -l < "$OUTPUT_DIR/subdomains/live_subs.txt" || echo 0)

echo
echo "───────────────"
ok "Resolved: $resolved_count"
ok "Live: $live_count"
echo "───────────────"

# ===== Port Scan =====
section "🔌 Port Scan (Naabu + Nmap)"
sed -i 's#^https\?://##' "$OUTPUT_DIR/subdomains/live_subs.txt"
naabu -list "$OUTPUT_DIR/subdomains/live_subs.txt" -p 0-65535 -rate 20000 -o "$OUTPUT_DIR/ports/naabu.txt" &
nmap -T4 -sC -sV -iL "$OUTPUT_DIR/subdomains/live_subs.txt" -oN "$OUTPUT_DIR/scans/nmap.txt" &
wait
ok "Port scanning complete."

# ===== URL Collection =====
if [[ "$MODE" != "fast" ]]; then
  section "🔗 URL Collection"
  (cat "$OUTPUT_DIR/subdomains/live_subs.txt" | gau > "$OUTPUT_DIR/urls/gau.txt") &
  (cat "$OUTPUT_DIR/subdomains/live_subs.txt" | waybackurls > "$OUTPUT_DIR/urls/wayback.txt") &
  wait
  cat "$OUTPUT_DIR/urls"/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/all.txt"
  url_count=$(wc -l < "$OUTPUT_DIR/urls/all.txt" || echo 0)
  ok "URLs collected: $url_count"
fi

# ===== Vulnerability Scan =====
if [[ "$MODE" != "fast" ]]; then
  section "🚨 Vulnerability Scan (Nuclei)"
  nuclei -l "$OUTPUT_DIR/subdomains/live_subs.txt" -c 50 -rl 100 -tags cves,exposures -o "$OUTPUT_DIR/scans/nuclei.txt"
  vulns=$(wc -l < "$OUTPUT_DIR/scans/nuclei.txt" || echo 0)
  ok "Nuclei findings: $vulns"
fi

# ===== Screenshots =====
section "📸 Capturing Screenshots"
if command -v gowitness >/dev/null 2>&1; then
  gowitness scan file -f "$OUTPUT_DIR/subdomains/live_subs.txt" --screenshot-path "$OUTPUT_DIR/screenshots" --timeout 10 --threads 10
  ok "Screenshots saved to $OUTPUT_DIR/screenshots"
else
  warn "gowitness not found, skipping screenshots."
fi

# ===== Directory Fuzzing =====
if [[ "$MODE" == "full" ]]; then
  section "📂 Directory Fuzzing"
  proto="https"
  if ! curl -Is --max-time 5 "https://$DOMAIN" >/dev/null 2>&1; then proto="http"; fi
  run_cmd "feroxbuster -u '${proto}://$DOMAIN' -w '$WORDLIST_DIR/common.txt' -t 30 -o '$OUTPUT_DIR/dirs/ferox_${DOMAIN}.txt' || true"
  ok "feroxbuster scan done"
  if command -v dirsearch >/dev/null 2>&1; then
    run_cmd "python3 ~/dirsearch/dirsearch.py -u '${proto}://$DOMAIN' -w '$WORDLIST_DIR/dir_medium.txt' -t 20 -o '$OUTPUT_DIR/dirs/dirsearch_root.txt' || true"
    ok "dirsearch run complete"
  fi
fi

# ===== Extracting potential parameters =====
section "🧩 Parameter Extraction"
cat "$OUTPUT_DIR/urls/all.txt" | gf xss > "$OUTPUT_DIR/params/xss.txt" &
cat "$OUTPUT_DIR/urls/all.txt" | gf sqli > "$OUTPUT_DIR/params/sqli.txt" &
cat "$OUTPUT_DIR/urls/all.txt" | gf lfi > "$OUTPUT_DIR/params/lfi.txt" &
cat "$OUTPUT_DIR/urls/all.txt" | gf ssrf > "$OUTPUT_DIR/params/ssrf.txt" &
wait
ok "Parameter extraction complete."

# ===== S3 Bucket Enumeration =====
section "🪣 S3 Bucket Enumeration"
touch "$OUTPUT_DIR/s3/found.txt"
while read -r b; do
  url="https://${b}.s3.amazonaws.com"
  if curl -I -s --max-time 5 "$url" | grep -qE "200|403"; then
    echo "$url" >> "$OUTPUT_DIR/s3/found.txt"
  fi
done < "$WORDLIST_DIR/s3.txt"
s3c=$(wc -l < "$OUTPUT_DIR/s3/found.txt" 2>/dev/null || echo 0)
((s3c>0)) && warn "Accessible S3 buckets: $s3c" || ok "No S3 buckets found"

# ===== Summary =====
section "📊 Recon Summary"
END_TS=$(date +%s)
DUR=$((END_TS-START_TS)); MIN=$((DUR/60)); SEC=$((DUR%60))
urls=$(wc -l < "$OUTPUT_DIR/urls/all.txt" 2>/dev/null || echo 0)
vulns=$(wc -l < "$OUTPUT_DIR/scans/nuclei.txt" 2>/dev/null || echo 0)
ok "Target: $DOMAIN"
echo "Mode: $MODE"
echo "Duration: ${MIN}m ${SEC}s"
echo "Subdomains: $total_subs"
echo "Live hosts: $live_count"
echo "URLs: $urls"
echo "Vulnerabilities: $vulns"
echo "Output: $OUTPUT_DIR/"
echo
ok "Recon complete!"
