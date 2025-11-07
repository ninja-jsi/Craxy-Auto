#!/usr/bin/env bash
# reckon.sh — Plain Bash recon (final)
# Usage: ./reckon.sh <domain> [mode] [-v|--verbose]
# Modes: fast | medium (default) | full
set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Args & flags
# -------------------------
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
  fast   - quick (subdomain + live check)
  medium - default (adds URL collection, basic scans)
  full   - deep (fuzzing, ports, nuclei)

Options:
  -v, --verbose   Show detailed command output and progress
  -h, --help      Show this help

Notes:
  - This script DOES NOT auto-install tools. Missing essentials will stop execution.
  - Wordlists are stored at: ~/Recon-Wordlists
  - Only run against targets you have permission to test.
HELP
      exit 0
      ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  echo "Error: target domain is required."
  echo "Run: $0 --help"
  exit 1
fi

# -------------------------
# Vars & colors
# -------------------------
OUTPUT_DIR="${DOMAIN}-recon"
WORDLIST_DIR="${HOME}/Recon-Wordlists"
TMP_DIR="$OUTPUT_DIR/temp"
START_TS=$(date +%s)

RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"

info(){ printf "%b\n" "${BLUE}[*]${NC} $*"; }
ok(){ printf "%b\n" "${GREEN}[✓]${NC} $*"; }
warn(){ printf "%b\n" "${YELLOW}[!]${NC} $*"; }
err(){ printf "%b\n" "${RED}[✗]${NC} $*"; }

# -------------------------
# Tools
# -------------------------
ESSENTIAL=(git curl wget jq awk sed sort unzip python3)
OPTIONAL=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner katana)
ALL_TOOLS=("${ESSENTIAL[@]}" "${OPTIONAL[@]}")

# -------------------------
# Helper: run command
# - If VERBOSE: prints and runs command (stdout/stderr visible)
# - If not VERBOSE: runs quietly, but returns exit code for checks
# -------------------------
run_cmd() {
  if $VERBOSE; then
    printf "%b\n" "${BLUE}→${NC} $*"
    eval "$@"
    return $?
  else
    eval "$@" >/dev/null 2>&1
    return $?
  fi
}

# -------------------------
# Check dependencies
# -------------------------
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

# Print simple lists (no boxes)
echo
echo -e "${GREEN}Present tools (${#present[@]}):${NC}"
for t in "${present[@]}"; do printf "  ✓ %s\n" "$t"; done
echo

if ((${#missing[@]})); then
  echo -e "${RED}Missing tools (${#missing[@]}):${NC}"
  for t in "${missing[@]}"; do printf "  ✗ %s\n" "$t"; done
  echo
else
  echo -e "${GREEN}No missing tools detected.${NC}"
  echo
fi

# If essentials missing -> stop
if ((${#essential_missing[@]})); then
  echo -e "${YELLOW}Essential tools missing:${NC}"
  for t in "${essential_missing[@]}"; do printf "  • %s\n" "$t"; done
  echo
  echo "Please install the essentials manually and re-run."
  echo "Examples:"
  echo "  Debian/Ubuntu/Kali: sudo apt update && sudo apt install -y git curl wget jq unzip python3"
  echo "  macOS (homebrew):   brew install git curl wget jq python3"
  echo
  exit 1
fi

# Warn for optional missing but continue
if ((${#optional_missing[@]})); then
  echo -e "${YELLOW}Optional tools missing (some features disabled):${NC}"
  for t in "${optional_missing[@]}"; do printf "  • %s\n" "$t"; done
  echo
fi

ok "All essential tools available. Proceeding."

# -------------------------
# Wordlists — central set (popular lists for directories, s3, etc.)
# -------------------------
mkdir -p "$WORDLIST_DIR"
declare -A WL=(
  [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
  [dir_medium]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
  [raft_small]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
  [raft_medium]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt"
  [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
  [s3]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/AWS/s3-buckets-top50.txt"
  [usernames]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt"
)
for k in "${!WL[@]}"; do
  tgt="$WORDLIST_DIR/$k.txt"
  if [ ! -s "$tgt" ]; then
    info "Downloading wordlist: $k"
    run_cmd "curl -sSfL '${WL[$k]}' -o '$tgt' || true"
    if [ -s "$tgt" ]; then ok "Downloaded $k"; else warn "Failed to download $k"; fi
  fi
done

# Ensure output dirs
mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp,s3}

# -------------------------
# Subdomain enumeration
# - use safe commands; sanitize outputs
# -------------------------
info "Running subdomain enumeration (subfinder, assetfinder, amass, crt.sh)..."

# run subfinder if available
if command -v subfinder >/dev/null 2>&1; then
  run_cmd "subfinder -silent -d '$DOMAIN' -o '$OUTPUT_DIR/temp/subfinder.txt' || true"
fi

# assetfinder
if command -v assetfinder >/dev/null 2>&1; then
  run_cmd "assetfinder --subs-only '$DOMAIN' > '$OUTPUT_DIR/temp/assetfinder.txt' 2>/dev/null || true"
fi

# amass (passive) for non-fast modes
if [[ "$MODE" != "fast" ]] && command -v amass >/dev/null 2>&1; then
  run_cmd "timeout 60 amass enum -passive -d '$DOMAIN' -o '$OUTPUT_DIR/temp/amass.txt' 2>/dev/null || true"
fi

# crt.sh
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  run_cmd "curl -s 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\\*\\.//g' > '$OUTPUT_DIR/temp/crtsh.txt' || true"
fi

# Merge and sanitize (remove leading dots, spaces, blank lines)
run_cmd "cat '$OUTPUT_DIR/temp'/*.txt 2>/dev/null | sed 's/^\\.*//;s/\\s//g' | tr '[:upper:]' '[:lower:]' | grep -E '^[a-z0-9._-]+\\.[a-z]{2,}$' | sort -u > '$OUTPUT_DIR/subdomains/all.txt' || true"

total_subs=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
ok "Subdomains enumerated: $total_subs"

# Show a small sample to user
if [ "$VERBOSE" = true ]; then
  info "Sample subdomains (top 20):"
  head -n 20 "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || true
fi

# -------------------------
# Live host detection (httpx or fallback)
# - feed via stdin to be compatible with different httpx releases
# -------------------------
info "Checking which hosts are serving HTTP(S)..."

if command -v dnsx >/dev/null 2>&1; then
  run_cmd "dnsx -silent -l '$OUTPUT_DIR/subdomains/all.txt' -o '$OUTPUT_DIR/subdomains/resolved.txt' 2>/dev/null || cp -f '$OUTPUT_DIR/subdomains/all.txt' '$OUTPUT_DIR/subdomains/resolved.txt'"
else
  cp -f "$OUTPUT_DIR/subdomains/all.txt" "$OUTPUT_DIR/subdomains/resolved.txt"
fi

# Use httpx by streaming the hosts through stdin (works regardless of -l support)
if command -v httpx >/dev/null 2>&1; then
  if $VERBOSE; then
    run_cmd "cat '$OUTPUT_DIR/subdomains/resolved.txt' | httpx -o '$OUTPUT_DIR/subdomains/live.txt' || cp -f '$OUTPUT_DIR/subdomains/resolved.txt' '$OUTPUT_DIR/subdomains/live.txt'"
  else
    run_cmd "cat '$OUTPUT_DIR/subdomains/resolved.txt' | httpx -silent -o '$OUTPUT_DIR/subdomains/live.txt' 2>/dev/null || cp -f '$OUTPUT_DIR/subdomains/resolved.txt' '$OUTPUT_DIR/subdomains/live.txt'"
  fi
else
  # fallback: assume all resolved hosts are "live" (less accurate but safe)
  cp -f "$OUTPUT_DIR/subdomains/resolved.txt" "$OUTPUT_DIR/subdomains/live.txt"
fi

live_count=$(wc -l < "$OUTPUT_DIR/subdomains/live.txt" 2>/dev/null || echo 0)
ok "Live hosts (web) detected: $live_count"

# -------------------------
# URL collection (gau + wayback)
# -------------------------
if [[ "$MODE" != "fast" ]]; then
  info "Collecting URLs (gau, waybackurls)..."

  # gau
  if command -v gau >/dev/null 2>&1; then
    if $VERBOSE; then
      run_cmd "cat '$OUTPUT_DIR/subdomains/live.txt' | gau --threads 10 > '$OUTPUT_DIR/urls/gau.txt' 2>/dev/null || true"
    else
      run_cmd "cat '$OUTPUT_DIR/subdomains/live.txt' | gau --threads 10 > '$OUTPUT_DIR/urls/gau.txt' 2>/dev/null || true"
    fi
  else
    warn "gau not available — skipping"
  fi

  # waybackurls
  if command -v waybackurls >/dev/null 2>&1; then
    run_cmd "cat '$OUTPUT_DIR/subdomains/live.txt' | waybackurls > '$OUTPUT_DIR/urls/wayback.txt' 2>/dev/null || true"
  else
    warn "waybackurls not available — skipping"
  fi

  # merge URLs
  run_cmd "cat '$OUTPUT_DIR/urls'/*.txt 2>/dev/null | sort -u > '$OUTPUT_DIR/urls/all.txt' || true"
  url_count=$(wc -l < "$OUTPUT_DIR/urls/all.txt" 2>/dev/null || echo 0)
  ok "Collected URLs: $url_count"
fi

# -------------------------
# Parameter extraction (gf)
# -------------------------
if [[ "$MODE" != "fast" ]] && command -v gf >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/urls/all.txt" ]; then
  info "Extracting interesting parameters via gf (xss, sqli, lfi)..."
  run_cmd "cat '$OUTPUT_DIR/urls/all.txt' | gf xss > '$OUTPUT_DIR/params/xss.txt' 2>/dev/null || true"
  run_cmd "cat '$OUTPUT_DIR/urls/all.txt' | gf sqli > '$OUTPUT_DIR/params/sqli.txt' 2>/dev/null || true"
  run_cmd "cat '$OUTPUT_DIR/urls/all.txt' | gf lfi > '$OUTPUT_DIR/params/lfi.txt' 2>/dev/null || true"
  ok "Parameter extraction (gf) done"
fi

# -------------------------
# JS secrets scan (quick)
# -------------------------
if [[ "$MODE" != "fast" ]] && [ -s "$OUTPUT_DIR/urls/all.txt" ]; then
  info "Searching JS files for secrets (quick)..."
  run_cmd "grep -Eoi '\\.js(\\?|$)' '$OUTPUT_DIR/urls/all.txt' 2>/dev/null | sed 's/^[^h]*//' | sort -u > '$OUTPUT_DIR/temp/js_candidates.txt' || true"
  # download up to 200 JS files (safe)
  mkdir -p "$OUTPUT_DIR/secrets/jsfiles"
  i=0
  while IFS= read -r jsu && [ $i -lt 200 ]; do
    f="$OUTPUT_DIR/secrets/jsfiles/$(echo -n "$jsu" | md5sum | awk '{print $1}').js"
    run_cmd "curl -sSfL '$jsu' -m 12 -o '$f' || true"
    ((i++))
  done < "$OUTPUT_DIR/temp/js_candidates.txt"
  # grep common secrets
  run_cmd "grep -ErohI 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}' '$OUTPUT_DIR/secrets/jsfiles' 2>/dev/null > '$OUTPUT_DIR/secrets/found.txt' || true"
  secret_count=$(wc -l < "$OUTPUT_DIR/secrets/found.txt" 2>/dev/null || echo 0)
  if [ "$secret_count" -gt 0 ]; then warn "Potential JS secrets found: $secret_count (see secrets/found.txt)"; else ok "No obvious JS secrets found"; fi
fi

# -------------------------
# Nuclei quick scan
# -------------------------
if [[ "$MODE" != "fast" ]] && command -v nuclei >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
  info "Running nuclei scan (quick severity default)..."
  run_cmd "nuclei -l '$OUTPUT_DIR/subdomains/live.txt' -silent -o '$OUTPUT_DIR/reports/nuclei.txt' || true"
  vcount=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" 2>/dev/null || echo 0)
  ok "Nuclei results: $vcount"
fi

# -------------------------
# Screenshots (gowitness)
# -------------------------
if command -v gowitness >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
  info "Capturing screenshots (gowitness)..."
  run_cmd "gowitness file -f '$OUTPUT_DIR/subdomains/live.txt' --destination '$OUTPUT_DIR/screenshots' --timeout 10 || true"
  ok "Screenshots saved to $OUTPUT_DIR/screenshots"
fi

# -------------------------
# Quick fuzzing: ffuf / feroxbuster / dirsearch
# - use central wordlists
# -------------------------
if command -v ffuf >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
  info "Running quick directory fuzz (ffuf) on up to 10 hosts..."
  WL="$WORDLIST_DIR/common.txt"
  [ ! -s "$WL" ] && WL="$WORDLIST_DIR/dir_medium.txt"
  head -n 10 "$OUTPUT_DIR/subdomains/live.txt" | while read -r h; do
    run_cmd "ffuf -u 'http://$h/FUZZ' -w '$WL' -t 30 -mc 200,301,302 -o '$OUTPUT_DIR/dirs/ffuf_${h}.json' -of json || true"
  done
  ok "ffuf completed (quick)"
fi

# feroxbuster
if command -v feroxbuster >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
  info "Running feroxbuster (quick) on first 10 hosts..."
  WL="$WORDLIST_DIR/common.txt"
  head -n 10 "$OUTPUT_DIR/subdomains/live.txt" | while read -r u; do
    run_cmd "feroxbuster -u 'http://$u' -w '$WL' -t 30 -o '$OUTPUT_DIR/dirs/ferox_${u}.txt' || true"
  done
  ok "feroxbuster quick runs complete"
fi

# dirsearch (if user has it locally)
if [ -d "$HOME/dirsearch" ] && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
  info "Running dirsearch against root domain (if installed locally)..."
  run_cmd "python3 '$HOME/dirsearch/dirsearch.py' -u 'https://$DOMAIN' -w '$WORDLIST_DIR/dir_medium.txt' -t 20 -o '$OUTPUT_DIR/dirs/dirsearch_root.txt' || true"
  ok "dirsearch (local) run complete"
fi

# -------------------------
# S3 bucket check (wordlist)
# -------------------------
if [ -s "$WORDLIST_DIR/s3.txt" ]; then
  info "Checking S3 candidate buckets..."
  run_cmd "while read -r b; do url=\"https://$b.s3.amazonaws.com\"; if curl -I -s --max-time 6 \"\$url\" | grep -q '200\\|403'; then echo \"\$url\" >> '$OUTPUT_DIR/s3/found.txt'; fi; done < '$WORDLIST_DIR/s3.txt' || true"
  scnt=$(wc -l < "$OUTPUT_DIR/s3/found.txt" 2>/dev/null || echo 0)
  if [ "$scnt" -gt 0 ]; then warn "Accessible S3 candidates: $scnt (see s3/found.txt)"; else ok "No accessible S3 buckets found (quick)"; fi
fi

# -------------------------
# Final report
# -------------------------
END_TS=$(date +%s)
DUR=$((END_TS - START_TS)); MIN=$((DUR/60)); SEC=$((DUR%60))

total_subs=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" 2>/dev/null || echo 0)
live_count=$(wc -l < "$OUTPUT_DIR/subdomains/live.txt" 2>/dev/null || echo 0)
url_count=$(wc -l < "$OUTPUT_DIR/urls/all.txt" 2>/dev/null || echo 0)
secret_count=$(wc -l < "$OUTPUT_DIR/secrets/found.txt" 2>/dev/null || echo 0)
vuln_count=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" 2>/dev/null || echo 0)
s3_count=$(wc -l < "$OUTPUT_DIR/s3/found.txt" 2>/dev/null || echo 0)

cat > "$OUTPUT_DIR/reports/REPORT.txt" <<REPORT
Recon Report - $DOMAIN
Mode: $MODE
Duration: ${MIN}m ${SEC}s
Date: $(date)

Summary:
  Subdomains: $total_subs
  Live Hosts: $live_count
  URLs: $url_count
  JS Secrets found: $secret_count
  Nuclei findings: $vuln_count
  S3 accessible: $s3_count

Files (partial):
  $OUTPUT_DIR/subdomains/all.txt
  $OUTPUT_DIR/subdomains/live.txt
  $OUTPUT_DIR/urls/all.txt
  $OUTPUT_DIR/secrets/found.txt
  $OUTPUT_DIR/s3/found.txt
  $OUTPUT_DIR/reports/nuclei.txt

REPORT

ok "Report written: $OUTPUT_DIR/reports/REPORT.txt"

# Friendly summary to user
echo
printf "%b\n" "${GREEN}=== RECON COMPLETE ===${NC}"
echo "Target: $DOMAIN"
echo "Mode: $MODE"
echo "Duration: ${MIN}m ${SEC}s"
echo "Subdomains: $total_subs"
echo "Live hosts: $live_count"
echo "URLs: $url_count"
[ "$secret_count" -gt 0 ] && echo "JS secrets: $secret_count (see secrets/found.txt)"
[ "$vuln_count" -gt 0 ] && echo "Nuclei results: $vuln_count (see reports/nuclei.txt)"
[ "$s3_count" -gt 0 ] && echo "S3 accessible: $s3_count (see s3/found.txt)"
echo "Output folder: $OUTPUT_DIR/"
echo

exit 0
