#!/usr/bin/env bash
# reckon.sh — v3 final: clean interface + dividers + modern tool support
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
  echo "Install manually, e.g.:"
  echo "  sudo apt install -y git curl wget jq unzip python3"
  die "Exiting — install essentials and re-run."
fi

if ((${#optional_missing[@]})); then
  warn "Optional tools missing (some features limited):"
  for t in "${optional_missing[@]}"; do echo "   • $t"; done
  echo
fi
ok "All essential tools available. Proceeding..."

mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp,s3}
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
run_cmd "subfinder -silent -d '$DOMAIN' -o '$OUTPUT_DIR/temp/subfinder.txt'"
run_cmd "assetfinder --subs-only '$DOMAIN' > '$OUTPUT_DIR/temp/assetfinder.txt'"
run_cmd "curl -s 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' > '$OUTPUT_DIR/temp/crtsh.txt'"

run_cmd "cat '$OUTPUT_DIR/temp'/*.txt 2>/dev/null | sed 's/^\\.*//;s/\\s//g' | tr '[:upper:]' '[:lower:]' | grep -E '^[a-z0-9._-]+\\.[a-z]{2,}$' | sort -u > '$OUTPUT_DIR/subdomains/all.txt'"
total_subs=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" || echo 0)
ok "Subdomains found: $total_subs"

# ===== Live Host Detection =====
section "🌐 Live Host Detection"
run_cmd "dnsx -l '$OUTPUT_DIR/subdomains/all.txt' -v > '$OUTPUT_DIR/subdomains/resolved.txt'"
run_cmd "httpx -l '$OUTPUT_DIR/subdomains/resolved.txt' -v > '$OUTPUT_DIR/subdomains/live.txt'"
live_count=$(wc -l < "$OUTPUT_DIR/subdomains/live.txt" || echo 0)
ok "Live web hosts: $live_count"

# ===== URL Collection =====
if [[ "$MODE" != "fast" ]]; then
  section "🔗 URL Collection"
  run_cmd "cat '$OUTPUT_DIR/subdomains/live.txt' | gau --threads 10 > '$OUTPUT_DIR/urls/gau.txt'"
  run_cmd "cat '$OUTPUT_DIR/subdomains/live.txt' | waybackurls > '$OUTPUT_DIR/urls/wayback.txt'"
  run_cmd "cat '$OUTPUT_DIR/urls'/*.txt 2>/dev/null | sort -u > '$OUTPUT_DIR/urls/all.txt'"
  url_count=$(wc -l < "$OUTPUT_DIR/urls/all.txt" || echo 0)
  ok "URLs collected: $url_count"
fi

# ===== JS Secret & Params =====
if [[ "$MODE" != "fast" ]]; then
  # ===== Robust JS extraction & secret hunting (replace previous fragile block) =====
  section "🔑 JS Secret Discovery (robust)"
  
  ALL_URLS_FILE="$OUTPUT_DIR/urls/all.txt"
  JS_URLS_FILE="$OUTPUT_DIR/temp/js_urls.txt"
  JS_STORE="$OUTPUT_DIR/secrets/jsfiles"
  FOUND_SECRETS="$OUTPUT_DIR/secrets/found.txt"
  
  # Ensure outputs/dirs exist and placeholders to avoid "no such file" later
  mkdir -p "$JS_STORE"
  touch "$FOUND_SECRETS" "$JS_URLS_FILE"
  
  # 1) Make sure we have URLs to work with
  if [ ! -s "$ALL_URLS_FILE" ]; then
    warn "No URLs file found at $ALL_URLS_FILE — skipping JS discovery."
  else
    info "Extracting JS URLs from $ALL_URLS_FILE"
  
    # 2) Extract full JS URLs (supports query strings, fragments), dedupe
    #    This grabs http/https links that end with .js or contain .js? or .js#
    #    It also tries to catch inline links like //cdn.example/file.js
    grep -Eo '(https?:)?//[^"'\''<>[:space:]]+\.js([?/#][^"'\''<>[:space:]]*)?' "$ALL_URLS_FILE" \
      | sed -E 's/^\/\///; s/^:?\/\///; s/^\/\///' \
      | sed -E 's/^([^h].*)$/http:\/\/\1/' \
      | sort -u > "$JS_URLS_FILE" || true
  
    # 3) If above produced nothing, try fallback: find any line with ".js" and try to extract a URL-ish piece
    if [ ! -s "$JS_URLS_FILE" ]; then
      warn "No explicit JS URLs found via regex — falling back to looser extraction (may be noisy)"
      grep -i '\.js' "$ALL_URLS_FILE" | grep -Eo 'https?://[^ ]+|//[^ ]+' | sed 's#^//#http://#' | sort -u >> "$JS_URLS_FILE" || true
    fi
  
    js_count_total=$(wc -l < "$JS_URLS_FILE" 2>/dev/null || echo 0)
    if [ "$js_count_total" -eq 0 ]; then
      warn "No JS files discovered (0 entries). Skipping download."
    else
      ok "Found $js_count_total unique JS URLs (will download up to first 200)"
  
      # 4) Limit download set (change head -n 200 if you want more)
      head -n 200 "$JS_URLS_FILE" > "$JS_URLS_FILE.tmp" && mv "$JS_URLS_FILE.tmp" "$JS_URLS_FILE"
  
      # 5) Download in parallel (10 workers) and save as md5-named .js files
      #    Each curl has a 12s timeout and will skip on error (|| true)
      export OUT="$JS_STORE"
      cat "$JS_URLS_FILE" | xargs -I{} -P 10 bash -c '
        url="$1"
        outdir="$OUT"
        fname="$(echo -n "$url" | md5sum | awk "{print \$1}").js"
        # Save quietly or show details depending on verbose
        if '"$VERBOSE"'; then
          echo "→ curl -sSfL \"$url\" -m 12 -o \"$outdir/$fname\" || true"
          curl -sSfL "$url" -m 12 -o "$outdir/$fname" || true
        else
          curl -sSfL "$url" -m 12 -o "$outdir/$fname" 2>/dev/null || true
        fi
      ' _ {}
  
      # 6) Hunt for tokens/patterns (AWS keys, Google API, GitHub tokens, Slack, JWTs, private keys)
      grep -Eroh "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----" "$JS_STORE" 2>/dev/null \
        | sort -u > "$FOUND_SECRETS" || true
  
      found_count=$(wc -l < "$FOUND_SECRETS" 2>/dev/null || echo 0)
      if [ "$found_count" -gt 0 ]; then
        warn "⚠️  Found $found_count potential secrets in JS files (saved to $FOUND_SECRETS)"
      else
        ok "No secrets found in JS files"
      fi
    fi
  fi
fi

# ===== Vulnerability Scan =====
if [[ "$MODE" != "fast" ]]; then
  section "🚨 Vulnerability Scan (Nuclei)"
  run_cmd "nuclei -l '$OUTPUT_DIR/subdomains/live.txt' -silent > '$OUTPUT_DIR/reports/nuclei.txt'"
  vulns=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" || echo 0)
  ok "Nuclei findings: $vulns"
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
    ok "dirsearch (local) run complete"
  fi
fi

# ===== Screenshots =====
section "📸 Capturing Screenshots"
if command -v gowitness >/dev/null 2>&1; then
  run_cmd "gowitness scan file -f '$OUTPUT_DIR/subdomains/live.txt' --write-db '$OUTPUT_DIR/screenshots' --timeout 10"
  ok "Screenshots saved to $OUTPUT_DIR/screenshots"
fi

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
vulns=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" 2>/dev/null || echo 0)
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
