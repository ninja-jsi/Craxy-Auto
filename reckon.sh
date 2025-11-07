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
  [dir_medium]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
  [raft_small]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
  [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
  [s3]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/AWS/s3-buckets-top50.txt"
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
run_cmd "dnsx -silent -l '$OUTPUT_DIR/subdomains/all.txt' > '$OUTPUT_DIR/subdomains/resolved.txt'"
run_cmd "httpx -l '$OUTPUT_DIR/subdomains/resolved.txt' -silent > '$OUTPUT_DIR/subdomains/live.txt'"
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
  section "🔑 JS Secret Discovery"
  touch "$OUTPUT_DIR/secrets/found.txt"
  run_cmd "grep -Eoi '\\.js(\\?|$)' '$OUTPUT_DIR/urls/all.txt' | sed 's/^[^h]*//' | sort -u > '$OUTPUT_DIR/temp/js_urls.txt'"
  while IFS= read -r jsu; do
    f="$OUTPUT_DIR/secrets/$(echo -n "$jsu" | md5sum | awk '{print $1}').js"
    run_cmd "curl -sSfL '$jsu' -m 10 -o '$f' || true"
  done < <(head -n 50 "$OUTPUT_DIR/temp/js_urls.txt")
  run_cmd "grep -ErohI 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}' '$OUTPUT_DIR/secrets' > '$OUTPUT_DIR/secrets/found.txt' || true"
  s_count=$(wc -l < "$OUTPUT_DIR/secrets/found.txt" 2>/dev/null || echo 0)
  ((s_count>0)) && warn "Secrets found: $s_count" || ok "No secrets found"
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
  run_cmd "gowitness scan --disable-db --input-file '$OUTPUT_DIR/subdomains/live.txt' --destination '$OUTPUT_DIR/screenshots' --timeout 10"
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
