#!/usr/bin/env bash
# reckon.sh — Clean Recon Tool (no boxes, no gum, plain output)
set -euo pipefail
IFS=$'\n\t'

DOMAIN="${1:-}"
MODE="${2:-medium}"
VERBOSE=false

for arg in "$@"; do
  if [[ "$arg" == "-v" || "$arg" == "--verbose" ]]; then VERBOSE=true; fi
done

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [mode] [-v]"
  echo "Example: ./reckon.sh example.com medium -v"
  exit 1
fi

# Colors
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"
info(){ echo -e "${BLUE}[*]${NC} $*"; }
ok(){ echo -e "${GREEN}[✓]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
die(){ echo -e "${RED}[✗]${NC} $*"; exit 1; }

run() {
  if $VERBOSE; then
    echo -e "${BLUE}→${NC} $*"
    eval "$*"
  else
    eval "$*" >/dev/null 2>&1 || true
  fi
}

OUTPUT_DIR="${DOMAIN}-recon"
WORDLIST_DIR="${HOME}/Recon-Wordlists"
START_TS=$(date +%s)

# ----------------------
# Tool lists
# ----------------------
ESSENTIAL=(git curl wget jq awk sed sort unzip python3)
OPTIONAL=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner katana)
ALL_TOOLS=("${ESSENTIAL[@]}" "${OPTIONAL[@]}")

# ----------------------
# Dependency check
# ----------------------
present=()
missing=()
essential_missing=()
optional_missing=()

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

# ----------------------
# Results
# ----------------------
echo
echo -e "${GREEN}=== Present Tools (${#present[@]}) ===${NC}"
for t in "${present[@]}"; do echo -e "  ${GREEN}✔${NC} $t"; done
echo

if ((${#missing[@]})); then
  echo -e "${RED}=== Missing Tools (${#missing[@]}) ===${NC}"
  for t in "${missing[@]}"; do echo -e "  ${RED}✗${NC} $t"; done
  echo
else
  echo -e "${GREEN}No missing tools detected.${NC}"
fi
echo

if ((${#essential_missing[@]})); then
  echo -e "${YELLOW}⚠️  Essential tools missing:${NC}"
  for t in "${essential_missing[@]}"; do echo "   • $t"; done
  echo
  echo "Install manually before continuing."
  echo "Example (Debian/Ubuntu):"
  echo "  sudo apt install -y git curl wget jq unzip python3"
  echo "Example (macOS):"
  echo "  brew install git curl wget jq python3"
  echo
  die "Cannot continue without essential tools."
fi

if ((${#optional_missing[@]})); then
  echo -e "${YELLOW}Optional tools missing (some features limited):${NC}"
  for t in "${optional_missing[@]}"; do echo "   • $t"; done
  echo
fi

ok "All essential tools available. Continuing..."
echo

# ----------------------
# Setup
# ----------------------
mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp}
mkdir -p "$WORDLIST_DIR"

declare -A WLS=(
  [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
  [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
)
for k in "${!WLS[@]}"; do
  tgt="$WORDLIST_DIR/${k}.txt"
  if [ ! -s "$tgt" ]; then
    info "Downloading wordlist: $k"
    run "curl -sSfL '${WLS[$k]}' -o '$tgt'"
  fi
done

# ----------------------
# Recon Phases
# ----------------------
ok "Starting recon on $DOMAIN (mode: $MODE)"

info "Enumerating subdomains..."
run "subfinder -silent -d '$DOMAIN' -o '$OUTPUT_DIR/temp/subfinder.txt'"
run "assetfinder --subs-only '$DOMAIN' > '$OUTPUT_DIR/temp/assetfinder.txt'"
run "curl -s 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' > '$OUTPUT_DIR/temp/crtsh.txt'"
cat "$OUTPUT_DIR/temp/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all.txt"
total_subs=$(wc -l < "$OUTPUT_DIR/subdomains/all.txt" || echo 0)
ok "Total subdomains: $total_subs"

info "Probing live hosts..."
if command -v httpx >/dev/null 2>&1; then
  run "httpx -l '$OUTPUT_DIR/subdomains/all.txt' -silent -o '$OUTPUT_DIR/subdomains/live.txt'"
else
  cp "$OUTPUT_DIR/subdomains/all.txt" "$OUTPUT_DIR/subdomains/live.txt"
fi
live=$(wc -l < "$OUTPUT_DIR/subdomains/live.txt" || echo 0)
ok "Live hosts: $live"

if [[ "$MODE" != "fast" ]]; then
  info "Collecting URLs..."
  run "cat '$OUTPUT_DIR/subdomains/live.txt' | gau > '$OUTPUT_DIR/urls/gau.txt'"
  run "cat '$OUTPUT_DIR/subdomains/live.txt' | waybackurls > '$OUTPUT_DIR/urls/wayback.txt'"
  cat "$OUTPUT_DIR/urls/"*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/all.txt"
  url_count=$(wc -l < "$OUTPUT_DIR/urls/all.txt" || echo 0)
  ok "URLs: $url_count"
fi

if [[ "$MODE" == "medium" || "$MODE" == "full" ]] && command -v nuclei >/dev/null 2>&1; then
  info "Running nuclei scan..."
  run "nuclei -l '$OUTPUT_DIR/subdomains/live.txt' -silent -o '$OUTPUT_DIR/reports/nuclei.txt'"
  vulns=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" || echo 0)
  ok "Vulnerabilities: $vulns"
fi

if command -v gowitness >/dev/null 2>&1; then
  info "Capturing screenshots..."
  run "gowitness file -f '$OUTPUT_DIR/subdomains/live.txt' --destination '$OUTPUT_DIR/screenshots' --timeout 10"
fi

END_TS=$(date +%s)
DUR=$((END_TS - START_TS))
MIN=$((DUR / 60)); SEC=$((DUR % 60))

echo
echo -e "${GREEN}=== RECON COMPLETE ===${NC}"
echo "Target: $DOMAIN"
echo "Mode: $MODE"
echo "Duration: ${MIN}m ${SEC}s"
echo "Subdomains: $total_subs"
echo "Live Hosts: $live"
echo "URLs: ${url_count:-0}"
echo "Output: $OUTPUT_DIR/"
echo
ok "Report complete."
