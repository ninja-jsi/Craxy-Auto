#!/usr/bin/env bash
# reckon.sh — Full Recon Script (Manual install, no gum)
# Compatible: Kali, Ubuntu, macOS
set -euo pipefail
IFS=$'\n\t'

DOMAIN="${1:-}"
MODE="${2:-medium}"
VERBOSE=false

for arg in "$@"; do
  if [[ "$arg" == "-v" || "$arg" == "--verbose" ]]; then
    VERBOSE=true
  fi
done

if [[ -z "$DOMAIN" ]]; then
  echo "Usage: $0 <domain> [mode] [-v|--verbose]"
  exit 1
fi

OUTPUT_DIR="${DOMAIN}-recon"
WORDLIST_DIR="${HOME}/Recon-Wordlists"
START_TS=$(date +%s)

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

# ------------------------
# Tool Lists
# ------------------------
ESSENTIAL=(git curl wget jq awk sed sort unzip python3)
OPTIONAL=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner katana)
ALL_TOOLS=("${ESSENTIAL[@]}" "${OPTIONAL[@]}")

# ------------------------
# Tool Check
# ------------------------
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

# ------------------------
# Display
# ------------------------
{
  COLS=3
  PAD=26

  format_grid() {
    local -n arr="$1"
    local symbol="$2"
    local color="$3"
    local i=0
    local line=""
    for item in "${arr[@]}"; do
      [[ -z "$item" ]] && continue
      local cell="${color}${symbol} ${item}${NC}"
      printf -v padded "%-${PAD}s" "$cell"
      line+="$padded"
      ((i++))
      if ((i % COLS == 0)); then
        echo -e "  $line"
        line=""
      fi
    done
    [[ -n "$line" ]] && echo -e "  $line"
  }

  present_count=${#present[@]}
  missing_count=${#missing[@]}

  echo
  echo "┌────────────────────────────────────────────────────────┐"
  printf "│ %-54s │\n" "✅ Present (${present_count})"
  echo "├────────────────────────────────────────────────────────┤"
  if (( present_count > 0 )); then
    format_grid present "✓" "$GREEN"
  else
    echo "  (none)"
  fi
  echo "└────────────────────────────────────────────────────────┘"
  echo

  echo "┌────────────────────────────────────────────────────────┐"
  printf "│ %-54s │\n" "❌ Missing (${missing_count})"
  echo "├────────────────────────────────────────────────────────┤"
  if (( missing_count > 0 )); then
    format_grid missing "✗" "$RED"
  else
    echo "  (none)"
  fi
  echo "└────────────────────────────────────────────────────────┘"
  echo

  if (( ${#essential_missing[@]} > 0 )); then
    echo -e "${YELLOW}⚠️  Essential tools missing:${NC}"
    for t in "${essential_missing[@]}"; do
      echo "   • $t"
    done
    echo
    echo -e "${YELLOW}Install these manually and re-run.${NC}"
    echo
    exit 1
  fi

  if (( ${#optional_missing[@]} > 0 )); then
    echo -e "${YELLOW}Optional tools missing (some features limited):${NC}"
    for t in "${optional_missing[@]}"; do
      echo "   • $t"
    done
    echo
  fi

  echo -e "${GREEN}All essential tools present! Continuing...${NC}"
  echo
} | cat  # ensures flush and full print

# ------------------------
# Prepare Directories
# ------------------------
mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp}
mkdir -p "$WORDLIST_DIR"

# ------------------------
# Wordlists (Central)
# ------------------------
declare -A WL=(
  [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
  [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
)
for k in "${!WL[@]}"; do
  tgt="$WORDLIST_DIR/${k}.txt"
  if [ ! -s "$tgt" ]; then
    info "Downloading wordlist: $k"
    curl -sSfL "${WL[$k]}" -o "$tgt" || warn "Failed: $k"
  fi
done

# ------------------------
# Recon Phases
# ------------------------
ok "Starting recon for: $DOMAIN (mode: $MODE)"

run "subfinder -silent -d $DOMAIN -o $OUTPUT_DIR/temp/subfinder.txt"
run "assetfinder --subs-only $DOMAIN > $OUTPUT_DIR/temp/assetfinder.txt"
run "curl -s 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' | sed 's/*\\.//g' > $OUTPUT_DIR/temp/crtsh.txt"

cat $OUTPUT_DIR/temp/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains/all_subs.txt"
total_subs=$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt" || echo 0)
ok "Subdomains found: $total_subs"

if command -v httpx >/dev/null 2>&1; then
  run "httpx -l $OUTPUT_DIR/subdomains/all_subs.txt -silent -o $OUTPUT_DIR/subdomains/live.txt"
else
  cp "$OUTPUT_DIR/subdomains/all_subs.txt" "$OUTPUT_DIR/subdomains/live.txt"
fi
live=$(wc -l < "$OUTPUT_DIR/subdomains/live.txt" || echo 0)
ok "Live hosts: $live"

if command -v gau >/dev/null 2>&1; then
  run "cat $OUTPUT_DIR/subdomains/live.txt | gau > $OUTPUT_DIR/urls/gau.txt"
fi
if command -v waybackurls >/dev/null 2>&1; then
  run "cat $OUTPUT_DIR/subdomains/live.txt | waybackurls > $OUTPUT_DIR/urls/wayback.txt"
fi
cat $OUTPUT_DIR/urls/*.txt 2>/dev/null | sort -u > "$OUTPUT_DIR/urls/all_urls.txt"
url_count=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" || echo 0)
ok "URLs collected: $url_count"

if [ "$MODE" != "fast" ] && command -v nuclei >/dev/null 2>&1; then
  run "nuclei -l $OUTPUT_DIR/subdomains/live.txt -o $OUTPUT_DIR/reports/nuclei.txt -silent"
  vuln_count=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" || echo 0)
  ok "Nuclei scan complete ($vuln_count findings)"
fi

if command -v gowitness >/dev/null 2>&1; then
  run "gowitness file -f $OUTPUT_DIR/subdomains/live.txt --destination $OUTPUT_DIR/screenshots --timeout 10"
fi

# ------------------------
# Final Summary
# ------------------------
END_TS=$(date +%s)
DUR=$((END_TS-START_TS))
MIN=$((DUR/60)); SEC=$((DUR%60))

echo
echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              RECON COMPLETE                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo
echo "Target: $DOMAIN"
echo "Mode: $MODE"
echo "Duration: ${MIN}m ${SEC}s"
echo
echo "Subdomains: $total_subs"
echo "Live Hosts: $live"
echo "URLs: $url_count"
echo "Report: $OUTPUT_DIR/"
echo
ok "Recon finished successfully."
