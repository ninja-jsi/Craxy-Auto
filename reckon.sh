#!/usr/bin/env bash
# reckon.sh — Plain Bash recon (no gum, manual install only)
# Usage: ./reckon.sh <domain> [mode] [-v|--verbose]
set -euo pipefail
IFS=$'\n\t'

# ---------- args ----------
DOMAIN="${1:-}"
MODE="${2:-medium}"
VERBOSE=false
for a in "$@"; do
  if [[ "$a" == "-v" || "$a" == "--verbose" ]]; then VERBOSE=true; fi
  if [[ "$a" == "-h" || "$a" == "--help" ]]; then
    cat <<EOF
Usage: $0 <domain> [mode] [-v|--verbose]
Mode: fast | medium (default) | full
-v shows verbose command output (progress)
This script DOES NOT auto-install tools. Install missing tools manually.
EOF
    exit 0
  fi
done

if [[ -z "$DOMAIN" ]]; then
  echo "Error: missing domain"
  echo "Usage: $0 <domain> [mode] [-v]"
  exit 1
fi

OUTPUT_DIR="${DOMAIN}-recon"
WORDLIST_DIR="${HOME}/Recon-Wordlists"
START_TS=$(date +%s)

# ---------- colors ----------
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"

info(){ printf "%b\n" "${BLUE}[*]${NC} $*"; }
ok(){ printf "%b\n" "${GREEN}[✓]${NC} $*"; }
warn(){ printf "%b\n" "${YELLOW}[!]${NC} $*"; }
die(){ printf "%b\n" "${RED}[✗]${NC} $*"; exit 1; }

# ---------- helpers ----------
run_cmd() {
  # run a command; if verbose, show it
  if $VERBOSE; then
    printf "%b\n" "${BLUE}→${NC} $*"
    eval "$@"
  else
    eval "$@" >/dev/null 2>&1 || true
  fi
}

# ---------- tool lists ----------
ESSENTIAL=(git curl wget jq awk sed sort unzip python3)
OPTIONAL=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner katana)
ALL_TOOLS=("${ESSENTIAL[@]}" "${OPTIONAL[@]}")

# ---------- check dependencies ----------
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

# ---------- print boxes (plain, always prints both) ----------
print_grid() {
  local -n arr="$1"; local symbol="$2"; local color="$3"
  local pad=26 col=0 cols=3 line=""
  for item in "${arr[@]}"; do
    [[ -z "$item" ]] && continue
    cell="${color}${symbol} ${item}${NC}"
    # pad to width
    printf -v padded "%-${pad}s" "$cell"
    line+="$padded"
    ((col++))
    if (( col % cols == 0 )); then
      printf "  %s\n" "$line"
      line=""
    fi
  done
  if [[ -n "$line" ]]; then
    printf "  %s\n" "$line"
  fi
}

# Prepare counts
present_count=${#present[@]}
missing_count=${#missing[@]}

printf "\n┌────────────────────────────────────────────────────────┐\n"
printf "│ %-54s │\n" "✅ Present (${present_count})"
printf "├────────────────────────────────────────────────────────┤\n"
if (( present_count > 0 )); then
  print_grid present "✓" "$GREEN"
else
  printf "  (none)\n"
fi
printf "└────────────────────────────────────────────────────────┘\n\n"

printf "┌────────────────────────────────────────────────────────┐\n"
printf "│ %-54s │\n" "❌ Missing (${missing_count})"
printf "├────────────────────────────────────────────────────────┤\n"
if (( missing_count > 0 )); then
  print_grid missing "✗" "$RED"
else
  printf "  (none)\n"
fi
printf "└────────────────────────────────────────────────────────┘\n\n"

# If any essential missing -> exit now
if (( ${#essential_missing[@]} > 0 )); then
  printf "%b\n" "${YELLOW}⚠️  Essential tools missing:${NC}"
  for t in "${essential_missing[@]}"; do printf "   • %s\n" "$t"; done
  echo
  printf "%b\n" "Install them manually (example):"
  printf "  %s\n" "  sudo apt update && sudo apt install -y git curl wget jq unzip python3"
  printf "  %s\n" "  brew install git curl wget jq python3    # on macOS"
  echo
  die "Exiting — install essential tools and re-run."
fi

# If optional missing -> warn but continue
if (( ${#optional_missing[@]} > 0 )); then
  printf "%b\n" "${YELLOW}Optional tools missing (features limited):${NC}"
  for t in "${optional_missing[@]}"; do printf "   • %s\n" "$t"; done
  echo
fi

printf "%b\n" "${GREEN}All essential tools present — continuing...${NC}"
echo

# ---------- ensure directories & wordlists ----------
mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp}
mkdir -p "$WORDLIST_DIR"

# Small set of wordlists (download if not present)
declare -A WLS=(
  [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
  [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
  [s3]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/AWS/s3-buckets-top50.txt"
)
for k in "${!WLS[@]}"; do
  tgt="$WORDLIST_DIR/${k}.txt"
  if [ ! -s "$tgt" ]; then
    info "Downloading wordlist: $k"
    run_cmd "curl -sSfL '${WLS[$k]}' -o '$tgt' || true"
  fi
done

# ---------- pipeline ----------
ok "Starting recon: $DOMAIN (mode: $MODE)"

# Subdomain enumeration
info "Subdomain enumeration..."
run_cmd "subfinder -silent -d '$DOMAIN' -o '$OUTPUT_DIR/temp/subfinder.txt' || true" || true
run_cmd "assetfinder --subs-only '$DOMAIN' > '$OUTPUT_DIR/temp/assetfinder.txt' 2>/dev/null || true" || true
# crt.sh
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  run_cmd "curl -s 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' | sed 's/\\*\\.//g' > '$OUTPUT_DIR/temp/crtsh.txt' || true" || true
fi
# merge
run_cmd "cat '$OUTPUT_DIR/temp'/*.txt 2>/dev/null | sed 's/\\*\\.//g' | grep -E '^[A-Za-z0-9._-]+\\.[A-Za-z]{2,}\$' | sort -u > '$OUTPUT_DIR/subdomains/all_subs.txt' || true"
total_subs=$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
ok "Subdomains: $total_subs"

# Live check
info "Detecting live hosts..."
if command -v dnsx >/dev/null 2>&1; then
  run_cmd "dnsx -silent -l '$OUTPUT_DIR/subdomains/all_subs.txt' -o '$OUTPUT_DIR/subdomains/resolved.txt' || cp -f '$OUTPUT_DIR/subdomains/all_subs.txt' '$OUTPUT_DIR/subdomains/resolved.txt'"
else
  run_cmd "cp -f '$OUTPUT_DIR/subdomains/all_subs.txt' '$OUTPUT_DIR/subdomains/resolved.txt'"
fi

if command -v httpx >/dev/null 2>&1; then
  run_cmd "cat '$OUTPUT_DIR/subdomains/resolved.txt' | httpx -silent -o '$OUTPUT_DIR/subdomains/live.txt' || cp -f '$OUTPUT_DIR/subdomains/resolved.txt' '$OUTPUT_DIR/subdomains/live.txt'"
else
  run_cmd "cp -f '$OUTPUT_DIR/subdomains/resolved.txt' '$OUTPUT_DIR/subdomains/live.txt'"
fi
live=$(wc -l < "$OUTPUT_DIR/subdomains/live.txt" 2>/dev/null || echo 0)
ok "Live hosts: $live"

# URLs (gau / wayback)
if [[ "$MODE" != "fast" ]]; then
  info "Gathering URLs (gau/wayback)..."
  if command -v gau >/dev/null 2>&1; then
    run_cmd "cat '$OUTPUT_DIR/subdomains/live.txt' | gau --threads 10 > '$OUTPUT_DIR/urls/gau.txt' 2>/dev/null || true"
  fi
  if command -v waybackurls >/dev/null 2>&1; then
    run_cmd "cat '$OUTPUT_DIR/subdomains/live.txt' | waybackurls > '$OUTPUT_DIR/urls/wayback.txt' 2>/dev/null || true"
  fi
  run_cmd "cat '$OUTPUT_DIR/urls'/*.txt 2>/dev/null | sort -u > '$OUTPUT_DIR/urls/all_urls.txt' || true"
  url_count=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
  ok "URLs collected: $url_count"
fi

# Parameter extraction using gf (if available)
if command -v gf >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/urls/all_urls.txt" ]; then
  info "Extracting params with gf..."
  run_cmd "cat '$OUTPUT_DIR/urls/all_urls.txt' | gf xss > '$OUTPUT_DIR/params/xss.txt' 2>/dev/null || true"
  run_cmd "cat '$OUTPUT_DIR/urls/all_urls.txt' | gf sqli > '$OUTPUT_DIR/params/sqli.txt' 2>/dev/null || true"
  ok "Parameter extraction done"
fi

# Nuclei (if mode != fast)
if [[ "$MODE" == "full" || "$MODE" == "medium" ]]; then
  if command -v nuclei >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
    info "Running nuclei (quick)..."
    run_cmd "nuclei -l '$OUTPUT_DIR/subdomains/live.txt' -silent -o '$OUTPUT_DIR/reports/nuclei.txt' || true"
    vuln_count=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" 2>/dev/null || echo 0)
    ok "Nuclei: $vuln_count findings"
  fi
fi

# Screenshots (gowitness)
if command -v gowitness >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
  info "Taking screenshots (gowitness)..."
  run_cmd "gowitness file -f '$OUTPUT_DIR/subdomains/live.txt' --destination '$OUTPUT_DIR/screenshots' --timeout 10 || true"
  ok "Screenshots complete"
fi

# Simple directory fuzzing (ffuf) for top hosts
if command -v ffuf >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/subdomains/live.txt" ]; then
  info "Running quick FFUF fuzz on up to 10 hosts..."
  WL="$WORDLIST_DIR/common.txt"
  head -n 10 "$OUTPUT_DIR/subdomains/live.txt" | while read -r h; do
    run_cmd "ffuf -u 'http://$h/FUZZ' -w '$WL' -t 30 -mc 200,301,302 -o '$OUTPUT_DIR/dirs/ffuf_${h}.json' -of json || true"
  done
  ok "FFUF fuzzing (quick) done"
fi

# S3 checks (wordlist)
if [ -s "$WORDLIST_DIR/s3.txt" ]; then
  info "Checking S3 buckets from wordlist..."
  run_cmd "while read -r b; do url=\"https://$b.s3.amazonaws.com\"; if curl -I -s --max-time 6 \"\$url\" | grep -q '200\\|403'; then echo \"\$url\" >> '$OUTPUT_DIR/s3/found.txt'; fi; done < '$WORDLIST_DIR/s3.txt' || true"
  ok "S3 checks done"
fi

# Report
END_TS=$(date +%s)
DUR=$((END_TS-START_TS)); MIN=$((DUR/60)); SEC=$((DUR%60))
cat > "$OUTPUT_DIR/reports/REPORT.txt" <<REPORT
Recon Report - $DOMAIN
Mode: $MODE
Duration: ${MIN}m ${SEC}s
Date: $(date)

Summary:
  Subdomains: $total_subs
  Live Hosts: $live
  URLs: ${url_count:-0}

Files:
  $OUTPUT_DIR/subdomains/all_subs.txt
  $OUTPUT_DIR/subdomains/live.txt
  $OUTPUT_DIR/urls/all_urls.txt
  $OUTPUT_DIR/dirs/
  $OUTPUT_DIR/reports/
REPORT

ok "Report saved: $OUTPUT_DIR/reports/REPORT.txt"

# final summary
echo
printf "%b\n" "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
printf "%b\n" "${GREEN}║              RECON COMPLETE                            ║${NC}"
printf "%b\n" "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo
echo "Target: $DOMAIN"
echo "Mode: $MODE"
echo "Duration: ${MIN}m ${SEC}s"
echo
echo "Subdomains: $total_subs"
echo "Live Hosts: $live"
echo "URLs: ${url_count:-0}"
echo "Report: $OUTPUT_DIR/reports/REPORT.txt"
echo

exit 0
