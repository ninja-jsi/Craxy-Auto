#!/usr/bin/env bash
# reckon.sh — Recon pipeline (manual-install only, no auto-install)
# Usage: ./reckon.sh <domain> [mode] [-v|--verbose]
# Modes: fast | medium (default) | full
set -euo pipefail
IFS=$'\n\t'

# --------------------
# Config & defaults
# --------------------
SCRIPT="$(basename "$0")"
DOMAIN="${1:-}"
MODE="${2:-medium}"
VERBOSE=false
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: $SCRIPT <domain> [mode] [-v|--verbose]"
  echo "Modes: fast | medium | full"
  exit 0
fi
# check for optional verbose flag anywhere
for a in "$@"; do
  if [[ "$a" == "-v" || "$a" == "--verbose" ]]; then VERBOSE=true; fi
done

if [ -z "$DOMAIN" ]; then
  echo "Error: missing domain."
  echo "Usage: $SCRIPT <domain> [mode] [-v|--verbose]"
  exit 1
fi

OUTPUT_DIR="${DOMAIN}-recon"
WORDLIST_DIR="${HOME}/Recon-Wordlists"
START_TS=$(date +%s)

# Colors
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"

# --------------------
# Tools
# --------------------
ESSENTIAL=(git curl wget jq awk sed sort unzip python3)
OPTIONAL=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner katana)

ALL_TOOLS=("${ESSENTIAL[@]}" "${OPTIONAL[@]}")

# --------------------
# Helpers
# --------------------
info(){ echo -e "${BLUE}[*]${NC} $*"; }
ok(){ echo -e "${GREEN}[✓]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
die(){ echo -e "${RED}[✗]${NC} $*"; exit 1; }

# run command helper: prints the command when verbose, otherwise hides its stdout/stderr
run_cmd() {
  if [ "$VERBOSE" = true ]; then
    echo -e "${BLUE}→${NC} $*"
    sh -c "$*"
  else
    sh -c "$*" >/dev/null 2>&1 || true
  fi
}

# pretty display that always prints both boxes and flushes output (uses tee to avoid truncation)
pretty_tools_display_and_exit_if_essential_missing() {
  local -n _present="$1"
  local -n _missing="$2"
  local -n _essential_missing="$3"

  {
    GREEN="\033[0;32m"
    RED="\033[0;31m"
    YELLOW="\033[1;33m"
    NC="\033[0m"
    PAD=26

    format_grid() {
      local -n arr="$1"; local symbol="$2"; local color="$3"
      local i=0; local line=""
      for item in "${arr[@]}"; do
        [[ -z "$item" ]] && continue
        local cell="${color}${symbol} ${item}${NC}"
        printf -v padded "%-${PAD}s" "$cell"
        line+="$padded"
        ((i++))
        if (( i % 3 == 0 )); then
          echo -e "  $line"
          line=""
        fi
      done
      [ -n "$line" ] && echo -e "  $line"
    }

    present_count=${#_present[@]}
    missing_count=${#_missing[@]}

    echo -e "\n┌────────────────────────────────────────────────────────┐"
    printf "│ %-54s │\n" "✅ Present (${present_count})"
    echo -e "├────────────────────────────────────────────────────────┤"
    if (( present_count > 0 )); then
      format_grid _present "✓" "$GREEN"
    else
      echo -e "  (none)"
    fi
    echo -e "└────────────────────────────────────────────────────────┘\n"
    sleep 0.08

    echo -e "┌────────────────────────────────────────────────────────┐"
    printf "│ %-54s │\n" "❌ Missing (${missing_count})"
    echo -e "├────────────────────────────────────────────────────────┤"
    if (( missing_count > 0 )); then
      format_grid _missing "✗" "$RED"
    else
      echo -e "  (none)"
    fi
    echo -e "└────────────────────────────────────────────────────────┘\n"

    # If any essential missing -> exit with message
    if (( ${#_essential_missing[@]} > 0 )); then
      echo -e "${YELLOW}⚠️  Essential tools missing:${NC}"
      for t in "${_essential_missing[@]}"; do
        echo "   • $t"
      done
      echo
      echo -e "${YELLOW}Manual install hint:${NC} Use your package manager or visit each project's README to install."
      echo -e "${RED}✗ Exiting — install the missing essential tools and re-run.${NC}\n"
      exit 1
    else
      echo -e "${GREEN}All essential tools present. Continuing...${NC}\n"
    fi
  } 2>&1 | tee /tmp/reckon-depcheck.log
}

show_manual_instructions() {
  echo
  echo "Manual install hints (examples):"
  echo "  Debian/Ubuntu/Kali:"
  echo "    sudo apt update && sudo apt install -y git curl wget jq unzip python3 python3-pip"
  echo "  macOS (Homebrew):"
  echo "    brew install git curl wget jq python3"
  echo
  echo "Go-based tools (after installing Go):"
  for k in "${!GO_PKGS[@]:-}"; do
    echo "  GO111MODULE=on go install ${GO_PKGS[$k]}"
  done 2>/dev/null || true
  echo
  echo "WPScan:"
  echo "  sudo gem install wpscan"
  echo "dirsearch:"
  echo "  git clone https://github.com/maurosoria/dirsearch.git ~/dirsearch"
  echo "s3scanner:"
  echo "  pip3 install --user s3scanner"
  echo
}

# mapping of some go packages (used for hint only)
declare -A GO_PKGS=(
  [subfinder]=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  [httpx]=github.com/projectdiscovery/httpx/cmd/httpx@latest
  [dnsx]=github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  [naabu]=github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  [nuclei]=github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  [gau]=github.com/lc/gau/v2/cmd/gau@latest
  [waybackurls]=github.com/tomnomnom/waybackurls@latest
)

# --------------------
# Wordlists (central)
# --------------------
ensure_wordlists() {
  mkdir -p "$WORDLIST_DIR"
  declare -A WL=(
    [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
    [s3]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/AWS/s3-buckets-top50.txt"
  )
  for k in "${!WL[@]}"; do
    tgt="$WORDLIST_DIR/${k}.txt"
    if [ ! -s "$tgt" ]; then
      info "Downloading wordlist: $k"
      if curl -sSfL "${WL[$k]}" -o "$tgt"; then ok "Downloaded $k"; else warn "Failed $k"; fi
    fi
  done
}

# --------------------
# Dependency check
# --------------------
present=(); missing=(); essential_missing=(); optional_missing=()
for t in "${ALL_TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    present+=("$t")
  else
    # classify
    if printf '%s\n' "${ESSENTIAL[@]}" | grep -Fxq "$t"; then
      essential_missing+=("$t")
    else
      optional_missing+=("$t")
    fi
    missing+=("$t")
  fi
done

# Show present/missing and exit if any essential missing
pretty_tools_display_and_exit_if_essential_missing present missing essential_missing

# If only optional missing, print a warning but continue
if (( ${#optional_missing[@]} > 0 )); then
  warn "Optional tools not present (features may be limited): ${optional_missing[*]}"
  echo
  show_manual_instructions
fi

# --------------------
# Prepare output dirs
# --------------------
ensure_wordlists
mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp}

# small helper for gum spinner availability
GUM="$(command -v gum 2>/dev/null || true)"
spin_run() {
  local title="$1"; shift
  local cmd="$*"
  if [ -n "$GUM" ]; then
    if [ "$VERBOSE" = true ]; then
      "$GUM" spin --spinner line --title "$title" -- sh -c "$cmd"
    else
      "$GUM" spin --spinner line --title "$title" -- sh -c "$cmd" >/dev/null 2>&1 || true
    fi
  else
    if [ "$VERBOSE" = true ]; then
      echo -e "${BLUE}[*]${NC} $title"
      sh -c "$cmd"
    else
      echo -n "$title ... "
      sh -c "$cmd" >/dev/null 2>&1 || true
      echo "done"
    fi
  fi
}

# --------------------
# Pipeline tasks
# --------------------
run_subdomain_enum(){
  spin_run "Subdomain enumeration" "
    mkdir -p \"$OUTPUT_DIR/temp\";
    [ -f \"$OUTPUT_DIR/temp/subfinder.txt\" ] && rm -f \"$OUTPUT_DIR/temp/subfinder.txt\";
    if command -v subfinder >/dev/null 2>&1; then subfinder -silent -d \"$DOMAIN\" -o \"$OUTPUT_DIR/temp/subfinder.txt\" 2>/dev/null || true; fi;
    if command -v assetfinder >/dev/null 2>&1; then assetfinder --subs-only \"$DOMAIN\" > \"$OUTPUT_DIR/temp/assetfinder.txt\" 2>/dev/null || true; fi;
    if command -v amass >/dev/null 2>&1 && [ \"$MODE\" != \"fast\" ]; then timeout 60 amass enum -passive -d \"$DOMAIN\" -o \"$OUTPUT_DIR/temp/amass.txt\" 2>/dev/null || true; fi;
    if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then curl -s \"https://crt.sh/?q=%25.$DOMAIN&output=json\" 2>/dev/null | jq -r '.[].name_value' | sed 's/\\*\\.//g' > \"$OUTPUT_DIR/temp/crtsh.txt\" || true; fi;
    cat \"$OUTPUT_DIR/temp\"/*.txt 2>/dev/null | sed 's/\\*\\.//g' | grep -E \"^[A-Za-z0-9._-]+\\.[A-Za-z]{2,}$\" | sort -u > \"$OUTPUT_DIR/subdomains/all_subs.txt\" || true
  "
  count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
  ok "Subdomain enumeration finished: $count"
}

run_live_check(){
  spin_run "Live host detection" "
    if command -v dnsx >/dev/null 2>&1; then dnsx -silent -l \"$OUTPUT_DIR/subdomains/all_subs.txt\" -o \"$OUTPUT_DIR/subdomains/resolved.txt\" 2>/dev/null || cp -f \"$OUTPUT_DIR/subdomains/all_subs.txt\" \"$OUTPUT_DIR/subdomains/resolved.txt\"; else cp -f \"$OUTPUT_DIR/subdomains/all_subs.txt\" \"$OUTPUT_DIR/subdomains/resolved.txt\"; fi;
    if command -v httpx >/dev/null 2>&1; then cat \"$OUTPUT_DIR/subdomains/resolved.txt\" | httpx -silent -o \"$OUTPUT_DIR/subdomains/live_subs.txt\" 2>/dev/null || cp -f \"$OUTPUT_DIR/subdomains/resolved.txt\" \"$OUTPUT_DIR/subdomains/live_subs.txt\"; else cp -f \"$OUTPUT_DIR/subdomains/resolved.txt\" \"$OUTPUT_DIR/subdomains/live_subs.txt\"; fi
  "
  live=$(wc -l < "$OUTPUT_DIR/subdomains/live_subs.txt" 2>/dev/null || echo 0)
  ok "Live hosts detected: $live"
}

run_url_collection(){
  [ "$MODE" = "fast" ] && return
  spin_run "URL collection (gau / wayback)" "
    mkdir -p \"$OUTPUT_DIR/urls\";
    > \"$OUTPUT_DIR/urls/all_urls.txt\";
    if command -v gau >/dev/null 2>&1; then cat \"$OUTPUT_DIR/subdomains/live_subs.txt\" | gau --threads 10 >> \"$OUTPUT_DIR/urls/all_urls.txt\" 2>/dev/null || true; fi;
    if command -v waybackurls >/dev/null 2>&1; then cat \"$OUTPUT_DIR/subdomains/live_subs.txt\" | waybackurls >> \"$OUTPUT_DIR/urls/all_urls.txt\" 2>/dev/null || true; fi;
    sort -u -o \"$OUTPUT_DIR/urls/all_urls.txt\" \"$OUTPUT_DIR/urls/all_urls.txt\" 2>/dev/null || true
  "
  ucount=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
  ok "URLs collected: $ucount"
}

run_param_extraction(){
  [ "$MODE" = "fast" ] && return
  if command -v gf >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/urls/all_urls.txt" ]; then
    spin_run "Parameter extraction (gf)" "
      mkdir -p \"$OUTPUT_DIR/params\";
      cat \"$OUTPUT_DIR/urls/all_urls.txt\" | gf xss > \"$OUTPUT_DIR/params/xss.txt\" 2>/dev/null || true;
      cat \"$OUTPUT_DIR/urls/all_urls.txt\" | gf sqli > \"$OUTPUT_DIR/params/sqli.txt\" 2>/dev/null || true;
      cat \"$OUTPUT_DIR/urls/all_urls.txt\" | gf lfi > \"$OUTPUT_DIR/params/lfi.txt\" 2>/dev/null || true
    "
    ok "Parameter extraction done"
  fi
}

run_js_secrets(){
  [ "$MODE" = "fast" ] && return
  spin_run "JS secret hunting" "
    mkdir -p \"$OUTPUT_DIR/secrets/jsfiles\";
    grep -iE '\\.js(\\?|$|#)' \"$OUTPUT_DIR/urls/all_urls.txt\" 2>/dev/null | head -n 200 > \"$OUTPUT_DIR/temp/js_urls.txt\" || true;
    i=0;
    while IFS= read -r jsu && [ \$i -lt 200 ]; do
      f=\$(echo -n \"\$jsu\" | md5sum | awk '{print \$1}').js;
      curl -sSfL \"\$jsu\" -m 15 -o \"$OUTPUT_DIR/secrets/jsfiles/\$f\" 2>/dev/null || true;
      i=\$((i+1));
    done < \"$OUTPUT_DIR/temp/js_urls.txt\";
    grep -ErohI 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}' \"$OUTPUT_DIR/secrets/jsfiles\" 2>/dev/null > \"$OUTPUT_DIR/secrets/found.txt\" || true
  "
  sc=$(wc -l < "$OUTPUT_DIR/secrets/found.txt" 2>/dev/null || echo 0)
  if [ "$sc" -gt 0 ]; then warn "Potential secrets found: $sc"; else ok "No obvious JS secrets found"; fi
}

run_portscan(){
  [ "$MODE" != "full" ] && return
  spin_run "Port scanning (naabu/nmap)" "
    mkdir -p \"$OUTPUT_DIR/ports\" \"$OUTPUT_DIR/scans\";
    if command -v naabu >/dev/null 2>&1 && [ -s \"$OUTPUT_DIR/subdomains/live_subs.txt\" ]; then
      cat \"$OUTPUT_DIR/subdomains/live_subs.txt\" | sed 's#https\\?://##g' | naabu -list - -silent -o \"$OUTPUT_DIR/ports/naabu.txt\" 2>/dev/null || true;
    fi;
    if command -v nmap >/dev/null 2>&1 && [ -s \"$OUTPUT_DIR/subdomains/live_subs.txt\" ]; then
      nmap -T4 -sC -sV -iL \"$OUTPUT_DIR/subdomains/live_subs.txt\" -oN \"$OUTPUT_DIR/scans/nmap.txt\" || true;
    fi
  "
  ok "Port scan complete"
}

run_vuln_scan(){
  spin_run "Vulnerability scanning (nuclei / wpscan)" "
    mkdir -p \"$OUTPUT_DIR/reports\";
    if command -v nuclei >/dev/null 2>&1 && [ -s \"$OUTPUT_DIR/subdomains/live_subs.txt\" ]; then
      nuclei -l \"$OUTPUT_DIR/subdomains/live_subs.txt\" -c 50 -o \"$OUTPUT_DIR/reports/nuclei.txt\" -silent 2>/dev/null || true;
    fi;
    if command -v wpscan >/dev/null 2>&1 && [ -s \"$OUTPUT_DIR/subdomains/live_subs.txt\" ]; then
      while IFS= read -r h; do
        if curl -s --max-time 8 -I \"https://$h/wp-admin/\" | grep -qi \"200\\|301\\|302\"; then
          wpscan --url \"https://$h\" --no-update --enumerate vp --output \"$OUTPUT_DIR/reports/wpscan_$h.txt\" || true;
        fi
      done < \"$OUTPUT_DIR/subdomains/live_subs.txt\";
    fi
  "
  ok "Vulnerability scanning done"
}

run_screenshots(){
  spin_run "Screenshots (gowitness)" "
    mkdir -p \"$OUTPUT_DIR/screenshots\";
    if command -v gowitness >/dev/null 2>&1 && [ -s \"$OUTPUT_DIR/subdomains/live_subs.txt\" ]; then
      gowitness file -f \"$OUTPUT_DIR/subdomains/live_subs.txt\" --destination \"$OUTPUT_DIR/screenshots\" --timeout 10 >/dev/null 2>&1 || true;
    fi
  "
  ok "Screenshots finished"
}

run_fuzzing(){
  spin_run "Directory fuzzing (ffuf/ferox/gobuster/dirsearch)" "
    mkdir -p \"$OUTPUT_DIR/dirs\";
    WL=\"$WORDLIST_DIR/common.txt\";
    if command -v ffuf >/dev/null 2>&1 && [ -s \"$OUTPUT_DIR/subdomains/live_subs.txt\" ]; then
      head -n 20 \"$OUTPUT_DIR/subdomains/live_subs.txt\" | while read -r h; do ffuf -u \"http://\$h/FUZZ\" -w \"$WL\" -t 50 -mc \"200,301,302,403\" -o \"$OUTPUT_DIR/dirs/ffuf_\$h.json\" -of json 2>/dev/null || true; done;
    fi;
    if command -v feroxbuster >/dev/null 2>&1 && [ -s \"$OUTPUT_DIR/subdomains/live_subs.txt\" ]; then
      while read -r u; do feroxbuster -u \"http://\$u\" -w \"$WL\" -t 50 -o \"$OUTPUT_DIR/dirs/ferox_\$u.txt\" >/dev/null 2>&1 || true; done < \"$OUTPUT_DIR/subdomains/live_subs.txt\";
    fi;
    if [ -d \"$HOME/dirsearch\" ]; then
      python3 \"$HOME/dirsearch/dirsearch.py\" -u \"https://$DOMAIN\" -w \"$WL\" -t 20 -o \"$OUTPUT_DIR/dirs/dirsearch_root.txt\" 2>/dev/null || true;
    fi;
    if command -v gobuster >/dev/null 2>&1; then
      gobuster dir -u \"https://$DOMAIN\" -w \"$WL\" -t 50 -o \"$OUTPUT_DIR/dirs/gobuster_root.txt\" 2>/dev/null || true;
    fi
  "
  ok "Fuzzing finished"
}

run_s3_check(){
  spin_run "S3 checks" "
    mkdir -p \"$OUTPUT_DIR/s3\";
    if [ -s \"$WORDLIST_DIR/s3.txt\" ]; then
      while IFS= read -r b; do
        url=\"https://$b.s3.amazonaws.com\";
        if curl -I -s --max-time 6 \"$url\" | grep -q \"200\\|403\"; then echo \"$url\" >> \"$OUTPUT_DIR/s3/found.txt\"; fi;
      done < \"$WORDLIST_DIR/s3.txt\";
    fi
  "
  ok "S3 checks done"
}

generate_report(){
  END_TS=$(date +%s)
  DUR=$((END_TS-START_TS)); MIN=$((DUR/60)); SEC=$((DUR%60))
  TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
  LIVE=$(wc -l < "$OUTPUT_DIR/subdomains/live_subs.txt" 2>/dev/null || echo 0)
  URLS=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
  SECRETS=$(wc -l < "$OUTPUT_DIR/secrets/found.txt" 2>/dev/null || echo 0)
  VULNS=$(wc -l < "$OUTPUT_DIR/reports/nuclei.txt" 2>/dev/null || echo 0)

  cat > "$OUTPUT_DIR/reports/REPORT.txt" <<REPORT
Recon Report - $DOMAIN
Mode: $MODE
Duration: ${MIN}m ${SEC}s
Date: $(date)

Summary:
  Subdomains: $TOTAL_SUBS
  Live Hosts: $LIVE
  URLs: $URLS
  Secrets: $SECRETS
  Vulnerabilities (nuclei): $VULNS

Files:
  $OUTPUT_DIR/subdomains/all_subs.txt
  $OUTPUT_DIR/subdomains/live_subs.txt
  $OUTPUT_DIR/urls/all_urls.txt
  $OUTPUT_DIR/dirs/
  $OUTPUT_DIR/reports/
REPORT

  ok "Report generated: $OUTPUT_DIR/reports/REPORT.txt"
}

# --------------------
# Run pipeline
# --------------------
ok "Starting recon for: $DOMAIN (mode: $MODE)"
run_subdomain_enum
run_live_check
run_url_collection
run_param_extraction
run_js_secrets
run_portscan
run_vuln_scan
run_screenshots
run_fuzzing
run_s3_check
generate_report

# final summary
TOTAL_SUBS=$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
LIVE=$(wc -l < "$OUTPUT_DIR/subdomains/live_subs.txt" 2>/dev/null || echo 0)
URLS=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)

echo
echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              RECON COMPLETE                            ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
echo
echo "Subdomains: $TOTAL_SUBS"
echo "Live Hosts: $LIVE"
[ "$URLS" -gt 0 ] && echo "URLs: $URLS"
echo "Report: $OUTPUT_DIR/reports/REPORT.txt"
echo

exit 0
