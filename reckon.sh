#!/usr/bin/env bash
# reckon.sh — Full Enterprise Recon Script (robust httpx + clear missing/present display)
set -euo pipefail
IFS=$'\n\t'

# Colors
RED='[0;31m'
GREEN='[0;32m'
YELLOW='[1;33m'
BLUE='[1;34m'
MAGENTA='[1;35m'
CYAN='[1;36m'
NC='[0m'

########################################
# Defaults
########################################
DOMAIN=""
MODE="medium"
INSTALL_MISSING=false
REFRESH_WORDLISTS=false
NO_SCREENSHOTS=false
SKIP_HTTPX=false
PORTS=""
TELEGRAM_CFG=""
SLACK_WEBHOOK=""
OUTPUT_SUFFIX="-recon"
GLOBAL_WORDLISTS="$HOME/.recon-wordlists"
INSTALL_PREFIX="$HOME/.local/bin"
export PATH="$INSTALL_PREFIX:$PATH:$HOME/go/bin"

########################################
# Arg parsing
########################################
usage(){
  cat <<USAGE
Usage: $0 <domain> [flags]
Flags:
  --mode <fast|medium|full>
  --install-missing
  --refresh-wordlists
  --no-screenshots
  --skip-httpx
  --ports "1-1000"
  --telegram TOKEN:CHATID
  --slack WEBHOOK_URL
Example: $0 example.com --install-missing
USAGE
  exit 1
}

if [ $# -lt 1 ]; then usage; fi
POSITIONAL=()
while (( $# )); do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --install-missing) INSTALL_MISSING=true; shift;;
    --refresh-wordlists) REFRESH_WORDLISTS=true; shift;;
    --no-screenshots) NO_SCREENSHOTS=true; shift;;
    --skip-httpx) SKIP_HTTPX=true; shift;;
    --ports) PORTS="$2"; shift 2;;
    --telegram) TELEGRAM_CFG="$2"; shift 2;;
    --slack) SLACK_WEBHOOK="$2"; shift 2;;
    -h|--help) usage;;
    *) POSITIONAL+=("$1"); shift;;
  esac
done
DOMAIN="${POSITIONAL[0]}"
OUTPUT="${DOMAIN}${OUTPUT_SUFFIX}"

########################################
# Tools to check
########################################
core_tools=(curl awk grep sed sort python3)
optional_tools=(subfinder assetfinder httpx naabu nuclei katana ffuf gau waybackurls gf jq nmap amass)

missing_tools=()
present_tools=()

check_tool(){
  local t="$1"
  if command -v "$t" >/dev/null 2>&1; then
    present_tools+=("$t")
  else
    missing_tools+=("$t")
  fi
}

echo -e "${YELLOW}[*] Checking dependencies...${NC}"
for t in "${core_tools[@]}"; do check_tool "$t"; done
for t in "${optional_tools[@]}"; do check_tool "$t"; done

# Pretty print present/missing
echo -e "\n${CYAN}───────────────────────────────${NC}"
if [ ${#present_tools[@]} -gt 0 ]; then
  echo -e "${GREEN}Present:${NC}"
  for p in "${present_tools[@]}"; do echo -e "  - $p"; done
else
  echo -e "${RED}No known tools present${NC}"
fi

echo -e "\n${YELLOW}Missing:${NC}"
if [ ${#missing_tools[@]} -gt 0 ]; then
  for m in "${missing_tools[@]}"; do echo -e "  - $m"; done
else
  echo -e "  (none)"
fi
echo -e "${CYAN}───────────────────────────────${NC}\n"

if [ "$INSTALL_MISSING" = true ] && [ ${#missing_tools[@]} -gt 0 ]; then
  echo -e "${YELLOW}[*] Attempting automatic install of missing tools...${NC}"
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    for m in "${missing_tools[@]}"; do
      echo -e "  Installing $m..."
      sudo apt-get install -y "$m" >/dev/null 2>&1 || echo -e "  ${RED}Failed to install $m via apt${NC}";
    done
  elif command -v yum >/dev/null 2>&1; then
    for m in "${missing_tools[@]}"; do
      sudo yum install -y "$m" >/dev/null 2>&1 || echo -e "  ${RED}Failed to install $m via yum${NC}";
    done
  else
    echo -e "${RED}Automatic install not supported on this OS. Install manually.${NC}"
  fi
fi

if [ ${#missing_tools[@]} -gt 0 ]; then
  echo -e "${YELLOW}⚠️  Some tools are missing and may limit functionality.${NC}\n"
fi

########################################
# Prepare directories
########################################
echo -e "${BLUE}[*] Setting up output directories...${NC}"
mkdir -p "$OUTPUT/subdomains" "$OUTPUT/logs" "$OUTPUT/params" "$OUTPUT/jsfiles" "$OUTPUT/dirs" "$OUTPUT/ports" "$OUTPUT/git" "$OUTPUT/s3"

########################################
# Banner
########################################
echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║               RECKON RECON PIPELINE                    ║${NC}"
echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}\n"

########################################
# Subdomain enumeration
########################################
echo -e "${YELLOW}[*] Subdomain enumeration...${NC}"
if command -v subfinder >/dev/null 2>&1; then
  subfinder -silent -d "$DOMAIN" -o "$OUTPUT/subdomains/subfinder.txt" || true
fi
if command -v assetfinder >/dev/null 2>&1; then
  assetfinder --subs-only "$DOMAIN" > "$OUTPUT/subdomains/assetfinder.txt" || true
fi
# merge
cat "$OUTPUT/subdomains"/*.txt 2>/dev/null | grep -E "^[A-Za-z0-9._-]+\.?[A-Za-z]{2,}$" | sort -u > "$OUTPUT/subdomains/all.txt" || true
subcount=$(wc -l < "$OUTPUT/subdomains/all.txt" 2>/dev/null || echo 0)
echo -e "  Found ${GREEN}$subcount${NC} unique subdomains.\n"

########################################
# Live host detection — robust httpx handling
########################################
echo -e "${YELLOW}[*] Live host detection...${NC}"
# ensure input exists
if [ ! -s "$OUTPUT/subdomains/all.txt" ]; then
  echo -e "  ${RED}No subdomains found to check.${NC}"
  touch "$OUTPUT/subdomains/live.txt"
else
  if [ "$SKIP_HTTPX" = true ] || ! command -v httpx >/dev/null 2>&1; then
    cp -f "$OUTPUT/subdomains/all.txt" "$OUTPUT/subdomains/live.txt" || true
    echo -e "  ${YELLOW}httpx skipped or not installed — using all subdomains as live fallback${NC}\n"
  else
    # Prefer piping to httpx (many builds support stdin). Try once; fallback to per-line concurrency loop.
    if cat "$OUTPUT/subdomains/all.txt" | httpx -json -o "$OUTPUT/subdomains/live_tmp.json" -silent >/dev/null 2>&1; then
      # Extract url/host lines to live.txt (some httpx outputs contain url field)
      jq -r '.url // .host // empty' "$OUTPUT/subdomains/live_tmp.json" 2>/dev/null | sed 's#https\?://##' | sort -u > "$OUTPUT/subdomains/live.txt" || true
      rm -f "$OUTPUT/subdomains/live_tmp.json" 2>/dev/null || true
    else
      echo -e "  ${YELLOW}httpx stdout mode failed; falling back to per-host httpx calls (slower)...${NC}"
      > "$OUTPUT/subdomains/live.txt"
      # Run in parallel with xargs (50 threads)
      cat "$OUTPUT/subdomains/all.txt" | xargs -P 50 -I % sh -c 'echo % | httpx -silent -no-color -status-code 2>/dev/null | sed -n "1p"' >> "$OUTPUT/subdomains/live.txt" 2>/dev/null || true
      # sanitize
      sed -i 's#https\?://##g' "$OUTPUT/subdomains/live.txt" 2>/dev/null || true
      sort -u -o "$OUTPUT/subdomains/live.txt" "$OUTPUT/subdomains/live.txt" 2>/dev/null || true
    fi
  fi
fi
livecount=$(wc -l < "$OUTPUT/subdomains/live.txt" 2>/dev/null || echo 0)
echo -e "  Live hosts detected: ${GREEN}$livecount${NC}\n"

# If still empty, fallback to all
if [ "$livecount" -eq 0 ]; then
  cp -f "$OUTPUT/subdomains/all.txt" "$OUTPUT/subdomains/live.txt" || true
  echo -e "  ${YELLOW}No live hosts detected; using all subdomains as fallback to continue pipeline.${NC}\n"
fi

########################################
# URL harvesting
########################################
echo -e "${YELLOW}[*] URL harvesting (gau/waybackurls)...${NC}"
> "$OUTPUT/params/gau.txt"
> "$OUTPUT/params/wayback.txt"
if command -v gau >/dev/null 2>&1; then
  cat "$OUTPUT/subdomains/all.txt" | head -n 200 | gau --threads 10 > "$OUTPUT/params/gau.txt" 2>/dev/null || true
fi
if command -v waybackurls >/dev/null 2>&1; then
  cat "$OUTPUT/subdomains/all.txt" | head -n 200 | waybackurls > "$OUTPUT/params/wayback.txt" 2>/dev/null || true
fi
cat "$OUTPUT/params"/*.txt 2>/dev/null | sort -u > "$OUTPUT/params/all.txt" || true
urlcount=$(wc -l < "$OUTPUT/params/all.txt" 2>/dev/null || echo 0)
echo -e "  URLs collected: ${GREEN}$urlcount${NC}\n"

########################################
# JS secrets
########################################
echo -e "${YELLOW}[*] JS file extraction & secret hunting...${NC}"
> "$OUTPUT/js_candidates.txt"
if [ -s "$OUTPUT/params/all.txt" ]; then
  grep -iE "\\.js(\\?|$|#)" "$OUTPUT/params/all.txt" 2>/dev/null | sort -u > "$OUTPUT/js_candidates.txt" || true
fi
if [ -s "$OUTPUT/js_candidates.txt" ]; then
  i=0
  while IFS= read -r jsu && [ $i -lt 200 ]; do
    safe=$(echo "$jsu" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-180)
    curl -sSfL "$jsu" -o "$OUTPUT/jsfiles/$safe" -m 10 || true
    i=$((i+1))
  done < "$OUTPUT/js_candidates.txt"
fi
# secret patterns
> "$OUTPUT/js_secrets.txt"
grep -Eroh "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|xox[baprs]-[A-Za-z0-9-]+|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48}" "$OUTPUT/jsfiles" 2>/dev/null | sort -u > "$OUTPUT/js_secrets.txt" || true
secretcount=$(wc -l < "$OUTPUT/js_secrets.txt" 2>/dev/null || echo 0)
echo -e "  Potential JS secrets found: ${RED}$secretcount${NC}\n"

########################################
# Port scan (naabu/nmap)
########################################
echo -e "${YELLOW}[*] Port scanning...${NC}"
if command -v naabu >/dev/null 2>&1; then
  cat "$OUTPUT/subdomains/live.txt" | head -n 200 | naabu -silent -o "$OUTPUT/ports/naabu.txt" || true
elif command -v nmap >/dev/null 2>&1; then
  nmap -iL "$OUTPUT/subdomains/live.txt" -oG "$OUTPUT/ports/nmap.txt" --open -T4 || true
else
  echo -e "  ${YELLOW}No port scanner installed (naabu/nmap). Skipping port scan.${NC}"
fi

########################################
# Nuclei
########################################
echo -e "${YELLOW}[*] Running nuclei (if available)...${NC}"
if command -v nuclei >/dev/null 2>&1; then
  if [ -s "$OUTPUT/subdomains/live.txt" ]; then
    nuclei -l "$OUTPUT/subdomains/live.txt" -severity low,medium,high,critical -o "$OUTPUT/nuclei.txt" -silent || true
  fi
else
  echo -e "  ${YELLOW}nuclei not installed. Skipping.${NC}"
fi

########################################
# Final summary
########################################
echo -e "\n${MAGENTA}───────────────────────────────${NC}"
echo -e "${CYAN}Recon Complete for:${NC} ${YELLOW}$DOMAIN${NC}"
echo -e "${MAGENTA}───────────────────────────────${NC}"
echo -e "  Subdomains:      ${GREEN}$(wc -l < "$OUTPUT/subdomains/all.txt" 2>/dev/null || echo 0)${NC}"
echo -e "  Live Hosts:      ${GREEN}$(wc -l < "$OUTPUT/subdomains/live.txt" 2>/dev/null || echo 0)${NC}"
echo -e "  URLs:            ${GREEN}$urlcount${NC}"
echo -e "  JS Secrets:      ${RED}$secretcount${NC}"
echo -e "${MAGENTA}───────────────────────────────${NC}"
echo -e "  Present Tools:    ${GREEN}${#present_tools[@]}${NC}"
echo -e "  Missing Tools:    ${YELLOW}${#missing_tools[@]}${NC}"
echo -e "${MAGENTA}───────────────────────────────${NC}\n"

if [ ${#missing_tools[@]} -gt 0 ]; then
  echo -e "${YELLOW}Some tools are missing. Re-run with --install-missing or install manually. Example:${NC}"
  echo -e "  ${BLUE}go install github.com/tomnomnom/waybackurls@latest${NC}"
fi

exit 0
