#!/usr/bin/env bash
# reckon.sh — Full Enterprise Recon Script with Fixed Dependency Check + Tool Summary
set -euo pipefail
IFS=$'\n\t'

########################################
# Defaults
########################################
DOMAIN=""
MODE="medium"
INSTALL_MISSING=false
OUTPUT_SUFFIX="-recon"
GLOBAL_WORDLISTS="$HOME/.recon-wordlists"
INSTALL_PREFIX="$HOME/.local/bin"
export PATH="$INSTALL_PREFIX:$PATH:$HOME/go/bin"

########################################
# Argument Parsing
########################################
usage() {
cat <<'USAGE'
Usage: reckon.sh <domain> [flags]
Flags:
  --mode <fast|medium|full>
  --install-missing
  --refresh-wordlists
  --no-screenshots
  --skip-httpx
  --ports "1-1000"
  --telegram TOKEN:CHATID
  --slack WEBHOOK_URL

Example:
  ./reckon.sh example.com --mode fast --install-missing
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
if [ ${#POSITIONAL[@]} -lt 1 ]; then usage; fi
DOMAIN="${POSITIONAL[0]}"
OUTPUT="${DOMAIN}${OUTPUT_SUFFIX}"

########################################
# Dependency Check + Install Logic
########################################
missing_tools=()
present_tools=()

core_tools=(curl awk grep sed sort python3)
optional_tools=(subfinder assetfinder httpx naabu nuclei katana ffuf gau waybackurls gf jq nmap amass)

check_tool() {
  local tool="$1"
  if command -v "$tool" >/dev/null 2>&1; then
    present_tools+=("$tool")
  else
    missing_tools+=("$tool")
  fi
}

echo "[*] Checking dependencies..."
for tool in "${core_tools[@]}"; do
  check_tool "$tool"
done
for tool in "${optional_tools[@]}"; do
  check_tool "$tool"
done

echo "\n───────────────────────────────"
echo "Present tools: ${present_tools[*]}"
echo "Missing tools: ${missing_tools[*]:-(none)}"
echo "───────────────────────────────"

if [ "$INSTALL_MISSING" = true ] && [ ${#missing_tools[@]} -gt 0 ]; then
  echo "\n[*] Attempting to install missing tools automatically..."
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    for tool in "${missing_tools[@]}"; do
      sudo apt-get install -y "$tool" >/dev/null 2>&1 || echo "✗ Failed to install $tool"
    done
  elif command -v yum >/dev/null 2>&1; then
    for tool in "${missing_tools[@]}"; do
      sudo yum install -y "$tool" >/dev/null 2>&1 || echo "✗ Failed to install $tool"
    done
  else
    echo "✗ Automatic installation not supported on this system."
  fi
fi

if [ ${#missing_tools[@]} -gt 0 ]; then
  echo "\n⚠️  Some tools are missing and may limit functionality."
  echo "Install manually if automatic installation failed."
  echo "Example: sudo apt install ${missing_tools[*]}"
else
  echo "\n✅ All tools verified. Proceeding..."
fi

########################################
# Setup Output
########################################
echo "[*] Setting up output directories..."
mkdir -p "$OUTPUT/subdomains" "$OUTPUT/logs" "$OUTPUT/params" "$OUTPUT/jsfiles" "$OUTPUT/dirs" "$OUTPUT/ports" "$OUTPUT/git" "$OUTPUT/s3"

########################################
# Recon Workflow
########################################
echo "\n[*] Starting reconnaissance for: $DOMAIN (mode: $MODE)"

# Subdomain enumeration
echo "[*] Running subdomain enumeration..."
if command -v subfinder >/dev/null 2>&1; then
  subfinder -silent -d "$DOMAIN" -o "$OUTPUT/subdomains/subfinder.txt" || echo "subfinder failed"
fi
if command -v assetfinder >/dev/null 2>&1; then
  assetfinder --subs-only "$DOMAIN" > "$OUTPUT/subdomains/assetfinder.txt" || echo "assetfinder failed"
fi
cat "$OUTPUT"/subdomains/*.txt 2>/dev/null | sort -u > "$OUTPUT/subdomains/all.txt"
echo "  Found $(wc -l < "$OUTPUT/subdomains/all.txt" 2>/dev/null || echo 0) unique subdomains."

# Live host detection
echo "[*] Checking live hosts..."
if command -v httpx >/dev/null 2>&1; then
  httpx -l "$OUTPUT/subdomains/all.txt" -o "$OUTPUT/subdomains/live.txt" -no-color -json -threads 50 || true || echo "httpx failed"
  echo "  $(wc -l < "$OUTPUT/subdomains/live.txt" 2>/dev/null || echo 0) live hosts detected."
fi

# URL harvesting
echo "[*] Gathering URLs..."
if command -v gau >/dev/null 2>&1; then
  gau "$DOMAIN" > "$OUTPUT/params/gau.txt" || true
fi
if command -v waybackurls >/dev/null 2>&1; then
  waybackurls "$DOMAIN" > "$OUTPUT/params/wayback.txt" || true
fi
cat "$OUTPUT/params"/*.txt 2>/dev/null | sort -u > "$OUTPUT/params/all.txt"
echo "  $(wc -l < "$OUTPUT/params/all.txt" 2>/dev/null || echo 0) URLs collected."

# JS Secret Scan
echo "[*] Extracting JS files and secrets..."
grep -iE "\.js(\?|$|#)" "$OUTPUT/params/all.txt" 2>/dev/null | sort -u > "$OUTPUT/js_candidates.txt" || true
if [ -s "$OUTPUT/js_candidates.txt" ]; then
  while IFS= read -r js; do
    name=$(echo "$js" | sed 's#[^A-Za-z0-9._-]#_#g')
    curl -s "$js" -o "$OUTPUT/jsfiles/$name" -m 10 || true
  done < "$OUTPUT/js_candidates.txt"
fi
grep -Eroh "AKIA[0-9A-Z]{16}" "$OUTPUT/jsfiles" > "$OUTPUT/js_secrets.txt" || true

# Port scanning
echo "[*] Running port scan..."
if command -v naabu >/dev/null 2>&1; then
  naabu -list "$OUTPUT/subdomains/live.txt" -o "$OUTPUT/ports/naabu.txt" -silent || true
fi

# Nuclei scanning (if installed)
echo "[*] Running nuclei (if available)..."
if command -v nuclei >/dev/null 2>&1; then
  nuclei -l "$OUTPUT/subdomains/live.txt" -severity low,medium,high,critical -o "$OUTPUT/nuclei.txt" -silent || true
fi

########################################
# Final Summary
########################################
echo "\n───────────────────────────────"
echo "Recon Complete for: $DOMAIN"
echo "───────────────────────────────"
echo "Subdomains: $(wc -l < "$OUTPUT/subdomains/all.txt" 2>/dev/null || echo 0)"
echo "Live Hosts: $(wc -l < "$OUTPUT/subdomains/live.txt" 2>/dev/null || echo 0)"
echo "URLs: $(wc -l < "$OUTPUT/params/all.txt" 2>/dev/null || echo 0)"
echo "JS Secrets: $(wc -l < "$OUTPUT/js_secrets.txt" 2>/dev/null || echo 0)"
echo "───────────────────────────────"
echo "Present Tools: ${#present_tools[@]}"
echo "Missing Tools: ${#missing_tools[@]}"
echo "───────────────────────────────"
if [ ${#missing_tools[@]} -gt 0 ]; then
  echo "Some tools missing. Re-run with --install-missing or install manually."
else
  echo "All tools present. Full pipeline executed."
fi
