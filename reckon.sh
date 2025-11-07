#!/usr/bin/env bash
# full-auto-recon-tui.sh
# Full Auto Recon (TUI) - gum interface, full toolset, shared wordlists, auto-install support
# Usage: ./full-auto-recon-tui.sh <domain> [mode]
# mode: fast | medium | full  (default: medium)

set -euo pipefail

####################################
# Help Section / Argument Parser
####################################

show_help() {
  cat << 'EOF'
Usage: full-auto-recon-tui.sh <domain> [mode] [options]

Description:
  Full Automated Reconnaissance Script with a TUI interface (gum-based),
  one-time wordlist management, automatic dependency installation, and
  full bug bounty recon pipeline.

Modes:
  fast     - Minimal scan (subdomains + live hosts)
  medium   - Standard scan (default) (adds URLs, parameters, secrets)
  full     - Deep scan (includes ports, nuclei, screenshots, dirs, etc.)

Options:
  -h, --help               Show this help menu and exit.
  --no-install             Skip automatic tool installation (useful for CI).
  --update-wordlists       Force refresh of all wordlists in ~/Recon-Wordlists/.
  --no-tui                 Disable gum UI (fallback to basic terminal output).
  --tools-only             Run only the dependency check & installer, then exit.
  --report-only            Generate final summary/report from existing data.
  --mode=<mode>            Explicitly set scan mode (fast, medium, full).
  --domain=<domain>        Explicitly set target domain (useful for automation).

Examples:
  ./full-auto-recon-tui.sh example.com
  ./full-auto-recon-tui.sh example.com full
  ./full-auto-recon-tui.sh --domain target.com --mode fast --no-install
  ./full-auto-recon-tui.sh --update-wordlists

Output:
  Results saved to <domain>-recon/ directory.
  Wordlists stored centrally in ~/Recon-Wordlists/

Dependencies:
  gum, curl, jq, go, pip3, gem, subfinder, assetfinder, amass, httpx,
  dnsx, gau, waybackurls, gf, naabu, nmap, nuclei, gowitness, ffuf,
  feroxbuster, dirsearch, gobuster, wpscan, s3scanner.

EOF
}

# ----------------------------
# Parse Args
# ----------------------------
DOMAIN=""
MODE="medium"
NO_INSTALL=false
NO_TUI=false
TOOLS_ONLY=false
REPORT_ONLY=false
UPDATE_WORDLISTS=false

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      show_help
      exit 0
      ;;
    --no-install)
      NO_INSTALL=true
      shift
      ;;
    --no-tui)
      NO_TUI=true
      shift
      ;;
    --tools-only)
      TOOLS_ONLY=true
      shift
      ;;
    --report-only)
      REPORT_ONLY=true
      shift
      ;;
    --update-wordlists)
      UPDATE_WORDLISTS=true
      shift
      ;;
    --mode=*)
      MODE="${arg#*=}"
      shift
      ;;
    --domain=*)
      DOMAIN="${arg#*=}"
      shift
      ;;
    *)
      # If positional argument is not flag, treat as domain or mode
      if [ -z "$DOMAIN" ]; then
        DOMAIN="$arg"
      elif [ "$MODE" = "medium" ]; then
        MODE="$arg"
      fi
      ;;
  esac
done

IFS=$'\n\t'

# ----------------------------
# Config / Defaults
# ----------------------------
DOMAIN="${1:-}"
MODE="${2:-medium}"
OUTPUT="${DOMAIN}-recon"
START_TS=$(date +%s)
WORDLIST_DIR="${HOME}/Recon-Wordlists"
GUM_BIN="$(command -v gum 2>/dev/null || true)"
GO_BIN="$(command -v go 2>/dev/null || true)"
PKG_MANAGER=""

# Colors (fallback if no gum)
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; MAGENTA="\033[0;35m"; NC="\033[0m"

# Tools (essentials + optional)
ESSENTIAL=(curl jq grep awk sed sort)
TOOLS=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner)

# Map of go packages for go-installable tools
declare -A GO_PKGS=(
  [subfinder]=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  [httpx]=github.com/projectdiscovery/httpx/cmd/httpx@latest
  [dnsx]=github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  [naabu]=github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
  [nuclei]=github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  [gowitness]=github.com/sensepost/gowitness@latest
  [gau]=github.com/lc/gau/v2/cmd/gau@latest
  [waybackurls]=github.com/tomnomnom/waybackurls@latest
  [gf]=github.com/tomnomnom/gf@latest
  [ffuf]=github.com/ffuf/ffuf/v2@latest
  [katana]=github.com/projectdiscovery/katana/cmd/katana@latest
)

# Scripts that need git clone or pip/gem:
# - feroxbuster (go install available), feroxbuster: github.com/epi052/feroxbuster/v2
# - dirsearch (python: pip install -r requirements)
# - wpscan (gem install)
# - s3scanner (pip install s3scanner) - many alternatives exist; we use pip s3scanner

# ----------------------------
# Helpers
# ----------------------------
die(){ echo -e "${RED}[✗]${NC} $*"; exit 1; }
info(){ echo -e "${BLUE}[*]${NC} $*"; }
ok(){ echo -e "${GREEN}[✓]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }

# check which package manager is present
detect_pkg_manager(){
  if command -v apt >/dev/null 2>&1 || command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
  elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
  elif command -v brew >/dev/null 2>&1; then
    PKG_MANAGER="brew"
  else
    PKG_MANAGER=""
  fi
}

# gum wrapper: if gum not installed, fallback to echo
gum_print(){
  if [ -n "$GUM_BIN" ]; then
    "$GUM_BIN" style --foreground 212 "$1"
  else
    echo "$1"
  fi
}

# spinner wrapper using gum if exists else simple echo
spinner_run(){
  local title="$1"; shift
  if [ -n "$GUM_BIN" ]; then
    "$GUM_BIN" spin --spinner line --title "$title" -- "$@" >/dev/null 2>&1 || true
  else
    echo -n "$title ... "
    "$@" >/dev/null 2>&1 || true
    echo "done"
  fi
}

# go install helper
go_install_tool(){
  local tool=$1 pkg=${GO_PKGS[$tool]:-}
  if [ -z "$pkg" ]; then
    return 1
  fi
  if [ -z "$GO_BIN" ]; then
    return 2
  fi
  info "Installing $tool via go install ($pkg)..."
  # set GOPATH bin into PATH if not present
  export PATH="$HOME/go/bin:$PATH"
  GO111MODULE=on go install "$pkg" >/dev/null 2>&1 && return 0 || return 1
}

# apt install helper
apt_install(){
  local package="$1"
  if [ "$PKG_MANAGER" = "apt" ]; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    sudo apt-get install -y "$package"
    return $?
  elif [ "$PKG_MANAGER" = "yum" ]; then
    sudo yum install -y "$package"
    return $?
  elif [ "$PKG_MANAGER" = "brew" ]; then
    brew install "$package"
    return $?
  else
    return 1
  fi
}

# pip install helper (user)
pip_install(){
  local pkg="$1"
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install --user "$pkg"
    return $?
  fi
  return 1
}

# gem install helper (user may need sudo for system gems)
gem_install(){
  local pkg="$1"
  if command -v gem >/dev/null 2>&1; then
    sudo gem install "$pkg" || gem install --user-install "$pkg"
    return $?
  fi
  return 1
}

# create wordlist dir and ensure lists
ensure_wordlists(){
  mkdir -p "$WORDLIST_DIR"
  # small selection from SecLists
  declare -A WL=(
    [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
    [raft]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
    [big]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
    [s3]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/AWS/s3-buckets-top50.txt"
  )
  for k in "${!WL[@]}"; do
    tgt="$WORDLIST_DIR/${k}.txt"
    if [ ! -s "$tgt" ]; then
      info "Downloading wordlist: $k"
      curl -sSfL "${WL[$k]}" -o "$tgt" || warn "Failed to download $k"
    fi
  done
}

# show manual install commands when auto install fails
show_manual_instructions(){
  echo
  echo -e "${YELLOW}If automatic install fails, run these manual commands:${NC}"
  echo
  # apt suggestions (common)
  echo "Debian/Ubuntu (examples):"
  echo "  sudo apt update && sudo apt install -y git curl wget jq ruby ruby-dev build-essential libcurl4-openssl-dev"
  echo
  echo "Go tools (after installing Go):"
  for t in "${!GO_PKGS[@]}"; do
    echo "  GO111MODULE=on go install ${GO_PKGS[$t]}"
  done
  echo
  echo "Python tools (pip):"
  echo "  pip3 install --user s3scanner"
  echo
  echo "WPScan (Ruby gem):"
  echo "  sudo gem install wpscan"
  echo
}

# ----------------------------
# Pre-checks & interactive UI
# ----------------------------
if [ -z "$DOMAIN" ]; then
  echo "Usage: $0 <domain> [mode]"
  exit 1
fi

detect_pkg_manager

# Make output directories
mkdir -p "$OUTPUT"/{subdomains,ports,scans,screenshots,params,dirs,wordlists,temp,reports,secrets}

# Check tools presence
missing=()
present=()
for t in "${ESSENTIAL[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then present+=("$t"); else missing+=("$t"); fi
done
for t in "${TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then present+=("$t"); else missing+=("$t"); fi
done

# Always ensure jq for json parsing
if ! command -v jq >/dev/null 2>&1; then missing+=("jq"); fi

# Interactive display - if gum available use it; else plain
if [ -n "$GUM_BIN" ]; then
  $GUM_BIN style --border normal --margin "1 2" --padding "1 2" --align center "🌐 Full Auto Recon (TUI)  — Target: $DOMAIN — Mode: $MODE"
  $GUM_BIN style --foreground 34 "✅ Present tools:"; printf '%s\n' "${present[@]}" | $GUM_BIN format
  $GUM_BIN style --foreground 203 "❌ Missing tools:"; printf '%s\n' "${missing[@]:-(none)}" | $GUM_BIN format || true
else
  echo "============================================="
  echo "Full Auto Recon (TUI)  — Target: $DOMAIN — Mode: $MODE"
  echo "Present tools:"; printf '  - %s\n' "${present[@]}"
  echo "Missing tools:"; printf '  - %s\n' "${missing[@]:-(none)}"
  echo "============================================="
fi

# Prompt to auto-install if anything missing
if [ ${#missing[@]} -gt 0 ]; then
  if [ -n "$GUM_BIN" ]; then
    if $GUM_BIN confirm "Attempt to auto-install missing tools? (requires sudo/go/pip/gem)"; then
      AUTO_INSTALL=true
    else
      AUTO_INSTALL=false
    fi
  else
    read -p "Attempt to auto-install missing tools? (y/N): " ans
    if [[ "$ans" =~ ^[Yy] ]]; then AUTO_INSTALL=true; else AUTO_INSTALL=false; fi
  fi
else
  AUTO_INSTALL=false
fi

# Try to install missing tools if user agreed
if [ "$AUTO_INSTALL" = true ]; then
  info "Auto-install enabled. This may require sudo and network access."
  # Install gum if not present (for prettier UI)
  if [ -z "$GUM_BIN" ]; then
    info "Attempting to install gum for TUI..."
    if [ "$PKG_MANAGER" = "apt" ]; then
      apt_install gum || true
    elif [ "$PKG_MANAGER" = "brew" ]; then
      brew install gum || true
    fi
    GUM_BIN="$(command -v gum 2>/dev/null || true)"
  fi

  # Ensure Go exists for go installs
  if command -v go >/dev/null 2>&1; then
    GO_BIN=$(command -v go)
    export PATH="$HOME/go/bin:$PATH"
  fi

  # Attempt to install missing items using best option
  for tool in "${missing[@]}"; do
    info "Installing: $tool"
    case "$tool" in
      # apt packages
      jq|nmap|ruby|python3|pip3|git|wget|curl)
        if apt_install "$tool"; then ok "Installed $tool via $PKG_MANAGER"; else warn "Failed apt install for $tool"; fi
        ;;
      # go-backed tools
      subfinder|httpx|dnsx|naabu|nuclei|gowitness|gau|waybackurls|gf|ffuf|katana)
        if go_install_tool "$tool"; then ok "Installed $tool via go"; else warn "Failed go install for $tool"; fi
        ;;
      # pip tools
      s3scanner)
        if pip_install s3scanner; then ok "Installed s3scanner via pip"; else warn "Failed pip install s3scanner"; fi
        ;;
      # gem tools
      wpscan)
        if gem_install wpscan; then ok "Installed wpscan via gem"; else warn "Failed gem install wpscan"; fi
        ;;
      # feroxbuster: go install
      feroxbuster)
        if go install github.com/epi052/feroxbuster/v2@latest >/dev/null 2>&1; then ok "Installed feroxbuster via go"; else warn "Failed feroxbuster go install"; fi
        ;;
      # dirsearch: clone
      dirsearch)
        if [ ! -d "$HOME/dirsearch" ]; then
          git clone https://github.com/maurosoria/dirsearch.git "$HOME/dirsearch" >/dev/null 2>&1 || true
          if [ -f "$HOME/dirsearch/dirsearch.py" ]; then ok "Cloned dirsearch"; else warn "Failed to clone dirsearch"; fi
        fi
        ;;
      # gobuster: apt or go
      gobuster)
        if apt_install gobuster; then ok "Installed gobuster via apt"; else
          if go install github.com/OJ/gobuster/v3@latest >/dev/null 2>&1; then ok "Installed gobuster via go"; else warn "Failed to install gobuster"; fi
        fi
        ;;
      # ferox/ffuf fallback
      ffuf)
        if go install github.com/ffuf/ffuf/v2@latest >/dev/null 2>&1; then ok "Installed ffuf via go"; else warn "Failed to install ffuf"; fi
        ;;
      *)
        warn "No automatic installer for $tool implemented; you must install manually"
        ;;
    esac
  done

  # re-evaluate which missing remain
  missing=()
  present=()
  for t in "${ESSENTIAL[@]}" "${TOOLS[@]}"; do
    if command -v "$t" >/dev/null 2>&1; then
      present+=("$t")
    else
      missing+=("$t")
    fi
  done

  # show results
  ok "Auto-install attempts complete."
  if [ ${#missing[@]} -gt 0 ]; then
    warn "Still missing: ${missing[*]}"
    show_manual_instructions
    if [ -n "$GUM_BIN" ]; then
      if !$GUM_BIN confirm "Proceed anyway (missing tools may limit functionality)?"; then
        die "Install missing tools and re-run."
      fi
    else
      read -p "Proceed anyway (missing tools may limit functionality)? (y/N): " cont
      [[ "$cont" =~ ^[Yy] ]] || die "Install missing tools and re-run."
    fi
  fi
else
  if [ ${#missing[@]} -gt 0 ]; then
    warn "Missing tools: ${missing[*]}"
    show_manual_instructions
    if [ -n "$GUM_BIN" ]; then
      if !$GUM_BIN confirm "Install them now automatically?"; then
        die "Install missing tools and re-run."
      else
        exec "$0" "$DOMAIN" "$MODE"
      fi
    else
      read -p "Install missing tools now automatically? (y/N): " ans2
      if [[ "$ans2" =~ ^[Yy] ]]; then exec "$0" "$DOMAIN" "$MODE"; else die "Install missing tools and re-run."; fi
    fi
  fi
fi

# Ensure wordlists exist
info "Ensuring central wordlist directory: $WORDLIST_DIR"
ensure_wordlists
ok "Wordlists ready"

# ----------------------------
# Pipeline phases (robust)
# ----------------------------

# Phase helper to run with spinner and logging
phase_run(){
  local title="$1"; shift
  gum_print "• $title"
  spinner_run "$title" "$@"
}

############
# Subdomain enumeration (multi tool)
############
phase_run "Subdomain enumeration" bash -c '
mkdir -p "'"$OUTPUT"'/subdomains" "'"$OUTPUT"'/temp"
# run tools if available
if command -v subfinder >/dev/null 2>&1; then subfinder -silent -d "'"$DOMAIN"'" -o "'"$OUTPUT"'/temp/subfinder.txt" 2>/dev/null || true; fi
if command -v assetfinder >/dev/null 2>&1; then assetfinder --subs-only "'"$DOMAIN"'" > "'"$OUTPUT"'/temp/assetfinder.txt" 2>/dev/null || true; fi
if command -v amass >/dev/null 2>&1 && [ "'"$MODE"'" != "fast" ]; then timeout 60 amass enum -passive -d "'"$DOMAIN"'" -o "'"$OUTPUT"'/temp/amass.txt" 2>/dev/null || true; fi
# crt.sh via curl/jq
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  curl -s "https://crt.sh/?q=%25.'"$DOMAIN"'&output=json" 2>/dev/null | jq -r ".[].name_value" | sed "s/\\*\\.//g" > "'"$OUTPUT"'/temp/crtsh.txt" || true
fi
# merge
cat "'"$OUTPUT"'/temp"/*.txt 2>/dev/null | sed "s/\\*\\.//g" | grep -E "^[A-Za-z0-9._-]+\\.[A-Za-z]{2,}$" | sort -u > "'"$OUTPUT"'/subdomains/all_subs.txt" || touch "'"$OUTPUT"'/subdomains/all_subs.txt"
'

subcount=$(wc -l < "$OUTPUT/subdomains/all_subs.txt" 2>/dev/null || echo 0)
ok "Subdomain enumeration finished (total: $subcount)"
sleep 0.5

############
# Live host detection
############
phase_run "Live host detection" bash -c '
mkdir -p "'"$OUTPUT"'/subdomains"
# try dnsx if available to filter resolvable hosts
if command -v dnsx >/dev/null 2>&1; then
  dnsx -silent -l "'"$OUTPUT"'/subdomains/all_subs.txt" -r 1.1.1.1 -o "'"$OUTPUT"'/subdomains/resolved.txt" 2>/dev/null || cp -f "'"$OUTPUT"'/subdomains/all_subs.txt" "'"$OUTPUT"'/subdomains/resolved.txt"
else
  cp -f "'"$OUTPUT"'/subdomains/all_subs.txt" "'"$OUTPUT"'/subdomains/resolved.txt"
fi
# probe HTTP(S)
if command -v httpx >/dev/null 2>&1; then
  # try httpx streaming JSON mode; fallback to basic httpx
  if cat "'"$OUTPUT"'/subdomains/resolved.txt" | httpx -silent -o "'"$OUTPUT"'/subdomains/live_subs.txt" 2>/dev/null; then
    true
  else
    cat "'"$OUTPUT"'/subdomains/resolved.txt" | xargs -P 50 -I % sh -c "httpx -silent -u % 2>/dev/null" > "'"$OUTPUT"'/subdomains/live_subs.txt" 2>/dev/null || true
  fi
else
  cp -f "'"$OUTPUT"'/subdomains/resolved.txt" "'"$OUTPUT"'/subdomains/live_subs.txt"
fi
'

livecount=$(wc -l < "$OUTPUT/subdomains/live_subs.txt" 2>/dev/null || echo 0)
ok "Live discovery finished (live: $livecount)"
sleep 0.5

############
# Port scan & service detection (naabu + nmap)
############
phase_run "Port scanning & service detection" bash -c '
mkdir -p "'"$OUTPUT"'/ports" "'"$OUTPUT"'/scans"
if command -v naabu >/dev/null 2>&1; then
  sed -i "s#https\\?://##g" "'"$OUTPUT"'/subdomains/live_subs.txt" 2>/dev/null || true
  cat "'"$OUTPUT"'/subdomains/live_subs.txt" | naabu -list - -silent -o "'"$OUTPUT"'/ports/naabu.txt" 2>/dev/null || true
else
  echo "[info] naabu not installed; skipping naabu"
fi
# nmap if installed and live sub list exists
if command -v nmap >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/subdomains/live_subs.txt" ]; then
  nmap -T4 -sC -sV -iL "'"$OUTPUT"'/subdomains/live_subs.txt" -oN "'"$OUTPUT"'/scans/nmap.txt" || true
fi
'

ok "Port scan & service detection complete"
sleep 0.5

############
# Nuclei (vuln scan) + WPScan
############
phase_run "Vulnerability scanning (nuclei & wpscan)" bash -c '
mkdir -p "'"$OUTPUT"'/reports"
if command -v nuclei >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/subdomains/live_subs.txt" ]; then
  nuclei -l "'"$OUTPUT"'/subdomains/live_subs.txt" -c 50 -o "'"$OUTPUT"'/reports/nuclei.txt" -silent 2>/dev/null || true
else
  echo "[info] nuclei not installed or no live hosts"
fi
# WPScan: run against live hosts that look like WordPress
if command -v wpscan >/dev/null 2>&1; then
  while IFS= read -r h; do
    # quick check for wp-admin presence
    if curl -s --max-time 8 -I \"https://$h/wp-admin/\" | grep -qi \"200\|301\|302\"; then
      wpscan --url \"https://$h\" --no-update --enumerate vp --output \"'"$OUTPUT"'/reports/wpscan_$h.txt\" || true
    fi
  done < "'"$OUTPUT"'/subdomains/live_subs.txt"
else
  echo "[info] wpscan not installed; skipping WP scans"
fi
'

ok "Vulnerability scanning done"
sleep 0.5

############
# Screenshots - gowitness
############
phase_run "Screenshots (gowitness)" bash -c '
mkdir -p "'"$OUTPUT"'/screenshots"
if command -v gowitness >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/subdomains/live_subs.txt" ]; then
  gowitness file -f "'"$OUTPUT"'/subdomains/live_subs.txt" --destination "'"$OUTPUT"'/screenshots" --timeout 10 >/dev/null 2>&1 || true
else
  echo "[info] gowitness not installed or no live hosts"
fi
'

ok "Screenshots finished"
sleep 0.5

############
# URL collection (gau/waybackurls) + parameter extraction
############
phase_run "URL collection & parameter extraction" bash -c '
mkdir -p "'"$OUTPUT"'/urls" "'"$OUTPUT"'/params"
> "'"$OUTPUT"'/urls/all_urls.txt"
if command -v gau >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/subdomains/live_subs.txt" ]; then
  cat "'"$OUTPUT"'/subdomains/live_subs.txt" | gau --threads 10 >> "'"$OUTPUT"'/urls/all_urls.txt" 2>/dev/null || true
fi
if command -v waybackurls >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/subdomains/live_subs.txt" ]; then
  cat "'"$OUTPUT"'/subdomains/live_subs.txt" | waybackurls >> "'"$OUTPUT"'/urls/all_urls.txt" 2>/dev/null || true
fi
sort -u -o "'"$OUTPUT"'/urls/all_urls.txt" "'"$OUTPUT"'/urls/all_urls.txt" 2>/dev/null || true

# gf patterns
if command -v gf >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/urls/all_urls.txt" ]; then
  cat "'"$OUTPUT"'/urls/all_urls.txt" | gf xss > "'"$OUTPUT"'/params/xss.txt" 2>/dev/null || true
  cat "'"$OUTPUT"'/urls/all_urls.txt" | gf sqli > "'"$OUTPUT"'/params/sqli.txt" 2>/dev/null || true
  cat "'"$OUTPUT"'/urls/all_urls.txt" | gf lfi > "'"$OUTPUT"'/params/lfi.txt" 2>/dev/null || true
fi
'

ok "URL collection & parameter extraction complete"
sleep 0.5

############
# Directory fuzzing (ffuf / feroxbuster / dirsearch / gobuster)
############
phase_run "Directory fuzzing" bash -c '
mkdir -p "'"$OUTPUT"'/dirs"
WL="'"$WORDLIST_DIR"'/common.txt"
# if ffuf installed, run per-host upto 20 hosts (safeguard)
if command -v ffuf >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/subdomains/live_subs.txt" ]; then
  head -n 20 "'"$OUTPUT"'/subdomains/live_subs.txt" | while read -r h; do
    url="http://$h"
    ffuf -u "$url/FUZZ" -w "$WL" -t 50 -mc "200,301,302,403" -o "'"$OUTPUT"'/dirs/ffuf_$h.json" -of json 2>/dev/null || true
  done
fi

# feroxbuster if installed
if command -v feroxbuster >/dev/null 2>&1 && [ -s "'"$OUTPUT"'/subdomains/live_subs.txt" ]; then
  while read -r u; do
    feroxbuster -u "http://$u" -w "$WL" -t 50 -o "'"$OUTPUT"'/dirs/ferox_$u.txt" >/dev/null 2>&1 || true
  done < "'"$OUTPUT"'/subdomains/live_subs.txt"
fi

# dirsearch (python) basic run against root domain
if [ -d "$HOME/dirsearch" ]; then
  python3 "$HOME/dirsearch/dirsearch.py" -u "https://'"$DOMAIN"'" -e php,aspx,html -w "$WL" -t 20 -o "'"$OUTPUT"'/dirs/dirsearch_root.txt" 2>/dev/null || true
fi

# gobuster fallback
if command -v gobuster >/dev/null 2>&1; then
  gobuster dir -u "https://$DOMAIN" -w "$WL" -t 50 -o "'"$OUTPUT"'/dirs/gobuster_root.txt" 2>/dev/null || true
fi
'

ok "Directory fuzzing done"
sleep 0.5

############
# S3 bucket discovery (basic) - attempts common prefixes
############
phase_run "S3 bucket discovery" bash -c '
mkdir -p "'"$OUTPUT"'/s3"
if [ -s "'"$WORDLIST_DIR"'/s3.txt" ]; then
  while IFS= read -r b; do
    # attempt list or head
    url="https://$b.s3.amazonaws.com"
    if curl -I -s --max-time 6 "$url" | grep -q "200\|403"; then
      echo "$url" >> "'"$OUTPUT"'/s3/found.txt"
    fi
  done < "'"$WORDLIST_DIR"'/s3.txt"
fi
'

ok "S3 check complete"
sleep 0.5

############
# Final report
############
GENERATE_REPORT(){
  END_TS=$(date +%s)
  DUR=$((END_TS-START_TS))
  MIN=$((DUR/60)); SEC=$((DUR%60))
  TOTAL_SUBS=$(wc -l < "$OUTPUT/subdomains/all_subs.txt" 2>/dev/null || echo 0)
  LIVE=$(wc -l < "$OUTPUT/subdomains/live_subs.txt" 2>/dev/null || echo 0)
  URLS=$(wc -l < "$OUTPUT/urls/all_urls.txt" 2>/dev/null || echo 0)
  SECRETS=$(wc -l < "$OUTPUT/secrets/found.txt" 2>/dev/null || echo 0)
  VULNS=$(wc -l < "$OUTPUT/reports/nuclei.txt" 2>/dev/null || echo 0)
  cat > "$OUTPUT/reports/REPORT.txt" <<EOF
Recon Report - $DOMAIN
Mode: $MODE
Duration: ${MIN}m ${SEC}s
Date: $(date)

Summary:
  Subdomains: $TOTAL_SUBS
  Live Hosts: $LIVE
  URLs: $URLS
  Secrets found: $SECRETS
  Vulnerabilities (nuclei): $VULNS

Files:
  $OUTPUT/subdomains/all_subs.txt
  $OUTPUT/subdomains/live_subs.txt
  $OUTPUT/urls/all_urls.txt
  $OUTPUT/dirs/
  $OUTPUT/reports/
  $OUTPUT/screenshots/
EOF
  ok "Report saved: $OUTPUT/reports/REPORT.txt"
}

phase_run "Generating final report" GENERATE_REPORT

# Show final summary via gum (or plain)
if [ -n "$GUM_BIN" ]; then
  $GUM_BIN style --border normal --border-foreground 212 --padding "1 2" "✅ Recon complete for: $DOMAIN" "Subdomains: $TOTAL_SUBS" "Live Hosts: $LIVE" "URLs: $URLS" "Report: $OUTPUT/reports/REPORT.txt"
else
  echo "=== Recon finished ==="
  echo "Subdomains: $TOTAL_SUBS"
  echo "Live Hosts: $LIVE"
  echo "URLs: $URLS"
  echo "Report: $OUTPUT/reports/REPORT.txt"
fi

# Exit clean
exit 0
