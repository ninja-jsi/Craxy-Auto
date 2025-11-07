#!/usr/bin/env bash
# full-auto-recon-tui-updated.sh
# Full Auto Recon (TUI) - OS-aware installers, central wordlists, fail-fast if essentials missing
# Usage: ./full-auto-recon-tui-updated.sh <domain> [mode] [--os=<os>] [--no-install] [--verbose]

set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Config / Defaults
# -------------------------
SCRIPT_NAME="$(basename "$0")"
DOMAIN=""
MODE="medium"               # fast | medium | full
OUTPUT_DIR=""
WORDLIST_DIR="${HOME}/Recon-Wordlists"
GUM="$(command -v gum 2>/dev/null || true)"
GO_BIN="$(command -v go 2>/dev/null || true)"
PKG_MANAGER=""
AUTO_INSTALL=true
VERBOSE=false
OS_NAME=""
TOOLS_ONLY=false
REPORT_ONLY=false
UPDATE_WORDLISTS=false

START_TS=$(date +%s)

# -------------------------
# Colors
# -------------------------
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"

# -------------------------
# Tools lists
# -------------------------
# Essentials for bug-bounty and general environment
ESSENTIAL=(git curl wget jq awk sed sort unzip ca-certificates build-essential python3 python3-pip ruby make gcc)

# Tools (scanners and helpers)
TOOLS=(subfinder assetfinder amass httpx dnsx gau waybackurls gf naabu nmap nuclei gowitness ffuf feroxbuster dirsearch gobuster wpscan s3scanner katana gauplus)

# go packages mapping for go-installable tools
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
  [feroxbuster]=github.com/epi052/feroxbuster/v2@latest
  [gobuster]=github.com/OJ/gobuster/v3@latest
  [katana]=github.com/projectdiscovery/katana/cmd/katana@latest
)

# -------------------------
# Helpers
# -------------------------
show_help() {
  cat <<'EOF'
Usage: full-auto-recon-tui-updated.sh <domain> [mode] [options]

Modes:
  fast     - minimal (subdomains + live)
  medium   - default (URLs, params, JS secrets)
  full     - deep (ports, fuzzing, nuclei, screenshots, wpscan)

Options:
  -h, --help           Show this help
  --os=<os>            Your OS: ubuntu|debian|kali|macos|arch|centos
  --no-install         Do not attempt automatic installation
  --verbose            Show verbose installer output
  --update-wordlists   Force refresh of central wordlists
  --tools-only         Run dependency check/installer then exit
  --report-only        Only generate report from existing output (no scanning)
  --mode=<mode>        Set mode: fast|medium|full

Examples:
  $SCRIPT_NAME example.com
  $SCRIPT_NAME example.com full --os=ubuntu --verbose
EOF
}

# parse arguments
for arg in "$@"; do
  case "$arg" in
    -h|--help) show_help; exit 0;;
    --no-install) AUTO_INSTALL=false; shift;;
    --verbose) VERBOSE=true; shift;;
    --tools-only) TOOLS_ONLY=true; shift;;
    --report-only) REPORT_ONLY=true; shift;;
    --update-wordlists) UPDATE_WORDLISTS=true; shift;;
    --mode=*) MODE="${arg#*=}"; shift;;
    --os=*) OS_NAME="${arg#*=}"; shift;;
    --*) echo "Unknown option: $arg"; show_help; exit 1;;
    *)
      if [ -z "$DOMAIN" ]; then DOMAIN="$arg"; else MODE="$arg"; fi
      shift
      ;;
  esac
done

if [ -z "$DOMAIN" ]; then echo "Error: missing domain"; show_help; exit 1; fi
OUTPUT_DIR="${DOMAIN}-recon"

info(){ echo -e "${BLUE}[*]${NC} $*"; }
ok(){ echo -e "${GREEN}[✓]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
die(){ echo -e "${RED}[✗]${NC} $*"; exit 1; }

gum_yesno(){
  if [ -n "$GUM" ]; then
    "$GUM" confirm "$@"
  else
    read -p "$1 [y/N]: " ans
    [[ "$ans" =~ ^[Yy] ]]
  fi
}

gum_style(){
  if [ -n "$GUM" ]; then
    "$GUM" style "$@"
  else
    echo "$1"
  fi
}

gum_spin_run(){
  local title="$1"; shift
  if [ -n "$GUM" ]; then
    if [ "$VERBOSE" = true ]; then
      "$GUM" spin --spinner line --title "$title" -- sh -c "$*"
    else
      "$GUM" spin --spinner line --title "$title" -- sh -c "$*" >/dev/null 2>&1 || true
    fi
  else
    echo -n "$title ... "
    if [ "$VERBOSE" = true ]; then sh -c "$*"; else sh -c "$*" >/dev/null 2>&1 || true; fi
    echo "done"
  fi
}

# detect package manager
detect_pkg_manager(){
  if [ -n "$OS_NAME" ]; then
    case "$OS_NAME" in
      ubuntu|debian|kali) PKG_MANAGER="apt";;
      macos|darwin) PKG_MANAGER="brew";;
      centos|rhel) PKG_MANAGER="yum";;
      arch) PKG_MANAGER="pacman";;
      *) PKG_MANAGER="";;
    esac
  else
    if command -v apt-get >/dev/null 2>&1; then PKG_MANAGER="apt"
    elif command -v brew >/dev/null 2>&1; then PKG_MANAGER="brew"
    elif command -v yum >/dev/null 2>&1; then PKG_MANAGER="yum"
    elif command -v pacman >/dev/null 2>&1; then PKG_MANAGER="pacman"
    else PKG_MANAGER=""
    fi
  fi
}

# pretty tools display
pretty_tools_display() {
  local -n _present="$1"
  local -n _missing="$2"

  local GREEN="\033[0;32m"
  local RED="\033[0;31m"
  local NC="\033[0m"
  local COLS=3
  local PAD=26

  format_grid() {
    local -n arr="$1"; local symbol="$2"; local color="$3"
    local i=0; local out_lines=(); local line=""
    for item in "${arr[@]}"; do
      local short="$(printf '%.20s' "$item")"
      local cell="$(printf '%s %s' "$symbol" "$short")"
      cell="${color}${cell}${NC}"
      printf -v padded "%-${PAD}s" "$cell"
      line+="$padded"
      ((i++))
      if (( i % COLS == 0 )); then out_lines+=("$line"); line=""; fi
    done
    [ -n "$line" ] && out_lines+=("$line")
    for l in "${out_lines[@]}"; do echo -e "  $l"; done
  }

  local present_count=${#_present[@]}
  local missing_count=${#_missing[@]}
  local present_header="✅ Present (${present_count})"
  local missing_header="❌ Missing (${missing_count})"

  if [ -n "$GUM" ]; then
    $GUM style --border normal --padding "1 2" --border-foreground 33 "$present_header"
    format_grid _present "✓" "$GREEN"
    echo
    $GUM style --border normal --padding "1 2" --border-foreground 160 "$missing_header"
    format_grid _missing "✗" "$RED"
    echo
  else
    printf "┌%s┐\n" "$(printf '─%.0s' {1..60})"
    printf "│ %-58s │\n" "$present_header"
    printf "├%s┤\n" "$(printf '─%.0s' {1..60})"
    format_grid _present "✓" "$GREEN"
    printf "└%s┘\n\n" "$(printf '─%.0s' {1..60})"
    printf "┌%s┐\n" "$(printf '─%.0s' {1..60})"
    printf "│ %-58s │\n" "$missing_header"
    printf "├%s┤\n" "$(printf '─%.0s' {1..60})"
    format_grid _missing "✗" "$RED"
    printf "└%s┘\n\n" "$(printf '─%.0s' {1..60})"
  fi

  if (( missing_count > 0 )); then
    echo -e "${YELLOW}Next:${NC} Install missing tools or run with --no-install to skip automatic install."
  else
    echo -e "${GREEN}All required tools are present. Ready to run the pipeline.${NC}"
  fi
  echo
}

# installers
apt_install(){ sudo apt-get update -y >/dev/null 2>&1 || true; sudo apt-get install -y "$@" ; }
yum_install(){ sudo yum install -y "$@" ; }
brew_install(){ brew install "$@" ; }
pip_install(){ pip3 install --user "$@" ; }
gem_install(){ sudo gem install "$@" || gem install --user-install "$@" ; }
go_install_tool(){
  local t="$1" pkg="${GO_PKGS[$t]:-}"
  if [ -z "$pkg" ]; then return 1; fi
  if ! command -v go >/dev/null 2>&1; then return 2; fi
  export PATH="$HOME/go/bin:$PATH"
  GO111MODULE=on go install "$pkg" >/dev/null 2>&1 && return 0 || return 1
}

show_manual_instructions(){
  echo
  echo "Manual install hints:"
  echo "  - Debian/Ubuntu: sudo apt install git curl wget jq build-essential ruby python3-pip go"
  echo "  - Go tools (after installing Go):"
  for k in "${!GO_PKGS[@]}"; do echo "      GO111MODULE=on go install ${GO_PKGS[$k]}"; done
  echo "  - WPScan: sudo gem install wpscan"
  echo "  - dirsearch: git clone https://github.com/maurosoria/dirsearch.git ~/dirsearch"
  echo "  - s3scanner: pip3 install --user s3scanner"
  echo
}

# ensure central wordlists
ensure_wordlists(){
  mkdir -p "$WORDLIST_DIR"
  declare -A WL=(
    [common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
    [params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
    [raft]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
    [s3]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/AWS/s3-buckets-top50.txt"
  )
  for k in "${!WL[@]}"; do
    tgt="$WORDLIST_DIR/${k}.txt"
    if [ ! -s "$tgt" ] || [ "${UPDATE_WORDLISTS}" = true ]; then
      info "Downloading $k wordlist..."
      if curl -sSfL "${WL[$k]}" -o "$tgt"; then ok "Downloaded $k"; else warn "Failed $k"; fi
    fi
  done
}

# -------------------------
# Start: detect pkg manager & check tools
# -------------------------
detect_pkg_manager

# build present and missing
present=(); missing=()
for t in "${ESSENTIAL[@]}" "${TOOLS[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then present+=("$t"); else missing+=("$t"); fi
done
# ensure jq present as essential (if not already)
if ! command -v jq >/dev/null 2>&1; then missing+=("jq"); fi

pretty_tools_display present missing

# If report-only or tools-only, handle separately
if [ "${REPORT_ONLY:-false}" = true ]; then
  generate_report(){ :; } # placeholder - user can call report generator later
  ok "Report-only mode; exiting."
  exit 0
fi

if [ "${TOOLS_ONLY:-false}" = true ] && [ ${#missing[@]} -eq 0 ]; then
  ok "All tools present."
  exit 0
fi

# Auto-install logic
if (( ${#missing[@]} > 0 )); then
  if [ "$AUTO_INSTALL" = true ]; then
    if gum_yesno "Attempt to auto-install missing tools? (requires sudo/go/pip/gem)"; then
      info "Attempting auto-install..."
      # ensure go if needed
      if ! command -v go >/dev/null 2>&1; then
        case "$PKG_MANAGER" in
          apt) sudo apt-get update -y >/dev/null 2>&1 || true; sudo apt-get install -y golang >/dev/null 2>&1 || true;;
          brew) brew install go >/dev/null 2>&1 || true;;
        esac
      fi
      for t in "${missing[@]}"; do
        info "Installing: $t"
        if [[ "$t" == "wpscan" ]]; then
          if command -v gem >/dev/null 2>&1; then
            if [ "$VERBOSE" = true ]; then gem install wpscan || warn "Failed gem install wpscan"; else gem install wpscan >/dev/null 2>&1 || warn "Failed wpscan"; fi
          else
            warn "gem not found; can't auto-install wpscan"
          fi
        elif [[ -n "${GO_PKGS[$t]:-}" ]]; then
          if go_install_tool "$t"; then ok "Installed $t via go"; else warn "go install failed for $t"; fi
        elif [[ "$t" == "s3scanner" ]]; then
          if pip_install s3scanner; then ok "Installed s3scanner via pip"; else warn "pip install s3scanner failed"; fi
        elif [[ "$t" == "dirsearch" ]]; then
          if [ ! -d "$HOME/dirsearch" ]; then git clone https://github.com/maurosoria/dirsearch.git "$HOME/dirsearch" >/dev/null 2>&1 || warn "Failed to clone dirsearch"; fi
          ok "dirsearch cloned to ~/dirsearch"
        else
          case "$PKG_MANAGER" in
            apt) apt_install "$t" >/dev/null 2>&1 && ok "apt installed $t" || warn "apt failed for $t";;
            brew) brew_install "$t" >/dev/null 2>&1 && ok "brew installed $t" || warn "brew failed for $t";;
            yum) yum_install "$t" >/dev/null 2>&1 && ok "yum installed $t" || warn "yum failed for $t";;
            pacman) sudo pacman -S --noconfirm "$t" >/dev/null 2>&1 && ok "pacman installed $t" || warn "pacman failed for $t";;
            *) warn "No package manager to auto-install $t";;
          esac
        fi
      done
      # re-evaluate present/missing
      present=(); missing=()
      for t in "${ESSENTIAL[@]}" "${TOOLS[@]}"; do
        if command -v "$t" >/dev/null 2>&1; then present+=("$t"); else missing+=("$t"); fi
      done
      pretty_tools_display present missing

      # --- FAIL-FAST: Exit if still missing essentials ---
      if (( ${#missing[@]} > 0 )); then
        echo
        die "Required tools are still missing. Please install them manually before running."
        echo "Missing tools:"
        for t in "${missing[@]}"; do echo "  • $t"; done
        show_manual_instructions
        exit 1
      fi
    else
      die "Auto-install declined. Install missing tools and re-run."
    fi
  else
    die "Missing required tools: ${missing[*]}. Rerun with --no-install to skip auto-install or install manually."
  fi
fi

# ensure wordlists
ensure_wordlists

# Make directories
mkdir -p "$OUTPUT_DIR"/{subdomains,urls,params,secrets,dirs,ports,reports,screenshots,temp}

# ------------- Pipeline phases (abridged but functional) -------------
run_subdomain_enum(){
  gum_spin_run "Subdomain enumeration" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/temp"
    if command -v subfinder >/dev/null 2>&1; then subfinder -silent -d "'"$DOMAIN"'" -o "'"$OUTPUT_DIR"'/temp/subfinder.txt" 2>/dev/null || true; fi
    if command -v assetfinder >/dev/null 2>&1; then assetfinder --subs-only "'"$DOMAIN"'" > "'"$OUTPUT_DIR"'/temp/assetfinder.txt" 2>/dev/null || true; fi
    if command -v amass >/dev/null 2>&1 && [ "'"$MODE"'" != "fast" ]; then timeout 60 amass enum -passive -d "'"$DOMAIN"'" -o "'"$OUTPUT_DIR"'/temp/amass.txt" 2>/dev/null || true; fi
    if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then curl -s "https://crt.sh/?q=%25.'"$DOMAIN"'&output=json" 2>/dev/null | jq -r ".[].name_value" | sed "s/\\*\\.//g" > "'"$OUTPUT_DIR"'/temp/crtsh.txt" || true; fi
    cat "'"$OUTPUT_DIR"'/temp"/*.txt 2>/dev/null | sed "s/\\*\\.//g" | grep -E "^[A-Za-z0-9._-]+\\.[A-Za-z]{2,}$" | sort -u > "'"$OUTPUT_DIR"'/subdomains/all_subs.txt" || touch "'"$OUTPUT_DIR"'/subdomains/all_subs.txt"
  '
  local count; count=$(wc -l < "$OUTPUT_DIR/subdomains/all_subs.txt" 2>/dev/null || echo 0)
  ok "Subdomain enumeration done: $count"
}

run_live_check(){
  gum_spin_run "Live host detection" bash -lc '
    if command -v dnsx >/dev/null 2>&1; then dnsx -silent -l "'"$OUTPUT_DIR"'/subdomains/all_subs.txt" -o "'"$OUTPUT_DIR"'/subdomains/resolved.txt" 2>/dev/null || cp -f "'"$OUTPUT_DIR"'/subdomains/all_subs.txt" "'"$OUTPUT_DIR"'/subdomains/resolved.txt"; else cp -f "'"$OUTPUT_DIR"'/subdomains/all_subs.txt" "'"$OUTPUT_DIR"'/subdomains/resolved.txt"; fi
    if command -v httpx >/dev/null 2>&1; then cat "'"$OUTPUT_DIR"'/subdomains/resolved.txt" | httpx -silent -o "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" 2>/dev/null || true; else cp -f "'"$OUTPUT_DIR"'/subdomains/resolved.txt" "'"$OUTPUT_DIR"'/subdomains/live_subs.txt"; fi
  '
  local live; live=$(wc -l < "$OUTPUT_DIR/subdomains/live_subs.txt" 2>/dev/null || echo 0)
  ok "Live hosts detected: $live"
}

run_url_collection(){
  [ "$MODE" = "fast" ] && return
  gum_spin_run "URL collection" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/urls"
    > "'"$OUTPUT_DIR"'/urls/all_urls.txt"
    if command -v gau >/dev/null 2>&1; then cat "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" | gau --threads 10 >> "'"$OUTPUT_DIR"'/urls/all_urls.txt" 2>/dev/null || true; fi
    if command -v waybackurls >/dev/null 2>&1; then cat "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" | waybackurls >> "'"$OUTPUT_DIR"'/urls/all_urls.txt" 2>/dev/null || true; fi
    sort -u -o "'"$OUTPUT_DIR"'/urls/all_urls.txt" "'"$OUTPUT_DIR"'/urls/all_urls.txt" 2>/dev/null || true
  '
  local ucount; ucount=$(wc -l < "$OUTPUT_DIR/urls/all_urls.txt" 2>/dev/null || echo 0)
  ok "URLs collected: $ucount"
  if command -v gf >/dev/null 2>&1 && [ -s "$OUTPUT_DIR/urls/all_urls.txt" ]; then
    gum_spin_run "Parameter extraction" bash -lc '
      mkdir -p "'"$OUTPUT_DIR"'/params"
      cat "'"$OUTPUT_DIR"'/urls/all_urls.txt" | gf xss > "'"$OUTPUT_DIR"'/params/xss.txt" 2>/dev/null || true
      cat "'"$OUTPUT_DIR"'/urls/all_urls.txt" | gf sqli > "'"$OUTPUT_DIR"'/params/sqli.txt" 2>/dev/null || true
      cat "'"$OUTPUT_DIR"'/urls/all_urls.txt" | gf lfi > "'"$OUTPUT_DIR"'/params/lfi.txt" 2>/dev/null || true
    '
    ok "Parameter extraction complete"
  fi
}

run_js_secrets(){
  [ "$MODE" = "fast" ] && return
  gum_spin_run "JS secret hunting" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/secrets/jsfiles"
    grep -iE "\.js(\?|$|#)" "'"$OUTPUT_DIR"'/urls/all_urls.txt" 2>/dev/null | head -n 100 > "'"$OUTPUT_DIR"'/temp/js_urls.txt" || true
    i=0
    while IFS= read -r jsu && [ $i -lt 200 ]; do
      f=$(echo -n "$jsu" | md5sum | awk "{print \$1}").js
      curl -sSfL "$jsu" -m 15 -o "'"$OUTPUT_DIR"'/secrets/jsfiles/$f" 2>/dev/null || true
      i=$((i+1))
    done < "'"$OUTPUT_DIR"'/temp/js_urls.txt"
    grep -ErohI "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" "'"$OUTPUT_DIR"'/secrets/jsfiles" 2>/dev/null > "'"$OUTPUT_DIR"'/secrets/found.txt" || true
  '
  local sc; sc=$(wc -l < "$OUTPUT_DIR/secrets/found.txt" 2>/dev/null || echo 0)
  if [ "$sc" -gt 0 ]; then warn "Potential secrets: $sc"; else ok "No obvious secrets in JS files"; fi
}

run_portscan(){
  [ "$MODE" != "full" ] && return
  gum_spin_run "Port scanning" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/ports" "'"$OUTPUT_DIR"'/scans"
    if command -v naabu >/dev/null 2>&1 && [ -s "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" ]; then
      cat "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" | sed "s#https\?://##g" | naabu -list - -silent -o "'"$OUTPUT_DIR"'/ports/naabu.txt" 2>/dev/null || true
    fi
    if command -v nmap >/dev/null 2>&1 && [ -s "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" ]; then
      nmap -T4 -sC -sV -iL "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" -oN "'"$OUTPUT_DIR"'/scans/nmap.txt" || true
    fi
  '
  ok "Port scan & service detection done"
}

run_vuln_scan(){
  gum_spin_run "Vulnerability scanning" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/reports"
    if command -v nuclei >/dev/null 2>&1 && [ -s "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" ]; then
      nuclei -l "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" -c 50 -o "'"$OUTPUT_DIR"'/reports/nuclei.txt" -silent 2>/dev/null || true
    fi
    if command -v wpscan >/dev/null 2>&1 && [ -s "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" ]; then
      while IFS= read -r h; do
        if curl -s --max-time 8 -I "https://$h/wp-admin/" | grep -qi "200\|301\|302"; then
          wpscan --url "https://$h" --no-update --enumerate vp --output "'"$OUTPUT_DIR"'/reports/wpscan_$h.txt" || true
        fi
      done < "'"$OUTPUT_DIR"'/subdomains/live_subs.txt"
    fi
  '
  ok "Vulnerability scanning complete"
}

run_screenshots(){
  gum_spin_run "Screenshots (gowitness)" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/screenshots"
    if command -v gowitness >/dev/null 2>&1 && [ -s "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" ]; then
      gowitness file -f "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" --destination "'"$OUTPUT_DIR"'/screenshots" --timeout 10 >/dev/null 2>&1 || true
    fi
  '
  ok "Screenshots finished"
}

run_fuzzing(){
  gum_spin_run "Directory fuzzing" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/dirs"
    WL="'"$WORDLIST_DIR"'/common.txt"
    if command -v ffuf >/dev/null 2>&1 && [ -s "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" ]; then
      head -n 20 "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" | while read -r h; do
        ffuf -u "http://$h/FUZZ" -w "$WL" -t 50 -mc "200,301,302,403" -o "'"$OUTPUT_DIR"'/dirs/ffuf_$h.json" -of json 2>/dev/null || true
      done
    fi
    if command -v feroxbuster >/dev/null 2>&1 && [ -s "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" ]; then
      while read -r u; do feroxbuster -u "http://$u" -w "$WL" -t 50 -o "'"$OUTPUT_DIR"'/dirs/ferox_$u.txt" >/dev/null 2>&1 || true; done < "'"$OUTPUT_DIR"'/subdomains/live_subs.txt"
    fi
    if [ -d "$HOME/dirsearch" ]; then
      python3 "$HOME/dirsearch/dirsearch.py" -u "https://'"$DOMAIN"'" -w "$WL" -t 20 -o "'"$OUTPUT_DIR"'/dirs/dirsearch_root.txt" 2>/dev/null || true
    fi
    if command -v gobuster >/dev/null 2>&1; then
      gobuster dir -u "https://$DOMAIN" -w "$WL" -t 50 -o "'"$OUTPUT_DIR"'/dirs/gobuster_root.txt" 2>/dev/null || true
    fi
  '
  ok "Directory fuzzing done"
}

run_s3_check(){
  gum_spin_run "S3 bucket checks" bash -lc '
    mkdir -p "'"$OUTPUT_DIR"'/s3"
    if [ -s "'"$WORDLIST_DIR"'/s3.txt" ]; then
      while IFS= read -r b; do
        url="https://$b.s3.amazonaws.com"
        if curl -I -s --max-time 6 "$url" | grep -q "200\|403"; then echo "$url" >> "'"$OUTPUT_DIR"'/s3/found.txt"; fi
      done < "'"$WORDLIST_DIR"'/s3.txt"
    fi
  '
  ok "S3 checks done"
}

generate_report(){
  gum_spin_run "Generating report" bash -lc '
    END_TS=$(date +%s)
    DUR=$((END_TS-'"$START_TS"'))
    MIN=$((DUR/60)); SEC=$((DUR%60))
    TOTAL_SUBS=$(wc -l < "'"$OUTPUT_DIR"'/subdomains/all_subs.txt" 2>/dev/null || echo 0)
    LIVE=$(wc -l < "'"$OUTPUT_DIR"'/subdomains/live_subs.txt" 2>/dev/null || echo 0)
    URLS=$(wc -l < "'"$OUTPUT_DIR"'/urls/all_urls.txt" 2>/dev/null || echo 0)
    SECRETS=$(wc -l < "'"$OUTPUT_DIR"'/secrets/found.txt" 2>/dev/null || echo 0)
    VULNS=$(wc -l < "'"$OUTPUT_DIR"'/reports/nuclei.txt" 2>/dev/null || echo 0)
    cat > "'"$OUTPUT_DIR"'/reports/REPORT.txt" << EOF
Recon Report - '"$DOMAIN"'
Mode: '"$MODE"'
Duration: ${MIN}m ${SEC}s
Date: $(date)

Summary:
  Subdomains: $TOTAL_SUBS
  Live Hosts: $LIVE
  URLs: $URLS
  Secrets found: $SECRETS
  Vulnerabilities (nuclei): $VULNS

Files:
  '"$OUTPUT_DIR"'/subdomains/all_subs.txt
  '"$OUTPUT_DIR"'/subdomains/live_subs.txt
  '"$OUTPUT_DIR"'/urls/all_urls.txt
  '"$OUTPUT_DIR"'/dirs/
  '"$OUTPUT_DIR"'/reports/
  '"$OUTPUT_DIR"'/screenshots/
EOF
  '
  ok "Report saved: $OUTPUT_DIR/reports/REPORT.txt"
}

# -------------------------
# Run pipeline
# -------------------------
ok "Starting recon for $DOMAIN (mode: $MODE)"
ensure_wordlists
mkdir -p "$OUTPUT_DIR"

run_subdomain_enum
run_live_check
run_url_collection
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

if [ -n "$GUM" ]; then
  $GUM style --border normal --padding "1 2" --border-foreground 34 "✅ Recon complete for: $DOMAIN"
  echo "Subdomains: $TOTAL_SUBS"
  echo "Live Hosts: $LIVE"
  echo "URLs: $URLS"
  echo "Report: $OUTPUT_DIR/reports/REPORT.txt"
else
  echo "=== Recon complete ==="
  echo "Subdomains: $TOTAL_SUBS"
  echo "Live Hosts: $LIVE"
  echo "URLs: $URLS"
  echo "Report: $OUTPUT_DIR/reports/REPORT.txt"
fi

exit 0
