#!/usr/bin/env bash
# reckon-fixed.sh — Fixed dependency checks + optional auto-installation
# Usage: ./reckon-fixed.sh example.com --mode <fast|medium|full> [--install-missing] [--refresh-wordlists] [--no-screenshots] [--skip-httpx] [--ports "1-1000"] [--telegram TOKEN:CHATID] [--slack WEBHOOK]
set -euo pipefail
IFS=$'\n\t'

########################################
# Defaults
########################################
PROGNAME="$(basename "$0")"
DOMAIN=""
MODE="medium"   # fast, medium, full
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

# Track background PIDs for cleanup
declare -a BG_PIDS=()
DASH_PID=""

# Lists to record install failures
declare -a INSTALL_FAILED=()

# Cleanup handler
cleanup() {
    echo ""
    echo "[cleanup] Stopping background tasks..."
    for pid in "${BG_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    if [ -n "$DASH_PID" ] && kill -0 "$DASH_PID" 2>/dev/null; then
        kill "$DASH_PID" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
    echo "[cleanup] Done"
}
trap cleanup EXIT INT TERM

########################################
# Usage help
########################################
usage() {
cat <<'USAGE'
Usage: reckon-fixed.sh <domain> [flags]
Flags:
  --mode <fast|medium|full>
  --install-missing
  --refresh-wordlists
  --no-screenshots
  --skip-httpx
  --ports "1-1000"
  --telegram TOKEN:CHATID   (optional)
  --slack WEBHOOK_URL       (optional)

Example:
  ./reckon-fixed.sh example.com --mode fast --install-missing --telegram 123:456 --slack https://hooks.slack.com/....

Only run against targets you have permission to test.
USAGE
  exit 1
}

# Parse args
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
    --) shift; break;;
    -*|--*) echo "Unknown option: $1"; usage;;
    *) POSITIONAL+=("$1"); shift;;
  esac
done

if [ ${#POSITIONAL[@]} -lt 1 ]; then usage; fi
DOMAIN="${POSITIONAL[0]}"
OUTPUT="${DOMAIN}${OUTPUT_SUFFIX}"

########################################
# Helpers for installing packages
########################################
# try to install a package using common package managers
try_pkg_install(){
  pkg_name="$1"
  echo "[*] Attempting to install: $pkg_name"

  # prefer non-interactive package managers if available
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y >/dev/null 2>&1 || true
    if sudo apt-get install -y "$pkg_name" >/dev/null 2>&1; then
      echo "  ✓ Installed $pkg_name via apt-get"
      return 0
    fi
  fi

  if command -v yum >/dev/null 2>&1; then
    if sudo yum install -y "$pkg_name" >/dev/null 2>&1; then
      echo "  ✓ Installed $pkg_name via yum"
      return 0
    fi
  fi

  if command -v brew >/dev/null 2>&1; then
    if brew install "$pkg_name" >/dev/null 2>&1; then
      echo "  ✓ Installed $pkg_name via brew"
      return 0
    fi
  fi

  # fallback: try pip3 for python packages
  if [ "$pkg_name" = "flask" ] || [ "$pkg_name" = "python3-flask" ]; then
    if command -v pip3 >/dev/null 2>&1; then
      if pip3 install --user flask >/dev/null 2>&1; then
        echo "  ✓ Installed flask via pip3"
        return 0
      fi
    fi
  fi

  return 1
}

# try installing go-based tools (go install)
try_go_install(){
  tool_pkg="$1" # e.g. github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  binary_name="$2" # e.g. subfinder

  if ! command -v go >/dev/null 2>&1; then
    echo "  ✗ Go not found; cannot install $binary_name via go. Install Go first."
    return 1
  fi

  if GO111MODULE=on go install -v "$tool_pkg" >/dev/null 2>&1; then
    echo "  ✓ Installed $binary_name via go install"
    return 0
  else
    echo "  ✗ go install failed for $binary_name"
    return 1
  fi
}

########################################
# Create directory structure FIRST
########################################
echo "[*] Setting up output directories..."
mkdir -p "$OUTPUT"
mkdir -p "$OUTPUT/logs"
mkdir -p "$OUTPUT/logs/status"
mkdir -p "$OUTPUT/subdomains"
mkdir -p "$OUTPUT/params"
mkdir -p "$OUTPUT/katana"
mkdir -p "$OUTPUT/s3"
mkdir -p "$OUTPUT/git"
mkdir -p "$OUTPUT/dirs"
mkdir -p "$OUTPUT/ports"
mkdir -p "$OUTPUT/jsfiles"
mkdir -p "$OUTPUT/screenshots"
mkdir -p "$GLOBAL_WORDLISTS"

# Verify critical directories exist
if [ ! -d "$OUTPUT/logs" ]; then
    echo "[error] Failed to create logs directory: $OUTPUT/logs"
    exit 1
fi

# Get local IP
get_local_ip(){
  ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' || hostname -I | awk '{print $1}' || echo "127.0.0.1"
}
LOCAL_IP="$(get_local_ip)"
DASH_PORT=8000

# Status helpers
status_dir="$OUTPUT/logs/status"

write_status(){
  local task="$1" st="$2" pid_val="$3" msg="$4"
  local ts safe_msg
  ts="$(date --iso-8601=seconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S')"
  safe_msg="${msg//\"/\'}"
  printf '{"task":"%s","status":"%s","pid":%s,"msg":"%s","ts":"%s"}\n' \
    "$task" "$st" "$pid_val" "$safe_msg" "$ts" > "$status_dir/${task}.json"
}

append_log(){
  local task="$1" line="$2"
  echo "[$(date +'%F %T')] $line" >> "$OUTPUT/logs/${task}.log"
}

notify(){
  local msg="$1"
  append_log notifier "$msg"
  
  # Telegram
  if [ -n "$TELEGRAM_CFG" ]; then
    IFS=':' read -r token chatid <<< "$TELEGRAM_CFG"
    if [ -n "$token" ] && [ -n "$chatid" ]; then
      curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" \
        -d "chat_id=$chatid" \
        -d "text=[Recon][$DOMAIN] $msg" >/dev/null 2>&1 || true
    fi
  fi
  
  # Slack
  if [ -n "$SLACK_WEBHOOK" ]; then
    local safe_msg="${msg//\"/\'}"
    local payload
    payload=$(printf '{"text":"[Recon][%s] %s"}' "$DOMAIN" "$safe_msg")
    curl -s -X POST -H 'Content-type: application/json' \
      --data "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
  fi
}

# Run task in background with monitoring
run_task_bg(){
  local task="$1"
  shift
  local cmd=( "$@" )
  
  append_log "$task" "START: ${cmd[*]}"
  local tmpf="$OUTPUT/logs/${task}_cmd.sh"
  
  {
    printf '%s\n' "#!/usr/bin/env bash"
    printf 'set -euo pipefail\n'
    printf '%s' "${cmd[@]}"
  } > "$tmpf"
  chmod +x "$tmpf"
  
  # Run in subshell
  (
    if "$tmpf" >> "$OUTPUT/logs/${task}.log" 2>&1; then
      write_status "$task" "done" 0 "completed successfully"
      append_log "$task" "COMPLETED (rc=0)"
      notify "Task $task completed"
    else
      rc=$?
      write_status "$task" "failed" 0 "exit code: $rc"
      append_log "$task" "FAILED (rc=$rc)"
      notify "Task $task failed (rc=$rc)"
    fi
  ) &
  
  local pid=$!
  BG_PIDS+=("$pid")
  write_status "$task" "running" "$pid" "started"
}

########################################
# Check dependencies (improved)
########################################
check_deps(){
  local missing_ess=()
  local missing_opt=()

  # Essential core commands expected on every system
  for cmd in curl sort awk sed grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_ess+=("$cmd")
    fi
  done

  # Python for dashboard
  if ! command -v python3 >/dev/null 2>&1; then
    missing_ess+=("python3")
  fi

  # pip3 recommended
  if ! command -v pip3 >/dev/null 2>&1; then
    missing_opt+=("pip3")
  fi

  # Check Python Flask availability
  if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c "import flask" 2>/dev/null; then
      missing_opt+=("flask (python package)")
    fi
  fi

  # Optional security tooling (useful but not essential)
  for cmd in subfinder assetfinder httpx naabu nuclei katana ffuf gau waybackurls gf jq amass nmap; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing_opt+=("$cmd")
    fi
  done

  # Show summary
  if [ ${#missing_ess[@]} -gt 0 ]; then
    echo "[error] Missing essential tools: ${missing_ess[*]}"
    if [ "$INSTALL_MISSING" = true ]; then
      echo "[*] --install-missing specified. Attempting to install essential tools..."
      for p in "${missing_ess[@]}"; do
        if try_pkg_install "$p"; then
          echo "  Installed $p"
        else
          echo "  Failed to install $p automatically"
          INSTALL_FAILED+=("$p")
        fi
      done
    else
      echo "Please install the missing essential tools and re-run, or re-run with --install-missing to try automatic installation."
      echo "Manual install suggestions:"
      echo "  Debian/Ubuntu: sudo apt-get install -y ${missing_ess[*]}"
      echo "  RHEL/CentOS: sudo yum install -y ${missing_ess[*]}"
      echo "  Mac (brew): brew install ${missing_ess[*]}"
      exit 1
    fi
  fi

  # Try to install optional tools if user asked
  if [ "$INSTALL_MISSING" = true ] && [ ${#missing_opt[@]} -gt 0 ]; then
    echo "[*] Attempting to install optional tools: ${missing_opt[*]}"

    # Install Go-based tools if go available
    if command -v go >/dev/null 2>&1; then
      # map known go tools -> package
      declare -A GOTABLE
      GOTABLE[subfinder]=github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
      GOTABLE[httpx]=github.com/projectdiscovery/httpx/cmd/httpx@latest
      GOTABLE[naabu]=github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
      GOTABLE[nuclei]=github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
      GOTABLE[katana]=github.com/projectdiscovery/katana/cmd/katana@latest
      GOTABLE[gau]=github.com/tomnomnom/gau@latest
      GOTABLE[gau_v2]=github.com/lc/gau/v2/cmd/gau@latest
      GOTABLE[gf]=github.com/tomnomnom/gf@latest
      GOTABLE[ffuf]=github.com/ffuf/ffuf/v2@latest

      for tool in subfinder httpx naabu nuclei katana gau gf ffuf; do
        if command -v "$tool" >/dev/null 2>&1; then
          continue
        fi
        pkg=${GOTABLE[$tool]}
        if [ -n "$pkg" ]; then
          if try_go_install "$pkg" "$tool"; then
            continue
          else
            INSTALL_FAILED+=("$tool")
          fi
        fi
      done
    else
      echo "  Note: Go not found — skipping go-based tools installation. Install Go and re-run with --install-missing if you want automatic go installs."
    fi

    # Try pip install for flask
    if [[ " ${missing_opt[*]} " == *"flask (python package)"* ]]; then
      if command -v pip3 >/dev/null 2>&1; then
        if pip3 install --user flask >/dev/null 2>&1; then
          echo "  ✓ Installed flask via pip3"
        else
          echo "  ✗ Failed to install flask via pip3"
          INSTALL_FAILED+=("flask")
        fi
      else
        echo "  pip3 not available; cannot install flask automatically"
      fi
    fi

    # Try to install jq via package manager if missing
    if [[ " ${missing_opt[*]} " == *"jq"* ]]; then
      if try_pkg_install jq; then
        true
      else
        INSTALL_FAILED+=("jq")
      fi
    fi
  fi

  # Final checks: if anything failed to install, notify and exit
  if [ ${#INSTALL_FAILED[@]} -gt 0 ]; then
    echo "\n[error] Some packages failed to install automatically: ${INSTALL_FAILED[*]}"
    echo "Please install them manually and re-run the script. Suggested commands:"
    echo "  Debian/Ubuntu: sudo apt-get install -y ${INSTALL_FAILED[*]}"
    echo "  RHEL/CentOS: sudo yum install -y ${INSTALL_FAILED[*]}"
    echo "  Mac (brew): brew install ${INSTALL_FAILED[*]}"
    echo "Or install Go and then use: GO111MODULE=on go install <package>@latest for go-based tools."
    exit 1
  fi

  # Success: nothing critical missing
  echo "[*] Dependency check completed. All required tools present."
}

# Run dependency check
check_deps

# The rest of the script remains mostly unchanged from your original pipeline.
# For brevity we will not duplicate every function here in this fixed-script template.
# In practice you can append the rest of your original script after this point.

cat <<'NOTE'

Dependency checks finished. If you used --install-missing the script attempted to install tools.

What changed in this fixed script:
  • Clear separation between essential and optional tools.
  • If essentials are missing and --install-missing is NOT provided, the script exits with
    a helpful message and suggested manual install commands.
  • If --install-missing is provided the script attempts to install essentials and common
    optional tools via apt/yum/brew/pip3/go. Failures are collected and shown with manual
    remediation steps.
  • Better messages and a recorded INSTALL_FAILED array so you know what to install manually.

Next steps:
  1) Replace the remainder of your original script (task functions, dashboard code, etc.)
     after the dependency-check block above. The check_deps function will exit on failure,
     so the rest of your pipeline will only run when dependencies are satisfied.
  2) Run: ./reckon-fixed.sh example.com --install-missing  (to let the script try to install)
  3) Or manually install missing packages if automatic install fails.

NOTE

exit 0
