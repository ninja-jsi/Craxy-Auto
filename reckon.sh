#!/usr/bin/env bash
# reckon.sh — Enterprise recon + dashboard (hardened & fixed)
# Usage: ./reckon.sh example.com --mode <fast|medium|full> [--install-missing] [--telegram TOKEN:CHATID] [--slack WEBHOOK]
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
Usage: reckon.sh <domain> [flags]
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
  ./reckon.sh example.com --mode fast --telegram 123:456 --slack https://hooks.slack.com/....

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

# Create all needed directories upfront
mkdir -p "$OUTPUT"/{logs,subdomains,params,katana,s3,git,dirs,ports,jsfiles,screenshots} "$GLOBAL_WORDLISTS"

# Get local IP
get_local_ip(){
  ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' || hostname -I | awk '{print $1}' || echo "127.0.0.1"
}
LOCAL_IP="$(get_local_ip)"
DASH_PORT=8000

# Status helpers
status_dir="$OUTPUT/logs/status"
mkdir -p "$status_dir"

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
# Check dependencies
########################################
check_deps(){
  local missing=()
  local optional=()
  
  # Essential
  for cmd in curl sort awk sed grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  
  # Python for dashboard
  if ! command -v python3 >/dev/null 2>&1; then
    missing+=("python3")
  fi
  
  # Check Python Flask
  if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c "import flask" 2>/dev/null; then
      echo "[warn] Flask not installed. Installing via pip3..."
      pip3 install --user flask 2>/dev/null || missing+=("flask")
    fi
  fi
  
  # Optional tools
  for cmd in subfinder assetfinder httpx naabu nuclei katana ffuf gau waybackurls gf jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      optional+=("$cmd")
    fi
  done
  
  if [ ${#missing[@]} -gt 0 ]; then
    echo "[error] Missing essential tools: ${missing[*]}"
    echo "Install them or use --install-missing flag"
    exit 1
  fi
  
  if [ ${#optional[@]} -gt 0 ]; then
    echo "[warn] Optional tools not found: ${optional[*]}"
    echo "Some features may not work. Use --install-missing to auto-install"
  fi
}

check_deps

########################################
# Dashboard Python file
########################################
cat > "$OUTPUT/dashboard.py" <<'PYDASH'
#!/usr/bin/env python3
from flask import Flask, render_template_string
import os
import json
import time

app = Flask(__name__)
BASE = os.path.dirname(os.path.abspath(__file__))
STATUS_DIR = os.path.join(BASE, 'logs', 'status')
LOG_DIR = os.path.join(BASE, 'logs')

TEMPLATE = """<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Recon Dashboard - {{domain}}</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
            background: #0f1722;
            color: #e6eef8;
            padding: 20px;
            margin: 0;
        }
        h1 { 
            color: #8be9fd;
            border-bottom: 2px solid #8be9fd;
            padding-bottom: 10px;
        }
        h2 {
            color: #50fa7b;
            margin-top: 30px;
        }
        h3 {
            color: #f1fa8c;
            margin-top: 20px;
        }
        .info-box {
            background: #1a2332;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #8be9fd;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: #1a2332;
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background: #162030;
            padding: 12px;
            text-align: left;
            color: #8be9fd;
            font-weight: 600;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #223;
        }
        tr:hover {
            background: #1e2938;
        }
        .status-running { color: #f1fa8c; font-weight: bold; }
        .status-done { color: #50fa7b; font-weight: bold; }
        .status-failed { color: #ff5555; font-weight: bold; }
        .status-starting { color: #bd93f9; font-weight: bold; }
        pre {
            background: #071226;
            padding: 15px;
            border-radius: 6px;
            max-height: 300px;
            overflow: auto;
            border: 1px solid #223;
            font-size: 12px;
            line-height: 1.4;
        }
        .refresh-note {
            color: #6272a4;
            font-size: 14px;
            font-style: italic;
        }
    </style>
    <meta http-equiv="refresh" content="5">
</head>
<body>
    <h1>🔍 Recon Dashboard: {{domain}}</h1>
    <div class="info-box">
        <p><strong>Host:</strong> {{host}}:{{port}} | <strong>Updated:</strong> {{ts}}</p>
        <p class="refresh-note">Auto-refreshes every 5 seconds</p>
    </div>
    
    <h2>📊 Task Status</h2>
    <table>
        <tr>
            <th>Task</th>
            <th>Status</th>
            <th>PID</th>
            <th>Message</th>
            <th>Last Updated</th>
        </tr>
        {% for t in tasks %}
        <tr>
            <td><strong>{{t.task}}</strong></td>
            <td><span class="status-{{t.status}}">{{t.status}}</span></td>
            <td>{{t.pid if t.pid else 'N/A'}}</td>
            <td>{{t.msg}}</td>
            <td>{{t.ts}}</td>
        </tr>
        {% endfor %}
    </table>
    
    <h2>📝 Recent Logs</h2>
    {% for logfile in logs %}
    <h3>{{logfile}}</h3>
    <pre>{{logs_content[logfile]}}</pre>
    {% endfor %}
</body>
</html>"""

@app.route('/')
def index():
    domain = os.environ.get('RECON_DOMAIN', 'unknown')
    host = os.environ.get('RECON_HOST', '0.0.0.0')
    port = os.environ.get('RECON_PORT', '8000')
    
    tasks = []
    if os.path.isdir(STATUS_DIR):
        for fn in sorted(os.listdir(STATUS_DIR)):
            if not fn.endswith('.json'):
                continue
            path = os.path.join(STATUS_DIR, fn)
            try:
                with open(path, 'r') as f:
                    d = json.load(f)
                    tasks.append(d)
            except Exception as e:
                print(f"Error reading {fn}: {e}")
                continue
    
    logs_content = {}
    if os.path.isdir(LOG_DIR):
        for lf in sorted(os.listdir(LOG_DIR)):
            if lf.endswith('.log'):
                try:
                    with open(os.path.join(LOG_DIR, lf), 'r') as f:
                        lines = f.readlines()
                        logs_content[lf] = ''.join(lines[-100:])
                except Exception as e:
                    logs_content[lf] = f"(error reading: {e})"
    
    return render_template_string(
        TEMPLATE,
        domain=domain,
        host=host,
        port=port,
        ts=time.strftime('%Y-%m-%d %H:%M:%S'),
        tasks=tasks,
        logs=sorted(logs_content.keys()),
        logs_content=logs_content
    )

if __name__ == '__main__':
    port = int(os.environ.get('RECON_PORT', '8000'))
    print(f"Starting dashboard on 0.0.0.0:{port}")
    app.run(host='0.0.0.0', port=port, debug=False)
PYDASH

chmod +x "$OUTPUT/dashboard.py"

########################################
# Wordlists (persistent)
########################################
echo "[*] Setting up wordlists..."
declare -A WL
WL[common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
WL[params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
WL[dir_med]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
WL[raft_small]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"

for k in "${!WL[@]}"; do
  tgt="$GLOBAL_WORDLISTS/${k}.txt"
  if [ "$REFRESH_WORDLISTS" = true ] || [ ! -s "$tgt" ]; then
    echo "  Downloading $k wordlist..."
    if curl -sSfL "${WL[$k]}" -o "$tgt" 2>/dev/null; then
      sed -i 's/\r$//' "$tgt" 2>/dev/null || dos2unix "$tgt" 2>/dev/null || true
      echo "  ✓ $k downloaded"
    else
      echo "  ✗ Failed to download $k"
    fi
  else
    echo "  ✓ $k exists"
  fi
done

# Create combined wordlist
if [ -f "$GLOBAL_WORDLISTS/common.txt" ]; then
  cat "$GLOBAL_WORDLISTS/common.txt" 2>/dev/null | head -n 5000 | sort -u > "$GLOBAL_WORDLISTS/fuzz-combined-small.txt" || true
fi

########################################
# Optional installs
########################################
if [ "$INSTALL_MISSING" = true ]; then
  echo "[*] Installing missing tools..."
  if command -v go >/dev/null 2>&1; then
    echo "  Installing Go tools..."
    GO111MODULE=on go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/tomnomnom/waybackurls@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/lc/gau/v2/cmd/gau@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/tomnomnom/gf@latest 2>&1 | tail -n 1
    GO111MODULE=on go install -v github.com/ffuf/ffuf/v2@latest 2>&1 | tail -n 1
  else
    echo "  ✗ Go not found, skipping Go tools"
  fi
  
  if command -v pip3 >/dev/null 2>&1; then
    echo "  Installing Python tools..."
    pip3 install --user flask 2>&1 | tail -n 1
  fi
fi

########################################
# Task implementations
########################################
subenum_task(){
  write_status subenum starting 0 "starting subdomain enumeration"
  
  if command -v subfinder >/dev/null 2>&1; then
    run_task_bg subfinder subfinder -silent -d "$DOMAIN" -o "$OUTPUT/subdomains/subfinder.txt"
  else
    echo "$DOMAIN" > "$OUTPUT/subdomains/subfinder.txt"
    append_log subfinder "subfinder not available"
  fi
  
  if command -v assetfinder >/dev/null 2>&1; then
    run_task_bg assetfinder sh -c "assetfinder --subs-only '$DOMAIN' > '$OUTPUT/subdomains/assetfinder.txt'"
  else
    touch "$OUTPUT/subdomains/assetfinder.txt"
    append_log assetfinder "assetfinder not available"
  fi
  
  if [ "$MODE" = "full" ] && command -v amass >/dev/null 2>&1; then
    run_task_bg amass sh -c "timeout 600 amass enum -passive -d '$DOMAIN' -o '$OUTPUT/subdomains/amass.txt' || true"
  else
    touch "$OUTPUT/subdomains/amass.txt"
  fi
  
  # Wait and merge
  (
    sleep 15
    cat "$OUTPUT/subdomains"/*.txt 2>/dev/null | grep -E "^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$" | sort -u > "$OUTPUT/subdomains/all_subs.txt" || true
    count=$(wc -l < "$OUTPUT/subdomains/all_subs.txt" 2>/dev/null || echo 0)
    write_status subenum done 0 "found $count subdomains"
    append_log subenum "Merged $count unique subdomains"
  ) &
}

live_task(){
  write_status livecheck starting 0 "checking live hosts"
  
  # Wait for subdomain enum to have results
  local wait_count=0
  while [ ! -s "$OUTPUT/subdomains/all_subs.txt" ] && [ $wait_count -lt 30 ]; do
    sleep 2
    ((wait_count++))
  done
  
  if [ "$SKIP_HTTPX" = "true" ] || ! command -v httpx >/dev/null 2>&1; then
    cp -f "$OUTPUT/subdomains/all_subs.txt" "$OUTPUT/subdomains/live_subs.txt" 2>/dev/null || touch "$OUTPUT/subdomains/live_subs.txt"
    write_status livecheck done 0 "skipped or httpx not available"
    return
  fi
  
  run_task_bg httpx sh -c "httpx -silent -l '$OUTPUT/subdomains/all_subs.txt' -o '$OUTPUT/subdomains/live_subs.txt' -timeout 10 -retries 2"
}

katana_task(){
  write_status katana starting 0 "starting katana crawl"
  
  if ! command -v katana >/dev/null 2>&1; then
    write_status katana failed 0 "katana not found"
    return
  fi
  
  # Wait for live hosts
  local wait_count=0
  while [ ! -s "$OUTPUT/subdomains/live_subs.txt" ] && [ $wait_count -lt 60 ]; do
    sleep 2
    ((wait_count++))
  done
  
  local count=0
  local max_hosts=50
  
  if [ -s "$OUTPUT/subdomains/live_subs.txt" ]; then
    while IFS= read -r host && [ $count -lt $max_hosts ]; do
      hostn=$(echo "$host" | sed -E 's#https?://##;s#/$##;s#[^a-zA-Z0-9.-]#_#g')
      run_task_bg "katana_${hostn}" katana -u "$host" -d 2 -jc -kf all -c 5 -o "$OUTPUT/katana/katana_${hostn}.txt"
      ((count++))
    done < "$OUTPUT/subdomains/live_subs.txt"
  fi
  
  write_status katana running 0 "launched $count katana jobs"
}

urlharvest_task(){
  write_status urlharvest starting 0 "harvesting URLs"
  
  # Wait for subdomains
  local wait_count=0
  while [ ! -s "$OUTPUT/subdomains/all_subs.txt" ] && [ $wait_count -lt 30 ]; do
    sleep 2
    ((wait_count++))
  done
  
  if command -v gau >/dev/null 2>&1; then
    run_task_bg gau_task sh -c "cat '$OUTPUT/subdomains/all_subs.txt' | head -n 100 | gau --threads 5 > '$OUTPUT/params/gau.txt' 2>/dev/null || true"
  else
    touch "$OUTPUT/params/gau.txt"
  fi
  
  if command -v waybackurls >/dev/null 2>&1; then
    run_task_bg wayback_task sh -c "cat '$OUTPUT/subdomains/all_subs.txt' | head -n 100 | waybackurls > '$OUTPUT/params/wayback.txt' 2>/dev/null || true"
  else
    touch "$OUTPUT/params/wayback.txt"
  fi
  
  # Merge URLs
  (
    sleep 30
    cat "$OUTPUT/params"/*.txt "$OUTPUT/katana"/*.txt 2>/dev/null | sort -u > "$OUTPUT/params/all_urls.txt" || true
    count=$(wc -l < "$OUTPUT/params/all_urls.txt" 2>/dev/null || echo 0)
    write_status urlharvest done 0 "collected $count URLs"
  ) &
}

gf_task(){
  write_status gf starting 0 "extracting interesting URLs"
  
  if ! command -v gf >/dev/null 2>&1; then
    write_status gf failed 0 "gf not installed"
    return
  fi
  
  # Wait for URLs
  local wait_count=0
  while [ ! -s "$OUTPUT/params/all_urls.txt" ] && [ $wait_count -lt 60 ]; do
    sleep 2
    ((wait_count++))
  done
  
  if [ -s "$OUTPUT/params/all_urls.txt" ]; then
    run_task_bg gf_xss sh -c "cat '$OUTPUT/params/all_urls.txt' | gf xss > '$OUTPUT/params/xss.txt' 2>/dev/null || true"
    run_task_bg gf_sqli sh -c "cat '$OUTPUT/params/all_urls.txt' | gf sqli > '$OUTPUT/params/sqli.txt' 2>/dev/null || true"
    run_task_bg gf_lfi sh -c "cat '$OUTPUT/params/all_urls.txt' | gf lfi > '$OUTPUT/params/lfi.txt' 2>/dev/null || true"
    run_task_bg gf_ssrf sh -c "cat '$OUTPUT/params/all_urls.txt' | gf ssrf > '$OUTPUT/params/ssrf.txt' 2>/dev/null || true"
  fi
}

dirfuzz_task(){
  write_status dirfuzz starting 0 "starting directory fuzzing"
  
  if ! command -v ffuf >/dev/null 2>&1; then
    write_status dirfuzz failed 0 "ffuf not installed"
    return
  fi
  
  local WL_USE="$GLOBAL_WORDLISTS/fuzz-combined-small.txt"
  if [ "$MODE" = "medium" ] && [ -f "$GLOBAL_WORDLISTS/dir_med.txt" ]; then
    WL_USE="$GLOBAL_WORDLISTS/dir_med.txt"
  elif [ "$MODE" = "full" ] && [ -f "$GLOBAL_WORDLISTS/raft_small.txt" ]; then
    WL_USE="$GLOBAL_WORDLISTS/raft_small.txt"
  fi
  
  if [ ! -f "$WL_USE" ]; then
    write_status dirfuzz failed 0 "wordlist not found: $WL_USE"
    return
  fi
  
  # Wait for live hosts
  local wait_count=0
  while [ ! -s "$OUTPUT/subdomains/live_subs.txt" ] && [ $wait_count -lt 60 ]; do
    sleep 2
    ((wait_count++))
  done
  
  local count=0
  local max_hosts=20
  
  if [ -s "$OUTPUT/subdomains/live_subs.txt" ]; then
    while IFS= read -r host && [ $count -lt $max_hosts ]; do
      hn=$(echo "$host" | sed -E 's#https?://##;s#/$##;s#[^a-zA-Z0-9.-]#_#g')
      run_task_bg "ffuf_${hn}" ffuf -u "${host}/FUZZ" -w "$WL_USE" -t 50 -mc 200,204,301,302,307,401,403 -o "$OUTPUT/dirs/ffuf_${hn}.json" -of json -s 2>/dev/null
      ((count++))
    done < "$OUTPUT/subdomains/live_subs.txt"
  fi
  
  write_status dirfuzz running 0 "launched $count ffuf jobs"
}

s3_task(){
  write_status s3 starting 0 "checking S3 buckets"
  
  # Wait for subdomains
  local wait_count=0
  while [ ! -s "$OUTPUT/subdomains/all_subs.txt" ] && [ $wait_count -lt 30 ]; do
    sleep 2
    ((wait_count++))
  done
  
  # Generate S3 candidates
  if [ -s "$OUTPUT/subdomains/all_subs.txt" ]; then
    cut -d. -f1 "$OUTPUT/subdomains/all_subs.txt" | sort -u > "$OUTPUT/s3/candidates.txt" 2>/dev/null
    echo "$DOMAIN" >> "$OUTPUT/s3/candidates.txt"
    sort -u -o "$OUTPUT/s3/candidates.txt" "$OUTPUT/s3/candidates.txt"
  else
    echo "$DOMAIN" > "$OUTPUT/s3/candidates.txt"
  fi
  
  # Basic S3 check using curl
  (
    while IFS= read -r bucket; do
      for region in "" "us-west-2" "eu-west-1"; do
        if [ -z "$region" ]; then
          url="https://${bucket}.s3.amazonaws.com"
        else
          url="https://${bucket}.s3.${region}.amazonaws.com"
        fi
        
        if curl -sSf -I "$url" -m 5 >/dev/null 2>&1; then
          echo "$url - ACCESSIBLE" >> "$OUTPUT/s3/found.txt"
          append_log s3 "Found: $url"
          break
        fi
      done
    done < "$OUTPUT/s3/candidates.txt"
    
    if [ -f "$OUTPUT/s3/found.txt" ]; then
      count=$(wc -l < "$OUTPUT/s3/found.txt")
      write_status s3 done 0 "found $count accessible buckets"
      notify "Found $count accessible S3 buckets!"
    else
      write_status s3 done 0 "no accessible buckets found"
    fi
  ) &
}

js_secret_task(){
  write_status js_secret starting 0 "hunting JS secrets"
  
  # Wait for URLs
  local wait_count=0
  while [ ! -s "$OUTPUT/params/all_urls.txt" ] && [ $wait_count -lt 60 ]; do
    sleep 2
    ((wait_count++))
  done
  
  if [ ! -s "$OUTPUT/params/all_urls.txt" ]; then
    write_status js_secret failed 0 "no URLs to analyze"
    return
  fi
  
  # Extract JS files
  grep -iE "\.js(\?|$|#)" "$OUTPUT/params/all_urls.txt" 2>/dev/null | sort -u > "$OUTPUT/js_candidates.txt" || touch "$OUTPUT/js_candidates.txt"
  
  local count=0
  local max_js=100
  
  if [ -s "$OUTPUT/js_candidates.txt" ]; then
    while IFS= read -r jsu && [ $count -lt $max_js ]; do
      safe_name=$(echo "$jsu" | sed 's#[^A-Za-z0-9._-]#_#g' | cut -c1-200)
      out="$OUTPUT/jsfiles/${safe_name}.js"
      curl -sSfL "$jsu" -o "$out" -m 10 2>/dev/null || true
      ((count++))
    done < "$OUTPUT/js_candidates.txt"
  fi
  
  # Hunt for secrets
  if [ -d "$OUTPUT/jsfiles" ] && [ "$(ls -A "$OUTPUT/jsfiles" 2>/dev/null)" ]; then
    grep -Eroh "AKIA[0-9A-Z]{16}" "$OUTPUT/jsfiles" 2>/dev/null >> "$OUTPUT/jssecrets.txt" || true
    grep -Eroh "AIza[0-9A-Za-z_-]{35}" "$OUTPUT/jsfiles" 2>/dev/null >> "$OUTPUT/jssecrets.txt" || true
    grep -Eroh "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" "$OUTPUT/jsfiles" 2>/dev/null >> "$OUTPUT/jssecrets.txt" || true
    grep -Eroh "xox[baprs]-[A-Za-z0-9-]+" "$OUTPUT/jsfiles" 2>/dev/null >> "$OUTPUT/jssecrets.txt" || true
    grep -Eroh "ghp_[A-Za-z0-9]{36}" "$OUTPUT/jsfiles" 2>/dev/null >> "$OUTPUT/jssecrets.txt" || true
    grep -Eroh "sk-[A-Za-z0-9]{48}" "$OUTPUT/jsfiles" 2>/dev/null >> "$OUTPUT/jssecrets.txt" || true
    
    sort -u -o "$OUTPUT/jssecrets.txt" "$OUTPUT/jssecrets.txt" 2>/dev/null || true
  fi
  
  if [ -s "$OUTPUT/jssecrets.txt" ]; then
    secret_count=$(wc -l < "$OUTPUT/jssecrets.txt")
    append_log js_secret "Found $secret_count potential secrets"
    notify "⚠️ Found $secret_count potential secrets in JS files!"
    write_status js_secret done 0 "found $secret_count secrets"
  else
    write_status js_secret done 0 "no secrets found"
  fi
}

git_task(){
  write_status git starting 0 "searching GitHub"
  
  # Basic GitHub dorking using curl
  (
    query="$DOMAIN"
    api_url="https://api.github.com/search/code?q=${query}+in:file&per_page=30"
    
    result=$(curl -sSf "$api_url" -m 15 2>/dev/null || echo '{"items":[]}')
    echo "$result" > "$OUTPUT/git/github_search.json"
    
    # Extract URLs
    if command -v jq >/dev/null 2>&1; then
      echo "$result" | jq -r '.items[]?.html_url // empty' 2>/dev/null > "$OUTPUT/git/github_urls.txt" || true
      count=$(wc -l < "$OUTPUT/git/github_urls.txt" 2>/dev/null || echo 0)
      
      if [ "$count" -gt 0 ]; then
        append_log git "Found $count GitHub results"
        notify "Found $count GitHub code results for $DOMAIN"
        write_status git done 0 "found $count results"
      else
        write_status git done 0 "no results found"
      fi
    else
      write_status git done 0 "completed (jq not available for parsing)"
    fi
  ) &
}

port_scan_task(){
  write_status portscan starting 0 "scanning ports"
  
  if ! command -v nmap >/dev/null 2>&1 && ! command -v naabu >/dev/null 2>&1; then
    write_status portscan failed 0 "no port scanner available"
    return
  fi
  
  # Wait for subdomains
  local wait_count=0
  while [ ! -s "$OUTPUT/subdomains/all_subs.txt" ] && [ $wait_count -lt 30 ]; do
    sleep 2
    ((wait_count++))
  done
  
  local scan_ports="80,443,8080,8443,3000,8000,8888"
  if [ -n "$PORTS" ]; then
    scan_ports="$PORTS"
  fi
  
  if command -v naabu >/dev/null 2>&1; then
    run_task_bg naabu sh -c "cat '$OUTPUT/subdomains/all_subs.txt' | head -n 50 | naabu -silent -p '$scan_ports' -o '$OUTPUT/ports/naabu.txt'"
  elif command -v nmap >/dev/null 2>&1; then
    run_task_bg nmap sh -c "nmap -iL '$OUTPUT/subdomains/all_subs.txt' -p '$scan_ports' -oG '$OUTPUT/ports/nmap.txt' --open -T4 || true"
  fi
}

nuclei_task(){
  write_status nuclei starting 0 "running nuclei scans"
  
  if ! command -v nuclei >/dev/null 2>&1; then
    write_status nuclei failed 0 "nuclei not installed"
    return
  fi
  
  # Wait for live hosts
  local wait_count=0
  while [ ! -s "$OUTPUT/subdomains/live_subs.txt" ] && [ $wait_count -lt 60 ]; do
    sleep 2
    ((wait_count++))
  done
  
  if [ "$MODE" = "fast" ]; then
    severity="critical,high"
  elif [ "$MODE" = "medium" ]; then
    severity="critical,high,medium"
  else
    severity="critical,high,medium,low"
  fi
  
  run_task_bg nuclei nuclei -l "$OUTPUT/subdomains/live_subs.txt" -severity "$severity" -o "$OUTPUT/nuclei_results.txt" -stats -silent
}

########################################
# Initialize and start dashboard
########################################
write_status runner initialized 0 "pipeline starting"
notify "🚀 Recon started for $DOMAIN - Dashboard: http://${LOCAL_IP}:${DASH_PORT}"

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║        Enterprise Reconnaissance Pipeline              ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""
echo "  Target:    $DOMAIN"
echo "  Mode:      $MODE"
echo "  Output:    $OUTPUT"
echo "  Dashboard: http://${LOCAL_IP}:${DASH_PORT}"
echo ""
echo "─────────────────────────────────────────────────────────"
echo ""

# Start dashboard
export RECON_DOMAIN="$DOMAIN"
export RECON_HOST="$LOCAL_IP"
export RECON_PORT="$DASH_PORT"

# Ensure logs directory exists before starting dashboard
mkdir -p "$OUTPUT/logs"

(
  cd "$OUTPUT"
  python3 dashboard.py >> "$OUTPUT/logs/dashboard.log" 2>&1
) &
DASH_PID=$!

sleep 2

if kill -0 "$DASH_PID" 2>/dev/null; then
  write_status dashboard running "$DASH_PID" "dashboard online"
  append_log dashboard "Dashboard started at http://${LOCAL_IP}:${DASH_PORT}"
  echo "✓ Dashboard started successfully"
else
  write_status dashboard failed 0 "failed to start"
  echo "✗ Dashboard failed to start (check logs/dashboard.log)"
fi

echo ""

########################################
# Execute reconnaissance tasks
########################################
echo "[*] Starting reconnaissance tasks..."
echo ""

# Phase 1: Subdomain enumeration
echo "  Phase 1: Subdomain Enumeration"
subenum_task
sleep 5

# Phase 2: Live host detection
echo "  Phase 2: Live Host Detection"
live_task
sleep 10

# Phase 3: Port scanning (optional)
if [ "$MODE" != "fast" ]; then
  echo "  Phase 3: Port Scanning"
  port_scan_task
  sleep 5
fi

# Phase 4: Content discovery
echo "  Phase 4: Content Discovery"
katana_task
urlharvest_task
sleep 8

# Phase 5: Analysis
echo "  Phase 5: Analysis & Fuzzing"
gf_task
dirfuzz_task
js_secret_task
s3_task
git_task

# Phase 6: Vulnerability scanning
if [ "$MODE" = "full" ]; then
  echo "  Phase 6: Vulnerability Scanning"
  sleep 10
  nuclei_task
fi

echo ""
echo "[*] All tasks launched. Monitoring progress..."
echo ""

########################################
# Monitor task completion
########################################
monitor_tasks(){
  local all_done=false
  local last_status=""
  local check_count=0
  local max_checks=360  # 30 minutes max (360 * 5 seconds)
  
  while [ "$all_done" = false ] && [ $check_count -lt $max_checks ]; do
    all_done=true
    running_tasks=()
    done_tasks=()
    failed_tasks=()
    
    shopt -s nullglob
    for f in "$status_dir"/*.json; do
      [ -f "$f" ] || continue
      
      if command -v jq >/dev/null 2>&1; then
        task=$(jq -r '.task // "unknown"' "$f" 2>/dev/null)
        status=$(jq -r '.status // "unknown"' "$f" 2>/dev/null)
      else
        task=$(grep -oP '"task":"\K[^"]+' "$f" 2>/dev/null || echo "unknown")
        status=$(grep -oP '"status":"\K[^"]+' "$f" 2>/dev/null || echo "unknown")
      fi
      
      case "$status" in
        running|starting)
          all_done=false
          running_tasks+=("$task")
          ;;
        done)
          done_tasks+=("$task")
          ;;
        failed)
          failed_tasks+=("$task")
          ;;
      esac
    done
    
    # Create status summary
    current_status="Running: ${#running_tasks[@]} | Done: ${#done_tasks[@]} | Failed: ${#failed_tasks[@]}"
    
    # Only print if status changed
    if [ "$current_status" != "$last_status" ]; then
      echo "[$(date +'%H:%M:%S')] $current_status"
      if [ ${#running_tasks[@]} -gt 0 ] && [ ${#running_tasks[@]} -le 5 ]; then
        echo "  Active: ${running_tasks[*]}"
      fi
      last_status="$current_status"
    fi
    
    ((check_count++))
    sleep 5
  done
  
  if [ $check_count -ge $max_checks ]; then
    echo ""
    echo "[!] Maximum monitoring time reached. Some tasks may still be running."
  fi
}

monitor_tasks

########################################
# Generate final report
########################################
echo ""
echo "─────────────────────────────────────────────────────────"
echo ""
echo "[*] Generating final report..."

report_file="$OUTPUT/REPORT.txt"

cat > "$report_file" <<REPORT
╔════════════════════════════════════════════════════════╗
║        RECONNAISSANCE REPORT                           ║
╚════════════════════════════════════════════════════════╝

Target:     $DOMAIN
Date:       $(date)
Mode:       $MODE
Output Dir: $OUTPUT

═══════════════════════════════════════════════════════════

SUBDOMAINS DISCOVERED
═══════════════════════════════════════════════════════════
REPORT

if [ -f "$OUTPUT/subdomains/all_subs.txt" ]; then
  sub_count=$(wc -l < "$OUTPUT/subdomains/all_subs.txt" 2>/dev/null || echo 0)
  echo "Total: $sub_count" >> "$report_file"
  echo "" >> "$report_file"
  head -n 50 "$OUTPUT/subdomains/all_subs.txt" >> "$report_file" 2>/dev/null || true
  if [ "$sub_count" -gt 50 ]; then
    echo "... ($(($sub_count - 50)) more)" >> "$report_file"
  fi
else
  echo "None found" >> "$report_file"
fi

cat >> "$report_file" <<REPORT

═══════════════════════════════════════════════════════════
LIVE HOSTS
═══════════════════════════════════════════════════════════
REPORT

if [ -f "$OUTPUT/subdomains/live_subs.txt" ]; then
  live_count=$(wc -l < "$OUTPUT/subdomains/live_subs.txt" 2>/dev/null || echo 0)
  echo "Total: $live_count" >> "$report_file"
  echo "" >> "$report_file"
  cat "$OUTPUT/subdomains/live_subs.txt" >> "$report_file" 2>/dev/null || true
else
  echo "None found" >> "$report_file"
fi

cat >> "$report_file" <<REPORT

═══════════════════════════════════════════════════════════
URLS COLLECTED
═══════════════════════════════════════════════════════════
REPORT

if [ -f "$OUTPUT/params/all_urls.txt" ]; then
  url_count=$(wc -l < "$OUTPUT/params/all_urls.txt" 2>/dev/null || echo 0)
  echo "Total: $url_count" >> "$report_file"
else
  echo "None found" >> "$report_file"
fi

cat >> "$report_file" <<REPORT

═══════════════════════════════════════════════════════════
INTERESTING FINDINGS
═══════════════════════════════════════════════════════════
REPORT

# XSS
if [ -f "$OUTPUT/params/xss.txt" ] && [ -s "$OUTPUT/params/xss.txt" ]; then
  xss_count=$(wc -l < "$OUTPUT/params/xss.txt")
  echo "Potential XSS: $xss_count URLs" >> "$report_file"
fi

# SQLi
if [ -f "$OUTPUT/params/sqli.txt" ] && [ -s "$OUTPUT/params/sqli.txt" ]; then
  sqli_count=$(wc -l < "$OUTPUT/params/sqli.txt")
  echo "Potential SQLi: $sqli_count URLs" >> "$report_file"
fi

# Secrets
if [ -f "$OUTPUT/jssecrets.txt" ] && [ -s "$OUTPUT/jssecrets.txt" ]; then
  secret_count=$(wc -l < "$OUTPUT/jssecrets.txt")
  echo "JS Secrets: $secret_count found ⚠️" >> "$report_file"
fi

# S3 Buckets
if [ -f "$OUTPUT/s3/found.txt" ] && [ -s "$OUTPUT/s3/found.txt" ]; then
  s3_count=$(wc -l < "$OUTPUT/s3/found.txt")
  echo "S3 Buckets: $s3_count accessible ⚠️" >> "$report_file"
fi

# GitHub
if [ -f "$OUTPUT/git/github_urls.txt" ] && [ -s "$OUTPUT/git/github_urls.txt" ]; then
  git_count=$(wc -l < "$OUTPUT/git/github_urls.txt")
  echo "GitHub Mentions: $git_count" >> "$report_file"
fi

cat >> "$report_file" <<REPORT

═══════════════════════════════════════════════════════════
TASK STATUS SUMMARY
═══════════════════════════════════════════════════════════
REPORT

shopt -s nullglob
for f in "$status_dir"/*.json; do
  [ -f "$f" ] || continue
  if command -v jq >/dev/null 2>&1; then
    jq -r '"\(.task): \(.status)"' "$f" >> "$report_file" 2>/dev/null || cat "$f" >> "$report_file"
  else
    basename "$f" .json >> "$report_file"
  fi
done

cat >> "$report_file" <<REPORT

═══════════════════════════════════════════════════════════
NEXT STEPS
═══════════════════════════════════════════════════════════
1. Review all discovered subdomains and URLs
2. Investigate any secrets found in JS files
3. Check accessible S3 buckets for sensitive data
4. Analyze interesting parameters for vulnerabilities
5. Run manual testing on high-value targets
6. Review nuclei results if vulnerability scanning was enabled

═══════════════════════════════════════════════════════════
Dashboard: http://${LOCAL_IP}:${DASH_PORT}
Output:    $OUTPUT
Report:    $report_file
═══════════════════════════════════════════════════════════
REPORT

echo "✓ Report generated: $report_file"
echo ""

# Display summary
cat <<SUMMARY
╔════════════════════════════════════════════════════════╗
║              RECONNAISSANCE COMPLETE                   ║
╚════════════════════════════════════════════════════════╝

$(if [ -f "$OUTPUT/subdomains/all_subs.txt" ]; then echo "  Subdomains:  $(wc -l < "$OUTPUT/subdomains/all_subs.txt")"; fi)
$(if [ -f "$OUTPUT/subdomains/live_subs.txt" ]; then echo "  Live Hosts:  $(wc -l < "$OUTPUT/subdomains/live_subs.txt")"; fi)
$(if [ -f "$OUTPUT/params/all_urls.txt" ]; then echo "  URLs:        $(wc -l < "$OUTPUT/params/all_urls.txt")"; fi)
$(if [ -f "$OUTPUT/jssecrets.txt" ] && [ -s "$OUTPUT/jssecrets.txt" ]; then echo "  ⚠️ Secrets:   $(wc -l < "$OUTPUT/jssecrets.txt")"; fi)
$(if [ -f "$OUTPUT/s3/found.txt" ] && [ -s "$OUTPUT/s3/found.txt" ]; then echo "  ⚠️ S3 Buckets: $(wc -l < "$OUTPUT/s3/found.txt")"; fi)

─────────────────────────────────────────────────────────
  Dashboard:  http://${LOCAL_IP}:${DASH_PORT}
  Report:     $report_file
  Output:     $OUTPUT
─────────────────────────────────────────────────────────

Press Ctrl+C to stop the dashboard server.
SUMMARY

notify "✅ Recon complete for $DOMAIN. Check report: $report_file"
write_status runner done 0 "pipeline completed successfully"

# Keep dashboard running
wait
