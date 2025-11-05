#!/usr/bin/env bash
# crazy-auto-recon-enterprise-with-dashboard.sh
# Enterprise Recon + Dashboard + Notifications + JS secret hunter + Cloud bucket sweeper
# Single-file runner: generates a small Python Flask dashboard (dashboard.py) into the output dir and runs it.
# Usage:
#   chmod +x crazy-auto-recon-enterprise-with-dashboard.sh
#   ./crazy-auto-recon-enterprise-with-dashboard.sh example.com --mode medium [--install-missing] [--telegram TOKEN:CHATID] [--slack WEBHOOK]
#
# WARNING: Only run against targets you have permission to test.

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

########################################
# Helpers
########################################
usage(){
  cat <<EOF
$PROGNAME <domain> [flags]
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
  $PROGNAME example.com --mode fast --telegram 123:456 --slack https://hooks.slack.com/....

This script writes status files and launches a small web dashboard accessible on your LAN.
EOF
  exit 1
}

# parse args
if [ $# -lt 1 ]; then usage; fi
ARGS=("$@")
POSITIONAL=()
# Use arithmetic context without quotes
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
    -h|--help) usage; shift;;
    --) shift; break;;
    -*|--*) echo "Unknown option: $1"; usage;;
    *) POSITIONAL+=("$1"); shift;;
  esac
done
if [ ${#POSITIONAL[@]} -lt 1 ]; then usage; fi
DOMAIN="${POSITIONAL[0]}"
OUTPUT="${DOMAIN}${OUTPUT_SUFFIX}"
mkdir -p "$OUTPUT" "$OUTPUT/logs" "$OUTPUT/subdomains" "$OUTPUT/params" "$OUTPUT/katana" "$OUTPUT/s3" "$OUTPUT/git" "$GLOBAL_WORDLISTS"

# get local IP to show dashboard binding
get_local_ip(){
  ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' || hostname -I | awk '{print $1}' || echo "127.0.0.1"
}
LOCAL_IP="$(get_local_ip)"
DASH_PORT=8000

# status helpers: write basic JSON status files used by dashboard
status_dir="$OUTPUT/logs/status"
mkdir -p "$status_dir"
write_status(){
  # write_status <task> <status> <pid> <msg>
  task="$1"; st="$2"; pid_val="$3"; msg="$4"
  ts="$(date --iso-8601=seconds 2>/dev/null || date +%s)"
  # replace double quotes in msg so JSON stays valid
  safe_msg="${msg//\"/'}"
  printf '{"task":"%s","status":"%s","pid":%s,"msg":"%s","ts":"%s"}\n' "${task}" "${st}" "${pid_val}" "${safe_msg}" "${ts}" > "$status_dir/${task}.json"
}

append_log(){
  # append_log <task> <line>
  task="$1"; line="$2"; echo "[$(date +'%F %T')] $line" >> "$OUTPUT/logs/${task}.log"
}

notify(){
  # notify <short message>
  msg="$1"
  append_log notifier "$msg"
  # telegram
  if [ -n "$TELEGRAM_CFG" ]; then
    IFS=':' read -r token chatid <<< "$TELEGRAM_CFG"
    if [ -n "$token" ] && [ -n "$chatid" ]; then
      curl -s -X POST "https://api.telegram.org/bot${token}/sendMessage" -d chat_id="$chatid" -d text="[Recon][$DOMAIN] $msg" >/dev/null 2>&1 || true
    fi
  fi

  # slack (build payload safely)
  if [ -n "$SLACK_WEBHOOK" ]; then
    safe_msg="${msg//\"/'}"   # replace any double-quotes in msg with single-quotes
    # using printf avoids nested-quote issues
    payload=$(printf '{"text":"[Recon][%s] %s"}' "$DOMAIN" "$safe_msg")
    curl -s -X POST -H 'Content-type: application/json' --data "$payload" "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
  fi
}

# wrapper to run tasks and update status files
run_task_bg(){
  # run_task_bg <taskname> <command...>
  task="$1"; shift
  # build command string safely
  cmd=( "$@" )
  append_log "$task" "START: ${cmd[*]}"
  tmpf="$OUTPUT/logs/${task}_cmd.sh"
  # create a script that preserves quoting
  {
    printf '%s\n' "#!/usr/bin/env bash"
    printf '%s\n' "${cmd[@]}"
  } > "$tmpf"
  chmod +x "$tmpf"
  ( "$tmpf" >> "$OUTPUT/logs/${task}.log" 2>&1 ) &
  pid=$!
  write_status "$task" "running" "$pid" "started"
  # monitor it
  ( while kill -0 "$pid" 2>/dev/null; do sleep 1; done; wait "$pid"; rc=$?; if [ $rc -eq 0 ]; then write_status "$task" "done" 0 "exit 0"; append_log "$task" "COMPLETED (rc=0)"; notify "Task $task completed"; else write_status "$task" "failed" 0 "rc=$rc"; append_log "$task" "FAILED (rc=$rc)"; notify "Task $task failed (rc=$rc)"; fi ) &
}

# prepare dashboard.py into OUTPUT for live UI
# prepare dashboard.py into OUTPUT for live UI
cat > "$OUTPUT/dashboard.py" << 'EOF'
from flask import Flask, jsonify, render_template_string
import os, json, time

app = Flask(__name__)
BASE = os.path.dirname(__file__)
STATUS_DIR = os.path.join(BASE,'logs','status')
LOG_DIR = os.path.join(BASE,'logs')

TEMPLATE = """<!doctype html><html><head><meta charset=utf-8><title>Recon Dashboard</title>
<style>body{font-family:Inter,Arial;background:#0f1722;color:#e6eef8;padding:20px}h1{color:#8be9fd}table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #223}pre{background:#071226;padding:10px;border-radius:6px;max-height:240px;overflow:auto}</style>
<meta http-equiv="refresh" content="5"></head><body>
<h1>Recon Dashboard: {{domain}}</h1>
<p>Host: <b>{{host}}:{{port}}</b> | Updated: {{ts}}</p>
<h2>Tasks status</h2>
<table><tr><th>Task</th><th>Status</th><th>PID</th><th>Message</th><th>Updated</th></tr>
{% for t in tasks %}
<tr><td>{{t.task}}</td><td>{{t.status}}</td><td>{{t.pid}}</td><td>{{t.msg}}</td><td>{{t.ts}}</td></tr>
{% endfor %}
</table>
<h2>Logs (latest)</h2>
{% for logfile in logs %}
<h3>{{logfile}}</h3>
<pre>{{logs_content[logfile]}}</pre>
{% endfor %}
</body></html>"""

@app.route('/')
def index():
    domain = os.environ.get('RECON_DOMAIN','unknown')
    host = os.environ.get('RECON_HOST','0.0.0.0')
    port = os.environ.get('RECON_PORT','8000')

    tasks = []
    if os.path.isdir(STATUS_DIR):
        for fn in sorted(os.listdir(STATUS_DIR)):
            path = os.path.join(STATUS_DIR,fn)
            try:
                with open(path) as f:
                    tasks.append(json.load(f))
            except:
                continue

    logs_content = {}
    if os.path.isdir(LOG_DIR):
        for lf in sorted(os.listdir(LOG_DIR)):
            if lf.endswith('.log'):
                try:
                    with open(os.path.join(LOG_DIR,lf)) as f:
                        logs_content[lf] = ''.join(f.readlines()[-200:])
                except:
                    logs_content[lf] = "(error reading)"

    return render_template_string(
        TEMPLATE, domain=domain, host=host, port=port, ts=time.ctime(),
        tasks=tasks, logs=sorted(logs_content.keys()),
        logs_content=logs_content
    )

if __name__ == '__main__':
    import os
    os.environ.setdefault('RECON_PORT','8000')
    app.run(host='0.0.0.0', port=int(os.environ.get('RECON_PORT',8000)))
EOF

chmod +x "$OUTPUT/dashboard.py"

# initial status
write_status runner "initialized" 0 "ready"

########################################
# Wordlists (persistent, only download missing unless refresh requested)
########################################
declare -A WL
WL[common]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
WL[params]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt"
WL[dir_med]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt"
WL[raft_small]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt"
WL[js]="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/JS-Files/all-js-files.txt"

for k in "${!WL[@]}"; do
  tgt="$GLOBAL_WORDLISTS/${k}.txt"
  if [ "$REFRESH_WORDLISTS" = true ] || [ ! -s "$tgt" ]; then
    echo "[wordlists] downloading $k"
    if command -v wget >/dev/null 2>&1; then wget -q "${WL[$k]}" -O "$tgt" || true; else curl -sSfL "${WL[$k]}" -o "$tgt" || true; fi
    sed -i 's/\r$//' "$tgt" 2>/dev/null || true
  fi
done

# combined small for fast runs
cat "$GLOBAL_WORDLISTS/common.txt" "$GLOBAL_WORDLISTS/dir_med.txt" 2>/dev/null | sort -u > "$GLOBAL_WORDLISTS/fuzz-combined-small.txt" || true

########################################
# Optional: install missing tools (best effort)
########################################
if [ "$INSTALL_MISSING" = true ]; then
  echo "[installer] install-missing requested: attempting best-effort installs"
  if command -v go >/dev/null 2>&1; then
    for pkg in "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" "github.com/projectdiscovery/httpx/cmd/httpx@latest" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" "github.com/projectdiscovery/katana/cmd/katana@latest"; do
      GO111MODULE=on go install "$pkg" || true
    done
  fi
  if command -v pip3 >/dev/null 2>&1; then
    pip3 install --user gitdorker gitleaks dork-cli || true
  fi
fi

########################################
# Task implementations (they use run_task_bg wrapper)
########################################
subenum_task(){
  write_status subenum starting 0 "starting subdomain enumeration"
  run_task_bg subfinder subfinder -silent -d "$DOMAIN" -o "$OUTPUT/subdomains/subfinder.txt"
  run_task_bg assetfinder assetfinder --subs-only "$DOMAIN"
  if [ "$MODE" != "fast" ]; then
    run_task_bg amass timeout 600 amass enum -passive -d "$DOMAIN" -o "$OUTPUT/subdomains/amass.txt"
  fi
  (sleep 12; cat "$OUTPUT/subdomains"/*.txt 2>/dev/null | sort -u > "$OUTPUT/subdomains/all_subs.txt"; write_status subenum running 0 "merged initial outputs" ) &
}

live_task(){
  write_status livecheck starting 0 "httpx live check starting"
  if [ "$SKIP_HTTPX" = "true" ]; then
    cp -f "$OUTPUT/subdomains/all_subs.txt" "$OUTPUT/subdomains/live_subs.txt" || true
    write_status livecheck done 0 "skipped"
    return
  fi
  run_task_bg httpx httpx -silent -l "$OUTPUT/subdomains/all_subs.txt" -o "$OUTPUT/subdomains/live_subs.txt"
}

katana_task(){
  write_status katana starting 0 "katana crawling"
  if ! command -v katana >/dev/null 2>&1; then write_status katana failed 0 "katana not found"; return; fi
  while IFS= read -r host; do
    hostn=$(echo "$host" | sed -E 's#https?://##;s#/$##')
    run_task_bg katana_${hostn} katana -u "https://$hostn" -a -t 4 -o "$OUTPUT/katana/katana_${hostn}.txt"
  done < <(sed -n '1,200p' "$OUTPUT/subdomains/all_subs.txt" 2>/dev/null || true)
  write_status katana running 0 "launched katana per-host jobs"
}

urlharvest_task(){
  write_status urlharvest starting 0 "url gather"
  run_task_bg gau_task sh -c "xargs -a $OUTPUT/subdomains/all_subs.txt -I {} -P 10 sh -c 'echo https://{} | xargs -I % sh -c \"gau %\"' > $OUTPUT/params/gau.txt"
  run_task_bg wayback_task sh -c "xargs -a $OUTPUT/subdomains/all_subs.txt -I {} -P 10 sh -c 'echo https://{} | xargs -I % sh -c \"waybackurls %\"' > $OUTPUT/params/wayback.txt"
  (sleep 5; cat "$OUTPUT/params"/*.txt 2>/dev/null | sort -u > "$OUTPUT/params/all_urls.txt"; write_status urlharvest running 0 "merged urls") &
}

gf_task(){
  write_status gf starting 0 "gf extraction"
  run_task_bg gf_xss sh -c "cat $OUTPUT/params/all_urls.txt | gf xss > $OUTPUT/params/xss.txt"
  run_task_bg gf_sqli sh -c "cat $OUTPUT/params/all_urls.txt | gf sqli > $OUTPUT/params/sqli.txt"
  run_task_bg gf_lfi sh -c "cat $OUTPUT/params/all_urls.txt | gf lfi > $OUTPUT/params/lfi.txt"
  run_task_bg gf_ssrf sh -c "cat $OUTPUT/params/all_urls.txt | gf ssrf > $OUTPUT/params/ssrf.txt"
}

dirfuzz_task(){
  write_status dirfuzz starting 0 "dir fuzz"
  WL_USE="$GLOBAL_WORDLISTS/fuzz-combined-small.txt"
  if [ "$MODE" = "medium" ]; then WL_USE="$GLOBAL_WORDLISTS/dir_med.txt"; fi
  if [ "$MODE" = "full" ]; then WL_USE="$GLOBAL_WORDLISTS/raft_small.txt"; fi
  if [ -f "$OUTPUT/ports/naabu.txt" ]; then
    while IFS= read -r line; do
      port=$(echo "$line" | awk -F: '{print $NF}')
      host=$(echo "$line" | awk -F: '{$NF=""; sub(/:$/,""); print $0}')
      run_task_bg ffuf_${host}_${port} ffuf -u "http://$host:$port/FUZZ" -w "$WL_USE" -t 150 -o "$OUTPUT/dirs/ffuf_${host}_${port}.json"
    done < "$OUTPUT/ports/naabu.txt"
  else
    while IFS= read -r host; do
      hn=$(echo "$host" | sed -E 's#https?://##;s#/$##')
      run_task_bg ffuf_${hn} ffuf -u "http://$hn/FUZZ" -w "$WL_USE" -t 80 -o "$OUTPUT/dirs/ffuf_${hn}.json"
    done < "$OUTPUT/subdomains/all_subs.txt"
  fi
}

s3_task(){
  write_status s3 starting 0 "s3 checks"
  cut -d. -f1 "$OUTPUT/subdomains/all_subs.txt" | sort -u > "$OUTPUT/s3/candidates.txt" 2>/dev/null || true
  echo "$DOMAIN" >> "$OUTPUT/s3/candidates.txt"
  sort -u -o "$OUTPUT/s3/candidates.txt" "$OUTPUT/s3/candidates.txt" || true
  if command -v s3scanner >/dev/null 2>&1; then
    while IFS= read -r c; do
      run_task_bg s3_${c} s3scanner --bucket "$c" --no-color --output "$OUTPUT/s3/s3scanner_${c}.json"
    done < "$OUTPUT/s3/candidates.txt"
  fi
  if command -v s3recon >/dev/null 2>&1; then
    run_task_bg s3recon s3recon -l "$OUTPUT/s3/candidates.txt" -o "$OUTPUT/s3/s3recon_results.json"
  fi
}

js_secret_task(){
  write_status js_secret starting 0 "js secret hunt"
  mkdir -p "$OUTPUT/jsfiles"
  urls_file="$OUTPUT/params/all_urls.txt"
  grep -E "\.js(\?|$)" "$urls_file" | sort -u > "$OUTPUT/js_candidates.txt" 2>/dev/null || true
  head -n 200 "$OUTPUT/js_candidates.txt" | while read -r jsu; do
    safe_name=$(echo "$jsu" | sed 's/[^A-Za-z0-9._-]/_/g')
    out="$OUTPUT/jsfiles/$safe_name"
    (curl -sSfL "$jsu" -o "$out" || true)
  done
  grep -Eroh "(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z-_]{35}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|xox[baprs]-[A-Za-z0-9-]+)" "$OUTPUT/jsfiles" 2>/dev/null | sort -u > "$OUTPUT/jssecrets.txt" || true
  if [ -s "$OUTPUT/jssecrets.txt" ]; then
    append_log js_secret "Found secrets; see jssecrets.txt"
    notify "JS secrets found (sample). Review $OUTPUT/jssecrets.txt"
    write_status js_secret done 0 "found secrets"
  else
    write_status js_secret done 0 "no secrets found"
  fi
}

git_task(){
  write_status git starting 0 "github dork"
  if command -v gitdorker >/dev/null 2>&1; then
    run_task_bg gitdork gitdorker --query "$DOMAIN" --output "$OUTPUT/git/gitdorker_${DOMAIN}.json"
  fi
  if command -v gitleaks >/dev/null 2>&1; then
    append_log git "gitleaks available; run manually on repo list"
  fi
}

# notify dashboard start
notify "Dashboard binding: http://${LOCAL_IP}:${DASH_PORT} — open in browser"

# Start the dashboard server (python) in background with env
export RECON_DOMAIN="$DOMAIN"
export RECON_HOST="$LOCAL_IP"
export RECON_PORT="$DASH_PORT"
( cd "$OUTPUT" && python3 dashboard.py >/dev/null 2>&1 & )
write_status dashboard running 0 "dashboard started at ${LOCAL_IP}:${DASH_PORT}"
append_log dashboard "started dashboard at http://${LOCAL_IP}:${DASH_PORT}"

# Kickoff tasks (order & pacing)
subenum_task
sleep 3
live_task
sleep 8
katana_task
urlharvest_task
sleep 6
gf_task
# background tasks
js_secret_task &
dirfuzz_task &
s3_task &
git_task &

# runtime summary loop
echo "Dashboard: http://${LOCAL_IP}:${DASH_PORT}"
while true; do
  echo "---- Status summary ($(date +'%H:%M:%S')) ----"
  shopt -s nullglob
  for f in "$status_dir"/*.json; do
    [ -f "$f" ] || continue
    if command -v jq >/dev/null 2>&1; then
      jq -r '.task+" | "+.status+" | pid:"+(.pid|tostring)+" | "+.msg' "$f" 2>/dev/null || cat "$f"
    else
      cat "$f"
    fi
  done
  # break when all are done/failed
  all_done=true
  for f in "$status_dir"/*.json; do
    [ -f "$f" ] || continue
    st=$(jq -r '.status' "$f" 2>/dev/null || echo "")
    if [ "$st" = "running" ] || [ "$st" = "starting" ]; then all_done=false; fi
  done
  if [ "$all_done" = true ]; then break; fi
  sleep 8
done

notify "Recon pipeline finished for $DOMAIN"
write_status runner done 0 "all tasks finished"
cat <<EOF
Recon finished. Dashboard: http://${LOCAL_IP}:${DASH_PORT}
Results: $OUTPUT
EOF
