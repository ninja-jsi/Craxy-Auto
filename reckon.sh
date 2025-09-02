#!/bin/bash

# ----------------------------
# Full Bug Bounty Recon Script
# ----------------------------
# Tools Required:
# subfinder, assetfinder, amass, httpx (or httprobe),
# naabu, nmap, nuclei, gowitness,
# gau, waybackurls, gf, feroxbuster
# ----------------------------

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
OUTPUT="$DOMAIN-recon"
mkdir -p $OUTPUT/{subdomains,ports,scans,screenshots,params,dirs}

echo "[+] Enumerating subdomains..."
subfinder -silent -d $DOMAIN -o $OUTPUT/subdomains/subfinder.txt &
assetfinder --subs-only $DOMAIN | tee $OUTPUT/subdomains/assetfinder.txt &
amass enum -passive -d $DOMAIN -o $OUTPUT/subdomains/amass.txt &
wait

cat $OUTPUT/subdomains/*.txt | sort -u > $OUTPUT/subdomains/all_subs.txt

echo "[+] Checking live hosts..."
cat $OUTPUT/subdomains/all_subs.txt | httpx -silent -o $OUTPUT/subdomains/live_subs.txt

echo "[+] Port scanning with Naabu..."
sed -i 's#^https\?://##' $OUTPUT/subdomains/live_subs.txt
naabu -list $OUTPUT/subdomains/live_subs.txt -p 0-65535 -rate 20000 -o $OUTPUT/ports/naabu.txt &

echo "[+] Service detection with Nmap..."
nmap -T4 -sC -sV -iL $OUTPUT/subdomains/live_subs.txt -oN $OUTPUT/scans/nmap.txt &
wait

echo "[+] Running nuclei (common templates)..."
nuclei -l $OUTPUT/subdomains/live_subs.txt -c 50 -rl 100 -tags cves,exposures -o $OUTPUT/scans/nuclei.txt &

echo "[+] Taking screenshots..."
gowitness scan file -f  "$OUTPUT/subdomains/live_subs.txt" --screenshot-path "$OUTPUT/screenshots" --timeout 10 

echo "[+] Directory Bruteforcing..."
for port in $(cat ./ports/naabu.txt); do
    ffuf -u http://$DOMAIN:$port/FUZZ -w /usr/share/wordlists/dirb/common.txt -o ffuf_$port.json
done

# -----------------------------------
# Parameter Discovery (for XSS/SQLi)
# -----------------------------------
echo "[+] Gathering URLs for parameter discovery..."
(cat $OUTPUT/subdomains/live_subs.txt | gau > $OUTPUT/params/gau.txt) &
(cat $OUTPUT/subdomains/live_subs.txt | waybackurls > $OUTPUT/params/wayback.txt) &
wait

cat $OUTPUT/params/*.txt | sort -u > $OUTPUT/params/all_urls.txt

echo "[+] Extracting potential parameters..."
cat $OUTPUT/params/all_urls.txt | gf xss > $OUTPUT/params/xss.txt &
cat $OUTPUT/params/all_urls.txt | gf sqli > $OUTPUT/params/sqli.txt &
cat $OUTPUT/params/all_urls.txt | gf lfi > $OUTPUT/params/lfi.txt &
cat $OUTPUT/params/all_urls.txt | gf ssrf > $OUTPUT/params/ssrf.txt &
wait

# -----------------------------------
# Directory/File Bruteforce
# -----------------------------------
echo "[+] Running directory brute force..."

dirsearch -u https://$DOMAIN -o $OUTPUT/dirs/dirsearch-$DOMAIN.txt
gobuster dir -u https://$DOMAIN -w /usr/share/wordlists/dirb/common.txt -o $OUTPUT/dirs/gobuster-$DOMAIN.txt

while read url; do
    echo "Scanning $url ..."
    feroxbuster -u $url -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -o "$OUTPUT/dirs/$(echo $url | sed 's/https\?:\/\///').txt" &
done < $OUTPUT/subdomains/live_subs.txt
wait

echo "[+] Recon completed for $DOMAIN!"
echo "Results saved in: $OUTPUT/"
