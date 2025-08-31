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
subfinder -silent -d $DOMAIN -o $OUTPUT/subdomains/subfinder.txt
assetfinder --subs-only $DOMAIN | tee $OUTPUT/subdomains/assetfinder.txt
amass enum -passive -d $DOMAIN -o $OUTPUT/subdomains/amass.txt

cat $OUTPUT/subdomains/*.txt | sort -u > $OUTPUT/subdomains/all_subs.txt

echo "[+] Checking live hosts..."
cat $OUTPUT/subdomains/all_subs.txt | httpx -silent -o $OUTPUT/subdomains/live_subs.txt

echo "[+] Port scanning with Naabu..."
naabu -list $OUTPUT/subdomains/live_subs.txt -p - -o $OUTPUT/ports/naabu.txt

echo "[+] Service detection with Nmap..."
nmap -sC -sV -iL $OUTPUT/subdomains/live_subs.txt -oN $OUTPUT/scans/nmap.txt

echo "[+] Running nuclei (common templates)..."
nuclei -l $OUTPUT/subdomains/live_subs.txt -o $OUTPUT/scans/nuclei.txt

echo "[+] Taking screenshots..."
gowitness file -f $OUTPUT/subdomains/live_subs.txt -P $OUTPUT/screenshots/ --timeout 10

# -----------------------------------
# Parameter Discovery (for XSS/SQLi)
# -----------------------------------
echo "[+] Gathering URLs for parameter discovery..."
cat $OUTPUT/subdomains/live_subs.txt | gau | tee $OUTPUT/params/gau.txt
cat $OUTPUT/subdomains/live_subs.txt | waybackurls | tee $OUTPUT/params/wayback.txt

cat $OUTPUT/params/*.txt | sort -u > $OUTPUT/params/all_urls.txt

echo "[+] Extracting potential parameters..."
cat $OUTPUT/params/all_urls.txt | gf xss > $OUTPUT/params/xss.txt
cat $OUTPUT/params/all_urls.txt | gf sqli > $OUTPUT/params/sqli.txt
cat $OUTPUT/params/all_urls.txt | gf lfi > $OUTPUT/params/lfi.txt
cat $OUTPUT/params/all_urls.txt | gf ssrf > $OUTPUT/params/ssrf.txt

# -----------------------------------
# Directory/File Bruteforce
# -----------------------------------
echo "[+] Running directory brute force (feroxbuster)..."
while read url; do
    echo "Scanning $url ..."
    feroxbuster -u $url -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 50 -o "$OUTPUT/dirs/$(echo $url | sed 's/https\?:\/\///').txt"
done < $OUTPUT/subdomains/live_subs.txt

echo "[+] Recon completed for $DOMAIN!"
echo "Results saved in: $OUTPUT/"
