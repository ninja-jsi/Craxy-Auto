# Craxy-Auto
Automated recon script to perform subdomain enumeration, live host discovery, port scanning, vulnerability scanning, parameter discovery, directory brute-forcing, and screenshots.

# Prerequisites

Run the Recon Tools Setup repo first to install dependencies and tools.
Ensure Go binaries are in PATH.

# Usage

**Clone this repository:**
```
git clone https://github.com/ninja-jsi/Craxy-Auto.git
cd Craxy-Auto
```

**Run the recon script:**
```
chmod +x reckon.sh
./reckon.sh target.com
```

```
**Output Structure**
target.com-reckon/
 ├── subdomains/        # discovered subdomains
 ├── ports/             # port scan results
 ├── scans/             # nmap & nuclei results
 ├── screenshots/       # screenshots of live hosts
 ├── params/            # potential XSS/SQLi/SSRF/LFI URLs
 └── dirs/              # directories discovered via feroxbuster
```

# Notes / Best Practices

- Always test in-scope targets.
- Use screen or tmux to avoid losing progress.
- Organize outputs per target.

# Disclaimer

Only scan authorized targets. Unauthorized scanning is illegal.
