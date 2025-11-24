#!/bin/bash
# find-dc.sh - HTB-ready Domain Controller hunter (no ipcalc needed)
# Works on any HTB attack box

echo "[*] Enumerating non-loopback IPv4 addresses..."
mapfile -t ips < <(
  ip -4 addr show 2>/dev/null | 
  grep -v "lo:" | 
  grep -oE "inet ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/[0-9]+" | 
  awk '{print $2}' | 
  cut -d'/' -f1 | 
  grep -vE "^(127\.|169\.254\.)"
)

if [ ${#ips[@]} -eq 0 ]; then
  echo "[-] No valid IPs found. Check network connectivity." >&2
  exit 1
fi

# Convert IPs to /24 subnets (e.g., 10.10.15.254 → 10.10.15.0/24)
declare -A subnets
for ip in "${ips[@]}"; do
  subnet="${ip%.*}.0/24"
  subnets["$subnet"]=1
done

echo "[*] Scanning subnets: ${!subnets[@]}"

# Scan each subnet in background
for net in "${!subnets[@]}"; do
  (
    echo "[+] Probing $net..."
    # Ping sweep to find live hosts
    nmap -T4 -sn "$net" -n --max-retries 1 --host-timeout 3s 2>/dev/null | 
    grep "Nmap scan report" | 
    awk '{print $NF}' | 
    xargs -P 30 -I {} sh -c '
      h="{}"
      # Quick port 389 check
      if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$h/389" 2>/dev/null; then
        # Confirm with LDAP rootDSE
        if nmap -p 389 --script ldap-rootdse --open -Pn "$h" 2>/dev/null | grep -q namingContexts; then
          echo "✅ DC FOUND: $h"
          kill -TERM -$$ 2>/dev/null
        fi
      fi
    '
  ) &
done

# Wait max 60 sec
sleep 60
echo "[-] No Domain Controller found."
exit 1
