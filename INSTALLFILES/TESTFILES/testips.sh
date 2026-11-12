#!/bin/bash

echo "======================================"
echo " OPNsense / Suricata IPS Test Menu"
echo "======================================"
echo
echo "1) curl http://testmyids.com"
echo "2) nikto http://testphp.vulnweb.com"
echo "3) gobuster dir (testphp.vulnweb.com)"
echo "4) sqlmap (testphp.vulnweb.com)"
echo
read -p "Select an option (1, 2, 3, or 4): " choice

case "$choice" in
  1)
    echo
    echo "[*] Running curl test against testmyids.com"
    curl -v http://testmyids.com
    ;;
  2)
    echo
    echo "[*] Running Nikto scan against testphp.vulnweb.com"
    nikto -h http://testphp.vulnweb.com -C all
    ;;
  3)
    WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"

    if [ ! -f "$WORDLIST" ]; then
      echo
      echo "[!] Wordlist not found:"
      echo "    $WORDLIST"
      echo
      echo "    Install it with:"
      echo "    sudo apt install seclists"
      exit 1
    fi

    echo
    echo "[*] Running Gobuster directory brute force"
    echo "[*] Target: http://testphp.vulnweb.com"
    echo "[*] Wordlist: $WORDLIST"
    echo

    gobuster dir \
      -u http://testphp.vulnweb.com \
      -w "$WORDLIST" \
      -t 50
    ;;
  4)
    echo
    echo "[*] Running SQLMap test against testphp.vulnweb.com"
    echo "[*] Target: listproducts.php?cat=1"
    echo

    sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --batch
    ;;
  *)
    echo
    echo "[!] Invalid"
    ;;
esac
