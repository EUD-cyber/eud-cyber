#!/bin/bash

echo "==============================="
echo " OPNsense / Suricata IPS Test "
echo "==============================="
echo
echo "1) curl http://testmyids.com"
echo "2) nikto http://testphp.vulnweb.com"
echo
read -p "Select an option (1 or 2): " choice

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
  *)
    echo
    echo "[!] Invalid option"
    exit 1
    ;;
esac
