# ScanWiFi

## Purpose
Routine to scan seen WiFi networks and report on connected network advertised data of connected clients

## Filename
scanwifi.py
<kbd> **aided by Claude** </kbd>

## Date
20261115

## Use notes

- executed on macOS 27.2.1

## Output contents

wifiscan.py - Wi-Fi + LAN scanner for macOS.  Output columns:
    NAME | MAC | IP | MDNS | OBSERVATIONS<br>

Table 1: nearby access points (SSID, BSSID, channel, security, signal, vendor).
         IP/MDNS are only knowable for the network you are connected to
         (its gateway); other rows show "-".<br><br>
Table 2: devices on the network you ARE connected to, found via ping sweep,
         ARP, mDNS/Bonjour (with TXT model info), SSDP/UPnP, optional port
         scan, and an IEEE vendor (OUI) lookup.



<img width="683" height="407" alt="Table1" src="https://github.com/user-attachments/assets/d8e56cd7-2462-4e52-923d-f8c5eceb7817" />

<img width="1085" height="187" alt="Table2" src="https://github.com/user-attachments/assets/ae9d85c8-c828-4a05-ab80-0e5bbe24c4ec" />




