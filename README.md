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
         (its gateway); other rows show "-".<br>
Table 2: devices on the network you ARE connected to, found via ping sweep,
         ARP, mDNS/Bonjour (with TXT model info), SSDP/UPnP, optional port
         scan, and an IEEE vendor (OUI) lookup.

