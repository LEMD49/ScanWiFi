#!/usr/bin/env python3
"""
date: 20261115
created by: maricq@ieee.org, using promtps to claude
prompt:
write a program to run on macos 27 on macbookair m1 to. scan all wifi networks 
and for each report in table format - NAME, MAC, IP, MDNS, OBSERVATIONS
and also include mDNS data

wifiscan.py - Wi-Fi + LAN scanner for macOS.  Output columns:
    NAME | MAC | IP | MDNS | OBSERVATIONS

Table 1: nearby access points (SSID, BSSID, channel, security, signal, vendor).
         IP/MDNS are only knowable for the network you are connected to
         (its gateway); other rows show "-".
Table 2: devices on the network you ARE connected to, found via ping sweep,
         ARP, mDNS/Bonjour (with TXT model info), SSDP/UPnP, optional port
         scan, and an IEEE vendor (OUI) lookup.

Setup (once):
    python3 -m pip install pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation zeroconf
Run:
    python3 wifiscan.py                      # defaults
    python3 wifiscan.py --duration 30 --passes 2 --ports
    python3 wifiscan.py --interface en0 --no-hosts

Permissions: grant your terminal Location Services (else SSID/BSSID are
redacted) and Local Network (else multicast/mDNS is silently blocked), both
under System Settings > Privacy & Security.

Only scan networks you own or are authorised to inspect.
"""
import argparse
import csv
import ipaddress
import re
import shutil
import socket
import subprocess
import sys
import textwrap
import time
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout
from pathlib import Path
from urllib.parse import urlparse

try:
    import CoreLocation
    import CoreWLAN
    from Foundation import NSDate, NSRunLoop
    from zeroconf import IPVersion, ServiceBrowser, Zeroconf, ZeroconfServiceTypes
except ImportError:
    sys.exit("Missing dependencies. Run:\n  python3 -m pip install "
             "pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation zeroconf")

SECURITY = [
    (0, "Open"), (1, "WEP"), (2, "WPA"), (3, "WPA/WPA2"), (4, "WPA2"),
    (6, "DynWEP"), (7, "WPA-Ent"), (8, "WPA/2-Ent"), (9, "WPA2-Ent"),
    (10, "Enterprise"), (11, "WPA3"), (12, "WPA3-Ent"), (13, "WPA3/2"),
    (14, "OWE"), (15, "OWE-Trans"),
]
BAND = {1: "2.4GHz", 2: "5GHz", 3: "6GHz"}
WIDTH = {1: "20", 2: "40", 3: "80", 4: "160"}
COMMON_PORTS = [22, 23, 53, 80, 139, 443, 445, 554, 631, 1883, 3389, 5000,
                5900, 7000, 8008, 8009, 8080, 8443, 9100, 62078]
MODEL_KEYS = ("model", "am", "md", "ty", "rpMd", "product")
NAME_PRIORITY = ("_companion-link", "_device-info", "_airplay", "_googlecast",
                 "_raop", "_printer", "_ipp", "_hap", "_spotify-connect")
OUI = {}


# ------------------------------------------------------------------ helpers
def sh(cmd, timeout=5):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:
        return ""


def norm_mac(mac):
    if not mac:
        return None
    return ":".join(p.zfill(2) for p in mac.lower().split(":"))


def is_random_mac(mac):
    """Locally-administered bit set => usually a privacy/randomised MAC."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


def load_oui():
    """IEEE OUI database, cached in ~/.cache/wifiscan/oui.csv."""
    path = Path.home() / ".cache" / "wifiscan" / "oui.csv"
    if not path.exists():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            req = urllib.request.Request(
                "https://standards-oui.ieee.org/oui/oui.csv",
                headers={"User-Agent": "Mozilla/5.0 wifiscan"})
            path.write_bytes(urllib.request.urlopen(req, timeout=20).read())
        except Exception as e:
            print(f"! Could not download vendor database ({e}); "
                  "vendor lookup disabled.", file=sys.stderr)
            return {}
    db = {}
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        rd = csv.reader(f)
        next(rd, None)
        for row in rd:
            if len(row) >= 3:
                db[row[1].upper()] = row[2]
    return db


def vendor(mac):
    if not mac or not OUI or is_random_mac(mac):
        return None
    return OUI.get(mac.replace(":", "")[:6].upper())


def ensure_location(timeout=20):
    mgr = CoreLocation.CLLocationManager.alloc().init()
    if mgr.authorizationStatus() == 0:  # not determined -> ask
        mgr.requestWhenInUseAuthorization()
        mgr.startUpdatingLocation()
        end = time.time() + timeout
        while mgr.authorizationStatus() == 0 and time.time() < end:
            NSRunLoop.currentRunLoop().runUntilDate_(
                NSDate.dateWithTimeIntervalSinceNow_(0.25))
    return mgr, mgr.authorizationStatus() in (3, 4)


def rdns(ip, timeout=2.0):
    with ThreadPoolExecutor(1) as ex:
        fut = ex.submit(socket.gethostbyaddr, ip)
        try:
            return fut.result(timeout=timeout)[0]
        except (FTimeout, Exception):
            return None


def default_gateway():
    m = re.search(r"gateway:\s*(\S+)", sh(["route", "-n", "get", "default"]))
    return m.group(1) if m else None


# --------------------------------------------------------------- nearby APs
def scan_networks(iface, connected_bssid, gateway):
    nets, err = iface.scanForNetworksWithName_error_(None, None)
    if nets is None:
        sys.exit(f"Scan failed: {err}")
    rows, by_ssid = [], defaultdict(list)
    for n in nets:
        ssid = n.ssid()
        bssid = norm_mac(n.bssid())
        ch = n.wlanChannel()
        sec = [name for v, name in SECURITY if n.supportsSecurity_(v)] or ["?"]
        by_ssid[ssid or ""].append((bssid, sec))
        rows.append(dict(ssid=ssid, bssid=bssid, rssi=n.rssiValue(),
                         noise=n.noiseMeasurement(),
                         chan=ch.channelNumber() if ch else None,
                         band=ch.channelBand() if ch else None,
                         width=ch.channelWidth() if ch else None,
                         sec=sec, ibss=n.ibss()))
    rows.sort(key=lambda r: -r["rssi"])

    table = []
    for r in rows:
        obs = [f"ch{r['chan']}", BAND.get(r["band"], "?"),
               WIDTH.get(r["width"], "?") + "MHz",
               "+".join(r["sec"]), f"{r['rssi']}dBm"]
        if r["noise"]:
            obs.append(f"SNR {r['rssi'] - r['noise']}dB")
        v = vendor(r["bssid"])
        if v:
            obs.append(f"vendor: {v}")
        if "Open" in r["sec"]:
            obs.append("OPEN (no encryption)")
        if any(s in r["sec"] for s in ("WEP", "DynWEP", "WPA")):
            obs.append("LEGACY security")
        if r["rssi"] <= -80:
            obs.append("weak signal")
        elif r["rssi"] >= -50:
            obs.append("very strong")
        if r["band"] == 1 and r["chan"] not in (1, 6, 11):
            obs.append("2.4GHz non-standard channel (overlap)")
        if not r["ssid"]:
            obs.append("hidden/redacted SSID")
        if r["ibss"]:
            obs.append("ad-hoc")
        group = by_ssid[r["ssid"] or ""]
        if r["ssid"] and len(group) > 1:
            secs = {tuple(s) for _, s in group}
            obs.append(f"{len(group)} APs share SSID" +
                       (" - DIFFERENT SECURITY (check evil twin)" if len(secs) > 1
                        else " (mesh/ESS)"))
        ip = mdns = "-"
        if connected_bssid and r["bssid"] == connected_bssid:
            obs.insert(0, "** CONNECTED **")
            if gateway:
                ip = gateway
                mdns = rdns(gateway) or "-"
        table.append([r["ssid"] or "<hidden>", r["bssid"] or "<redacted>",
                      ip, mdns, "; ".join(obs)])
    return table


# ---------------------------------------------------------------- discovery
def mdns_map(my_ip, duration, passes):
    """mDNS/Bonjour: {ipv4: {host, friendly, model, svcs}} (merged over passes)."""
    zc = Zeroconf(interfaces=[my_ip]) if my_ip else Zeroconf()
    found = {}

    class Listener:
        def __init__(self, bag):
            self.bag = bag
        def add_service(self, _zc, t, name):
            self.bag.add((t, name))
        def update_service(self, *a): pass
        def remove_service(self, *a): pass

    try:
        types = set(ZeroconfServiceTypes.find(zc=zc, timeout=3) or ())
        for _ in range(max(1, passes)):
            bag = set()
            browsers = [ServiceBrowser(zc, t, Listener(bag)) for t in types]
            time.sleep(duration)

            def resolve(item):
                t, name = item
                return t, name, zc.get_service_info(t, name, timeout=2000)

            with ThreadPoolExecutor(16) as ex:
                results = list(ex.map(resolve, list(bag)))
            for b in browsers:
                b.cancel()
            for t, name, info in results:
                if not info or not info.server:
                    continue
                props = {}
                for k, v in (info.properties or {}).items():
                    props[k.decode(errors="ignore")] = (v or b"").decode(errors="ignore")
                stype = t.split(".")[0]
                inst = name[: -len("." + t)] if name.endswith("." + t) else name
                for ip in info.parsed_addresses(IPVersion.V4Only):
                    e = found.setdefault(ip, {"host": info.server.rstrip("."),
                                              "friendly": None, "prio": 99,
                                              "model": None, "svcs": set()})
                    e["svcs"].add(stype.lstrip("_"))
                    if not e["model"]:
                        e["model"] = next((props[k] for k in MODEL_KEYS
                                           if props.get(k)), None)
                    fn = props.get("fn")  # Chromecast friendly name
                    cand = fn or (inst if "@" not in inst else inst.split("@", 1)[1])
                    prio = 0 if fn else (NAME_PRIORITY.index(stype) + 1
                                         if stype in NAME_PRIORITY else 50)
                    if cand and prio < e["prio"]:
                        e["friendly"], e["prio"] = cand, prio
    finally:
        zc.close()
    return found


def ssdp_map(my_ip, wait=4):
    """SSDP/UPnP: {ip: {server, friendly, model, maker}}."""
    msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.bind((my_ip, 0))
        s.settimeout(0.5)
        for _ in range(2):
            s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, addr = s.recvfrom(8192)
            except socket.timeout:
                continue
            hdr = {}
            for line in data.decode(errors="ignore").split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdr[k.strip().lower()] = v.strip()
            d = found.setdefault(addr[0], {"server": None, "location": None})
            d["server"] = d["server"] or hdr.get("server")
            d["location"] = d["location"] or hdr.get("location")
    except OSError as e:
        print(f"! SSDP skipped ({e})", file=sys.stderr)
    finally:
        s.close()

    def describe(item):
        ip, d = item
        loc = d.get("location")
        if loc and urlparse(loc).hostname == ip:  # only talk to the responder
            try:
                root = ET.fromstring(urllib.request.urlopen(loc, timeout=2).read(65536))
                def tag(name):
                    for el in root.iter():
                        if el.tag.endswith("}" + name) or el.tag == name:
                            return (el.text or "").strip() or None
                d.update(friendly=tag("friendlyName"), model=tag("modelName"),
                         maker=tag("manufacturer"))
            except Exception:
                pass
        return ip, d

    with ThreadPoolExecutor(8) as ex:
        return dict(ex.map(describe, list(found.items())))


def scan_ports(ips):
    jobs = [(ip, p) for ip in ips for p in COMMON_PORTS]

    def probe(job):
        ip, p = job
        s = socket.socket()
        s.settimeout(0.5)
        try:
            return job if s.connect_ex((ip, p)) == 0 else None
        finally:
            s.close()

    out = defaultdict(list)
    with ThreadPoolExecutor(128) as ex:
        for r in ex.map(probe, jobs):
            if r:
                out[r[0]].append(r[1])
    return out


def read_arp(ifname, net):
    found = {}
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at (\S+) on (\S+)",
                         sh(["arp", "-an"])):
        ip, mac, dev = m.groups()
        if dev != ifname or "incomplete" in mac or mac.lower().startswith("ff:ff"):
            continue
        if ipaddress.ip_address(ip) in net:
            found[ip] = norm_mac(mac)
    return found


def lan_hosts(iface, gateway, args):
    ifname = iface.interfaceName()
    my_ip = sh(["ipconfig", "getifaddr", ifname])
    mask = sh(["ipconfig", "getoption", ifname, "subnet_mask"]) or "255.255.255.0"
    if not my_ip:
        return []
    net = ipaddress.ip_interface(f"{my_ip}/{mask}").network
    if net.prefixlen < 24:
        net = ipaddress.ip_network(f"{my_ip}/24", strict=False)

    print("Ping sweep...")
    with ThreadPoolExecutor(64) as ex:
        list(ex.map(lambda ip: subprocess.run(
            ["ping", "-c", "1", "-W", "800", str(ip)], capture_output=True),
            net.hosts()))

    print(f"Listening for mDNS/Bonjour ({args.passes} x {args.duration}s)...")
    mdns = mdns_map(my_ip, args.duration, args.passes)
    ssdp = {}
    if not args.no_ssdp:
        print("SSDP/UPnP discovery...")
        ssdp = ssdp_map(my_ip)

    found = read_arp(ifname, net)  # re-read: discovery may have refreshed ARP
    for ip in list(mdns) + list(ssdp):  # seen on the wire but not in ARP
        if ip not in found and ipaddress.ip_address(ip) in net:
            found[ip] = read_arp(ifname, net).get(ip)
    found[my_ip] = norm_mac(iface.hardwareAddress())
    me_local = sh(["scutil", "--get", "LocalHostName"])
    if me_local:
        mdns.setdefault(my_ip, {"host": me_local + ".local", "friendly": None,
                                "model": None, "svcs": set()})

    ips = sorted(found, key=ipaddress.ip_address)
    with ThreadPoolExecutor(32) as ex:
        rnames = dict(zip(ips, ex.map(rdns, ips)))
    ports = {}
    if args.ports:
        print(f"Scanning {len(COMMON_PORTS)} common TCP ports per host...")
        ports = scan_ports(ips)

    table = []
    for ip in ips:
        mac = found[ip]
        m, u = mdns.get(ip), ssdp.get(ip, {})
        host = m["host"] if m else None
        name = ((m or {}).get("friendly") or u.get("friendly") or host
                or rnames[ip] or "-")
        obs = []
        if ip == my_ip:
            obs.append("this Mac")
        if ip == gateway:
            obs.append("default gateway")
        v = vendor(mac) or u.get("maker")
        if v:
            obs.append(f"vendor: {v}")
        if mac and is_random_mac(mac):
            obs.append("randomised/private MAC")
        model = (m or {}).get("model") or u.get("model")
        if model:
            obs.append(f"model: {model}")
        if m and m["svcs"]:
            obs.append("mDNS: " + ",".join(sorted(m["svcs"])))
        elif not host:
            obs.append("silent on mDNS")
        if u.get("server"):
            obs.append(f"UPnP: {u['server']}")
        if ports.get(ip):
            obs.append("ports: " + ",".join(map(str, sorted(ports[ip]))))
        table.append([name, mac or "-", ip, host or "-", "; ".join(obs)])
    return table


# ------------------------------------------------------------------- output
def print_table(title, rows):
    """Boxed table: every cell has its own border; long cells wrap."""
    head = ["NAME", "MAC", "IP", "MDNS", "OBSERVATIONS"]
    rows = [[str(c) for c in r] for r in rows]
    term = shutil.get_terminal_size((160, 24)).columns
    w = [min(32, max(len(r[i]) for r in rows + [head])) for i in range(4)]
    longest_obs = max(len(r[4]) for r in rows + [head])
    w.append(max(20, min(longest_obs, term - sum(w) - 16)))

    def rule(l, m, r):
        return l + m.join("─" * (x + 2) for x in w) + r

    def line(cells):
        wrapped = [textwrap.wrap(c, w[i], break_long_words=True) or [""]
                   for i, c in enumerate(cells)]
        out = []
        for k in range(max(len(x) for x in wrapped)):
            parts = [(x[k] if k < len(x) else "").ljust(w[i])
                     for i, x in enumerate(wrapped)]
            out.append("│ " + " │ ".join(parts) + " │")
        return out

    print(f"\n{title}  ({len(rows)})")
    print(rule("┌", "┬", "┐"))
    print("\n".join(line(head)))
    print(rule("├", "┼", "┤"))
    for i, r in enumerate(rows):
        print("\n".join(line(r)))
        if i < len(rows) - 1:
            print(rule("├", "┼", "┤"))
    print(rule("└", "┴", "┘"))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--no-hosts", action="store_true",
                    help="skip scanning devices on the connected network")
    ap.add_argument("--duration", type=int, default=15,
                    help="seconds to listen for mDNS per pass (default 15)")
    ap.add_argument("--passes", type=int, default=1,
                    help="repeat the mDNS listen N times and merge (default 1)")
    ap.add_argument("--interface", help="Wi-Fi interface name (default: system Wi-Fi)")
    ap.add_argument("--ports", action="store_true",
                    help="TCP-probe common ports on each LAN host (opt-in)")
    ap.add_argument("--no-ssdp", action="store_true", help="skip SSDP/UPnP discovery")
    ap.add_argument("--no-vendor", action="store_true",
                    help="skip IEEE vendor (OUI) lookup / download")
    args = ap.parse_args()

    _mgr, ok = ensure_location()  # keep referenced while scanning
    if not ok:
        print("! Location Services not granted: SSIDs/BSSIDs will be redacted.\n"
              "  Enable it for your terminal in System Settings > Privacy & Security.",
              file=sys.stderr)

    if not args.no_vendor:
        OUI.update(load_oui())

    client = CoreWLAN.CWWiFiClient.sharedWiFiClient()
    iface = (client.interfaceWithName_(args.interface) if args.interface
             else client.interface())
    if iface is None:
        sys.exit("No Wi-Fi interface found.")
    if not iface.powerOn():
        sys.exit("Wi-Fi is turned off.")

    gw = default_gateway()
    cur_bssid = norm_mac(iface.bssid())
    print(f"Interface {iface.interfaceName()}  connected to: "
          f"{iface.ssid() or '(none / redacted)'}")

    print_table("NEARBY WI-FI NETWORKS", scan_networks(iface, cur_bssid, gw))

    if not args.no_hosts:
        rows = lan_hosts(iface, gw, args)
        if rows:
            print_table("DEVICES ON CONNECTED NETWORK", rows)
        else:
            print("\nNot connected to a network; skipping device scan.")


if __name__ == "__main__":
    main()
