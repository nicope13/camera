#!/usr/bin/env python3
"""
scan_cameras.py - list the Wi-Fi / IP cameras on your local network.

Designed to run on an Android phone (e.g. Pixel 8a) inside Termux, but works
on any Linux / macOS / Windows machine with Python 3.8+. Standard library only.

How cameras are detected (no root needed, works on Android 10+ where the
ARP table and MAC addresses are hidden from apps):

  1. ONVIF WS-Discovery   multicast probe on UDP 3702 (most IP cameras / NVRs)
  2. SSDP / UPnP          multicast M-SEARCH on UDP 1900 + device description
  3. TCP port sweep       of the whole subnet on camera-typical ports
                          (RTSP 554/8554, Hikvision 8000, Dahua 37777,
                          XMeye 34567, Tapo/ONVIF 2020, ...)
  4. Fingerprinting       RTSP OPTIONS + HTTP banner/title/realm keywords

Usage:
  python scan_cameras.py                 # auto-detect subnet (/24)
  python scan_cameras.py --subnet 192.168.1.0/24
  python scan_cameras.py --all           # also list non-camera devices
  python scan_cameras.py --json          # machine-readable output
"""

import argparse
import concurrent.futures as cf
import ipaddress
import json
import re
import socket
import sys
import time
import urllib.request
import uuid
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------

# Ports that are (almost) only used by cameras / NVRs / DVRs.
CAMERA_PORTS = {
    554: "RTSP",
    8554: "RTSP-alt",
    2020: "ONVIF (TP-Link Tapo/Vigi)",
    8000: "Hikvision SDK",
    37777: "Dahua SDK",
    34567: "XMeye/Sofia DVR",
    1935: "RTMP",
    6668: "Tuya",
    8899: "ONVIF-alt",
    10080: "Camera web (alt)",
}
# Generic web ports: only used to grab a banner for fingerprinting.
WEB_PORTS = [80, 8080, 443, 88, 81, 8081, 8443]

ALL_PORTS = sorted(set(CAMERA_PORTS) | set(WEB_PORTS))

# Keyword -> vendor hint, matched case-insensitively against banners/titles.
VENDOR_KEYWORDS = [
    ("hikvision", "Hikvision"), ("dnvrs-webs", "Hikvision"), ("app-webs", "Hikvision"),
    ("hikvision-webs", "Hikvision"), ("ezviz", "EZVIZ"),
    ("dahua", "Dahua"), ("dh_", "Dahua"), ("amcrest", "Amcrest"), ("imou", "Imou"),
    ("lorex", "Lorex"), ("reolink", "Reolink"), ("axis", "Axis"),
    ("foscam", "Foscam"), ("tapo", "TP-Link Tapo"), ("vigi", "TP-Link Vigi"),
    ("tp-link ipc", "TP-Link"), ("uniview", "Uniview"), ("unv", "Uniview"),
    ("hanwha", "Hanwha"), ("wisenet", "Hanwha"), ("samsung techwin", "Hanwha"),
    ("vivotek", "Vivotek"), ("mobotix", "Mobotix"), ("ubiquiti", "Ubiquiti"),
    ("unifi protect", "Ubiquiti"), ("uvc", "Ubiquiti"), ("annke", "Annke"),
    ("swann", "Swann"), ("xmeye", "XMeye"), ("sofia", "XMeye"),
    ("netsurveillance", "XMeye"), ("wyze", "Wyze"), ("arlo", "Arlo"),
    ("eufy", "Eufy"), ("yi ", "YI"), ("xiaomi", "Xiaomi"), ("mijia", "Xiaomi"),
    ("d-link", "D-Link"), ("dcs-", "D-Link"), ("trendnet", "TRENDnet"),
    ("grandstream", "Grandstream"), ("milesight", "Milesight"),
    ("bosch", "Bosch"), ("panasonic", "Panasonic"), ("sony", "Sony"),
    ("hipcam", "HiSilicon"), ("goahead", "Generic IPCam"), ("boa/", "Generic IPCam"),
    ("thttpd", "Generic IPCam"), ("ipcam", "Generic IPCam"),
    ("webcam", "Generic IPCam"), ("ip camera", "Generic IPCam"),
    ("network camera", "Generic IPCam"), ("netcam", "Generic IPCam"),
    ("nvr", "NVR"), ("dvr", "DVR"), ("onvif", "ONVIF"),
]
CAMERA_WORDS = ("camera", "cam", "ipc", "nvr", "dvr", "video", "onvif",
                "surveillance", "doorbell", "mediaserver", "rtsp")


def vendor_from_text(text):
    t = (text or "").lower()
    for kw, vendor in VENDOR_KEYWORDS:
        if kw in t:
            return vendor
    return None


# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------

def local_ip():
    """Return the IP of the interface used for the default route (no packet sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def tcp_open(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def recv_all(sock, limit=8192):
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except OSError:
        pass
    return data


def rtsp_options(ip, port, timeout):
    """Send RTSP OPTIONS. Returns dict with status/server or None."""
    req = (f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
           f"CSeq: 1\r\nUser-Agent: scan_cameras\r\n\r\n").encode()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req)
            resp = recv_all(s).decode("latin-1", "replace")
    except OSError:
        return None
    if not resp.startswith("RTSP/"):
        return None
    server = re.search(r"^Server:\s*(.+)$", resp, re.M | re.I)
    return {"status": resp.split("\r\n", 1)[0],
            "server": server.group(1).strip() if server else ""}


def http_banner(ip, port, timeout):
    """GET / and return {'server','title','realm','status'} or None."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    ctx = None
    if scheme == "https":
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # cameras use self-signed certs

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(
        NoRedirect, urllib.request.HTTPSHandler(context=ctx),
        urllib.request.ProxyHandler({}))  # never go through a proxy on the LAN
    headers, body, status = {}, "", None
    try:
        r = opener.open(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}),
                        timeout=timeout)
        status, headers = r.status, dict(r.headers)
        body = r.read(16384).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:  # 401/302 etc. still carry useful headers
        status, headers = e.code, dict(e.headers or {})
        try:
            body = e.read(16384).decode("utf-8", "replace")
        except Exception:
            pass
    except Exception:
        return None
    h = {k.lower(): v for k, v in headers.items()}
    title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    realm = re.search(r'realm="?([^",]+)', h.get("www-authenticate", ""), re.I)
    return {
        "status": status,
        "server": h.get("server", ""),
        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:80] if title else "",
        "realm": realm.group(1) if realm else "",
        "location": h.get("location", ""),
    }


def reverse_dns(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return "" if name == ip else name
    except OSError:
        return ""


# --------------------------------------------------------------------------
# Multicast discovery
# --------------------------------------------------------------------------

def ws_discovery(timeout=3.0):
    """ONVIF WS-Discovery probe. Returns {ip: info}."""
    msg_id = f"uuid:{uuid.uuid4()}"
    probe = f"""<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
 <e:Header>
  <w:MessageID>{msg_id}</w:MessageID>
  <w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
  <w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
 </e:Header>
 <e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>
</e:Envelope>""".encode()
    # A second probe without type filter catches cameras that only answer generic probes.
    probe_any = re.sub(rb"<d:Types>.*?</d:Types>", b"", probe).replace(
        msg_id.encode(), f"uuid:{uuid.uuid4()}".encode())

    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.5)
        for p in (probe, probe_any):
            s.sendto(p, ("239.255.255.250", 3702))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("utf-8", "replace")
            if "ProbeMatch" not in text:
                continue
            xaddrs = re.search(r"<[^>]*XAddrs>(.*?)</", text, re.S)
            scopes = re.search(r"<[^>]*Scopes[^>]*>(.*?)</", text, re.S)
            types = re.search(r"<[^>]*Types>(.*?)</", text, re.S)
            info = {"xaddrs": xaddrs.group(1).split() if xaddrs else [],
                    "types": types.group(1).strip() if types else ""}
            if scopes:
                for sc in scopes.group(1).split():
                    m = re.match(r"onvif://www\.onvif\.org/(name|hardware|location/.*?|mac)/(.+)", sc)
                    if m:
                        key = m.group(1).split("/")[0]
                        info[key] = urllib.request.unquote(m.group(2))
            # Ignore printers / PCs answering generic WS-Discovery
            t = (info["types"] + " " + " ".join(info.get(k, "") for k in ("name", "hardware"))).lower()
            if "networkvideo" in t or "onvif" in text.lower():
                found[ip] = info
    except OSError as e:
        print(f"  [!] WS-Discovery unavailable: {e}", file=sys.stderr)
    finally:
        s.close()
    return found


def ssdp_discovery(timeout=3.0):
    """SSDP M-SEARCH. Returns {ip: {'server','location','st'}}."""
    req = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(0.5)
        for _ in range(2):
            s.sendto(req, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, (ip, _) = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("latin-1", "replace")
            hdr = {}
            for line in text.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdr[k.strip().lower()] = v.strip()
            entry = found.setdefault(ip, {"server": "", "location": "", "st": set()})
            entry["server"] = entry["server"] or hdr.get("server", "")
            entry["location"] = entry["location"] or hdr.get("location", "")
            if hdr.get("st"):
                entry["st"].add(hdr["st"])
    except OSError as e:
        print(f"  [!] SSDP unavailable: {e}", file=sys.stderr)
    finally:
        s.close()
    return found


def upnp_description(location, timeout):
    """Fetch UPnP device description: friendlyName / manufacturer / model."""
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        xml = opener.open(location, timeout=timeout).read(65536).decode("utf-8", "replace")
    except Exception:
        return {}
    out = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType"):
        m = re.search(rf"<{tag}>(.*?)</{tag}>", xml, re.S)
        if m:
            out[tag] = m.group(1).strip()
    return out


# --------------------------------------------------------------------------
# Main scan
# --------------------------------------------------------------------------

def probe_host(ip, timeout):
    """Port-sweep one host. Returns list of open ports (may be empty)."""
    return [p for p in ALL_PORTS if tcp_open(ip, p, timeout)]


def fingerprint(ip, ports, timeout):
    """Collect RTSP / HTTP banners for a host with open ports."""
    fp = {"rtsp": None, "http": []}
    for p in (554, 8554):
        if p in ports:
            r = rtsp_options(ip, p, timeout * 3)
            if r:
                fp["rtsp"] = dict(r, port=p)
                break
    for p in WEB_PORTS:
        if p in ports:
            b = http_banner(ip, p, timeout * 4)
            if b:
                fp["http"].append(dict(b, port=p))
    return fp


def classify(dev):
    """Decide camera / possible / other and compute a vendor guess."""
    reasons = []
    texts = []
    if dev.get("onvif"):
        reasons.append("ONVIF")
        texts += [dev["onvif"].get("name", ""), dev["onvif"].get("hardware", "")]
    if dev.get("rtsp"):
        reasons.append(f"RTSP:{dev['rtsp']['port']}")
        texts.append(dev["rtsp"].get("server", ""))
    strong = [p for p in dev["ports"] if p in CAMERA_PORTS and p not in (554, 8554, 1935, 6668)]
    reasons += [f"{CAMERA_PORTS[p]}:{p}" for p in strong]
    for h in dev.get("http", []):
        texts += [h.get("server", ""), h.get("title", ""), h.get("realm", "")]
    upnp = dev.get("upnp") or {}
    texts += [upnp.get("friendlyName", ""), upnp.get("manufacturer", ""),
              upnp.get("modelName", ""), upnp.get("deviceType", ""),
              (dev.get("ssdp") or {}).get("server", ""), dev.get("hostname", "")]

    blob = " | ".join(t for t in texts if t)
    vendor = (upnp.get("manufacturer") if upnp.get("manufacturer")
              and vendor_from_text(upnp.get("manufacturer")) else None) or vendor_from_text(blob)
    keyword_hit = vendor is not None or any(w in blob.lower() for w in CAMERA_WORDS)
    if keyword_hit:
        reasons.append("banner")

    if dev.get("onvif") or dev.get("rtsp") or strong:
        kind = "camera"
    elif keyword_hit or 554 in dev["ports"] or 8554 in dev["ports"]:
        kind = "possible"
    else:
        kind = "other"

    model = ""
    if dev.get("onvif"):
        model = " ".join(x for x in (dev["onvif"].get("name", ""),
                                     dev["onvif"].get("hardware", "")) if x)
    if not model and upnp:
        model = " ".join(x for x in (upnp.get("manufacturer", ""), upnp.get("modelName", ""))
                         if x) or upnp.get("friendlyName", "")
    if not model:
        for h in dev.get("http", []):
            model = h.get("title") or h.get("realm") or h.get("server") or ""
            if model:
                break
    if not model and dev.get("rtsp"):
        model = dev["rtsp"].get("server", "")
    return kind, vendor or "", model.strip(), reasons


def main():
    ap = argparse.ArgumentParser(description="List Wi-Fi / IP cameras on the local network.")
    ap.add_argument("--subnet", help="CIDR to scan, e.g. 192.168.1.0/24 (default: auto /24)")
    ap.add_argument("--timeout", type=float, default=0.6, help="TCP connect timeout (s)")
    ap.add_argument("--workers", type=int, default=128, help="parallel connections")
    ap.add_argument("--all", action="store_true", help="also list non-camera devices")
    ap.add_argument("--json", action="store_true", help="output JSON")
    ap.add_argument("--no-sweep", action="store_true", help="multicast discovery only (fast)")
    args = ap.parse_args()

    me = local_ip()
    if args.subnet:
        net = ipaddress.ip_network(args.subnet, strict=False)
    else:
        if me.startswith("127."):
            sys.exit("Could not detect your Wi-Fi IP. Are you connected? Use --subnet.")
        net = ipaddress.ip_network(f"{me}/24", strict=False)
    if net.num_addresses > 4096:
        sys.exit(f"{net} is too large; pass a smaller --subnet (max /20).")

    log = (lambda *a: print(*a, file=sys.stderr)) if args.json else print
    log(f"Phone IP: {me}   scanning {net} ...")

    devices = {}

    def dev(ip):
        return devices.setdefault(ip, {"ip": ip, "ports": [], "http": []})

    # 1+2: multicast discovery in parallel
    log("  - ONVIF WS-Discovery & SSDP/UPnP ...")
    with cf.ThreadPoolExecutor(2) as ex:
        f_ws = ex.submit(ws_discovery)
        f_ssdp = ex.submit(ssdp_discovery)
        onvif, ssdp = f_ws.result(), f_ssdp.result()
    for ip, info in onvif.items():
        dev(ip)["onvif"] = info
    for ip, info in ssdp.items():
        d = dev(ip)
        d["ssdp"] = {"server": info["server"], "location": info["location"]}
        if info["location"]:
            d["upnp"] = upnp_description(info["location"], 2)

    # 3: TCP sweep
    if not args.no_sweep:
        hosts = [str(h) for h in net.hosts() if str(h) != me]
        log(f"  - Port sweep of {len(hosts)} hosts on {len(ALL_PORTS)} ports ...")
        jobs = [(ip, p) for ip in hosts for p in ALL_PORTS]
        done = 0
        with cf.ThreadPoolExecutor(args.workers) as ex:
            futs = {ex.submit(tcp_open, ip, p, args.timeout): (ip, p) for ip, p in jobs}
            for f in cf.as_completed(futs):
                done += 1
                ip, p = futs[f]
                if f.result():
                    dev(ip)["ports"].append(p)
                if not args.json and done % 500 == 0:
                    print(f"\r    {done * 100 // len(jobs):3d}%", end="", flush=True)
        if not args.json:
            print("\r    100%")

    # 4: fingerprint
    devices.pop(me, None)
    log(f"  - Fingerprinting {len(devices)} responding devices ...")
    with cf.ThreadPoolExecutor(32) as ex:
        fps = {ip: ex.submit(fingerprint, ip, sorted(d["ports"]), args.timeout)
               for ip, d in devices.items()}
        names = {ip: ex.submit(reverse_dns, ip) for ip in devices}
    for ip, d in devices.items():
        d["ports"] = sorted(set(d["ports"]))
        fp = fps[ip].result()
        d["rtsp"] = fp["rtsp"]
        d["http"] = fp["http"]
        d["hostname"] = names[ip].result()
        d["kind"], d["vendor"], d["model"], d["reasons"] = classify(d)

    order = {"camera": 0, "possible": 1, "other": 2}
    rows = sorted(devices.values(),
                  key=lambda d: (order[d["kind"]], ipaddress.ip_address(d["ip"])))
    if not args.all:
        rows = [d for d in rows if d["kind"] != "other"]

    if args.json:
        print(json.dumps(rows, indent=2, default=list))
        return

    print()
    if not rows:
        print("No camera found. Tips: make sure the phone is on the same Wi-Fi (not guest"
              " network / client isolation), and try --all to see every device.")
        return
    for d in rows:
        tag = {"camera": "[CAMERA]  ", "possible": "[POSSIBLE]", "other": "[other]   "}[d["kind"]]
        print(f"{tag} {d['ip']:<15} {d['vendor'] or '?':<16} {d['model'][:40]}")
        if d["hostname"]:
            print(f"            hostname : {d['hostname']}")
        if d["ports"]:
            print(f"            ports    : {', '.join(map(str, d['ports']))}")
        if d["reasons"]:
            print(f"            why      : {', '.join(d['reasons'])}")
        if d.get("rtsp"):
            print(f"            stream   : rtsp://{d['ip']}:{d['rtsp']['port']}/  ({d['rtsp']['status']})")
        web = next((h for h in d["http"]), None)
        if web:
            scheme = "https" if web["port"] in (443, 8443) else "http"
            print(f"            web UI   : {scheme}://{d['ip']}:{web['port']}/")
        print()
    n = sum(1 for d in rows if d["kind"] == "camera")
    p = sum(1 for d in rows if d["kind"] == "possible")
    print(f"{n} camera(s), {p} possible camera(s) found.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")
