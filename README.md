# camera — list the Wi-Fi cameras on your network from your phone

`scan_cameras.py` finds IP / Wi-Fi cameras (and NVR/DVR recorders) on the Wi-Fi
network your phone is connected to. It needs only Python and its standard
library, and works without root on Android (tested target: **Pixel 8a**).

## Run it on the Pixel 8a (Termux)

1. Install **Termux** from F-Droid (https://f-droid.org/packages/com.termux/)
   or GitHub. The Play Store version is outdated.
2. In Termux:
   ```sh
   pkg update && pkg install python git
   git clone https://github.com/nicope13/camera.git
   cd camera
   python scan_cameras.py
   ```
   (Or skip git: copy `scan_cameras.py` to the phone and run
   `python scan_cameras.py`.)
3. Keep Wi-Fi on and the screen awake while it runs (about 20–60 s for a /24 network).

Example output:

```
[CAMERA]   192.168.1.42    Hikvision        DS-2CD2143G0-I
            ports    : 80, 554, 8000
            why      : ONVIF, RTSP:554, Hikvision SDK:8000, banner
            stream   : rtsp://192.168.1.42:554/  (RTSP/1.0 401 Unauthorized)
            web UI   : http://192.168.1.42:80/

[POSSIBLE] 192.168.1.57    TP-Link Tapo     Tapo C200
...
2 camera(s), 1 possible camera(s) found.
```

### Options

| Option | Meaning |
|---|---|
| `--subnet 192.168.1.0/24` | scan this range instead of the auto-detected /24 |
| `--all` | also list devices that don't look like cameras |
| `--json` | JSON output |
| `--no-sweep` | ONVIF/UPnP discovery only (a few seconds, finds less) |
| `--timeout 1.0` | longer TCP timeout for a slow Wi-Fi network |

## How it detects cameras

Android 10 and later hides the ARP table and MAC addresses from apps, so the
script can't identify devices by manufacturer MAC prefix. It uses network
protocols instead:

1. **ONVIF WS-Discovery** (UDP 3702 multicast). Most IP cameras and NVRs
   answer, often with their name and model.
2. **SSDP/UPnP** (UDP 1900). Reads the device description: manufacturer and model.
3. **TCP port sweep** of the subnet on camera ports: RTSP 554/8554, Hikvision
   8000, Dahua 37777, XMeye 34567, Tapo ONVIF 2020, RTMP 1935, …
4. **Fingerprinting**: an RTSP `OPTIONS` request and the HTTP `Server` header,
   page title, and auth realm, checked against known vendor names.

`[CAMERA]` means a strong signal (ONVIF, a working RTSP server, or a
camera-only vendor port). `[POSSIBLE]` means only a keyword or an RTSP port matched.

## Limitations

- **Cloud-only cameras** (Ring, Nest, Arlo, Blink, many Wyze/Eufy models) open
  no local ports and don't answer ONVIF. They may show only with `--all` as an
  unknown device, or not at all. Your router's device list (or an app such as
  Fing) is the best way to spot those, because it can see MAC addresses.
- A **guest network** or "AP/client isolation" blocks the phone from seeing
  other devices.
- Only scan networks you own or have permission to scan.
