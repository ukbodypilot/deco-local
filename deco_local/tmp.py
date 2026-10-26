"""
Deco TMP protocol client: local, no-cloud control of a TP-Link Deco mesh
over the SSH-tunnelled "Tether Management Protocol" the Deco app uses.
Reimplemented from the public protocol writeup of mthsg/pydeco-tmp
(https://github.com/mthsg/pydeco-tmp, MIT): opcode tables and framing only,
no code copied.

Auth: your TP-Link *account* email + password (not the admin web UI
password). Username on the SSH port is hex(SHA-1(email)).

Transport: SSH (dropbear) on TCP 20001 -> direct-tcpip channel to the
router's local TMP daemon at 127.0.0.1:20002.

Safety model:
  - get()/raw(opcode) with no params are reads: no state changes possible.
  - set(name, params, confirm=True) is a write. Every WRITE entry below is
    tagged "verified" (we proved it changes state and reverts cleanly) or
    "unverified" (the opcode exists in the public opcode-numbering pattern
    but nobody has confirmed what it actually does -- see homeshield,
    which ACKs with error_code 0 and silently does nothing).
  - set() refuses unverified writes unless allow_unverified=True, so a
    caller has to opt in with eyes open rather than trust a 200 that may
    be a no-op.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import time
import zlib
from dataclasses import dataclass
from typing import Any

import paramiko

from . import busy

TMP_PORT = 20001
TMP_LOCAL = ("127.0.0.1", 20002)
TMP_ORIGIN = ("127.0.0.1", 54321)
CRC_PLACEHOLDER = 0x5A6B7C8D
VER_BIZ = 2
PT_PUSH, PT_RESP, PT_PULL = 2, 5, 4
OP_ALLOC = 0x0001


class DecoError(RuntimeError):
    pass


@dataclass(frozen=True)
class Op:
    code: int
    verified: bool = False  # proved to actually change state, with read-back
    note: str = ""

    @property
    def tier(self) -> str:
        """verified | upstream (seen in app captures upstream) | noop (proved to do nothing) | inferred."""
        if self.verified:
            return "verified"
        if "NO-OP" in self.note:
            return "noop"
        if self.note.startswith("upstream-confirmed"):
            return "upstream"
        return "inferred"


# ---------------------------------------------------------------- reads
# Name -> opcode. All reads are safe (no params sent beyond config_version).
READ: dict[str, int] = {
    "system_info": 0x4001, "wan_lan_status": 0x4004, "ipv6": 0x4006,
    "wifi_bands_info": 0x4009, "device_list": 0x400F, "speedtest": 0x4010,
    "client_list": 0x4012, "client_list_speed": 0x4014, "blocked_list": 0x4018,
    "led_schedule": 0x401A, "messages": 0x4028, "iot_scan": 0x4040,
    "rooms": 0x4050, "scenes": 0x4070, "tasks": 0x4080,
    "operation_mode": 0x40A0, "port_forwarding": 0x40B0, "reservations": 0x40C0,
    "ddns": 0x40D0, "ieee_802_11r": 0x4208, "iptv_vlan": 0x420D,
    "lan_ip": 0x4211, "dhcp_server": 0x4213, "wps": 0x4215,
    "qos_bandwidth": 0x4219, "beamforming": 0x421B, "sip_alg": 0x421D,
    "monthly_report": 0x4222, "mac_clone": 0x4226, "dns_servers": 0x4228,
    "permissions": 0x4229, "device_list_speed": 0x422F, "dhcp_leases": 0x423D,
    "fixed_wan_port": 0x4242, "upnp": 0x424A, "network_quality": 0x4265,
    "homeshield": 0x4267, "parental_controls": 0x4270, "family_time": 0x4278,
    "timezone": 0x427C, "auto_update": 0x427E, "app_block_list": 0x428B,
    "cloud_service_state_check": 0x428F, "mac_clone_client_list": 0x4293,
    "static_routes": 0x4294, "system_routes": 0x4298, "reboot_schedule": 0x42E0,
    "wifi_bands": 0x42F0, "device_led_category": 0x42F7, "firmware": 0x4301,
    "client_isolation": 0x4302, "device_resource_info": 0x4317,
    "wireless_link": 0x4318, "time_machine": 0x432B, "family_care": 0x4330,
    "mlo": 0x43B0, "tss_device_list": 0x43BB, "cameras": 0x43BE,
    "blocked_period": 0x43C4, "doh": 0x43D0, "doh_dot_server_test": 0x43D3,
    "internet_backup": 0x43E0, "vpn_discover": 0x43E2, "vpn_config": 0x4360,
    "vpn_client_info": 0x4370, "dpi_qos": 0x4378, "usb_scan": 0x4380,
    "usb_devices": 0x4381, "usb_sharing": 0x4383, "privacy_policy": 0x4385,
    "access_control_mode": 0x4401, "access_control_white_list": 0x4403,
    "access_control_apply_list": 0x4406,
}

# Fields in these reads are secrets or otherwise shouldn't be echoed into
# logs, a web page, or an MCP tool response by default.
SENSITIVE_READ_FIELDS: dict[str, tuple[str, ...]] = {
    "vpn_config": ("private_key", "psk", "preshared_key"),
    "wifi_bands": ("password", "psk"),
    "wifi_bands_info": ("password", "psk"),
    "internet_backup": ("password",),  # hotspot_list[].password, base64 but still the password
}

# name -> Op(opcode, verified, note). "verified" = proven live on an X55
# (firmware 1.11.1) with a before/after read-back; "upstream-confirmed" = seen
# in real app captures by pydeco-tmp, not re-tested here; the rest follow the
# opcode-numbering pattern only and nobody has confirmed what they do.
WRITE: dict[str, Op] = {
    # -- verified live --
    "led_set": Op(0x401B, True, "toggled enable_night_mode true/false, read-back confirmed"),

    # -- README "confirmed" list (observed in real app captures upstream;
    #    not independently re-verified here) --
    "upnp_set": Op(0x424B, False, "upstream-confirmed, not re-tested here"),
    "doh_set": Op(0x43D1, False, "upstream-confirmed, not re-tested here"),
    "reservation_add": Op(0x40C1, False, "upstream-confirmed, not re-tested here"),
    "reservation_modify": Op(0x40C2, False, "upstream-confirmed, not re-tested here"),
    "reservation_remove": Op(0x40C3, False, "upstream-confirmed, not re-tested here"),
    "ddns_set": Op(0x40D1, False, "upstream-confirmed; touches DDNS, test carefully"),
    "internet_backup_set": Op(0x43E1, False, "upstream-confirmed; can affect WAN failover"),
    "ipv6_set": Op(0x4007, False, "upstream-confirmed; can affect WAN connectivity"),
    "guest_network_set": Op(0x4008, False, "upstream-confirmed, not re-tested here"),
    "wps_set": Op(0x4216, False, "upstream-confirmed, not re-tested here"),
    "ieee_802_11r_set": Op(0x4209, False, "upstream-confirmed, not re-tested here"),
    "dns_servers_set": Op(0x4011, False, "upstream-confirmed, not re-tested here"),

    # -- unconfirmed / inferred from opcode numbering only --
    "manager_roles_set": Op(0x422A, False, "inferred opcode, unconfirmed"),
    "homeshield_features_set": Op(0x43C6, False, "PROVED NO-OP: ACKs, read-back unchanged (likely cloud-subscription gated)"),
    "account_modify": Op(0x4038, False, "inferred opcode, unconfirmed"),
    "env_var_sync": Op(0x4204, False, "inferred opcode, unconfirmed"),
    "avira_scan_start": Op(0x4263, False, "inferred opcode, unconfirmed"),
    "avira_scan_stop": Op(0x4264, False, "inferred opcode, unconfirmed"),
    "data_analysis_set": Op(0x437E, False, "inferred opcode, unconfirmed"),
    "parental_owner_add": Op(0x4271, False, "inferred opcode, unconfirmed"),
    "parental_owner_remove": Op(0x4272, False, "inferred opcode, unconfirmed"),
    "parental_owner_modify": Op(0x4273, False, "inferred opcode, unconfirmed"),
    "parental_owner_bonus_add": Op(0x4274, False, "inferred opcode, unconfirmed"),
    "parental_ignore_owner_request": Op(0x4277, False, "inferred opcode, unconfirmed"),
    "family_time_set": Op(0x4279, False, "inferred opcode, unconfirmed"),
    "family_whitelist_add": Op(0x427A, False, "inferred opcode, unconfirmed"),
    "family_whitelist_remove": Op(0x427B, False, "inferred opcode, unconfirmed"),
    "dpi_app_limit_add": Op(0x428D, False, "inferred opcode, unconfirmed"),
    "dpi_app_limit_modify": Op(0x429D, False, "inferred opcode, unconfirmed"),
    "dpi_app_limit_remove": Op(0x429F, False, "inferred opcode, unconfirmed"),
    "qos_bandwidth_set": Op(0x421A, False, "inferred opcode, unconfirmed"),
    "dpi_qos_info_set": Op(0x4379, False, "inferred opcode, unconfirmed"),
    "dpi_qos_mode_item_remove": Op(0x437A, False, "inferred opcode, unconfirmed"),
    "port_forwarding_add": Op(0x40B1, False, "inferred opcode, unconfirmed"),
    "port_forwarding_modify": Op(0x40B2, False, "inferred opcode, unconfirmed"),
    "port_forwarding_delete": Op(0x40B3, False, "inferred opcode, unconfirmed"),
    "fixed_wan_port_set": Op(0x4243, False, "inferred opcode, unconfirmed"),
    "access_control_mode_set": Op(0x4402, False, "inferred opcode, unconfirmed"),
    "access_control_white_list_add": Op(0x4404, False, "inferred opcode, unconfirmed"),
    "access_control_white_list_remove": Op(0x4405, False, "inferred opcode, unconfirmed"),
    "access_control_apply_list_set": Op(0x4407, False, "inferred opcode, unconfirmed"),
    "camera_security_set": Op(0x43BF, False, "inferred opcode, unconfirmed"),
    "mac_clone_set": Op(0x4227, False, "inferred opcode, unconfirmed; risky, changes WAN MAC"),
    "operation_mode_set": Op(0x40A1, False, "inferred opcode, unconfirmed; HIGH RISK, can change router/AP mode"),
}


@dataclass(frozen=True)
class Setting:
    """One editable thing: a read name, how to write it back, and a risk tier."""
    read: str
    kind: str  # "object" (whole-object set) | "list" (add/modify/remove by id)
    write: str = ""          # kind == "object"
    add: str = ""            # kind == "list"
    modify: str = ""         # kind == "list"
    remove: str = ""         # kind == "list"
    id_field: str = ""       # kind == "list": the key identifying a row
    risk: str = "low"        # low | medium | high (WAN/connectivity-affecting)
    label: str = ""


# Editable settings: the read that shows a setting, the write(s) that change it, and a
# risk tier a UI (or an AI) can use to decide how much confirmation to ask for.
SETTINGS: dict[str, Setting] = {
    "led_schedule": Setting("led_schedule", "object", write="led_set", risk="low", label="LED schedule"),
    "dns_servers": Setting("dns_servers", "object", write="dns_servers_set", risk="low", label="DNS servers"),
    "wps": Setting("wps", "object", write="wps_set", risk="low", label="WPS"),
    "upnp": Setting("upnp", "object", write="upnp_set", risk="low", label="UPnP"),
    "doh": Setting("doh", "object", write="doh_set", risk="medium", label="DNS-over-HTTPS"),
    "ieee_802_11r": Setting("ieee_802_11r", "object", write="ieee_802_11r_set", risk="medium", label="802.11r fast roaming"),
    "ddns": Setting("ddns", "object", write="ddns_set", risk="medium", label="DDNS"),
    "ipv6": Setting("ipv6", "object", write="ipv6_set", risk="high", label="IPv6 (can affect WAN)"),
    "internet_backup": Setting("internet_backup", "object", write="internet_backup_set", risk="high", label="Internet backup / failover"),
    "qos_bandwidth": Setting("qos_bandwidth", "object", write="qos_bandwidth_set", risk="medium", label="QoS bandwidth (unverified write)"),
    "access_control_mode": Setting("access_control_mode", "object", write="access_control_mode_set", risk="medium", label="Access control mode (unverified write)"),
    "homeshield": Setting("homeshield", "object", write="homeshield_features_set", risk="low", label="HomeShield (known no-op -- see WRITE table note)"),

    "port_forwarding": Setting("port_forwarding", "list", add="port_forwarding_add",
                                modify="port_forwarding_modify", remove="port_forwarding_delete",
                                id_field="port_forwarding_id", risk="medium",
                                label="Port forwarding (unverified write)"),
    "reservations": Setting("reservations", "list", add="reservation_add",
                             modify="reservation_modify", remove="reservation_remove",
                             id_field="mac", risk="low", label="DHCP reservations"),
    "access_control_white_list": Setting("access_control_white_list", "list",
                                          add="access_control_white_list_add",
                                          remove="access_control_white_list_remove",
                                          id_field="mac", risk="medium",
                                          label="Access control list / block client (unverified write)"),
}


# ---------------------------------------------------------------- framing
def _tmp_wrap(seq: int, payload: bytes) -> bytes:
    header = struct.pack(">BBBBHBBI", 1, 1, 5, 0, len(payload), 0, 0, seq)
    packet = header + struct.pack(">I", CRC_PLACEHOLDER) + payload
    crc = zlib.crc32(packet) & 0xFFFFFFFF
    return packet[:12] + struct.pack(">I", crc) + packet[16:]


def _biz_wrap(opcode: int, ptype: int, txid: int, body: bytes, total: int, offset: int) -> bytes:
    crc = zlib.crc32(body) & 0xFFFFFFFF if body else 0
    header = struct.pack(">BBHBBHIII", 1, VER_BIZ, opcode, ptype, 0, txid, crc, total, offset)
    return header + body


def _recv_exact(chan, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = chan.recv(n - len(buf))
        if not chunk:
            raise DecoError("TMP channel closed unexpectedly")
        buf += chunk
    return buf


def _recv_tmp_packet(chan) -> bytes:
    while True:
        head4 = _recv_exact(chan, 4)
        ptype = head4[2]
        if ptype == 4:  # keep-alive ping -> pong
            chan.sendall(bytes([1, 1, 4, 0]))
            continue
        if ptype == 2:  # stray connect ack
            continue
        if ptype != 5:
            raise DecoError(f"unexpected TMP frame type {ptype}")
        rest = _recv_exact(chan, 12)
        plen = struct.unpack(">H", (head4 + rest)[4:6])[0]
        return _recv_exact(chan, plen) if plen else b""


class DecoClient:
    """
    with DecoClient(host, email, password) as deco:
        deco.get("dhcp_leases")
        deco.set("led_set", {...}, confirm=True)
    """

    def __init__(self, host: str, email: str, password: str, timeout: float = 10.0):
        self.host = host
        self.email = email
        self.password = password
        self.timeout = timeout
        self._ssh: paramiko.Transport | None = None
        self._chan = None
        self._seq = 1
        self._txid = 0
        self.token: str | None = None

    def __enter__(self) -> "DecoClient":
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()

    def connect(self, attempts: int = 3) -> None:
        # After a write the router closes this port for ~60-90 s (busy.py);
        # refuse up front instead of hammering it, which only prolongs the outage.
        busy.check()
        # The router serves one TMP session at a time, so two processes can
        # collide. Back off and retry rather than fail the whole request.
        for i in range(attempts):
            try:
                self._connect_once()
                return
            except (paramiko.SSHException, OSError, DecoError):
                self.close()
                if i == attempts - 1:
                    raise
                time.sleep(2 * (i + 1))

    def _connect_once(self) -> None:
        self._chan = None
        self._seq, self._txid = 1, 0
        username = hashlib.sha1(self.email.encode()).hexdigest()
        self._ssh = paramiko.Transport((self.host, TMP_PORT))
        self._ssh.banner_timeout = self.timeout
        self._ssh.connect(username=username, password=self.password)
        self._chan = self._ssh.open_channel("direct-tcpip", TMP_LOCAL, TMP_ORIGIN)
        if self._chan is None:
            raise DecoError("could not open direct-tcpip channel to the TMP daemon")
        self._chan.settimeout(self.timeout)
        self.token = self._alloc()

    def close(self) -> None:
        try:
            if self._chan:
                self._chan.close()
        finally:
            if self._ssh:
                self._ssh.close()

    def _alloc(self) -> str:
        body = _biz_wrap(OP_ALLOC, PT_PUSH, 0, b"", 0, 0)
        self._chan.sendall(_tmp_wrap(self._seq, body))
        resp = _recv_tmp_packet(self._chan)
        return resp[20:].decode("ascii", errors="replace")

    def _call(self, opcode: int, params: dict | None = None) -> Any:
        self._txid = (self._txid + 1) & 0xFFFF
        txid = self._txid
        self._seq += 1
        body_dict: dict[str, Any] = {"config_version": int(time.time() * 1000)}
        if params is not None:
            body_dict["params"] = params
        payload = json.dumps(body_dict, separators=(",", ":")).encode()
        req = _biz_wrap(opcode, PT_PUSH, txid, payload, len(payload), 0)
        self._chan.sendall(_tmp_wrap(self._seq, req))

        buf = b""
        total = None
        while True:
            pkt = _recv_tmp_packet(self._chan)
            hdr = pkt[:20]
            _, _, ropcode, ptype, err, rtxid, _crc, rtotal, _offset = struct.unpack(">BBHBBHIII", hdr)
            if rtxid != txid:
                continue  # async traffic for a different request
            if err != 0:
                raise DecoError(f"TMP error_code={err} for opcode 0x{opcode:04X}")
            if ptype != PT_RESP:
                raise DecoError(f"unexpected business ptype={ptype}")
            buf += pkt[20:]
            total = rtotal
            if total == 0 or len(buf) >= total:
                break
            self._seq += 1
            pull = _biz_wrap(ropcode, PT_PULL, txid, b"", 0, len(buf))
            self._chan.sendall(_tmp_wrap(self._seq, pull))

        if not buf:
            return None
        doc = json.loads(buf.decode("utf-8", errors="replace"))
        if isinstance(doc, dict) and doc.get("error_code", 0) != 0:
            raise DecoError(f"router error_code={doc['error_code']} for opcode 0x{opcode:04X}")
        return doc.get("result", doc) if isinstance(doc, dict) else doc

    # -------------------------------------------------------------- public
    def get(self, name: str, *, reveal_secrets: bool = False) -> Any:
        if name not in READ:
            raise KeyError(f"unknown read: {name}")
        result = self._call(READ[name])
        return result if reveal_secrets else redact(name, result)

    def raw(self, opcode: int, params: dict | None = None) -> Any:
        """Escape hatch: call any opcode directly. Passing params makes it a write.
        Not redacted -- the caller is bypassing the name table, so there's no name
        to redact by."""
        return self._call(opcode, params)

    def set(self, name: str, params: dict, *, confirm: bool = False, allow_unverified: bool = False) -> Any:
        if name not in WRITE:
            raise KeyError(f"unknown write: {name}")
        op = WRITE[name]
        if not confirm:
            raise DecoError(f"write '{name}' refused: pass confirm=True")
        if not op.verified and not allow_unverified:
            raise DecoError(
                f"write '{name}' is UNVERIFIED ({op.note}); pass allow_unverified=True to try it anyway"
            )
        result = self._call(op.code, params)
        # The session stays usable for the caller's read-back; new connections are locked
        # until the router has finished applying (it drops the port a few seconds from now).
        busy.begin(name, self.host)
        return result

    def snapshot(self, names: list[str] | None = None, gap: float = 0.0) -> dict[str, Any]:
        """Read every (or a chosen subset of) READ opcodes; failures are recorded, not raised.
        `gap` seconds between reads: back-to-back reads were suspected of the port closing for 45+ min
        once, so a scheduled sweep should pace itself (1 s is plenty)."""
        out: dict[str, Any] = {}
        for i, name in enumerate(names or sorted(READ, key=lambda n: READ[n])):
            if i and gap > 0:
                time.sleep(gap)
            t0 = time.monotonic()
            try:
                out[name] = {"ok": True, "result": self.get(name)}
            except Exception as exc:  # noqa: BLE001 - want every opcode's own error captured
                out[name] = {"ok": False, "error": str(exc)}
            out[name]["ms"] = round((time.monotonic() - t0) * 1000)  # for the collect log's slowest reads
        return out


def redact(name: str, result: Any) -> Any:
    """Strip known-sensitive fields (VPN private keys, Wi-Fi passwords) before this
    leaves the process -- into a log, a web page, or an MCP tool response."""
    fields = SENSITIVE_READ_FIELDS.get(name)
    if not fields or not isinstance(result, dict):
        return result

    def scrub(obj):
        if isinstance(obj, dict):
            return {k: ("***REDACTED***" if k in fields else scrub(v)) for k, v in obj.items()}
        if isinstance(obj, list):
            return [scrub(v) for v in obj]
        return obj

    return scrub(result)
