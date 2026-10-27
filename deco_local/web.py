"""Read-only client for the Deco's local web interface (HTTP :80), the fallback when the TMP
control port (20001, tmp.py) refuses connections.

Why this exists: the Deco's TMP service has been seen to stay down for 45+ min after a node
reboot from the app (refused for every host on the LAN) while the admin web page on :80 kept
working. The web interface carries a smaller set of data, but it includes the node list (with each
node's upstream), the client list (with each client's node), WAN and CPU/memory. snapshot()
reshapes it into the same read names and shapes tmp.py returns, so callers don't care which
interface answered.

Protocol (the LuCI-style login TP-Link's own web UI uses, as described below and checked against an
X55; first learned from the tplinkrouterc6u project, https://github.com/AlexandrErohin/TP-Link-Archer-C6U,
whose code is not used here):
  1. POST /cgi-bin/luci/;stok=/login?form=keys&operation=read  -> RSA key (n, e) for the password
  2. POST /cgi-bin/luci/;stok=/login?form=auth&operation=read  -> RSA key (n, e) for signing + seq
  3. POST /cgi-bin/luci/;stok=/login?form=login   sign=..&data=..
       data = base64(AES-128-CBC(json)), key/iv = 16 random hex chars each, PKCS#7 padding
       json = {"params": {"password": hex(RSA-PKCS1v15(password))}, "operation": "login"}
       sign = hex(RSA-PKCS1v15(chunk)) for each 53-char chunk of
              "k=<key>&i=<iv>&h=<md5(admin+password)>&s=<seq + len(data)>"
     -> encrypted {"error_code":0,"result":{"stok":...}} plus a sysauth cookie
  4. POST /cgi-bin/luci/;stok=<stok>/<path>  same encryption; sign drops the k=&i= part
Only "read" operations are sent from here. Writes stay on TMP, where they're tiered and verified.

Sessions are reused across runs (config.state_path("web_session-<host>.json"), mode 600: stok, sysauth cookie, AES
key/iv, seq, signing key) and a fresh login happens only when the router rejects them. Logging in is the
slow step on a busy gateway (RSA on its CPU; one timed out at 10 s), and every login may also sign a
browser out of the admin page.

"""
import base64
import contextlib
import hashlib
import http.cookiejar
import json
import os
import secrets
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


from . import config

# Reads snapshot() can produce, under tmp.py's names
WEB_READS = ("device_list", "client_list", "client_list_speed", "wan_lan_status", "device_resource_info")


class DecoWebError(RuntimeError):
    pass


class SessionExpired(DecoWebError):
    pass


LAST = {}  # how the last session() got in: {"login": "reused" | "new" | "new (saved one rejected)"}


def _rsa_hex(data: str, n_hex: str, e_hex: str) -> str:
    key = rsa.RSAPublicNumbers(int(e_hex, 16), int(n_hex, 16)).public_key()
    return key.encrypt(data.encode(), padding.PKCS1v15()).hex()


class DecoWeb:
    def __init__(self, host: str, password: str, username: str = "admin", timeout: float = 20.0):
        self.base = f"http://{host}/cgi-bin/luci/;stok="
        self.password, self.username, self.timeout = password, username, timeout
        self._key = secrets.token_hex(8).encode()  # 16 ASCII chars, used directly as the AES key
        self._iv = secrets.token_hex(8).encode()
        self._hash = hashlib.md5((username + password).encode()).hexdigest()
        self._jar = http.cookiejar.CookieJar()
        self._open = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._jar)).open
        self._stok = None
        self._seq = None
        self._sign_key = None

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, *exc):
        self.logout()

    # ---------------------------------------------------------------- crypto
    def _aes(self, raw: str) -> str:
        b = raw.encode()
        pad = 16 - len(b) % 16
        enc = Cipher(algorithms.AES(self._key), modes.CBC(self._iv)).encryptor()
        return base64.b64encode(enc.update(b + bytes([pad]) * pad) + enc.finalize()).decode()

    def _unaes(self, data: str) -> dict:
        dec = Cipher(algorithms.AES(self._key), modes.CBC(self._iv)).decryptor()
        out = dec.update(base64.b64decode(data)) + dec.finalize()
        out = out[:-out[-1]] if out else out
        return json.loads(out.decode("utf-8", "ignore"))

    def _sign(self, data_len: int, login: bool) -> str:
        s = (f"k={self._key.decode()}&i={self._iv.decode()}&" if login else "") + f"h={self._hash}&s={self._seq + data_len}"
        return "".join(_rsa_hex(s[i:i + 53], *self._sign_key) for i in range(0, len(s), 53))

    # ---------------------------------------------------------------- http
    def _post(self, url: str, form: dict | None = None) -> dict:
        body = urllib.parse.urlencode(form).encode() if form is not None else b""
        req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json"})
        try:
            with self._open(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8", "ignore"))
        except OSError as exc:
            raise DecoWebError(f"{url.split(';stok=')[-1].split('?')[0] or 'login'}: {exc}") from exc

    def _encrypted(self, path: str, payload: dict, login: bool = False) -> dict:
        data = self._aes(json.dumps(payload))
        resp = self._post(self.base + (self._stok or "") + "/" + path, {"sign": self._sign(len(data), login), "data": data})
        if "data" not in resp:
            if not login and resp.get("error_code") not in (None, 0):
                raise SessionExpired(f"{path}: session rejected ({resp.get('error_code')})")
            raise DecoWebError(f"{path}: unencrypted reply {str(resp)[:200]}")
        try:
            out = self._unaes(resp["data"])
        except (ValueError, IndexError) as exc:  # wrong key/iv: the router dropped our session
            raise SessionExpired(f"{path}: reply not decryptable with this session") from exc
        if out.get("error_code") in (-40401, -40403, -40402) or out.get("errorcode") in (-40401,):
            raise SessionExpired(f"{path}: session rejected ({out.get('error_code')})")
        if out.get("error_code") != 0:
            raise DecoWebError(f"{path}: error_code {out.get('error_code')} {str(out)[:200]}")
        return out.get("result") or {}

    # ---------------------------------------------------------------- session
    def login(self):
        keys = self._post(self.base + "/login?form=keys&operation=read").get("result") or {}
        auth = self._post(self.base + "/login?form=auth&operation=read").get("result") or {}
        try:
            pwd_key = keys["password"]
            self._sign_key = auth["key"]
            self._seq = int(auth["seq"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DecoWebError(f"login: unexpected key exchange {keys} {auth}") from exc
        res = self._encrypted("login?form=login",
                              {"params": {"password": _rsa_hex(self.password, *pwd_key)}, "operation": "login"},
                              login=True)
        self._stok = res.get("stok")
        if not self._stok:
            raise DecoWebError("login: no stok in reply (wrong password?)")
        return self

    def logout(self):
        if self._stok:
            try:
                self._encrypted("admin/system?form=logout", {"operation": "logout"})
            except DecoWebError:
                pass
            self._stok = None

    def read(self, path: str, params: dict | None = None) -> dict:
        payload = {"operation": "read"}
        if params:
            payload["params"] = params
        return self._encrypted(path, payload)

    # ---------------------------------------------------------------- saved session
    def save(self, path=None):
        sysauth = next((c.value for c in self._jar if c.name == "sysauth"), None)
        if not (self._stok and sysauth):
            return
        path = path or self._session_path()
        tmp = path + ".tmp"
        with open(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump({"stok": self._stok, "sysauth": sysauth, "key": self._key.decode(), "iv": self._iv.decode(),
                       "seq": self._seq, "sign_key": self._sign_key, "hash": self._hash}, f)
        os.replace(tmp, path)

    def _session_path(self):
        return config.state_path(f"web_session-{urllib.parse.urlparse(self.base).hostname}.json")

    def restore(self, path=None) -> bool:
        try:
            with open(path or self._session_path()) as f:
                s = json.load(f)
        except (OSError, ValueError):
            return False
        if s.get("hash") != self._hash:  # password changed since
            return False
        self._stok, self._seq, self._sign_key = s["stok"], s["seq"], s["sign_key"]
        self._key, self._iv = s["key"].encode(), s["iv"].encode()
        host = urllib.parse.urlparse(self.base.split("/cgi-bin")[0]).hostname
        self._jar.set_cookie(http.cookiejar.Cookie(0, "sysauth", s["sysauth"], None, False, host, False, False, "/",
                                                   True, False, None, False, None, None, {}))
        return True

    # ---------------------------------------------------------------- reads
    def devices(self):
        return self.read("admin/device?form=device_list").get("device_list", [])

    def clients(self):
        return self.read("admin/client?form=client_list", {"device_mac": "default"}).get("client_list", [])

    def wan(self):
        return self.read("admin/network?form=wan_ipv4")

    def performance(self):
        return self.read("admin/network?form=performance")


@contextlib.contextmanager
def session(host: str, password: str):
    """A logged-in DecoWeb, reusing the saved session when the router still accepts it."""
    web = DecoWeb(host, password)
    if web.restore():
        try:
            web.read("admin/network?form=performance")  # cheap check that the session is alive
            LAST["login"] = "reused"
        except DecoWebError:  # expired, or answered with an HTTP error: start over
            web = DecoWeb(host, password).login()
            LAST["login"] = "new (saved one rejected)"
    else:
        web.login()
        LAST["login"] = "new"
    try:
        yield web
    finally:
        web.save()


class _Skip(Exception):
    """A read that wasn't asked for."""


def _ok(result):
    return {"ok": True, "result": result, "_at": time.monotonic()}


def _err(exc):
    return {"ok": False, "error": f"web fallback: {exc}", "_at": time.monotonic()}


NODE_MAP_TTL = 21600  # s before the whole client->node map is rebuilt
NODE_MAP_MIN_AGE = 600  # s; a client the map has never seen forces a rebuild only if the map is older than this


def _node_map_path():
    return config.state_path("web_nodes.json")


def _load_node_map():
    try:
        with open(_node_map_path()) as f:
            m = json.load(f)
        return m["at"], m["node_of"], set(m.get("seen", [])), m.get("cursor", 0)
    except (OSError, ValueError, KeyError):
        return 0, {}, set(), 0


def snapshot(host: str, password: str, names=None, gap: float = 1.5, probes: int = 2) -> dict:
    """Read what the web interface offers, reshaped into tmp.py's read names and shapes (WEB_READS:
    device_list, client_list, client_list_speed, wan_lan_status, device_resource_info), as
    {name: {"ok": True, "result": ...} | {"ok": False, "error": ...}, each with "ms"} like
    tmp.DecoClient.snapshot(). `names` limits it to some of those; the node list is always read,
    since the others need it to name the main node and each client's node.

    The router is slow to answer and a burst of requests pushes its CPU very high, so requests are
    `gap` seconds apart. Which node each client is on costs one request per node, so the map is
    kept in the state dir and only `probes` nodes are re-asked per call, rotating (a roam shows up
    after a few calls, not at once); a new client, or a map older than NODE_MAP_TTL, rebuilds it
    all. probes=0 only rebuilds."""
    want = set(names or WEB_READS)
    bad = want - set(WEB_READS)
    if bad:
        raise ValueError(f"not available from the web interface: {sorted(bad)}; it offers {list(WEB_READS)}")
    reads = {}
    started = time.monotonic()
    first = [True]

    def pace():
        if not first[0] and gap:
            time.sleep(gap)
        first[0] = False

    with session(host, password) as web:
        try:
            pace()
            devs = web.devices()
            by_mac = {d.get("mac"): d for d in devs}
            # the web list gives the master no device_id, but its children name it as their parent
            parents = [d.get("parent_device_id") for d in devs if d.get("role") != "master" and d.get("parent_device_id")]
            for d in devs:
                if d.get("role") == "master" and not d.get("device_id"):
                    d["device_id"] = max(set(parents), key=parents.count) if parents else d.get("mac")
            for d in devs:
                d.setdefault("ip", d.get("device_ip", ""))
                if d.get("role") == "master":
                    d.setdefault("parent_device_id", d.get("device_id"))
                elif "parent_device_id" not in d and d.get("previous") in by_mac:
                    d["parent_device_id"] = by_mac[d["previous"]].get("device_id")
            reads["device_list"] = _ok({"device_list": devs})
        except DecoWebError as exc:
            reads["device_list"] = _err(exc)
        try:
            if not want & {"client_list", "client_list_speed"}:
                raise _Skip
            pace()
            cl = web.clients()
            # The full list doesn't say which node a client is on; asking per node does
            # (device_mac=<node mac>; the per-node lists add up to the full one).
            at, node_of, seen, cursor = _load_node_map()
            age = time.time() - at
            unknown = any(c.get("mac") not in seen for c in cl)  # "seen", not node_of: a client no node list names must not force a rebuild every call
            nodes = [d for d in (reads.get("device_list", {}).get("result") or {}).get("device_list", [])
                     if d.get("group_status") in (None, "connected")]
            rebuild = age > NODE_MAP_TTL or (unknown and age > NODE_MAP_MIN_AGE)
            if rebuild:
                node_of, picked, cursor = {}, nodes, 0
            elif nodes and probes:
                picked = [nodes[(cursor + i) % len(nodes)] for i in range(min(probes, len(nodes)))]
                cursor = (cursor + len(picked)) % len(nodes)
            else:
                picked = []
            ok = True
            for d in picked:
                try:
                    pace()
                    for c in web.read("admin/client?form=client_list", {"device_mac": d.get("mac")}).get("client_list", []):
                        node_of[c.get("mac")] = d.get("device_id")
                except DecoWebError:
                    ok = False
            if picked and (ok or not rebuild):
                try:
                    path = _node_map_path()
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    with open(path, "w") as f:
                        json.dump({"at": time.time() if rebuild else at, "node_of": node_of, "cursor": cursor,
                                   "seen": [c.get("mac") for c in cl]}, f)
                except OSError:
                    pass
            speeds = []
            for c in cl:
                band = c.get("connection_type")
                if isinstance(band, str):  # web gives one band as a string; TMP gives linked_device_info
                    c.setdefault("linked_device_info", {"connection_type": [band] if band and band != "wired" else ["wired"]})
                if c.get("mac") in node_of:
                    c.setdefault("linked_device_info", {})["device_id"] = node_of[c["mac"]]
                speeds.append({"mac": c.get("mac"), "down_speed": c.get("down_speed"), "up_speed": c.get("up_speed")})
            reads["client_list"] = _ok({"client_list": cl})
            reads["client_list_speed"] = _ok({"client_list_speed": speeds})
        except _Skip:
            pass
        except DecoWebError as exc:
            reads["client_list"], reads["client_list_speed"] = _err(exc), _err(exc)
        try:
            if "wan_lan_status" in want:
                pace()
                reads["wan_lan_status"] = _ok(web.wan())
        except DecoWebError as exc:
            reads["wan_lan_status"] = _err(exc)
        try:
            if "device_resource_info" not in want:
                raise _Skip
            pace()
            p = web.performance()
            master = next((d.get("device_id") for d in (reads.get("device_list", {}).get("result") or {}).get("device_list", [])
                           if d.get("role") == "master"), None)
            mem = p.get("mem_usage")
            mem_pct = round(mem * 100, 1) if isinstance(mem, (int, float)) and mem <= 1 else mem
            cpu = p.get("cpu_usage")
            cpu_pct = round(cpu * 100) if isinstance(cpu, (int, float)) and cpu <= 1 else cpu
            # percentages only (no MB); memory_total 100 keeps usage/total a percentage
            reads["device_resource_info"] = _ok({"device_list": [{"device_id": master, "cpu_usage": cpu_pct,
                                                                  "memory_usage": mem_pct, "memory_total": 100,
                                                                  "percent_only": True}], "raw": p})
        except _Skip:
            pass
        except DecoWebError as exc:
            reads["device_resource_info"] = _err(exc)
    # each read's time = since the one before (the first includes the login), like tmp.py's "ms"
    prev = started
    for v in sorted(reads.values(), key=lambda v: v["_at"]):
        at = v.pop("_at")
        v["ms"] = round((at - prev) * 1000)
        prev = at
    return {k: v for k, v in reads.items() if k in want}

