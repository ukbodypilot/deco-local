"""MCP server: a TP-Link Deco mesh as tools for Claude (or any MCP client).

  deco-mcp                      after `pip install deco-local`
  python -m deco_local.mcp_server

Environment: DECO_HOST, DECO_EMAIL, DECO_PASSWORD (see config.py); DECO_MCP_READONLY=1 for a
read-only server (no writes, no unredacted read, no full snapshot) -- the right choice for anything
unattended.

Safety model:
  - Reads are always safe. Secrets (Wi-Fi passwords, VPN keys) are redacted unless the unredacted
    tool is used.
  - Writes marked unverified are refused unless the caller passes allow_unverified=True, and the
    refusal says why, so the model can ask the user.
  - Every write returns the router's read-back (`after`), not just its ACK: some writes ACK and do
    nothing.
  - After a write the router locks the control port for ~60-90 s; calls in that window are refused
    with a retry time instead of hammering the port (which keeps it shut longer).
  - When the control port is unavailable (locked, refused, timing out), the reads the local web
    interface also offers come from there instead; every read says which interface answered.
"""
from __future__ import annotations

import base64
import contextlib
import os
from typing import Any

import paramiko
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import busy, config, tmp, web

READONLY = os.environ.get("DECO_MCP_READONLY", "").lower() in ("1", "true", "yes")

_COMMON = (
    "Every read returns {source, result}: source is 'tmp' (the control port) or 'web' (the local web "
    "interface, used when the control port is unavailable; it offers fewer reads). Start with "
    "mesh_overview for questions about nodes, backhaul or which client is where. Each call logs in to "
    "the router, so prefer one targeted read over a full sweep."
)
server = MCPServer(
    name="deco",
    instructions=(
        "Read-only view of a TP-Link Deco mesh on the local network (no cloud). " + _COMMON if READONLY else
        "Local control of a TP-Link Deco mesh (no cloud, no app). Reads are always safe. Writes: "
        "list_writes marks each one verified (proven live to change state) or not; an unverified write "
        "may ACK and silently do nothing, or do something other than its name suggests, so ask the user "
        "before passing allow_unverified. Always report the `after` value a write returns, not just "
        "that it succeeded. Every write locks the router for ~60-90 s. " + _COMMON
    ),
)


def _full(fn):
    """Register fn as a tool unless this server runs read-only."""
    return fn if READONLY else server.tool()(fn)


def _unavailable(exc: BaseException) -> bool:
    """The control port itself is out (locked, refused, timing out), as opposed to a bad request."""
    return isinstance(exc, (busy.Busy, OSError, EOFError, paramiko.SSHException))


@contextlib.contextmanager
def _router():
    """A connected control-port client; failures reach the model as ToolError with their reason (the MCP
    SDK shows any other exception only as "Error executing tool ...")."""
    try:
        host, email, password = config.credentials()
        with tmp.DecoClient(host, email, password) as deco:
            yield deco
    except ToolError:
        raise
    except Exception as exc:  # noqa: BLE001 - router, network and refusal errors all go to the caller
        raise ToolError(f"{type(exc).__name__}: {exc}") from exc


def _read(names: list[str], reveal_secrets: bool = False) -> tuple[str, dict, str | None]:
    """(source, {name: result}, why the web interface was used) -- control port first, web fallback."""
    try:
        host, email, password = config.credentials()
        with tmp.DecoClient(host, email, password) as deco:
            return "tmp", {n: deco.get(n, reveal_secrets=reveal_secrets) for n in names}, None
    except Exception as exc:  # noqa: BLE001
        if not _unavailable(exc) or not set(names) <= set(web.WEB_READS):
            raise ToolError(f"{type(exc).__name__}: {exc}") from exc
        why = f"control port unavailable ({type(exc).__name__}: {exc})"
    try:
        got = web.snapshot(config.host(), config.web_password(), names)
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"{why}; web interface also failed: {type(exc).__name__}: {exc}") from exc
    failed = {n: v["error"] for n, v in got.items() if not v["ok"]}
    if failed:
        raise ToolError(f"{why}; web interface: {failed}")
    return "web", {n: v["result"] for n, v in got.items()}, why


def _known_read(name: str) -> None:
    if name not in tmp.READ:
        raise ToolError(f"unknown read '{name}'; call list_reads for valid names")


def _text(v) -> str:
    """Deco names are sometimes base64 (custom nicknames, client names)."""
    if not isinstance(v, str) or not v:
        return ""
    try:
        d = base64.b64decode(v, validate=True).decode("utf-8")
        if d.isprintable() and len(v) % 4 == 0:
            return d
    except ValueError:
        pass
    return v


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


@server.tool()
def list_reads() -> dict:
    """Every read this router exposes (client list, Wi-Fi config, QoS, port forwarding, DHCP, VPN config,
    firmware, ...), and which of them the web-interface fallback can also provide. Use get_router_data
    to read one."""
    return {"reads": sorted(tmp.READ), "web_fallback": list(web.WEB_READS)}


@server.tool()
def get_router_data(name: str) -> dict:
    """Read one named value from the Deco (see list_reads). Secrets (Wi-Fi passwords, VPN private keys)
    are redacted. Returns {source, result} and, when the web interface answered, why."""
    _known_read(name)
    source, res, why = _read([name])
    return {"source": source, "result": res[name], **({"fallback_reason": why} if why else {})}


@server.tool()
def mesh_overview() -> dict:
    """The mesh at a glance: each node (name, model, online, wired or wireless backhaul with signal 0-3,
    upstream node, IP, firmware, client count) and each online client (name, IP, node, band, signal).
    Two reads, with the web-interface fallback."""
    source, res, why = _read(["device_list", "client_list"])
    raw = (res["device_list"] or {}).get("device_list") or []
    name_of = {}
    for n in raw:
        if n.get("nickname") == "custom":
            nick = _text(n.get("custom_nickname"))
        else:  # a preset room: the control port gives its key ("master_bedroom"), the web interface a label
            nick = (n.get("nickname") or "").replace("_", " ")
            nick = nick.title() if nick.islower() else nick
        name_of[n.get("device_id")] = nick or n.get("device_model") or n.get("mac") or "?"
    clients = []
    per_node: dict[str, int] = {}
    for c in (res["client_list"] or {}).get("client_list") or []:
        if not c.get("online"):
            continue
        li = c.get("linked_device_info") or {}
        band = next((b for b in li.get("connection_type") or [] if b != "wired"), None)
        node = name_of.get(li.get("device_id"))
        if node:
            per_node[node] = per_node.get(node, 0) + 1
        nm = _text(c.get("name"))
        clients.append({"name": "" if nm.lower() == "none" else nm, "ip": c.get("ip"), "mac": c.get("mac"),
                        "node": node, "band": "wired" if c.get("wire_type") == "wired" else band,
                        "signal_dbm": (li.get("signal_strength") or {}).get(band) if band else None})
    nodes = []
    for n in raw:
        ct = n.get("connection_type") or []
        nm = name_of.get(n.get("device_id"))
        main = n.get("role") == "master"
        nodes.append({
            "name": nm, "model": n.get("device_model"), "main": main,
            "online": n.get("group_status") == "connected", "ip": n.get("ip") or n.get("device_ip"),
            "backhaul": None if main or not ct else ("wired" if "wired" in ct else "wireless"),
            "signal": None if main or "wired" in ct else
            {b: _int((n.get("signal_level") or {}).get(b)) for b in ct if b != "wired"} or None,
            "upstream": None if main else name_of.get(n.get("parent_device_id")),
            "firmware": (n.get("software_ver") or "").split(" ")[0] or None,
            "clients": per_node.get(nm, 0),
        })
    out = {"source": source, "nodes": nodes, "clients": clients,
           "note": "backhaul signal is 0-3 (3 best); client signal is dBm (above -65 is good)"}
    if why:
        out["fallback_reason"] = why
    return out


@server.tool()
def lockout_status() -> dict:
    """Whether the router is still applying a write (control port locked), and how the last lockout
    went. No router contact."""
    return busy.status()


@_full
def get_router_data_unredacted(name: str) -> dict:
    """Like get_router_data but includes secrets (e.g. Wi-Fi passwords, a WireGuard private key). Only
    use this when the user specifically needs the secret, and don't write it anywhere without asking."""
    _known_read(name)
    with _router() as deco:
        return {"source": "tmp", "result": deco.get(name, reveal_secrets=True)}


@_full
def router_snapshot() -> dict:
    """Read every known value in one pass (~70 reads, paced 1 s apart, so over a minute). Heavy on the
    router; use get_router_data for what you actually need."""
    with _router() as deco:
        return deco.snapshot(gap=1.0)


@_full
def list_writes() -> list[dict]:
    """Every write this server can attempt: verified (proven live with a read-back), upstream (seen in
    real app captures, not re-tested), noop (proven to do nothing) or inferred (opcode-numbering guess),
    with a note."""
    return [{"name": name, "opcode": hex(op.code), "tier": op.tier, "note": op.note}
            for name, op in sorted(tmp.WRITE.items())]


@_full
def write_router_setting(name: str, params: dict, allow_unverified: bool = False) -> dict:
    """Write a setting (see list_writes). Pass the whole object as read from the matching read, with
    your change made (e.g. read led_schedule, flip enable_night_mode, send it to led_set). Refuses
    unverified writes unless allow_unverified=True -- ask the user first. Returns the read-back
    (`after`); report that, not just success. The router then locks for ~60-90 s."""
    if name not in tmp.WRITE:
        raise ToolError(f"unknown write '{name}'; call list_writes for valid names")
    op = tmp.WRITE[name]
    if not op.verified and not allow_unverified:
        raise ToolError(f"write '{name}' is {op.tier.upper()} ({op.note}); ask the user, then pass "
                        "allow_unverified=True to try it anyway")
    read_name = next((r for r, s in tmp.SETTINGS.items() if name in (s.write, s.add, s.modify, s.remove)), None)
    with _router() as deco:
        result = deco.set(name, params, confirm=True, allow_unverified=allow_unverified)
        try:
            after = deco.get(read_name) if read_name else None
        except Exception as exc:  # noqa: BLE001 - the write went through; say so, not "failed"
            after = {"read_back_error": f"{type(exc).__name__}: {exc}"}
    return {"write_result": result, "read_back": read_name, "after": after,
            "note": "The router now refuses new connections for ~60-90 s while it applies this "
                    "(see lockout_status)."}


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
