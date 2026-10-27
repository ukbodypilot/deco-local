# deco-local

Local control of TP-Link Deco mesh routers: no cloud, no app. A Python library, a small CLI, and an
[MCP](https://modelcontextprotocol.io) server so Claude (or any MCP client) can look at your mesh and,
carefully, change it.

```
(an illustration)
You:     Which of my Deco nodes is on wireless backhaul, and how good is its link?
Claude:  (mesh_overview) One node is: "Attic", an M5 hanging off "Hallway" over 5 GHz and
         2.4 GHz, both at signal 2 of 3. The other four are wired. Attic has 3 clients...
```

## What it does that others don't

- **Two interfaces, one answer.** The Deco has a control port (the TMP protocol the app uses, SSH on
  port 20001) and a local web interface on port 80. The control port can do far more, but it locks up:
  for 60-90 s after every write, and sometimes much longer. When it does, the reads the web interface
  also offers (nodes, clients, WAN, CPU/memory) come from there instead, reshaped into the same names
  and fields. Every read says which interface answered.
- **Writes are graded by evidence.** Each write is `verified` (proven live with a before/after
  read-back), `upstream` (seen in real app captures by pydeco-tmp, not re-tested), `noop` (proven to
  ACK and do nothing, like HomeShield's toggle) or `inferred` (an opcode-numbering guess). Anything not
  verified is refused unless you opt in, and every write returns the router's read-back, not just its
  ACK.
- **It knows the router's moods.** After a write the router drops the control port for ~60-90 s.
  Connecting during that window keeps it shut longer, so a shared lockout makes every caller on the
  machine (MCP server, scripts) wait instead of hammering it.
- **Safe to hand to an AI.** Secrets are redacted by default, refusals say why (so the model asks you
  instead of guessing), and `DECO_MCP_READONLY=1` gives a server with no write tools at all, for
  anything unattended.

## Tested on

- Deco **X55** (hardware 1.0, firmware 1.11.1) as the main router, with **M5** satellites.

The control port is on the *main* Deco only; it reports the whole mesh. Other Deco models very likely
speak the same protocol (the app is the same), but they haven't been tried. If you try one, please open
an issue with what worked.

## Credentials

The control port logs in with your **TP-Link account** email and password, the ones you use in the Deco
app. The Deco checks them itself, locally; nothing is sent to TP-Link's cloud. The web interface uses
the same password on app-managed Decos (`DECO_WEB_PASSWORD` if yours differs).

| Variable | |
|---|---|
| `DECO_HOST` | the main Deco's LAN address (default `192.168.68.1`, the Deco default) |
| `DECO_EMAIL` | TP-Link account email |
| `DECO_PASSWORD` | TP-Link account password |
| `DECO_WEB_PASSWORD` | optional, if the web interface password differs |
| `DECO_MCP_READONLY` | `1` for a read-only MCP server |
| `DECO_STATE_DIR` | optional; lockout state, the web session and the client-to-node map (default `~/.local/state/deco-local`) |

## Use it with Claude

Needs [uv](https://docs.astral.sh/uv/) (`uvx` runs it without installing anything permanently). Or `pip install deco-local`, which gives the `deco` and `deco-mcp` commands.

**Claude Code:**

```bash
claude mcp add deco -e DECO_HOST=192.168.68.1 -e DECO_EMAIL=you@example.com -e DECO_PASSWORD='...' \
  -- uvx --from deco-local deco-mcp
```

Add `-e DECO_MCP_READONLY=1` for a read-only server.

**Claude Desktop:** Settings, Developer, Edit Config, and add:

```json
{
  "mcpServers": {
    "deco": {
      "command": "uvx",
      "args": ["--from", "deco-local", "deco-mcp"],
      "env": {
        "DECO_HOST": "192.168.68.1",
        "DECO_EMAIL": "you@example.com",
        "DECO_PASSWORD": "...",
        "DECO_MCP_READONLY": "1"
      }
    }
  }
}
```

Leave out `DECO_MCP_READONLY` if you want Claude to be able to change settings. It will still refuse
unverified writes unless you say so.

**Things to ask:**

- "Give me an overview of my mesh." / "Which node is my laptop on, and how's its signal?"
- "Is any node on wireless backhaul? How strong is it?"
- "What firmware are my Decos on?" / "Show my DHCP reservations and port forwards."
- "Which clients are on 2.4 GHz?" / "What DNS servers is the router using?"
- "Turn the LED night mode on." (a verified write: Claude reads the setting, changes one field, writes
  it, and shows you the read-back)

### Tools

| Tool | |
|---|---|
| `mesh_overview` | nodes (online, backhaul, signal, upstream, firmware, client count) and online clients (node, band, signal) |
| `get_router_data` | one named read, secrets redacted; falls back to the web interface where it can |
| `list_reads` | every read name, and which the web fallback covers |
| `lockout_status` | whether the router is still applying a write (no router contact) |
| `get_router_data_unredacted` | a read with secrets included (not in read-only mode) |
| `router_snapshot` | every read in one paced pass, over a minute (not in read-only mode) |
| `list_writes` | every write with its tier and note (not in read-only mode) |
| `write_router_setting` | a write, with the read-back (not in read-only mode) |

## Library

```python
from deco_local import DecoClient, WRITE

with DecoClient("192.168.68.1", "you@example.com", "password") as deco:
    nodes = deco.get("device_list")["device_list"]
    led = deco.get("led_schedule")
    deco.set("led_set", dict(led, enable_night_mode=True), confirm=True)  # verified write
    print(deco.get("led_schedule")["enable_night_mode"])                  # read it back
# the control port is now locked ~60-90 s; deco_local.busy.wait() blocks until it is back

from deco_local import web
reads = web.snapshot("192.168.68.1", "password", ["device_list", "client_list"])  # web interface
```

The web interface is slow and its CPU climbs under a burst of requests, so `web.snapshot` spaces them `gap` seconds apart (default 1.5).
Which node each client is on costs one request per node, so only `probes` nodes (default 2) are re-asked per call, rotating: a roam
shows up after a few calls, not at once. A new client, or a map older than 6 h, rebuilds it all.

`DecoClient.set` needs `confirm=True`, and `allow_unverified=True` for anything but a verified write.
Reads come back in the router's own shapes; `deco_local/tmp.py` lists every read and write.

## CLI

```bash
deco reads                      # every read name
deco writes                     # every write and its tier
deco read device_list wps       # over the control port (JSON)
deco read --web client_list     # over the web interface
deco status                     # post-write lockout (no router contact)
```

The CLI only reads. Writes go through the library or the MCP server.

## Writes: what's known

Only `led_set` is verified so far. 12 more are `upstream` (seen in app captures, including UPnP,
DoH, DHCP reservations, DDNS, IPv6, WPS, 802.11r, DNS servers), one is a proven no-op, and the rest are
guesses from the opcode numbering. Verifying one is simple and the most useful contribution: read the
setting, write a harmless change, read it back, write the original back, and open an issue or PR
moving it to verified, with your model and firmware. Avoid WAN-affecting ones (`ipv6_set`,
`internet_backup_set`, `mac_clone_set`, `operation_mode_set`) unless you can get to the router
another way if it goes wrong.

## The lockout

Measured on the X55: a write ACKs and reads back within ~3 s; then the control port closes ~5-14 s
later and stays closed until ~64-95 s after the write. Probing every 0.5 s kept it shut longer, so the
watcher probes every 5 s. The control port has also been seen to stay closed for 45+ min after a
node reboot from the app, while the web interface kept working; that is what the fallback is for. The
lock is a small state file, so every process on the machine respects it. A short-lived script's
watcher dies with it; the lock then simply expires after 150 s.

## No warranty

This talks to your router with undocumented protocols. Reads are harmless; writes change real
settings, and unverified ones may do something unexpected. MIT licensed, as is.

## Credits

Built on two projects' protocol work. No code from either is used here; the clients are
reimplementations from their descriptions:

- [mthsg/pydeco-tmp](https://github.com/mthsg/pydeco-tmp) (MIT): the Deco TMP protocol (SSH
  transport, framing, login, opcode tables) and the app-capture list behind the `upstream` tier.
- [tplinkrouterc6u](https://github.com/AlexandrErohin/TP-Link-Archer-C6U) (GPL-3.0): the encrypted
  login of TP-Link's local web interface. Compared line by line: no code in common, only the protocol.

## License

MIT
