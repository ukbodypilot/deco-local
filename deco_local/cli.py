"""deco: read a Deco mesh from the command line (JSON out). Settings come from the environment
(DECO_HOST, DECO_EMAIL, DECO_PASSWORD -- see config.py).

  deco reads                 every read name
  deco writes                every write, with its tier (verified / upstream / noop / inferred)
  deco read NAME [NAME ...]  read values over the control port (secrets redacted)
  deco read --web NAME       read through the web interface instead (device_list, client_list,
                             client_list_speed, wan_lan_status, device_resource_info)
  deco status                post-write lockout state (no router contact)

Writes are deliberately not here: use the library (DecoClient.set) or the MCP server, which both
tier them and read back the result.
"""
import argparse
import json
import sys

from . import busy, config, tmp, web


def main(argv=None):
    ap = argparse.ArgumentParser(prog="deco", description="Read a TP-Link Deco mesh locally.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("reads")
    sub.add_parser("writes")
    sub.add_parser("status")
    r = sub.add_parser("read")
    r.add_argument("names", nargs="+")
    r.add_argument("--web", action="store_true", help="use the local web interface (fewer reads)")
    a = ap.parse_args(argv)

    if a.cmd == "reads":
        out = {"reads": sorted(tmp.READ), "web": list(web.WEB_READS)}
    elif a.cmd == "writes":
        out = {n: {"opcode": hex(op.code), "tier": op.tier, "note": op.note} for n, op in sorted(tmp.WRITE.items())}
    elif a.cmd == "status":
        out = busy.status()
    else:
        try:
            if a.web:
                out = web.snapshot(config.host(), config.web_password(), a.names)
            else:
                bad = [n for n in a.names if n not in tmp.READ]
                if bad:
                    ap.error(f"unknown read(s) {bad}; see `deco reads`")
                host, email, password = config.credentials()
                with tmp.DecoClient(host, email, password) as deco:
                    out = deco.snapshot(a.names)
        except (RuntimeError, ValueError, OSError, busy.Busy) as exc:
            print(f"deco: {exc}", file=sys.stderr)
            return 1
    json.dump(out, sys.stdout, indent=2, default=str)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
