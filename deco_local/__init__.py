"""Local control of TP-Link Deco mesh routers, without the cloud or the app.

    from deco_local import DecoClient
    with DecoClient("192.168.68.1", "you@example.com", "account-password") as deco:
        deco.get("device_list")

tmp.py   the control port (TMP over SSH, port 20001): ~70 reads, tiered writes
web.py   the local web interface (:80): a read-only fallback for nodes, clients, WAN, CPU/memory
busy.py  the post-write lockout every caller on the machine shares
"""
from .busy import Busy
from .tmp import READ, SETTINGS, WRITE, DecoClient, DecoError

__all__ = ["Busy", "DecoClient", "DecoError", "READ", "SETTINGS", "WRITE"]
__version__ = "0.1.0"
