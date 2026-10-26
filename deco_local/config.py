"""Settings from the environment, and where deco-local keeps its small state files.

  DECO_HOST          the main Deco's LAN address (default 192.168.68.1, the Deco factory default)
  DECO_EMAIL         your TP-Link account email (what you log in to the Deco app with)
  DECO_PASSWORD      that account's password (DECO_ACCTPW is accepted too)
  DECO_WEB_PASSWORD  the local web interface's password, if different (it is the account password on
                     app-managed Decos)
  DECO_STATE_DIR     state files (lockout, web session); default $XDG_STATE_HOME/deco-local
                     or ~/.local/state/deco-local
"""
import os

DEFAULT_HOST = "192.168.68.1"


def host() -> str:
    return os.environ.get("DECO_HOST") or DEFAULT_HOST


def credentials() -> tuple[str, str, str]:
    """(host, email, password) for the control port. Raises RuntimeError naming what is missing."""
    email = os.environ.get("DECO_EMAIL")
    password = os.environ.get("DECO_PASSWORD") or os.environ.get("DECO_ACCTPW")
    missing = [n for n, v in (("DECO_EMAIL", email), ("DECO_PASSWORD", password)) if not v]
    if missing:
        raise RuntimeError(f"set {' and '.join(missing)} (your TP-Link account login)")
    return host(), email, password


def web_password() -> str:
    pw = os.environ.get("DECO_WEB_PASSWORD") or os.environ.get("DECO_PASSWORD") or os.environ.get("DECO_ACCTPW")
    if not pw:
        raise RuntimeError("set DECO_WEB_PASSWORD or DECO_PASSWORD")
    return pw


def state_path(name: str) -> str:
    base = os.environ.get("DECO_STATE_DIR") or os.path.join(
        os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "deco-local")
    os.makedirs(base, mode=0o700, exist_ok=True)
    return os.path.join(base, name)
